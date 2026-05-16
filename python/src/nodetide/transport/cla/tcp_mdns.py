"""TCP CLA with mDNS discovery for local networks."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, Awaitable

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf
from zeroconf.asyncio import AsyncZeroconf

from nodetide.transport.bundle import Bundle
from nodetide.transport.cla.base import CLA, CLAConfig, PeerInfo


logger = logging.getLogger(__name__)

SERVICE_TYPE = "_nodetide._tcp.local."
DEFAULT_PORT = 4556


@dataclass
class TcpMdnsConfig(CLAConfig):
    """Configuration for TCP/mDNS CLA."""

    port: int = DEFAULT_PORT
    bind_address: str = "0.0.0.0"
    service_name: str | None = None  # auto-generated if None
    announce: bool = True  # whether to announce via mDNS


@dataclass
class TcpPeer:
    """Internal peer tracking."""

    info: PeerInfo
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    last_activity: int = 0


class MdnsListener(ServiceListener):
    """Listener for mDNS service discovery."""

    def __init__(self, cla: TcpMdnsCLA):
        self.cla = cla

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is discovered."""
        asyncio.create_task(self._handle_service(zc, type_, name))

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is removed."""
        logger.debug(f"Service removed: {name}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a service is updated."""
        asyncio.create_task(self._handle_service(zc, type_, name))

    async def _handle_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle discovered service."""
        info = zc.get_service_info(type_, name)
        if info:
            await self.cla._on_service_discovered(info)


class TcpMdnsCLA(CLA):
    """TCP Convergence Layer Adapter with mDNS discovery."""

    def __init__(
        self,
        node_identity: str,
        config: TcpMdnsConfig | None = None,
    ):
        self.node_identity = node_identity
        self.config = config or TcpMdnsConfig()

        self._running = False
        self._server: asyncio.Server | None = None
        self._zeroconf: AsyncZeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._service_info: ServiceInfo | None = None

        self._peers: dict[str, TcpPeer] = {}  # address -> peer
        self._bundle_queue: asyncio.Queue[tuple[Bundle, PeerInfo]] = asyncio.Queue()
        self._bundle_handler: Callable[[Bundle, PeerInfo], Awaitable[None]] | None = None

    @property
    def cla_type(self) -> str:
        return "tcp_mdns"

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start the TCP server and mDNS discovery."""
        if self._running:
            return

        # Start TCP server
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.config.bind_address,
            self.config.port,
        )
        actual_port = self._server.sockets[0].getsockname()[1]
        self.config.port = actual_port

        # Start mDNS
        self._zeroconf = AsyncZeroconf()

        if self.config.announce:
            # Register our service
            service_name = self.config.service_name or f"nodetide-{self.node_identity[:8]}"
            self._service_info = ServiceInfo(
                SERVICE_TYPE,
                f"{service_name}.{SERVICE_TYPE}",
                port=actual_port,
                properties={
                    "identity": self.node_identity,
                    "version": "1",
                },
            )
            await self._zeroconf.async_register_service(self._service_info)

        # Start browsing for other services
        self._browser = ServiceBrowser(
            self._zeroconf.zeroconf,
            SERVICE_TYPE,
            MdnsListener(self),
        )

        self._running = True
        logger.info(f"TCP/mDNS CLA started on port {actual_port}")

    async def stop(self) -> None:
        """Stop the CLA."""
        if not self._running:
            return

        self._running = False

        # Close all peer connections
        for peer in list(self._peers.values()):
            await self._close_peer(peer)
        self._peers.clear()

        # Stop mDNS
        if self._browser:
            self._browser.cancel()
            self._browser = None

        if self._service_info and self._zeroconf:
            await self._zeroconf.async_unregister_service(self._service_info)

        if self._zeroconf:
            await self._zeroconf.async_close()
            self._zeroconf = None

        # Stop TCP server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        logger.info("TCP/mDNS CLA stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming TCP connection."""
        addr = writer.get_extra_info("peername")
        address = f"{addr[0]}:{addr[1]}"
        logger.debug(f"New connection from {address}")

        peer = TcpPeer(
            info=PeerInfo(
                node_identity=None,
                address=address,
                cla_type=self.cla_type,
                connected_at=int(time.time()),
            ),
            reader=reader,
            writer=writer,
            last_activity=int(time.time()),
        )
        self._peers[address] = peer

        try:
            await self._receive_loop(peer)
        except Exception as e:
            logger.debug(f"Connection error from {address}: {e}")
        finally:
            await self._close_peer(peer)
            self._peers.pop(address, None)

    async def _receive_loop(self, peer: TcpPeer) -> None:
        """Receive bundles from a peer."""
        reader = peer.reader
        if not reader:
            return

        while self._running:
            try:
                # Read length prefix (4 bytes, big endian)
                length_bytes = await reader.readexactly(4)
                length = struct.unpack(">I", length_bytes)[0]

                if length > 10 * 1024 * 1024:  # 10MB limit
                    logger.warning(f"Bundle too large from {peer.info.address}: {length}")
                    break

                # Read bundle data
                data = await reader.readexactly(length)
                peer.last_activity = int(time.time())

                # Parse bundle
                try:
                    bundle = Bundle.from_bytes(data)

                    # Update peer identity if we learn it
                    if peer.info.node_identity is None:
                        peer.info.node_identity = bundle.sender

                    # Queue or handle bundle
                    if self._bundle_handler:
                        await self._bundle_handler(bundle, peer.info)
                    else:
                        await self._bundle_queue.put((bundle, peer.info))

                except Exception as e:
                    logger.warning(f"Failed to parse bundle from {peer.info.address}: {e}")

            except asyncio.IncompleteReadError:
                break
            except asyncio.CancelledError:
                break

    async def _close_peer(self, peer: TcpPeer) -> None:
        """Close a peer connection."""
        if peer.writer:
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
            peer.writer = None
        peer.reader = None

    async def _connect_to_peer(self, host: str, port: int) -> TcpPeer | None:
        """Connect to a peer."""
        address = f"{host}:{port}"

        if address in self._peers:
            return self._peers[address]

        try:
            reader, writer = await asyncio.open_connection(host, port)

            peer = TcpPeer(
                info=PeerInfo(
                    node_identity=None,
                    address=address,
                    cla_type=self.cla_type,
                    connected_at=int(time.time()),
                ),
                reader=reader,
                writer=writer,
                last_activity=int(time.time()),
            )
            self._peers[address] = peer

            # Start receive loop in background
            asyncio.create_task(self._receive_loop_with_cleanup(peer, address))

            return peer

        except Exception as e:
            logger.debug(f"Failed to connect to {address}: {e}")
            return None

    async def _receive_loop_with_cleanup(self, peer: TcpPeer, address: str) -> None:
        """Receive loop with cleanup on exit."""
        try:
            await self._receive_loop(peer)
        finally:
            await self._close_peer(peer)
            self._peers.pop(address, None)

    async def _on_service_discovered(self, info: ServiceInfo) -> None:
        """Handle a discovered mDNS service."""
        if not info.addresses:
            return

        # Get identity from properties
        identity = info.properties.get(b"identity", b"").decode("utf-8")

        # Don't connect to ourselves
        if identity == self.node_identity:
            return

        # Connect to the discovered peer
        host = info.parsed_addresses()[0]
        port = info.port

        peer = await self._connect_to_peer(host, port)
        if peer and identity:
            peer.info.node_identity = identity
            logger.debug(f"Discovered peer: {identity[:8]}... at {host}:{port}")

    async def send(self, bundle: Bundle, peer: PeerInfo) -> bool:
        """Send a bundle to a specific peer."""
        tcp_peer = self._peers.get(peer.address)
        if not tcp_peer or not tcp_peer.writer:
            return False

        return await self._send_to_peer(bundle, tcp_peer)

    async def _send_to_peer(self, bundle: Bundle, peer: TcpPeer) -> bool:
        """Send a bundle to a TCP peer."""
        if not peer.writer:
            return False

        try:
            data = bundle.to_bytes()
            length = struct.pack(">I", len(data))

            peer.writer.write(length + data)
            await peer.writer.drain()
            peer.last_activity = int(time.time())
            return True

        except Exception as e:
            logger.debug(f"Failed to send to {peer.info.address}: {e}")
            return False

    async def broadcast(self, bundle: Bundle) -> int:
        """Broadcast a bundle to all connected peers."""
        sent = 0
        for peer in list(self._peers.values()):
            if await self._send_to_peer(bundle, peer):
                sent += 1
        return sent

    def get_peers(self) -> list[PeerInfo]:
        """Get list of connected peers."""
        return [p.info for p in self._peers.values()]

    async def receive(self) -> AsyncIterator[tuple[Bundle, PeerInfo]]:
        """Async iterator for received bundles."""
        while self._running:
            try:
                bundle, peer_info = await asyncio.wait_for(
                    self._bundle_queue.get(),
                    timeout=1.0,
                )
                yield bundle, peer_info
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def connect_to(self, host: str, port: int) -> PeerInfo | None:
        """Explicitly connect to a peer."""
        peer = await self._connect_to_peer(host, port)
        return peer.info if peer else None
