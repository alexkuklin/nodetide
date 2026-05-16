"""Background relay daemon."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web

from nodetide.core.identity import Identity, Sigchain
from nodetide.core.storage import Storage
from nodetide.transport.bundle import Bundle, BundleType, BundleQueue
from nodetide.transport.cla.base import PeerInfo
from nodetide.transport.cla.tcp_mdns import TcpMdnsCLA, TcpMdnsConfig


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DaemonState:
    """State of the running daemon."""

    identity: Identity
    storage: Storage
    cla: TcpMdnsCLA | None = None
    bundle_queue: BundleQueue = field(default_factory=BundleQueue)
    running: bool = False
    stats: dict[str, int] = field(default_factory=lambda: {
        "bundles_received": 0,
        "bundles_sent": 0,
        "peers_connected": 0,
    })


class Daemon:
    """Main daemon class."""

    def __init__(
        self,
        identity: Identity,
        storage: Storage,
        port: int = 4556,
    ):
        self.state = DaemonState(identity=identity, storage=storage)
        self.port = port
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the daemon."""
        logger.info(f"Starting daemon for identity {self.state.identity.identity_hash[:16]}...")

        # Initialize CLA
        config = TcpMdnsConfig(port=self.port)
        self.state.cla = TcpMdnsCLA(
            node_identity=self.state.identity.identity_hash,
            config=config,
        )

        # Set bundle handler
        self.state.cla.set_bundle_handler(self._handle_bundle)

        # Start CLA
        await self.state.cla.start()
        self.state.running = True

        logger.info(f"Daemon started on port {self.port}")

        # Start background tasks
        await asyncio.gather(
            self._process_queue(),
            self._cleanup_expired(),
            self._wait_for_shutdown(),
        )

    async def stop(self) -> None:
        """Stop the daemon."""
        logger.info("Stopping daemon...")
        self.state.running = False

        if self.state.cla:
            await self.state.cla.stop()

        self.state.storage.close()
        logger.info("Daemon stopped")

    async def _wait_for_shutdown(self) -> None:
        """Wait for shutdown signal."""
        await self._shutdown_event.wait()
        await self.stop()

    def shutdown(self) -> None:
        """Signal shutdown."""
        self._shutdown_event.set()

    async def _handle_bundle(self, bundle: Bundle, peer: PeerInfo) -> None:
        """Handle a received bundle."""
        logger.debug(f"Received bundle from {peer.node_identity or peer.address}: {bundle.bundle_type}")
        self.state.stats["bundles_received"] += 1

        # Check expiration
        if bundle.is_expired:
            logger.debug(f"Bundle expired, discarding")
            return

        # Handle by type
        if bundle.bundle_type == BundleType.REVOCATION:
            await self._handle_revocation(bundle)
        elif bundle.bundle_type == BundleType.SIGCHAIN:
            await self._handle_sigchain(bundle)
        elif bundle.bundle_type == BundleType.MESSAGE:
            await self._handle_message(bundle)
        elif bundle.bundle_type == BundleType.CONTENT_ANNOUNCE:
            await self._handle_content_announce(bundle)
        elif bundle.bundle_type == BundleType.DELIVERY_ACK:
            await self._handle_delivery_ack(bundle)
        else:
            logger.debug(f"Unknown bundle type: {bundle.bundle_type}")

        # Store for potential relay
        if not bundle.is_broadcast and bundle.recipient != self.state.identity.identity_hash:
            self.state.bundle_queue.push(bundle)

    async def _handle_revocation(self, bundle: Bundle) -> None:
        """Handle a revocation bundle - highest priority."""
        logger.info(f"Received revocation from {bundle.sender[:16]}...")

        # Get existing sigchain
        sigchain = self.state.storage.get_sigchain(bundle.sender)
        if not sigchain:
            logger.warning(f"No sigchain for {bundle.sender}, cannot process revocation")
            return

        # TODO: Apply revocation event to sigchain

        # Broadcast to other peers
        if self.state.cla:
            await self.state.cla.broadcast(bundle)

    async def _handle_sigchain(self, bundle: Bundle) -> None:
        """Handle a sigchain sync bundle."""
        logger.debug(f"Received sigchain from {bundle.sender[:16]}...")

        # Parse sigchain from payload
        try:
            events = bundle.payload.get("events", [])
            sigchain = Sigchain.from_list(events)

            # Verify
            valid, error = sigchain.verify()
            if not valid:
                logger.warning(f"Invalid sigchain from {bundle.sender}: {error}")
                return

            # Save
            self.state.storage.save_sigchain(sigchain)
            logger.info(f"Saved sigchain for {sigchain.identity_hash[:16]}...")

        except Exception as e:
            logger.warning(f"Failed to process sigchain: {e}")

    async def _handle_message(self, bundle: Bundle) -> None:
        """Handle a message bundle."""
        # Check if for us
        if bundle.recipient == self.state.identity.identity_hash:
            logger.info(f"Received message from {bundle.sender[:16]}...")

            # Save message
            self.state.storage.save_message(
                message_hash=bundle.bundle_hash,
                bundle_json=bundle.to_json(),
                sender_identity=bundle.sender,
                recipient_identity=bundle.recipient,
                message_type=bundle.bundle_type.value,
                created_at=bundle.created,
                received_at=int(time.time()),
                status="received",
            )

            # Send delivery ack if requested
            # TODO: Check request_receipt in payload

        elif bundle.is_broadcast:
            logger.debug(f"Received broadcast from {bundle.sender[:16]}...")
            # Save broadcast
            self.state.storage.save_message(
                message_hash=bundle.bundle_hash,
                bundle_json=bundle.to_json(),
                sender_identity=bundle.sender,
                recipient_identity=None,
                message_type=bundle.bundle_type.value,
                created_at=bundle.created,
                received_at=int(time.time()),
                status="received",
            )

    async def _handle_content_announce(self, bundle: Bundle) -> None:
        """Handle a content announcement."""
        logger.debug(f"Received content announcement from {bundle.sender[:16]}...")
        # TODO: Store content manifest

    async def _handle_delivery_ack(self, bundle: Bundle) -> None:
        """Handle a delivery acknowledgment."""
        logger.debug(f"Received delivery ack from {bundle.sender[:16]}...")
        # TODO: Update message status

    async def _process_queue(self) -> None:
        """Process queued bundles for relay."""
        while self.state.running:
            # Remove expired
            expired = self.state.bundle_queue.remove_expired()
            if expired:
                logger.debug(f"Removed {expired} expired bundles")

            # Try to deliver queued bundles
            bundle = self.state.bundle_queue.peek()
            if bundle and self.state.cla:
                # Check if we have a route to recipient
                for peer in self.state.cla.get_peers():
                    if peer.node_identity == bundle.recipient:
                        # Found direct route
                        if await self.state.cla.send(bundle, peer):
                            self.state.bundle_queue.pop()
                            self.state.stats["bundles_sent"] += 1
                            logger.debug(f"Delivered bundle to {bundle.recipient[:16]}...")
                        break

            await asyncio.sleep(1)

    async def _cleanup_expired(self) -> None:
        """Periodic cleanup of expired data."""
        while self.state.running:
            await asyncio.sleep(60)
            self.state.bundle_queue.remove_expired()

    def get_status(self) -> dict[str, Any]:
        """Get daemon status."""
        peers = []
        if self.state.cla:
            peers = [
                {
                    "address": p.address,
                    "identity": p.node_identity,
                    "connected_at": p.connected_at,
                }
                for p in self.state.cla.get_peers()
            ]

        return {
            "running": self.state.running,
            "identity": self.state.identity.identity_hash,
            "port": self.port,
            "peers": peers,
            "queue_size": len(self.state.bundle_queue),
            "stats": self.state.stats,
        }

    async def send_message(
        self,
        recipient: str,
        payload: dict[str, Any],
    ) -> str | None:
        """Send a message bundle."""
        if not self.state.cla:
            return None

        bundle = Bundle.create(
            keypair=self.state.identity.local_keypair,
            sender_identity=self.state.identity.identity_hash,
            recipient=recipient,
            bundle_type=BundleType.MESSAGE,
            payload=payload,
        )

        # Try direct delivery first
        for peer in self.state.cla.get_peers():
            if peer.node_identity == recipient:
                if await self.state.cla.send(bundle, peer):
                    self.state.stats["bundles_sent"] += 1
                    return bundle.bundle_hash

        # Queue for later delivery
        self.state.bundle_queue.push(bundle)
        return bundle.bundle_hash

    async def broadcast_sigchain(self) -> int:
        """Broadcast our sigchain to all peers."""
        if not self.state.cla:
            return 0

        bundle = Bundle.create(
            keypair=self.state.identity.local_keypair,
            sender_identity=self.state.identity.identity_hash,
            recipient="*",
            bundle_type=BundleType.SIGCHAIN,
            payload={"events": self.state.identity.sigchain.to_list()},
        )

        sent = await self.state.cla.broadcast(bundle)
        self.state.stats["bundles_sent"] += sent
        return sent


# HTTP API for local control


def create_api_app(daemon: Daemon) -> web.Application:
    """Create aiohttp application for local API."""

    async def handle_status(request: web.Request) -> web.Response:
        return web.json_response(daemon.get_status())

    async def handle_send(request: web.Request) -> web.Response:
        data = await request.json()
        recipient = data.get("recipient")
        payload = data.get("payload")

        if not recipient or not payload:
            return web.json_response({"error": "Missing recipient or payload"}, status=400)

        bundle_hash = await daemon.send_message(recipient, payload)
        if bundle_hash:
            return web.json_response({"bundle_hash": bundle_hash})
        else:
            return web.json_response({"error": "Failed to send"}, status=500)

    async def handle_broadcast_sigchain(request: web.Request) -> web.Response:
        sent = await daemon.broadcast_sigchain()
        return web.json_response({"sent_to": sent})

    async def handle_peers(request: web.Request) -> web.Response:
        if daemon.state.cla:
            peers = [
                {
                    "address": p.address,
                    "identity": p.node_identity,
                    "connected_at": p.connected_at,
                }
                for p in daemon.state.cla.get_peers()
            ]
            return web.json_response({"peers": peers})
        return web.json_response({"peers": []})

    app = web.Application()
    app.router.add_get("/status", handle_status)
    app.router.add_post("/send", handle_send)
    app.router.add_post("/broadcast-sigchain", handle_broadcast_sigchain)
    app.router.add_get("/peers", handle_peers)

    return app


async def run_daemon(
    identity: Identity,
    storage: Storage,
    port: int = 4556,
    api_port: int = 4557,
) -> None:
    """Run the daemon with HTTP API."""
    daemon = Daemon(identity=identity, storage=storage, port=port)

    # Setup signal handlers
    loop = asyncio.get_event_loop()

    def signal_handler():
        daemon.shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    # Create API app
    api_app = create_api_app(daemon)

    # Start API server
    runner = web.AppRunner(api_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", api_port)

    try:
        await site.start()
        logger.info(f"API server started on http://127.0.0.1:{api_port}")

        # Start daemon
        await daemon.start()

    finally:
        await runner.cleanup()
