"""Abstract base class for Convergence Layer Adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Callable, Awaitable

from nodetide.transport.bundle import Bundle


@dataclass
class PeerInfo:
    """Information about a connected peer."""

    node_identity: str | None  # may not know until handshake
    address: str
    cla_type: str
    connected_at: int


@dataclass
class CLAConfig:
    """Base configuration for CLAs."""

    enabled: bool = True


class CLA(ABC):
    """Abstract Convergence Layer Adapter.

    CLAs handle the actual transport of bundles over a specific medium.
    """

    @property
    @abstractmethod
    def cla_type(self) -> str:
        """Return the CLA type identifier."""
        ...

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Check if the CLA is running."""
        ...

    @abstractmethod
    async def start(self) -> None:
        """Start the CLA (begin listening/discovery)."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop the CLA."""
        ...

    @abstractmethod
    async def send(self, bundle: Bundle, peer: PeerInfo) -> bool:
        """Send a bundle to a specific peer.

        Returns True if sent successfully.
        """
        ...

    @abstractmethod
    async def broadcast(self, bundle: Bundle) -> int:
        """Broadcast a bundle to all connected peers.

        Returns number of peers sent to.
        """
        ...

    @abstractmethod
    def get_peers(self) -> list[PeerInfo]:
        """Get list of currently connected/known peers."""
        ...

    @abstractmethod
    async def receive(self) -> AsyncIterator[tuple[Bundle, PeerInfo]]:
        """Async iterator for received bundles."""
        ...

    def set_bundle_handler(
        self,
        handler: Callable[[Bundle, PeerInfo], Awaitable[None]],
    ) -> None:
        """Set callback for received bundles.

        Alternative to using receive() iterator.
        """
        self._bundle_handler = handler

    async def _handle_bundle(self, bundle: Bundle, peer: PeerInfo) -> None:
        """Internal: handle a received bundle."""
        if hasattr(self, "_bundle_handler"):
            await self._bundle_handler(bundle, peer)
