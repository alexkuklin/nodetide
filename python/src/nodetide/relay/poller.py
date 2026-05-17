"""Relay poller - fetches updates from distribution points."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from nodetide.core.storage import Storage
from nodetide.core.identity import Sigchain

logger = logging.getLogger(__name__)


@dataclass
class RelayPoller:
    """Polls distribution points for identity and message updates."""

    storage: Storage
    poll_interval: int = 300  # Default 5 minutes
    _running: bool = False
    _suspended: bool = False
    _task: asyncio.Task | None = None
    _poll_now_event: asyncio.Event = field(default_factory=asyncio.Event)

    async def start(self) -> None:
        """Start the polling loop."""
        if self._running:
            return

        self._running = True
        self._suspended = self.storage.get_relay_config("polling_suspended") == "1"

        # Load poll interval from config
        interval_str = self.storage.get_relay_config("poll_interval")
        if interval_str:
            self.poll_interval = int(interval_str)

        self._task = asyncio.create_task(self._poll_loop())
        logger.info(f"Relay poller started (interval={self.poll_interval}s, suspended={self._suspended})")

    async def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Relay poller stopped")

    def suspend(self) -> None:
        """Suspend polling without stopping."""
        self._suspended = True
        self.storage.set_relay_config("polling_suspended", "1")
        logger.info("Relay polling suspended")

    def resume(self) -> None:
        """Resume polling."""
        self._suspended = False
        self.storage.set_relay_config("polling_suspended", "0")
        self._poll_now_event.set()  # Trigger immediate poll
        logger.info("Relay polling resumed")

    def trigger_poll(self) -> None:
        """Trigger an immediate poll."""
        self._poll_now_event.set()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_suspended(self) -> bool:
        return self._suspended

    def set_interval(self, seconds: int) -> None:
        """Set the polling interval."""
        self.poll_interval = seconds
        self.storage.set_relay_config("poll_interval", str(seconds))
        logger.info(f"Relay poll interval set to {seconds}s")

    def get_status(self) -> dict[str, Any]:
        """Get poller status."""
        identities = self.storage.list_relayed_identities()
        return {
            "running": self._running,
            "suspended": self._suspended,
            "poll_interval": self.poll_interval,
            "identities_count": len(identities),
            "identities": [
                {
                    "identity_hash": i["identity_hash"],
                    "distribution_points": i.get("distribution_points", []),
                    "last_polled_at": i.get("last_polled_at"),
                    "last_poll_success": i.get("last_poll_success"),
                    "poll_error": i.get("poll_error"),
                }
                for i in identities
            ],
        }

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                # Wait for interval or trigger
                try:
                    await asyncio.wait_for(
                        self._poll_now_event.wait(),
                        timeout=self.poll_interval,
                    )
                    self._poll_now_event.clear()
                except asyncio.TimeoutError:
                    pass

                if not self._running:
                    break

                if self._suspended:
                    continue

                await self._poll_all_identities()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Error in poll loop: {e}")
                await asyncio.sleep(60)  # Wait before retry

    async def _poll_all_identities(self) -> None:
        """Poll all relayed identities."""
        identities = self.storage.list_relayed_identities()

        if not identities:
            return

        logger.debug(f"Polling {len(identities)} relayed identities")

        async with aiohttp.ClientSession() as session:
            for identity in identities:
                identity_hash = identity["identity_hash"]
                distribution_points = identity.get("distribution_points") or []

                if not distribution_points:
                    # Try to get distribution points from stored sigchain
                    sigchain = self.storage.get_sigchain(identity_hash)
                    if sigchain:
                        for event in sigchain.events:
                            if hasattr(event, 'distribution_points') and event.distribution_points:
                                distribution_points = event.distribution_points
                        if distribution_points:
                            self.storage.update_relayed_identity_distribution_points(
                                identity_hash, distribution_points
                            )

                if not distribution_points:
                    logger.debug(f"No distribution points for {identity_hash[:16]}...")
                    continue

                await self._poll_identity(session, identity_hash, distribution_points)

    async def _poll_identity(
        self,
        session: aiohttp.ClientSession,
        identity_hash: str,
        distribution_points: list[str],
    ) -> None:
        """Poll a single identity from its distribution points."""
        for dp in distribution_points:
            try:
                # Fetch sigchain
                sigchain_url = f"{dp.rstrip('/')}/api/identities/{identity_hash}"
                async with session.get(sigchain_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        # Parse and verify sigchain
                        if "sigchain" in data and data["sigchain"]:
                            new_sigchain = Sigchain.from_list(data["sigchain"])
                            valid, error = new_sigchain.verify()

                            if not valid:
                                logger.warning(f"Invalid sigchain from {dp}: {error}")
                                continue

                            # Check if we need to update
                            existing = self.storage.get_sigchain(identity_hash)
                            if not existing or len(new_sigchain.events) > len(existing.events):
                                self.storage.save_sigchain(new_sigchain)
                                logger.info(f"Updated sigchain for {identity_hash[:16]}... ({len(new_sigchain.events)} events)")

                        # Update distribution points if found in sigchain
                        if "sigchain" in data:
                            for event in data["sigchain"]:
                                if event.get("distribution_points"):
                                    self.storage.update_relayed_identity_distribution_points(
                                        identity_hash, event["distribution_points"]
                                    )

                        self.storage.update_relayed_identity_poll(identity_hash, success=True)

                        # Fetch messages
                        await self._fetch_messages(session, dp, identity_hash)

                        return  # Success, no need to try other distribution points

                    elif resp.status == 404:
                        logger.debug(f"Identity not found at {dp}")
                    else:
                        logger.warning(f"Error fetching from {dp}: {resp.status}")

            except asyncio.TimeoutError:
                logger.warning(f"Timeout polling {dp}")
            except aiohttp.ClientError as e:
                logger.warning(f"Error polling {dp}: {e}")
            except Exception as e:
                logger.exception(f"Unexpected error polling {dp}: {e}")

        # All distribution points failed
        self.storage.update_relayed_identity_poll(
            identity_hash,
            success=False,
            error="All distribution points failed",
        )

    async def _fetch_messages(
        self,
        session: aiohttp.ClientSession,
        distribution_point: str,
        identity_hash: str,
    ) -> None:
        """Fetch messages for an identity from a distribution point."""
        try:
            messages_url = f"{distribution_point.rstrip('/')}/api/messages?sender={identity_hash}&limit=100"
            async with session.get(messages_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    messages = data.get("messages", [])

                    for msg in messages:
                        # Check if we already have this message
                        msg_hash = msg.get("message_hash")
                        if not msg_hash:
                            # Compute hash if not provided
                            import hashlib
                            import json
                            msg_hash = hashlib.sha256(
                                json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
                            ).hexdigest()

                        existing = self.storage.get_message(msg_hash)
                        if not existing:
                            self.storage.save_message(
                                message_hash=msg_hash,
                                bundle_json=json.dumps(msg),
                                sender_identity=msg.get("sender", identity_hash),
                                recipient_identity=None,
                                message_type=msg.get("type", "public"),
                                created_at=msg.get("created_at", 0),
                            )
                            logger.debug(f"Saved message {msg_hash[:16]}... from {identity_hash[:16]}...")

        except Exception as e:
            logger.warning(f"Error fetching messages from {distribution_point}: {e}")
