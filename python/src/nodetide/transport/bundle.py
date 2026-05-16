"""Bundle format for transport layer.

Single bundle type with in-band type field for flexibility.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nodetide.core.crypto import KeyPair, VerifyKey, hash_json


class BundleType(str, Enum):
    """Bundle types for priority handling."""

    REVOCATION = "revocation"       # Highest priority
    SIGCHAIN = "sigchain"           # High priority
    MESSAGE = "message"             # Normal priority
    CONTENT_ANNOUNCE = "content_announce"
    CONTENT_CHUNK = "content_chunk"
    ACK = "ack"
    DELIVERY_ACK = "delivery_ack"
    READ_RECEIPT = "read_receipt"
    TRANSIT_REPORT = "transit_report"


# Priority ordering (lower = higher priority)
BUNDLE_PRIORITY = {
    BundleType.REVOCATION: 0,
    BundleType.SIGCHAIN: 1,
    BundleType.ACK: 2,
    BundleType.DELIVERY_ACK: 2,
    BundleType.MESSAGE: 3,
    BundleType.CONTENT_ANNOUNCE: 4,
    BundleType.CONTENT_CHUNK: 5,
    BundleType.READ_RECEIPT: 5,
    BundleType.TRANSIT_REPORT: 5,
}


@dataclass
class Bundle:
    """Transport bundle - the envelope for all data transfer."""

    version: int
    bundle_type: BundleType
    sender: str  # sender identity hash
    recipient: str  # recipient identity hash, or "*" for broadcast
    ttl: int  # time-to-live in seconds
    created: int  # creation timestamp
    payload: dict[str, Any]  # type-specific content
    signature: str = ""
    hints: list[str] = field(default_factory=list)  # optional routing hints

    @property
    def bundle_hash(self) -> str:
        """Hash of this bundle."""
        return hash_json(self.to_dict())

    @property
    def priority(self) -> int:
        """Priority for queue ordering."""
        return BUNDLE_PRIORITY.get(self.bundle_type, 10)

    @property
    def expires_at(self) -> int:
        """Expiration timestamp."""
        return self.created + self.ttl

    @property
    def is_expired(self) -> bool:
        """Check if bundle has expired."""
        return time.time() > self.expires_at

    @property
    def is_broadcast(self) -> bool:
        """Check if this is a broadcast bundle."""
        return self.recipient == "*"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "type": self.bundle_type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "ttl": self.ttl,
            "created": self.created,
            "hints": self.hints,
            "payload": self.payload,
            "signature": self.signature,
        }

    def signable_dict(self) -> dict[str, Any]:
        """Get dictionary for signing."""
        d = self.to_dict()
        del d["signature"]
        return d

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    def to_bytes(self) -> bytes:
        """Convert to bytes for transport."""
        return self.to_json().encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Bundle:
        """Load from dictionary."""
        return cls(
            version=data["version"],
            bundle_type=BundleType(data["type"]),
            sender=data["sender"],
            recipient=data["recipient"],
            ttl=data["ttl"],
            created=data["created"],
            hints=data.get("hints", []),
            payload=data["payload"],
            signature=data.get("signature", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> Bundle:
        """Load from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_bytes(cls, data: bytes) -> Bundle:
        """Load from bytes."""
        return cls.from_json(data.decode("utf-8"))

    def sign(self, keypair: KeyPair) -> None:
        """Sign this bundle."""
        signable = json.dumps(self.signable_dict(), sort_keys=True, separators=(",", ":"))
        self.signature = keypair.sign_hex(signable.encode("utf-8"))

    def verify(self, verify_key: VerifyKey) -> bool:
        """Verify the signature."""
        signable = json.dumps(self.signable_dict(), sort_keys=True, separators=(",", ":"))
        return verify_key.verify_hex(signable.encode("utf-8"), self.signature)

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        sender_identity: str,
        recipient: str,
        bundle_type: BundleType,
        payload: dict[str, Any],
        ttl: int = 86400 * 7,  # 7 days default
        hints: list[str] | None = None,
    ) -> Bundle:
        """Create and sign a new bundle."""
        bundle = cls(
            version=1,
            bundle_type=bundle_type,
            sender=sender_identity,
            recipient=recipient,
            ttl=ttl,
            created=int(time.time()),
            hints=hints or [],
            payload=payload,
            signature="",
        )
        bundle.sign(keypair)
        return bundle


@dataclass
class DeliveryAck:
    """Acknowledgment that a message was received."""

    message_hash: str
    recipient: str
    received_at: int
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_hash": self.message_hash,
            "recipient": self.recipient,
            "received_at": self.received_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeliveryAck:
        return cls(
            message_hash=data["message_hash"],
            recipient=data["recipient"],
            received_at=data["received_at"],
            signature=data.get("signature", ""),
        )

    @classmethod
    def create(cls, keypair: KeyPair, recipient_identity: str, message_hash: str) -> DeliveryAck:
        """Create and sign a delivery ack."""
        ack = cls(
            message_hash=message_hash,
            recipient=recipient_identity,
            received_at=int(time.time()),
            signature="",
        )
        signable = json.dumps({
            "message_hash": ack.message_hash,
            "recipient": ack.recipient,
            "received_at": ack.received_at,
        }, sort_keys=True, separators=(",", ":"))
        ack.signature = keypair.sign_hex(signable.encode("utf-8"))
        return ack


@dataclass
class ReadReceipt:
    """Receipt that a message was read/displayed."""

    message_hash: str
    recipient: str
    read_at: int
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_hash": self.message_hash,
            "recipient": self.recipient,
            "read_at": self.read_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReadReceipt:
        return cls(
            message_hash=data["message_hash"],
            recipient=data["recipient"],
            read_at=data["read_at"],
            signature=data.get("signature", ""),
        )


@dataclass
class TransitHop:
    """A single hop in a transit report."""

    node: str
    received: int
    forwarded: int


@dataclass
class TransitReport:
    """Report of hops a message took."""

    message_hash: str
    hops: list[TransitHop]
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_hash": self.message_hash,
            "hops": [{"node": h.node, "received": h.received, "forwarded": h.forwarded} for h in self.hops],
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransitReport:
        return cls(
            message_hash=data["message_hash"],
            hops=[TransitHop(**h) for h in data["hops"]],
            signature=data.get("signature", ""),
        )


@dataclass
class BundleQueue:
    """Priority queue for bundles."""

    bundles: list[Bundle] = field(default_factory=list)

    def push(self, bundle: Bundle) -> None:
        """Add a bundle to the queue."""
        self.bundles.append(bundle)
        self.bundles.sort(key=lambda b: (b.priority, b.created))

    def pop(self) -> Bundle | None:
        """Remove and return the highest priority bundle."""
        if self.bundles:
            return self.bundles.pop(0)
        return None

    def peek(self) -> Bundle | None:
        """Return the highest priority bundle without removing."""
        if self.bundles:
            return self.bundles[0]
        return None

    def remove_expired(self) -> int:
        """Remove expired bundles. Returns count removed."""
        before = len(self.bundles)
        self.bundles = [b for b in self.bundles if not b.is_expired]
        return before - len(self.bundles)

    def __len__(self) -> int:
        return len(self.bundles)

    def get_for_recipient(self, recipient: str) -> list[Bundle]:
        """Get all bundles for a specific recipient."""
        return [
            b for b in self.bundles
            if b.recipient == recipient or b.recipient == "*"
        ]
