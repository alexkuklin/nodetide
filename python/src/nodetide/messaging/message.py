"""Message types - private, group, and public messages."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nodetide.core.crypto import KeyPair, hash_json


class MessageType(str, Enum):
    """Message types."""

    PRIVATE = "private"
    GROUP = "group"
    PUBLIC = "public"


class ReceiptRequest(str, Enum):
    """What receipts to request."""

    NONE = "none"
    DELIVERY = "delivery"
    READ = "read"


@dataclass
class Message:
    """Base message class."""

    message_type: MessageType
    sender: str  # sender identity hash
    content: dict[str, Any]  # message content (MIME-style)
    created_at: int
    reply_to: str | None = None  # hash of message being replied to
    request_receipt: ReceiptRequest = ReceiptRequest.NONE
    request_transit_report: bool = False

    @property
    def message_hash(self) -> str:
        """Hash of this message."""
        return hash_json(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.message_type.value,
            "sender": self.sender,
            "content": self.content,
            "created_at": self.created_at,
            "reply_to": self.reply_to,
            "request_receipt": self.request_receipt.value,
            "request_transit_report": self.request_transit_report,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        """Load from dictionary."""
        msg_type = MessageType(data["type"])

        if msg_type == MessageType.PRIVATE:
            return PrivateMessage.from_dict(data)
        elif msg_type == MessageType.GROUP:
            return GroupMessage.from_dict(data)
        elif msg_type == MessageType.PUBLIC:
            return PublicMessage.from_dict(data)
        else:
            raise ValueError(f"Unknown message type: {msg_type}")


@dataclass
class PrivateMessage(Message):
    """Private message encrypted to specific recipient(s)."""

    recipient: str = ""  # recipient identity hash
    encrypted_to: list[str] = field(default_factory=list)  # device keys encrypted to
    ciphertext: bytes = b""  # encrypted content
    ephemeral_key: str | None = None  # optional for forward secrecy

    def __post_init__(self):
        self.message_type = MessageType.PRIVATE

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "recipient": self.recipient,
            "encrypted_to": self.encrypted_to,
            "ciphertext": self.ciphertext.hex(),
            "ephemeral_key": self.ephemeral_key,
        })
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PrivateMessage:
        return cls(
            message_type=MessageType.PRIVATE,
            sender=data["sender"],
            content=data.get("content", {}),  # may be empty for encrypted
            created_at=data["created_at"],
            reply_to=data.get("reply_to"),
            request_receipt=ReceiptRequest(data.get("request_receipt", "none")),
            request_transit_report=data.get("request_transit_report", False),
            recipient=data["recipient"],
            encrypted_to=data.get("encrypted_to", []),
            ciphertext=bytes.fromhex(data.get("ciphertext", "")),
            ephemeral_key=data.get("ephemeral_key"),
        )


class GroupEncryptionMode(str, Enum):
    """Group message encryption modes."""

    PER_MEMBER = "per_member"  # encrypt key to each member
    SHARED_KEY = "shared_key"  # group has shared symmetric key
    SENDER_KEY = "sender_key"  # each sender has their own key


@dataclass
class GroupMessage(Message):
    """Group message encrypted for group members."""

    group_id: str = ""
    encryption_mode: GroupEncryptionMode = GroupEncryptionMode.PER_MEMBER
    encrypted_keys: dict[str, str] = field(default_factory=dict)  # member -> encrypted key
    ciphertext: bytes = b""

    def __post_init__(self):
        self.message_type = MessageType.GROUP

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "group_id": self.group_id,
            "encryption_mode": self.encryption_mode.value,
            "encrypted_keys": self.encrypted_keys,
            "ciphertext": self.ciphertext.hex(),
        })
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroupMessage:
        return cls(
            message_type=MessageType.GROUP,
            sender=data["sender"],
            content=data.get("content", {}),
            created_at=data["created_at"],
            reply_to=data.get("reply_to"),
            request_receipt=ReceiptRequest(data.get("request_receipt", "none")),
            request_transit_report=data.get("request_transit_report", False),
            group_id=data["group_id"],
            encryption_mode=GroupEncryptionMode(data.get("encryption_mode", "per_member")),
            encrypted_keys=data.get("encrypted_keys", {}),
            ciphertext=bytes.fromhex(data.get("ciphertext", "")),
        )


@dataclass
class PublicMessage(Message):
    """Public message - signed but not encrypted."""

    signature: str = ""

    def __post_init__(self):
        self.message_type = MessageType.PUBLIC

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["signature"] = self.signature
        return d

    def signable_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        del d["signature"]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicMessage:
        return cls(
            message_type=MessageType.PUBLIC,
            sender=data["sender"],
            content=data["content"],
            created_at=data["created_at"],
            reply_to=data.get("reply_to"),
            request_receipt=ReceiptRequest(data.get("request_receipt", "none")),
            request_transit_report=data.get("request_transit_report", False),
            signature=data.get("signature", ""),
        )

    def sign(self, keypair: KeyPair) -> None:
        """Sign the message."""
        signable = json.dumps(self.signable_dict(), sort_keys=True, separators=(",", ":"))
        self.signature = keypair.sign_hex(signable.encode("utf-8"))

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        sender_identity: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        request_receipt: ReceiptRequest = ReceiptRequest.NONE,
    ) -> PublicMessage:
        """Create and sign a public message."""
        msg = cls(
            message_type=MessageType.PUBLIC,
            sender=sender_identity,
            content=content,
            created_at=int(time.time()),
            reply_to=reply_to,
            request_receipt=request_receipt,
            signature="",
        )
        msg.sign(keypair)
        return msg


@dataclass
class TextContent:
    """Simple text content."""

    text: str
    content_type: str = "text/plain"

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_type": self.content_type,
            "body": self.text,
        }


@dataclass
class EditContent:
    """Edit of previous content."""

    edit_of: str  # hash of original content
    version: int
    new_content: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "edit_of": self.edit_of,
            "version": self.version,
            "content": self.new_content,
        }


@dataclass
class DeleteRequest:
    """Request to delete content."""

    content_hash: str
    reason: str | None = None
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "reason": self.reason,
            "signature": self.signature,
        }
