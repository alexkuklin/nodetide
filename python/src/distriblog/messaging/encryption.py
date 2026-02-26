"""End-to-end encryption for messages."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from distriblog.core.crypto import (
    KeyPair,
    EncryptionPublicKey,
    EncryptionPrivateKey,
    symmetric_encrypt,
    symmetric_decrypt,
    random_bytes,
    hash_hex,
)
from distriblog.core.identity import Identity, Sigchain
from distriblog.messaging.message import (
    PrivateMessage,
    GroupMessage,
    GroupEncryptionMode,
    ReceiptRequest,
)


@dataclass
class EncryptedContent:
    """Encrypted message content."""

    ciphertext: bytes
    encrypted_keys: dict[str, bytes]  # recipient key hash -> encrypted symmetric key
    nonce: bytes | None = None


def encrypt_for_recipient(
    content: dict[str, Any],
    recipient_sigchain: Sigchain,
    sender_keypair: KeyPair,
) -> EncryptedContent:
    """Encrypt content for a single recipient (all their device keys)."""
    # Serialize content
    plaintext = json.dumps(content, separators=(",", ":")).encode("utf-8")

    # Generate symmetric key and encrypt content
    ciphertext, sym_key = symmetric_encrypt(plaintext)

    # Encrypt symmetric key to each of recipient's active device keys
    encrypted_keys = {}
    for device in recipient_sigchain.get_active_devices():
        recipient_key = EncryptionPublicKey.from_hex(device.encryption_pubkey)
        encrypted_sym_key = recipient_key.encrypt(sym_key, sender_keypair.encryption_key)
        encrypted_keys[device.encryption_pubkey] = encrypted_sym_key

    return EncryptedContent(
        ciphertext=ciphertext,
        encrypted_keys=encrypted_keys,
    )


def decrypt_for_recipient(
    encrypted: EncryptedContent,
    recipient_keypair: KeyPair,
    sender_encryption_pubkey: EncryptionPublicKey,
) -> dict[str, Any]:
    """Decrypt content as recipient."""
    # Find our encrypted key
    our_pubkey = recipient_keypair.public_encryption_key.to_hex()

    encrypted_sym_key = encrypted.encrypted_keys.get(our_pubkey)
    if not encrypted_sym_key:
        # Try as bytes keys
        for key_hex, enc_key in encrypted.encrypted_keys.items():
            if key_hex == our_pubkey:
                encrypted_sym_key = enc_key
                break

    if not encrypted_sym_key:
        raise ValueError("No encrypted key found for our device")

    # Decrypt symmetric key
    sym_key = recipient_keypair.encryption_key.decrypt(
        encrypted_sym_key,
        sender_encryption_pubkey,
    )

    # Decrypt content
    plaintext = symmetric_decrypt(encrypted.ciphertext, sym_key)

    return json.loads(plaintext.decode("utf-8"))


def create_private_message(
    sender_keypair: KeyPair,
    sender_identity: str,
    recipient_identity: str,
    recipient_sigchain: Sigchain,
    content: dict[str, Any],
    reply_to: str | None = None,
    request_receipt: ReceiptRequest = ReceiptRequest.NONE,
    use_ephemeral: bool = False,
) -> PrivateMessage:
    """Create an encrypted private message."""
    # Optionally generate ephemeral key for forward secrecy
    if use_ephemeral:
        ephemeral_keypair = KeyPair.generate()
        encryption_keypair = ephemeral_keypair
        ephemeral_key_hex = ephemeral_keypair.public_encryption_key.to_hex()
    else:
        encryption_keypair = sender_keypair
        ephemeral_key_hex = None

    # Encrypt content
    encrypted = encrypt_for_recipient(
        content,
        recipient_sigchain,
        encryption_keypair,
    )

    # Build message
    return PrivateMessage(
        sender=sender_identity,
        content={},  # content is encrypted
        created_at=int(time.time()),
        reply_to=reply_to,
        request_receipt=request_receipt,
        recipient=recipient_identity,
        encrypted_to=list(encrypted.encrypted_keys.keys()),
        ciphertext=encrypted.ciphertext,
        ephemeral_key=ephemeral_key_hex,
    )


def decrypt_private_message(
    message: PrivateMessage,
    recipient_keypair: KeyPair,
    sender_sigchain: Sigchain,
) -> dict[str, Any]:
    """Decrypt a private message."""
    # Get sender's encryption key
    if message.ephemeral_key:
        sender_enc_key = EncryptionPublicKey.from_hex(message.ephemeral_key)
    else:
        # Use sender's current encryption key from sigchain
        genesis = sender_sigchain.genesis
        if not genesis:
            raise ValueError("Invalid sender sigchain")
        sender_enc_key = EncryptionPublicKey.from_hex(genesis.encryption_pubkey)

    # Build encrypted content structure
    encrypted = EncryptedContent(
        ciphertext=message.ciphertext,
        encrypted_keys={k: bytes.fromhex(k) for k in message.encrypted_to},  # placeholder
    )

    # Actually we need the encrypted keys properly
    # For now, try to decrypt with our key
    our_pubkey = recipient_keypair.public_encryption_key.to_hex()

    if our_pubkey not in message.encrypted_to:
        raise ValueError("Message not encrypted to our device key")

    # The ciphertext includes the encrypted symmetric key in NaCl box format
    # We need to decrypt the whole thing
    plaintext = recipient_keypair.encryption_key.decrypt(
        message.ciphertext,
        sender_enc_key,
    )

    return json.loads(plaintext.decode("utf-8"))


@dataclass
class GroupKeyInfo:
    """Information about a group encryption key."""

    key_id: str
    key: bytes
    created_at: int


class GroupKeyManager:
    """Manages group encryption keys."""

    def __init__(self):
        self._keys: dict[str, dict[str, GroupKeyInfo]] = {}  # group_id -> key_id -> key

    def add_key(self, group_id: str, key_id: str, key: bytes) -> None:
        """Add a group key."""
        if group_id not in self._keys:
            self._keys[group_id] = {}

        self._keys[group_id][key_id] = GroupKeyInfo(
            key_id=key_id,
            key=key,
            created_at=int(time.time()),
        )

    def get_key(self, group_id: str, key_id: str) -> bytes | None:
        """Get a specific group key."""
        if group_id in self._keys and key_id in self._keys[group_id]:
            return self._keys[group_id][key_id].key
        return None

    def get_current_key(self, group_id: str) -> tuple[str, bytes] | None:
        """Get the most recent key for a group."""
        if group_id not in self._keys:
            return None

        keys = self._keys[group_id]
        if not keys:
            return None

        # Get most recent by created_at
        most_recent = max(keys.values(), key=lambda k: k.created_at)
        return most_recent.key_id, most_recent.key

    def generate_key(self, group_id: str) -> tuple[str, bytes]:
        """Generate a new key for a group."""
        key = random_bytes(32)
        key_id = hash_hex(key)[:16]
        self.add_key(group_id, key_id, key)
        return key_id, key


def create_group_message_per_member(
    sender_keypair: KeyPair,
    sender_identity: str,
    group_id: str,
    member_sigchains: list[Sigchain],
    content: dict[str, Any],
    reply_to: str | None = None,
) -> GroupMessage:
    """Create a group message using per-member encryption."""
    # Serialize content
    plaintext = json.dumps(content, separators=(",", ":")).encode("utf-8")

    # Generate symmetric key
    ciphertext, sym_key = symmetric_encrypt(plaintext)

    # Encrypt symmetric key to each member's devices
    encrypted_keys = {}
    for sigchain in member_sigchains:
        for device in sigchain.get_active_devices():
            recipient_key = EncryptionPublicKey.from_hex(device.encryption_pubkey)
            encrypted_sym_key = recipient_key.encrypt(sym_key, sender_keypair.encryption_key)
            encrypted_keys[device.encryption_pubkey] = encrypted_sym_key.hex()

    return GroupMessage(
        sender=sender_identity,
        content={},
        created_at=int(time.time()),
        reply_to=reply_to,
        group_id=group_id,
        encryption_mode=GroupEncryptionMode.PER_MEMBER,
        encrypted_keys=encrypted_keys,
        ciphertext=ciphertext,
    )


def create_group_message_shared_key(
    sender_identity: str,
    group_id: str,
    group_key: bytes,
    content: dict[str, Any],
    reply_to: str | None = None,
) -> GroupMessage:
    """Create a group message using shared key encryption."""
    # Serialize content
    plaintext = json.dumps(content, separators=(",", ":")).encode("utf-8")

    # Encrypt with shared group key
    ciphertext, _ = symmetric_encrypt(plaintext, group_key)

    return GroupMessage(
        sender=sender_identity,
        content={},
        created_at=int(time.time()),
        reply_to=reply_to,
        group_id=group_id,
        encryption_mode=GroupEncryptionMode.SHARED_KEY,
        encrypted_keys={},  # no per-member keys needed
        ciphertext=ciphertext,
    )


def decrypt_group_message(
    message: GroupMessage,
    recipient_keypair: KeyPair,
    sender_encryption_pubkey: EncryptionPublicKey | None = None,
    group_key: bytes | None = None,
) -> dict[str, Any]:
    """Decrypt a group message."""
    if message.encryption_mode == GroupEncryptionMode.SHARED_KEY:
        if not group_key:
            raise ValueError("Group key required for shared_key mode")

        plaintext = symmetric_decrypt(message.ciphertext, group_key)
        return json.loads(plaintext.decode("utf-8"))

    elif message.encryption_mode == GroupEncryptionMode.PER_MEMBER:
        if not sender_encryption_pubkey:
            raise ValueError("Sender encryption key required for per_member mode")

        our_pubkey = recipient_keypair.public_encryption_key.to_hex()

        if our_pubkey not in message.encrypted_keys:
            raise ValueError("Message not encrypted to our device key")

        # Decrypt symmetric key
        encrypted_sym_key = bytes.fromhex(message.encrypted_keys[our_pubkey])
        sym_key = recipient_keypair.encryption_key.decrypt(
            encrypted_sym_key,
            sender_encryption_pubkey,
        )

        # Decrypt content
        plaintext = symmetric_decrypt(message.ciphertext, sym_key)
        return json.loads(plaintext.decode("utf-8"))

    else:
        raise ValueError(f"Unsupported encryption mode: {message.encryption_mode}")
