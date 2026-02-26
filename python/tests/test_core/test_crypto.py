"""Tests for crypto module."""

import pytest

from distriblog.core.crypto import (
    SigningKey,
    VerifyKey,
    EncryptionPrivateKey,
    EncryptionPublicKey,
    KeyPair,
    hash_bytes,
    hash_hex,
    hash_json,
    symmetric_encrypt,
    symmetric_decrypt,
)


def test_signing_key_generate():
    """Test signing key generation."""
    key = SigningKey.generate()
    assert key.to_bytes()
    assert len(key.to_bytes()) == 32


def test_signing_key_roundtrip():
    """Test signing key serialization roundtrip."""
    key = SigningKey.generate()
    hex_str = key.to_hex()
    loaded = SigningKey.from_hex(hex_str)
    assert loaded.to_hex() == hex_str


def test_sign_and_verify():
    """Test signing and verification."""
    key = SigningKey.generate()
    message = b"Hello, World!"

    signature = key.sign(message)
    assert key.verify_key.verify(message, signature)


def test_verify_wrong_message():
    """Test verification fails for wrong message."""
    key = SigningKey.generate()
    signature = key.sign(b"Hello")
    assert not key.verify_key.verify(b"Goodbye", signature)


def test_keypair_generate():
    """Test keypair generation."""
    kp = KeyPair.generate()
    assert kp.signing_key
    assert kp.encryption_key
    assert kp.verify_key
    assert kp.public_encryption_key


def test_keypair_roundtrip():
    """Test keypair serialization roundtrip."""
    kp = KeyPair.generate()
    d = kp.to_dict()
    loaded = KeyPair.from_dict(d)
    assert loaded.signing_key.to_hex() == kp.signing_key.to_hex()


def test_encryption_roundtrip():
    """Test encryption and decryption."""
    sender = EncryptionPrivateKey.generate()
    recipient = EncryptionPrivateKey.generate()

    plaintext = b"Secret message"

    # Encrypt to recipient
    ciphertext = recipient.public_key.encrypt(plaintext, sender)

    # Decrypt as recipient
    decrypted = recipient.decrypt(ciphertext, sender.public_key)
    assert decrypted == plaintext


def test_symmetric_encryption():
    """Test symmetric encryption."""
    plaintext = b"Hello, symmetric!"

    ciphertext, key = symmetric_encrypt(plaintext)
    decrypted = symmetric_decrypt(ciphertext, key)

    assert decrypted == plaintext


def test_hash_bytes():
    """Test hashing bytes."""
    data = b"test data"
    h1 = hash_bytes(data)
    h2 = hash_bytes(data)
    assert h1 == h2
    assert len(h1) == 32  # SHA-256


def test_hash_json():
    """Test hashing JSON objects."""
    obj1 = {"a": 1, "b": 2}
    obj2 = {"b": 2, "a": 1}  # Same content, different order

    h1 = hash_json(obj1)
    h2 = hash_json(obj2)
    assert h1 == h2  # Should be equal (canonical JSON)


def test_identity_hash():
    """Test identity hash derivation."""
    kp = KeyPair.generate()
    assert kp.identity_hash
    assert len(kp.identity_hash) == 64  # hex-encoded SHA-256
