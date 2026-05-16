"""Tests for identity module."""

import pytest

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import (
    Identity,
    IdentityType,
    Sigchain,
    GenesisEvent,
    AddDeviceEvent,
    RevokeDeviceEvent,
    RotateMasterEvent,
    SetRecoveryEvent,
    DeviceCapability,
)


def test_create_identity():
    """Test creating a new identity."""
    ident = Identity.create(name="Alice")

    assert ident.identity_hash
    assert ident.is_own
    assert ident.local_keypair
    assert len(ident.sigchain.events) == 1
    assert isinstance(ident.sigchain.events[0], GenesisEvent)


def test_identity_verify():
    """Test identity verification."""
    ident = Identity.create(name="Bob")
    valid, error = ident.verify()
    assert valid
    assert error is None


def test_add_device():
    """Test adding a device."""
    ident = Identity.create(name="Charlie")

    device_kp, event = ident.add_device(label="phone")

    assert device_kp
    assert event
    assert event.label == "phone"
    assert len(ident.sigchain.events) == 2

    # Verify still valid
    valid, error = ident.verify()
    assert valid


def test_revoke_device():
    """Test revoking a device."""
    ident = Identity.create()

    device_kp, add_event = ident.add_device(label="laptop")
    revoke_event = ident.revoke_device(device_kp.verify_key.to_hex(), reason="lost")

    assert revoke_event
    assert len(ident.sigchain.events) == 3

    # Device should not be in active list
    devices = ident.sigchain.get_active_devices()
    assert all(d.pubkey != device_kp.verify_key.to_hex() for d in devices)


def test_rotate_master():
    """Test master key rotation."""
    ident = Identity.create()
    old_hash = ident.identity_hash

    new_kp, event = ident.rotate_master()

    assert new_kp
    assert event
    assert ident.identity_hash == old_hash  # Identity hash doesn't change

    # Verify still valid
    valid, error = ident.verify()
    assert valid


def test_set_recovery():
    """Test setting recovery trustees."""
    ident = Identity.create()

    # Create some trustee identities
    trustee1 = Identity.create(name="Trustee1")
    trustee2 = Identity.create(name="Trustee2")
    trustee3 = Identity.create(name="Trustee3")

    event = ident.set_recovery(
        primary_trustees=[
            trustee1.identity_hash,
            trustee2.identity_hash,
            trustee3.identity_hash,
        ],
        primary_threshold=2,
    )

    assert event
    assert event.primary_threshold == 2
    assert len(event.primary_trustees) == 3

    # Verify still valid
    valid, error = ident.verify()
    assert valid


def test_sigchain_serialization():
    """Test sigchain JSON serialization."""
    ident = Identity.create(name="Dana")
    ident.add_device(label="phone")

    json_str = ident.sigchain.to_json()
    loaded = Sigchain.from_json(json_str)

    assert loaded.identity_hash == ident.identity_hash
    assert len(loaded.events) == len(ident.sigchain.events)

    # Loaded sigchain should also verify
    valid, error = loaded.verify()
    assert valid


def test_ephemeral_identity():
    """Test creating ephemeral identity."""
    ident = Identity.create(identity_type=IdentityType.EPHEMERAL, ephemeral=True)

    genesis = ident.sigchain.genesis
    assert genesis.ephemeral
    assert genesis.identity_type == IdentityType.EPHEMERAL


def test_organization_identity():
    """Test creating organization identity."""
    ident = Identity.create(
        identity_type=IdentityType.ORGANIZATION,
        name="Acme Corp",
    )

    genesis = ident.sigchain.genesis
    assert genesis.identity_type == IdentityType.ORGANIZATION
    assert genesis.name == "Acme Corp"


def test_device_capabilities():
    """Test device with limited capabilities."""
    ident = Identity.create()

    device_kp, event = ident.add_device(
        label="read-only",
        capabilities=[DeviceCapability.ENCRYPT],
    )

    assert DeviceCapability.ENCRYPT.value in event.capabilities
    assert DeviceCapability.SIGN_IDENTITY.value not in event.capabilities


def test_get_current_master_key():
    """Test getting current master key after rotation."""
    ident = Identity.create()
    original_master = ident.sigchain.get_current_master_key()

    new_kp, _ = ident.rotate_master()
    new_master = ident.sigchain.get_current_master_key()

    assert original_master != new_master
    assert new_master == new_kp.verify_key.to_hex()
