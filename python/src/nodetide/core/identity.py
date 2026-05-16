"""Identity and sigchain implementation.

Identity = hash(genesis event)
Sigchain = append-only log of signed events
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nodetide.core.crypto import (
    KeyPair,
    VerifyKey,
    PublicKeyBundle,
    SigningKey,
    hash_json,
    hash_hex,
    DEFAULT_HASH_ALG,
    DEFAULT_SIGN_ALG,
)


class EventType(str, Enum):
    """Sigchain event types."""

    GENESIS = "genesis"
    ADD_DEVICE = "add_device"
    REVOKE_DEVICE = "revoke_device"
    ROTATE_MASTER = "rotate_master"
    SET_RECOVERY = "set_recovery"
    SOCIAL_RECOVERY = "social_recovery"
    RESOLVE_FORK = "resolve_fork"
    SET_DISTRIBUTION = "set_distribution"


class IdentityType(str, Enum):
    """Identity types."""

    PERSONAL = "personal"
    ORGANIZATION = "organization"
    EPHEMERAL = "ephemeral"


class DeviceCapability(str, Enum):
    """Device key capabilities."""

    SIGN_MESSAGES = "sign_messages"
    SIGN_FILES = "sign_files"
    SIGN_IDENTITY = "sign_identity"
    ENCRYPT = "encrypt"


@dataclass
class SigchainEvent:
    """Base sigchain event."""

    type: EventType
    timestamp: int
    prev: str | None  # hash of previous event, None for genesis
    signature: str
    signed_by: str  # public key hex that signed this
    version: int = 1
    alg: str = DEFAULT_SIGN_ALG
    hash_alg: str = DEFAULT_HASH_ALG

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "type": self.type.value,
            "alg": self.alg,
            "hash_alg": self.hash_alg,
            "timestamp": self.timestamp,
            "prev": self.prev,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }

    def signable_dict(self) -> dict[str, Any]:
        """Get dictionary for signing (excludes signature)."""
        d = self.to_dict()
        del d["signature"]
        return d

    def event_hash(self) -> str:
        """Hash of this event."""
        return hash_json(self.to_dict(), self.hash_alg)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SigchainEvent:
        """Load from dictionary. Dispatches to appropriate subclass."""
        event_type = EventType(data["type"])

        event_classes = {
            EventType.GENESIS: GenesisEvent,
            EventType.ADD_DEVICE: AddDeviceEvent,
            EventType.REVOKE_DEVICE: RevokeDeviceEvent,
            EventType.ROTATE_MASTER: RotateMasterEvent,
            EventType.SET_RECOVERY: SetRecoveryEvent,
            EventType.SOCIAL_RECOVERY: SocialRecoveryEvent,
            EventType.RESOLVE_FORK: ResolveForkEvent,
            EventType.SET_DISTRIBUTION: SetDistributionEvent,
        }

        event_class = event_classes.get(event_type)
        if event_class is None:
            raise ValueError(f"Unknown event type: {event_type}")

        return event_class._from_dict(data)


@dataclass(kw_only=True)
class GenesisEvent(SigchainEvent):
    """Genesis event - creates a new identity."""

    pubkey: str  # master public key hex
    encryption_pubkey: str  # encryption public key hex
    identity_type: IdentityType = IdentityType.PERSONAL
    name: str | None = None  # optional display name
    ephemeral: bool = False
    ownership_proof: str | None = None  # for ephemeral, link to persistent identity
    distribution_points: list[str] | None = None  # initial distribution endpoints

    def __post_init__(self):
        self.type = EventType.GENESIS
        self.prev = None

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "pubkey": self.pubkey,
            "encryption_pubkey": self.encryption_pubkey,
            "identity_type": self.identity_type.value,
            "name": self.name,
            "ephemeral": self.ephemeral,
            "ownership_proof": self.ownership_proof,
            "distribution_points": self.distribution_points,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GenesisEvent:
        return cls(
            type=EventType.GENESIS,
            timestamp=data["timestamp"],
            prev=None,
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            pubkey=data["pubkey"],
            encryption_pubkey=data["encryption_pubkey"],
            identity_type=IdentityType(data.get("identity_type", "personal")),
            name=data.get("name"),
            ephemeral=data.get("ephemeral", False),
            ownership_proof=data.get("ownership_proof"),
            distribution_points=data.get("distribution_points"),
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        identity_type: IdentityType = IdentityType.PERSONAL,
        name: str | None = None,
        ephemeral: bool = False,
        ownership_proof: str | None = None,
        distribution_points: list[str] | None = None,
    ) -> GenesisEvent:
        """Create and sign a new genesis event."""
        event = cls(
            type=EventType.GENESIS,
            timestamp=int(time.time()),
            prev=None,
            signature="",  # will be set below
            signed_by=keypair.verify_key.to_hex(),
            pubkey=keypair.verify_key.to_hex(),
            encryption_pubkey=keypair.public_encryption_key.to_hex(),
            identity_type=identity_type,
            name=name,
            ephemeral=ephemeral,
            ownership_proof=ownership_proof,
            distribution_points=distribution_points,
        )
        # Sign the event
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class AddDeviceEvent(SigchainEvent):
    """Add a device key to the identity."""

    device_pubkey: str
    device_encryption_pubkey: str
    label: str
    capabilities: list[str] = field(default_factory=lambda: [c.value for c in DeviceCapability])
    expires: int | None = None  # optional expiration timestamp

    def __post_init__(self):
        self.type = EventType.ADD_DEVICE

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "device_pubkey": self.device_pubkey,
            "device_encryption_pubkey": self.device_encryption_pubkey,
            "label": self.label,
            "capabilities": self.capabilities,
            "expires": self.expires,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AddDeviceEvent:
        return cls(
            type=EventType.ADD_DEVICE,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            device_pubkey=data["device_pubkey"],
            device_encryption_pubkey=data["device_encryption_pubkey"],
            label=data["label"],
            capabilities=data.get("capabilities", [c.value for c in DeviceCapability]),
            expires=data.get("expires"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        device_keypair: KeyPair,
        label: str,
        prev_hash: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
    ) -> AddDeviceEvent:
        """Create and sign an add device event."""
        caps = [c.value for c in capabilities] if capabilities else [c.value for c in DeviceCapability]
        event = cls(
            type=EventType.ADD_DEVICE,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            device_pubkey=device_keypair.verify_key.to_hex(),
            device_encryption_pubkey=device_keypair.public_encryption_key.to_hex(),
            label=label,
            capabilities=caps,
            expires=expires,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class RevokeDeviceEvent(SigchainEvent):
    """Revoke a device key."""

    device_pubkey: str
    reason: str | None = None

    def __post_init__(self):
        self.type = EventType.REVOKE_DEVICE

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "device_pubkey": self.device_pubkey,
            "reason": self.reason,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> RevokeDeviceEvent:
        return cls(
            type=EventType.REVOKE_DEVICE,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            device_pubkey=data["device_pubkey"],
            reason=data.get("reason"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        device_pubkey: str,
        prev_hash: str,
        reason: str | None = None,
    ) -> RevokeDeviceEvent:
        """Create and sign a revoke device event."""
        event = cls(
            type=EventType.REVOKE_DEVICE,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            device_pubkey=device_pubkey,
            reason=reason,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class RotateMasterEvent(SigchainEvent):
    """Rotate the master key."""

    new_pubkey: str
    new_encryption_pubkey: str

    def __post_init__(self):
        self.type = EventType.ROTATE_MASTER

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "new_pubkey": self.new_pubkey,
            "new_encryption_pubkey": self.new_encryption_pubkey,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> RotateMasterEvent:
        return cls(
            type=EventType.ROTATE_MASTER,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            new_pubkey=data["new_pubkey"],
            new_encryption_pubkey=data["new_encryption_pubkey"],
        )

    @classmethod
    def create(
        cls,
        old_keypair: KeyPair,
        new_keypair: KeyPair,
        prev_hash: str,
    ) -> RotateMasterEvent:
        """Create and sign a master key rotation event."""
        event = cls(
            type=EventType.ROTATE_MASTER,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=old_keypair.verify_key.to_hex(),
            new_pubkey=new_keypair.verify_key.to_hex(),
            new_encryption_pubkey=new_keypair.public_encryption_key.to_hex(),
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = old_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class SetRecoveryEvent(SigchainEvent):
    """Set or update recovery trustees."""

    primary_trustees: list[str]  # identity hashes
    primary_threshold: int
    backup_trustees: list[str] | None = None
    backup_threshold: int | None = None
    backup_activates_after: int | None = None  # seconds

    def __post_init__(self):
        self.type = EventType.SET_RECOVERY

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "primary_trustees": self.primary_trustees,
            "primary_threshold": self.primary_threshold,
            "backup_trustees": self.backup_trustees,
            "backup_threshold": self.backup_threshold,
            "backup_activates_after": self.backup_activates_after,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetRecoveryEvent:
        return cls(
            type=EventType.SET_RECOVERY,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            primary_trustees=data["primary_trustees"],
            primary_threshold=data["primary_threshold"],
            backup_trustees=data.get("backup_trustees"),
            backup_threshold=data.get("backup_threshold"),
            backup_activates_after=data.get("backup_activates_after"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        primary_trustees: list[str],
        primary_threshold: int,
        backup_trustees: list[str] | None = None,
        backup_threshold: int | None = None,
        backup_activates_after: int | None = None,
    ) -> SetRecoveryEvent:
        """Create and sign a set recovery event."""
        event = cls(
            type=EventType.SET_RECOVERY,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            primary_trustees=primary_trustees,
            primary_threshold=primary_threshold,
            backup_trustees=backup_trustees,
            backup_threshold=backup_threshold,
            backup_activates_after=backup_activates_after,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass
class RecoverySignature:
    """A trustee's signature for social recovery."""

    trustee_identity: str
    signature: str


@dataclass(kw_only=True)
class SocialRecoveryEvent(SigchainEvent):
    """Social recovery - threshold of trustees restore access."""

    new_pubkey: str
    new_encryption_pubkey: str
    recovery_signatures: list[dict[str, str]]  # list of {trustee_identity, signature}

    def __post_init__(self):
        self.type = EventType.SOCIAL_RECOVERY

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "new_pubkey": self.new_pubkey,
            "new_encryption_pubkey": self.new_encryption_pubkey,
            "recovery_signatures": self.recovery_signatures,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SocialRecoveryEvent:
        return cls(
            type=EventType.SOCIAL_RECOVERY,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            new_pubkey=data["new_pubkey"],
            new_encryption_pubkey=data["new_encryption_pubkey"],
            recovery_signatures=data["recovery_signatures"],
        )


@dataclass(kw_only=True)
class ResolveForkEvent(SigchainEvent):
    """Resolve a fork by choosing a branch."""

    chosen_branch_hash: str  # hash of the event to continue from
    rejected_branch_hash: str  # hash of the rejected event

    def __post_init__(self):
        self.type = EventType.RESOLVE_FORK

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "chosen_branch_hash": self.chosen_branch_hash,
            "rejected_branch_hash": self.rejected_branch_hash,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> ResolveForkEvent:
        return cls(
            type=EventType.RESOLVE_FORK,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            chosen_branch_hash=data["chosen_branch_hash"],
            rejected_branch_hash=data["rejected_branch_hash"],
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        chosen_branch_hash: str,
        rejected_branch_hash: str,
    ) -> ResolveForkEvent:
        """Create and sign a fork resolution event."""
        event = cls(
            type=EventType.RESOLVE_FORK,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            chosen_branch_hash=chosen_branch_hash,
            rejected_branch_hash=rejected_branch_hash,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class SetDistributionEvent(SigchainEvent):
    """Update distribution points for the identity."""

    distribution_points: list[str]  # list of endpoint URIs

    def __post_init__(self):
        self.type = EventType.SET_DISTRIBUTION

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "distribution_points": self.distribution_points,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetDistributionEvent:
        return cls(
            type=EventType.SET_DISTRIBUTION,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            distribution_points=data["distribution_points"],
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        distribution_points: list[str],
    ) -> SetDistributionEvent:
        """Create and sign a set distribution event."""
        event = cls(
            type=EventType.SET_DISTRIBUTION,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            distribution_points=distribution_points,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass
class DeviceInfo:
    """Information about an active device."""

    pubkey: str
    encryption_pubkey: str
    label: str
    capabilities: list[str]
    added_at: int
    expires: int | None


@dataclass
class Sigchain:
    """Append-only chain of signed events for an identity."""

    events: list[SigchainEvent] = field(default_factory=list)

    @property
    def genesis(self) -> GenesisEvent | None:
        """Get the genesis event."""
        if self.events and isinstance(self.events[0], GenesisEvent):
            return self.events[0]
        return None

    @property
    def identity_hash(self) -> str | None:
        """Get the identity hash (hash of genesis event)."""
        genesis = self.genesis
        if genesis:
            return genesis.event_hash()
        return None

    @property
    def head_hash(self) -> str | None:
        """Get the hash of the latest event."""
        if self.events:
            return self.events[-1].event_hash()
        return None

    def append(self, event: SigchainEvent) -> None:
        """Append an event to the chain."""
        self.events.append(event)

    def to_list(self) -> list[dict[str, Any]]:
        """Convert to list of dicts for serialization."""
        return [e.to_dict() for e in self.events]

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_list(), indent=2)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> Sigchain:
        """Load from list of dicts."""
        events = [SigchainEvent.from_dict(e) for e in data]
        return cls(events=events)

    @classmethod
    def from_json(cls, json_str: str) -> Sigchain:
        """Load from JSON string."""
        return cls.from_list(json.loads(json_str))

    def get_current_master_key(self) -> str | None:
        """Get the current master public key."""
        if not self.events:
            return None

        master_key = None
        for event in self.events:
            if isinstance(event, GenesisEvent):
                master_key = event.pubkey
            elif isinstance(event, RotateMasterEvent):
                master_key = event.new_pubkey
            elif isinstance(event, SocialRecoveryEvent):
                master_key = event.new_pubkey
        return master_key

    def get_active_devices(self, at_time: int | None = None) -> list[DeviceInfo]:
        """Get list of active device keys."""
        if at_time is None:
            at_time = int(time.time())

        devices: dict[str, DeviceInfo] = {}
        revoked: set[str] = set()

        for event in self.events:
            if isinstance(event, AddDeviceEvent):
                # Check if already expired at at_time
                if event.expires and event.expires < at_time:
                    continue
                devices[event.device_pubkey] = DeviceInfo(
                    pubkey=event.device_pubkey,
                    encryption_pubkey=event.device_encryption_pubkey,
                    label=event.label,
                    capabilities=event.capabilities,
                    added_at=event.timestamp,
                    expires=event.expires,
                )
            elif isinstance(event, RevokeDeviceEvent):
                revoked.add(event.device_pubkey)

        # Filter out revoked and expired
        active = []
        for pubkey, info in devices.items():
            if pubkey in revoked:
                continue
            if info.expires and info.expires < at_time:
                continue
            active.append(info)

        return active

    def get_recovery_config(self) -> SetRecoveryEvent | None:
        """Get the current recovery configuration."""
        recovery = None
        for event in self.events:
            if isinstance(event, SetRecoveryEvent):
                recovery = event
        return recovery

    def verify(self) -> tuple[bool, str | None]:
        """Verify the sigchain.

        Returns (is_valid, error_message).
        """
        if not self.events:
            return False, "Empty sigchain"

        # First event must be genesis
        if not isinstance(self.events[0], GenesisEvent):
            return False, "First event must be genesis"

        genesis = self.events[0]

        # Verify genesis is self-signed
        genesis_key = VerifyKey.from_hex(genesis.pubkey)
        signable = json.dumps(genesis.signable_dict(), sort_keys=True, separators=(",", ":"))
        if not genesis_key.verify_hex(signable.encode("utf-8"), genesis.signature):
            return False, "Genesis signature invalid"

        # Track current master key
        current_master = genesis.pubkey
        prev_hash = genesis.event_hash()

        # Verify each subsequent event
        for i, event in enumerate(self.events[1:], start=1):
            # Check prev hash
            if event.prev != prev_hash:
                return False, f"Event {i}: prev hash mismatch"

            # Get signer key
            signer_key = VerifyKey.from_hex(event.signed_by)

            # Verify signature
            signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
            if not signer_key.verify_hex(signable.encode("utf-8"), event.signature):
                return False, f"Event {i}: signature invalid"

            # Check authorization
            if isinstance(event, (AddDeviceEvent, RevokeDeviceEvent, SetRecoveryEvent, ResolveForkEvent, SetDistributionEvent)):
                # Must be signed by current master
                if event.signed_by != current_master:
                    return False, f"Event {i}: must be signed by master key"
            elif isinstance(event, RotateMasterEvent):
                # Must be signed by old master
                if event.signed_by != current_master:
                    return False, f"Event {i}: rotation must be signed by old master"
                current_master = event.new_pubkey
            elif isinstance(event, SocialRecoveryEvent):
                # TODO: verify threshold of trustee signatures
                current_master = event.new_pubkey

            prev_hash = event.event_hash()

        return True, None


@dataclass
class Identity:
    """A complete identity with sigchain and local keys."""

    sigchain: Sigchain
    local_keypair: KeyPair | None = None  # our key if we control this identity

    @property
    def identity_hash(self) -> str | None:
        """Get the identity hash."""
        return self.sigchain.identity_hash

    @property
    def is_own(self) -> bool:
        """Check if we control this identity."""
        return self.local_keypair is not None

    @classmethod
    def create(
        cls,
        identity_type: IdentityType = IdentityType.PERSONAL,
        name: str | None = None,
        ephemeral: bool = False,
        distribution_points: list[str] | None = None,
    ) -> Identity:
        """Create a new identity."""
        keypair = KeyPair.generate()
        genesis = GenesisEvent.create(
            keypair=keypair,
            identity_type=identity_type,
            name=name,
            ephemeral=ephemeral,
            distribution_points=distribution_points,
        )
        sigchain = Sigchain(events=[genesis])
        return cls(sigchain=sigchain, local_keypair=keypair)

    def add_device(
        self,
        label: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
    ) -> tuple[KeyPair, AddDeviceEvent]:
        """Add a new device. Returns (device_keypair, event)."""
        if not self.local_keypair:
            raise ValueError("Cannot add device: no local keypair")

        device_keypair = KeyPair.generate()
        event = AddDeviceEvent.create(
            master_keypair=self.local_keypair,
            device_keypair=device_keypair,
            label=label,
            prev_hash=self.sigchain.head_hash,
            capabilities=capabilities,
            expires=expires,
        )
        self.sigchain.append(event)
        return device_keypair, event

    def revoke_device(self, device_pubkey: str, reason: str | None = None) -> RevokeDeviceEvent:
        """Revoke a device key."""
        if not self.local_keypair:
            raise ValueError("Cannot revoke device: no local keypair")

        event = RevokeDeviceEvent.create(
            master_keypair=self.local_keypair,
            device_pubkey=device_pubkey,
            prev_hash=self.sigchain.head_hash,
            reason=reason,
        )
        self.sigchain.append(event)
        return event

    def rotate_master(self) -> tuple[KeyPair, RotateMasterEvent]:
        """Rotate the master key. Returns (new_keypair, event)."""
        if not self.local_keypair:
            raise ValueError("Cannot rotate: no local keypair")

        new_keypair = KeyPair.generate()
        event = RotateMasterEvent.create(
            old_keypair=self.local_keypair,
            new_keypair=new_keypair,
            prev_hash=self.sigchain.head_hash,
        )
        self.sigchain.append(event)
        self.local_keypair = new_keypair
        return new_keypair, event

    def set_recovery(
        self,
        primary_trustees: list[str],
        primary_threshold: int,
        backup_trustees: list[str] | None = None,
        backup_threshold: int | None = None,
        backup_activates_after: int | None = None,
    ) -> SetRecoveryEvent:
        """Set recovery trustees."""
        if not self.local_keypair:
            raise ValueError("Cannot set recovery: no local keypair")

        event = SetRecoveryEvent.create(
            master_keypair=self.local_keypair,
            prev_hash=self.sigchain.head_hash,
            primary_trustees=primary_trustees,
            primary_threshold=primary_threshold,
            backup_trustees=backup_trustees,
            backup_threshold=backup_threshold,
            backup_activates_after=backup_activates_after,
        )
        self.sigchain.append(event)
        return event

    def set_distribution_points(self, distribution_points: list[str]) -> SetDistributionEvent:
        """Set or update distribution points."""
        if not self.local_keypair:
            raise ValueError("Cannot set distribution points: no local keypair")

        event = SetDistributionEvent.create(
            master_keypair=self.local_keypair,
            prev_hash=self.sigchain.head_hash,
            distribution_points=distribution_points,
        )
        self.sigchain.append(event)
        return event

    def verify(self) -> tuple[bool, str | None]:
        """Verify the identity's sigchain."""
        return self.sigchain.verify()
