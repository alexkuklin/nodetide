"""Group management - groups have their own mini-sigchain."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nodetide.core.crypto import KeyPair, hash_json
from nodetide.messaging.message import GroupEncryptionMode


class MembershipPolicy(str, Enum):
    """Who can add members to the group."""

    ADMIN_ONLY = "admin_only"
    MEMBER_INVITE = "member_invite"
    OPEN = "open"


class GroupEventType(str, Enum):
    """Group event types."""

    CREATE = "create"
    ADD_MEMBER = "add_member"
    REMOVE_MEMBER = "remove_member"
    CHANGE_ADMIN = "change_admin"
    ROTATE_KEY = "rotate_key"
    UPDATE_SETTINGS = "update_settings"


class MemberRole(str, Enum):
    """Member roles in a group."""

    ADMIN = "admin"
    MEMBER = "member"


@dataclass
class GroupEvent:
    """Base group event."""

    event_type: GroupEventType
    group_id: str
    timestamp: int
    prev: str | None
    signed_by: str
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.event_type.value,
            "group_id": self.group_id,
            "timestamp": self.timestamp,
            "prev": self.prev,
            "signed_by": self.signed_by,
            "signature": self.signature,
        }

    def signable_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        del d["signature"]
        return d

    def event_hash(self) -> str:
        return hash_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroupEvent:
        event_type = GroupEventType(data["type"])

        if event_type == GroupEventType.CREATE:
            return GroupCreateEvent._from_dict(data)
        elif event_type == GroupEventType.ADD_MEMBER:
            return GroupAddMemberEvent._from_dict(data)
        elif event_type == GroupEventType.REMOVE_MEMBER:
            return GroupRemoveMemberEvent._from_dict(data)
        elif event_type == GroupEventType.CHANGE_ADMIN:
            return GroupChangeAdminEvent._from_dict(data)
        elif event_type == GroupEventType.ROTATE_KEY:
            return GroupRotateKeyEvent._from_dict(data)
        elif event_type == GroupEventType.UPDATE_SETTINGS:
            return GroupUpdateSettingsEvent._from_dict(data)
        else:
            raise ValueError(f"Unknown group event type: {event_type}")


@dataclass
class GroupCreateEvent(GroupEvent):
    """Create a new group."""

    name: str = ""
    membership_policy: MembershipPolicy = MembershipPolicy.ADMIN_ONLY
    encryption_mode: GroupEncryptionMode = GroupEncryptionMode.PER_MEMBER
    creator: str = ""

    def __post_init__(self):
        self.event_type = GroupEventType.CREATE
        self.prev = None

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "name": self.name,
            "membership_policy": self.membership_policy.value,
            "encryption_mode": self.encryption_mode.value,
            "creator": self.creator,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupCreateEvent:
        return cls(
            event_type=GroupEventType.CREATE,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=None,
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            name=data["name"],
            membership_policy=MembershipPolicy(data.get("membership_policy", "admin_only")),
            encryption_mode=GroupEncryptionMode(data.get("encryption_mode", "per_member")),
            creator=data["creator"],
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        creator_identity: str,
        name: str,
        membership_policy: MembershipPolicy = MembershipPolicy.ADMIN_ONLY,
        encryption_mode: GroupEncryptionMode = GroupEncryptionMode.PER_MEMBER,
    ) -> GroupCreateEvent:
        """Create and sign a new group creation event."""
        event = cls(
            event_type=GroupEventType.CREATE,
            group_id="",  # will be set to event hash
            timestamp=int(time.time()),
            prev=None,
            signed_by=creator_identity,
            signature="",
            name=name,
            membership_policy=membership_policy,
            encryption_mode=encryption_mode,
            creator=creator_identity,
        )

        # Group ID is hash of the creation event (without signature)
        event.group_id = hash_json(event.signable_dict())

        # Now sign
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = keypair.sign_hex(signable.encode("utf-8"))

        return event


@dataclass
class GroupAddMemberEvent(GroupEvent):
    """Add a member to the group."""

    member_identity: str = ""
    role: MemberRole = MemberRole.MEMBER
    invited_by: str = ""
    encrypted_group_key: str | None = None  # for shared_key mode

    def __post_init__(self):
        self.event_type = GroupEventType.ADD_MEMBER

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "member_identity": self.member_identity,
            "role": self.role.value,
            "invited_by": self.invited_by,
            "encrypted_group_key": self.encrypted_group_key,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupAddMemberEvent:
        return cls(
            event_type=GroupEventType.ADD_MEMBER,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=data["prev"],
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            member_identity=data["member_identity"],
            role=MemberRole(data.get("role", "member")),
            invited_by=data["invited_by"],
            encrypted_group_key=data.get("encrypted_group_key"),
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        inviter_identity: str,
        group_id: str,
        prev_hash: str,
        member_identity: str,
        role: MemberRole = MemberRole.MEMBER,
        encrypted_group_key: str | None = None,
    ) -> GroupAddMemberEvent:
        """Create and sign an add member event."""
        event = cls(
            event_type=GroupEventType.ADD_MEMBER,
            group_id=group_id,
            timestamp=int(time.time()),
            prev=prev_hash,
            signed_by=inviter_identity,
            signature="",
            member_identity=member_identity,
            role=role,
            invited_by=inviter_identity,
            encrypted_group_key=encrypted_group_key,
        )

        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = keypair.sign_hex(signable.encode("utf-8"))

        return event


@dataclass
class GroupRemoveMemberEvent(GroupEvent):
    """Remove a member from the group."""

    member_identity: str = ""
    reason: str | None = None

    def __post_init__(self):
        self.event_type = GroupEventType.REMOVE_MEMBER

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "member_identity": self.member_identity,
            "reason": self.reason,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupRemoveMemberEvent:
        return cls(
            event_type=GroupEventType.REMOVE_MEMBER,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=data["prev"],
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            member_identity=data["member_identity"],
            reason=data.get("reason"),
        )


@dataclass
class GroupChangeAdminEvent(GroupEvent):
    """Change a member's admin status."""

    member_identity: str = ""
    new_role: MemberRole = MemberRole.MEMBER

    def __post_init__(self):
        self.event_type = GroupEventType.CHANGE_ADMIN

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "member_identity": self.member_identity,
            "new_role": self.new_role.value,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupChangeAdminEvent:
        return cls(
            event_type=GroupEventType.CHANGE_ADMIN,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=data["prev"],
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            member_identity=data["member_identity"],
            new_role=MemberRole(data.get("new_role", "member")),
        )


@dataclass
class GroupRotateKeyEvent(GroupEvent):
    """Rotate the group encryption key."""

    new_key_id: str = ""
    encrypted_keys: dict[str, str] = field(default_factory=dict)  # member -> encrypted key

    def __post_init__(self):
        self.event_type = GroupEventType.ROTATE_KEY

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "new_key_id": self.new_key_id,
            "encrypted_keys": self.encrypted_keys,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupRotateKeyEvent:
        return cls(
            event_type=GroupEventType.ROTATE_KEY,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=data["prev"],
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            new_key_id=data["new_key_id"],
            encrypted_keys=data.get("encrypted_keys", {}),
        )


@dataclass
class GroupUpdateSettingsEvent(GroupEvent):
    """Update group settings."""

    name: str | None = None
    membership_policy: MembershipPolicy | None = None

    def __post_init__(self):
        self.event_type = GroupEventType.UPDATE_SETTINGS

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "name": self.name,
            "membership_policy": self.membership_policy.value if self.membership_policy else None,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GroupUpdateSettingsEvent:
        return cls(
            event_type=GroupEventType.UPDATE_SETTINGS,
            group_id=data["group_id"],
            timestamp=data["timestamp"],
            prev=data["prev"],
            signed_by=data["signed_by"],
            signature=data.get("signature", ""),
            name=data.get("name"),
            membership_policy=MembershipPolicy(data["membership_policy"]) if data.get("membership_policy") else None,
        )


@dataclass
class GroupMemberInfo:
    """Information about a group member."""

    identity: str
    role: MemberRole
    added_at: int
    invited_by: str


@dataclass
class Group:
    """A group with its event chain."""

    events: list[GroupEvent] = field(default_factory=list)

    @property
    def group_id(self) -> str | None:
        if self.events and isinstance(self.events[0], GroupCreateEvent):
            return self.events[0].group_id
        return None

    @property
    def name(self) -> str | None:
        name = None
        for event in self.events:
            if isinstance(event, GroupCreateEvent):
                name = event.name
            elif isinstance(event, GroupUpdateSettingsEvent) and event.name:
                name = event.name
        return name

    @property
    def head_hash(self) -> str | None:
        if self.events:
            return self.events[-1].event_hash()
        return None

    def get_members(self) -> list[GroupMemberInfo]:
        """Get current group members."""
        members: dict[str, GroupMemberInfo] = {}
        removed: set[str] = set()

        for event in self.events:
            if isinstance(event, GroupCreateEvent):
                # Creator is first admin
                members[event.creator] = GroupMemberInfo(
                    identity=event.creator,
                    role=MemberRole.ADMIN,
                    added_at=event.timestamp,
                    invited_by=event.creator,
                )
            elif isinstance(event, GroupAddMemberEvent):
                members[event.member_identity] = GroupMemberInfo(
                    identity=event.member_identity,
                    role=event.role,
                    added_at=event.timestamp,
                    invited_by=event.invited_by,
                )
            elif isinstance(event, GroupRemoveMemberEvent):
                removed.add(event.member_identity)
            elif isinstance(event, GroupChangeAdminEvent):
                if event.member_identity in members:
                    members[event.member_identity].role = event.new_role

        return [m for m in members.values() if m.identity not in removed]

    def get_admins(self) -> list[str]:
        """Get identity hashes of admins."""
        return [m.identity for m in self.get_members() if m.role == MemberRole.ADMIN]

    def is_member(self, identity: str) -> bool:
        """Check if identity is a member."""
        return any(m.identity == identity for m in self.get_members())

    def is_admin(self, identity: str) -> bool:
        """Check if identity is an admin."""
        return identity in self.get_admins()

    def append(self, event: GroupEvent) -> None:
        """Append an event."""
        self.events.append(event)

    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps([e.to_dict() for e in self.events], indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> Group:
        """Load from JSON."""
        data = json.loads(json_str)
        events = [GroupEvent.from_dict(e) for e in data]
        return cls(events=events)
