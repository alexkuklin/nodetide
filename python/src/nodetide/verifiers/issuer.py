"""The node's own attestation issuer: an organization identity with one signing device."""

from __future__ import annotations

from typing import Any

from nodetide.core.claims import (
    DEFAULT_ATTESTATION_LIFETIME,
    Attestation,
    AttestationRevocation,
)
from nodetide.core.crypto import KeyPair, SigningKey
from nodetide.core.identity import ClaimRecord, DeviceCapability, Identity, IdentityType
from nodetide.core.storage import Storage


class NodeIssuer:
    """Signs attestations on behalf of this node.

    The identity's master key is kept but never used for attestations; a
    separate device key with only `sign_identity` signs them, so it can be
    revoked and replaced without losing the issuer's identity.
    """

    def __init__(self, identity: Identity, device_key: SigningKey):
        self.identity = identity
        self.device_key = device_key

    @property
    def identity_hash(self) -> str:
        return self.identity.identity_hash or ""

    @property
    def name(self) -> str | None:
        genesis = self.identity.sigchain.genesis
        return genesis.name if genesis else None

    @classmethod
    def load_or_create(cls, storage: Storage, name: str) -> NodeIssuer:
        row = storage.get_node_issuer()
        if row is not None:
            chain = storage.get_sigchain(row["identity_hash"])
            if chain is None:
                raise RuntimeError("The node issuer's sigchain is missing from storage")
            keypair = KeyPair.from_dict({
                "signing_key": row["master_signing_key"],
                "encryption_key": row["master_encryption_key"],
            })
            return cls(Identity(sigchain=chain, local_keypair=keypair),
                       SigningKey.from_hex(row["device_signing_key"]))

        identity = Identity.create(identity_type=IdentityType.ORGANIZATION, name=name)
        device, _ = identity.add_device("attestation signer", capabilities=[DeviceCapability.SIGN_IDENTITY])
        storage.save_sigchain(identity.sigchain)
        assert identity.local_keypair is not None
        storage.save_node_issuer(
            identity_hash=identity.identity_hash or "",
            master_signing_key=identity.local_keypair.signing_key.to_hex(),
            master_encryption_key=identity.local_keypair.encryption_key.to_hex(),
            device_pubkey=device.verify_key.to_hex(),
            device_signing_key=device.signing_key.to_hex(),
        )
        return cls(identity, device.signing_key)

    def issue(
        self,
        subject: str,
        record: ClaimRecord,
        chain_head: str,
        method: str,
        assurance: str,
        evidence: dict[str, Any] | None = None,
        lifetime: int = DEFAULT_ATTESTATION_LIFETIME,
    ) -> Attestation:
        return Attestation.issue(
            self.identity_hash, self.device_key, subject, record, chain_head,
            method, assurance, evidence, lifetime,
        )

    def revoke(self, attestation_id: str, reason: str | None = None) -> AttestationRevocation:
        return AttestationRevocation.create(self.identity_hash, self.device_key, attestation_id, reason)
