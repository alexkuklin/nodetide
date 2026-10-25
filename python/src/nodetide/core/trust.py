"""Trust model - delegation of trust to attestation issuers.

Separate from identity system - this is about who you trust and how much.
Whether to believe an attestation is decided by the relying party; trust
delegations are one input to that decision (see "Claims and Attestations" in
identity-system.md).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from nodetide.core.crypto import KeyPair


@dataclass
class TrustDelegation:
    """Trust delegation - how much to trust someone to issue attestations.

    Weight ranges from 0.0 to 1.0:
      1.0 = fully trust their judgment
      0.5 = partial trust
      0.0 = ignore their attestations

    scope limits the delegation to some claim types (e.g. ["legal_name"]);
    None means every claim type.
    """

    from_identity: str  # who is delegating trust
    to_identity: str    # who is being trusted
    weight: float       # 0.0 to 1.0
    depth_limit: int | None = None  # optional limit on transitive depth
    timestamp: int = 0
    scope: list[str] | None = None  # claim types this delegation covers

    def __post_init__(self):
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        if self.scope is not None:
            if not isinstance(self.scope, list) or not all(isinstance(s, str) and s for s in self.scope):
                raise ValueError("Scope must be a list of claim type names")

    def covers(self, claim_type: str | None) -> bool:
        """Whether this delegation applies to the given claim type."""
        return claim_type is None or self.scope is None or claim_type in self.scope

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "from_identity": self.from_identity,
            "to_identity": self.to_identity,
            "weight": self.weight,
            "depth_limit": self.depth_limit,
            "timestamp": self.timestamp,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustDelegation:
        """Load from dictionary."""
        return cls(
            from_identity=data["from_identity"],
            to_identity=data["to_identity"],
            weight=data["weight"],
            depth_limit=data.get("depth_limit"),
            timestamp=data.get("timestamp", 0),
            scope=data.get("scope"),
        )


@dataclass
class TrustPath:
    """A path of delegations from self to an identity."""

    hops: list[str]  # identity hashes in the path, starting with self
    weights: list[float]  # delegation weights along the path
    combined_score: float  # product of the weights

    @property
    def depth(self) -> int:
        return len(self.hops) - 1


@dataclass
class TrustResult:
    """How much the calculating identity trusts another to issue attestations."""

    subject: str
    claim_type: str | None
    trust_score: float  # best path, 0.0 if none
    paths: list[TrustPath]


@dataclass
class TrustGraph:
    """Graph of trust delegations for calculating transitive trust."""

    my_identity: str
    delegations: dict[str, list[TrustDelegation]] = field(default_factory=dict)

    def add_delegation(self, delegation: TrustDelegation) -> None:
        """Add a trust delegation."""
        self.delegations.setdefault(delegation.from_identity, []).append(delegation)

    def get_delegations_from(self, identity: str) -> list[TrustDelegation]:
        """Get delegations from an identity."""
        return self.delegations.get(identity, [])

    def calculate_trust(
        self,
        subject: str,
        claim_type: str | None = None,
        max_depth: int = 3,
    ) -> TrustResult:
        """Trust in `subject` as an issuer of `claim_type` attestations.

        Every delegation path from self to the subject scores the product of its
        weights; the best path wins. Only delegations whose scope covers the
        claim type are followed. A delegation's own depth_limit caps how far
        trust may continue beyond it.
        """
        if subject == self.my_identity:
            return TrustResult(subject, claim_type, 1.0, [TrustPath([subject], [], 1.0)])

        paths: list[TrustPath] = []
        # (path, weights, remaining depth budget imposed by earlier delegations)
        queue: list[tuple[list[str], list[float], int]] = [([self.my_identity], [], max_depth)]

        while queue:
            path, weights, budget = queue.pop(0)
            if budget <= 0:
                continue
            for delegation in self.get_delegations_from(path[-1]):
                target = delegation.to_identity
                if target in path or not delegation.covers(claim_type):
                    continue
                new_weights = weights + [delegation.weight]
                new_path = path + [target]
                if target == subject:
                    score = 1.0
                    for w in new_weights:
                        score *= w
                    paths.append(TrustPath(new_path, new_weights, score))
                    continue  # no need to go through the subject to reach it
                new_budget = budget - 1
                if delegation.depth_limit is not None:
                    new_budget = min(new_budget, delegation.depth_limit)
                queue.append((new_path, new_weights, new_budget))

        best = max((p.combined_score for p in paths), default=0.0)
        return TrustResult(subject, claim_type, best, sorted(paths, key=lambda p: -p.combined_score))


@dataclass
class RelayWarning:
    """Warning about an unreliable relay node."""

    relay_node: str  # node identity hash
    reporter: str    # who reported this
    issue: str       # "drops_messages", "logs_metadata", "selective_delivery", "spam"
    confidence: float  # 0.0 to 1.0
    evidence: str | None
    timestamp: int
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "relay_node": self.relay_node,
            "reporter": self.reporter,
            "issue": self.issue,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    def signable_dict(self) -> dict[str, Any]:
        """Get dictionary for signing."""
        d = self.to_dict()
        del d["signature"]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelayWarning:
        """Load from dictionary."""
        return cls(
            relay_node=data["relay_node"],
            reporter=data["reporter"],
            issue=data["issue"],
            confidence=data["confidence"],
            evidence=data.get("evidence"),
            timestamp=data["timestamp"],
            signature=data.get("signature", ""),
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        reporter_identity: str,
        relay_node: str,
        issue: str,
        confidence: float,
        evidence: str | None = None,
    ) -> RelayWarning:
        """Create and sign a relay warning."""
        warning = cls(
            relay_node=relay_node,
            reporter=reporter_identity,
            issue=issue,
            confidence=confidence,
            evidence=evidence,
            timestamp=int(time.time()),
            signature="",
        )

        signable = json.dumps(warning.signable_dict(), sort_keys=True, separators=(",", ":"))
        warning.signature = keypair.sign_hex(signable.encode("utf-8"))
        return warning
