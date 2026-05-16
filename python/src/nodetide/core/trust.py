"""Trust model - identity assertions and delegation.

Separate from identity system - this is about who you trust and how much.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nodetide.core.crypto import KeyPair, hash_json


class VerificationLevel(str, Enum):
    """How an identity was verified."""

    IN_PERSON = "in_person"      # Physical key exchange
    VIDEO = "video"              # Live video verification
    VOUCHED = "vouched"          # Verified by someone you trust
    SOCIAL_PROOF = "social_proof"  # Public proofs (signed statement on known account)
    CLAIMED = "claimed"          # Unverified self-assertion


@dataclass
class IdentityAssertion:
    """Assertion about who an identity belongs to.

    Confidence ranges from -1.0 to 1.0:
      +1.0 = certain this is the claimed person
      +0.5 = reasonably confident
       0.0 = no information
      -0.5 = doubtful this is the claimed person
      -1.0 = certain this is NOT the claimed person (impersonation)
    """

    asserter: str  # identity hash of the person making this assertion
    subject: str   # identity hash being asserted about
    claimed_name: str | None
    verification: VerificationLevel
    confidence: float  # -1.0 to 1.0
    timestamp: int
    note: str | None = None
    signature: str = ""

    def __post_init__(self):
        if not -1.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between -1.0 and 1.0")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asserter": self.asserter,
            "subject": self.subject,
            "claimed_name": self.claimed_name,
            "verification": self.verification.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "note": self.note,
            "signature": self.signature,
        }

    def signable_dict(self) -> dict[str, Any]:
        """Get dictionary for signing."""
        d = self.to_dict()
        del d["signature"]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityAssertion:
        """Load from dictionary."""
        return cls(
            asserter=data["asserter"],
            subject=data["subject"],
            claimed_name=data.get("claimed_name"),
            verification=VerificationLevel(data["verification"]),
            confidence=data["confidence"],
            timestamp=data["timestamp"],
            note=data.get("note"),
            signature=data.get("signature", ""),
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        asserter_identity: str,
        subject: str,
        claimed_name: str | None,
        verification: VerificationLevel,
        confidence: float,
        note: str | None = None,
    ) -> IdentityAssertion:
        """Create and sign a new assertion."""
        assertion = cls(
            asserter=asserter_identity,
            subject=subject,
            claimed_name=claimed_name,
            verification=verification,
            confidence=confidence,
            timestamp=int(time.time()),
            note=note,
            signature="",
        )

        signable = json.dumps(assertion.signable_dict(), sort_keys=True, separators=(",", ":"))
        assertion.signature = keypair.sign_hex(signable.encode("utf-8"))
        return assertion


@dataclass
class TrustDelegation:
    """Trust delegation - how much to trust someone's identity assertions.

    Weight ranges from 0.0 to 1.0:
      1.0 = fully trust their judgment
      0.5 = partial trust
      0.0 = ignore their assertions
    """

    from_identity: str  # who is delegating trust
    to_identity: str    # who is being trusted
    weight: float       # 0.0 to 1.0
    depth_limit: int | None = None  # optional limit on transitive depth
    timestamp: int = 0

    def __post_init__(self):
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "from_identity": self.from_identity,
            "to_identity": self.to_identity,
            "weight": self.weight,
            "depth_limit": self.depth_limit,
            "timestamp": self.timestamp,
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
        )


@dataclass
class TrustResult:
    """Result of a trust calculation for an identity."""

    subject: str
    claimed_name: str | None
    trust_score: float  # combined score
    is_contested: bool  # positive and negative assertions conflict
    assertions: list[IdentityAssertion]
    paths: list[TrustPath]  # how we reached this conclusion


@dataclass
class TrustPath:
    """A path of trust from self to a subject."""

    hops: list[str]  # identity hashes in the path
    weights: list[float]  # delegation weights along the path
    final_confidence: float  # assertion confidence at the end
    combined_score: float  # product of weights * confidence

    @property
    def depth(self) -> int:
        return len(self.hops) - 1


@dataclass
class TrustGraph:
    """Graph of trust relationships for calculating transitive trust."""

    my_identity: str
    delegations: dict[str, list[TrustDelegation]] = field(default_factory=dict)
    assertions: dict[str, list[IdentityAssertion]] = field(default_factory=dict)

    def add_delegation(self, delegation: TrustDelegation) -> None:
        """Add a trust delegation."""
        if delegation.from_identity not in self.delegations:
            self.delegations[delegation.from_identity] = []
        self.delegations[delegation.from_identity].append(delegation)

    def add_assertion(self, assertion: IdentityAssertion) -> None:
        """Add an identity assertion."""
        if assertion.subject not in self.assertions:
            self.assertions[assertion.subject] = []
        self.assertions[assertion.subject].append(assertion)

    def get_delegations_from(self, identity: str) -> list[TrustDelegation]:
        """Get delegations from an identity."""
        return self.delegations.get(identity, [])

    def get_assertions_about(self, subject: str) -> list[IdentityAssertion]:
        """Get assertions about a subject."""
        return self.assertions.get(subject, [])

    def calculate_trust(
        self,
        subject: str,
        max_depth: int = 3,
    ) -> TrustResult:
        """Calculate trust for a subject identity.

        Uses BFS to find all paths, then combines using max() for multiple paths.
        Detects contested identities (positive + negative assertions).
        """
        all_paths: list[TrustPath] = []

        # BFS to find all paths to people who have made assertions
        visited: set[str] = set()
        queue: list[tuple[list[str], list[float]]] = [([self.my_identity], [])]

        while queue:
            path, weights = queue.pop(0)
            current = path[-1]

            if current in visited and current != self.my_identity:
                continue
            visited.add(current)

            # Check if current identity has assertions about subject
            for assertion in self.get_assertions_about(subject):
                if assertion.asserter == current:
                    # Calculate combined score for this path
                    if weights:
                        path_weight = 1.0
                        for w in weights:
                            path_weight *= w
                    else:
                        path_weight = 1.0  # direct assertion from self

                    combined = path_weight * assertion.confidence

                    all_paths.append(TrustPath(
                        hops=path.copy(),
                        weights=weights.copy(),
                        final_confidence=assertion.confidence,
                        combined_score=combined,
                    ))

            # Continue BFS if under depth limit
            if len(path) - 1 < max_depth:
                for delegation in self.get_delegations_from(current):
                    # Check depth limit on this delegation
                    if delegation.depth_limit is not None:
                        if len(path) - 1 >= delegation.depth_limit:
                            continue

                    if delegation.to_identity not in path:  # avoid cycles
                        queue.append((
                            path + [delegation.to_identity],
                            weights + [delegation.weight],
                        ))

        # Combine paths
        if not all_paths:
            return TrustResult(
                subject=subject,
                claimed_name=None,
                trust_score=0.0,
                is_contested=False,
                assertions=[],
                paths=[],
            )

        # Get all assertions from people in paths
        all_assertions = []
        asserters_seen = set()
        for p in all_paths:
            for assertion in self.get_assertions_about(subject):
                if assertion.asserter in asserters_seen:
                    continue
                if assertion.asserter == p.hops[-1]:
                    all_assertions.append(assertion)
                    asserters_seen.add(assertion.asserter)

        # Check for contested (positive and negative assertions)
        positive_paths = [p for p in all_paths if p.combined_score > 0]
        negative_paths = [p for p in all_paths if p.combined_score < 0]
        is_contested = bool(positive_paths and negative_paths)

        # Combine scores using max() for same-sign, flag contested for mixed
        if is_contested:
            # Take the stronger signal for display, but flag as contested
            all_scores = [p.combined_score for p in all_paths]
            if abs(max(all_scores)) >= abs(min(all_scores)):
                trust_score = max(all_scores)
            else:
                trust_score = min(all_scores)
        else:
            # Use max for positive, min for negative
            scores = [p.combined_score for p in all_paths]
            if any(s > 0 for s in scores):
                trust_score = max(s for s in scores if s > 0)
            elif any(s < 0 for s in scores):
                trust_score = min(s for s in scores if s < 0)
            else:
                trust_score = 0.0

        # Get claimed name from highest confidence positive assertion
        claimed_name = None
        best_positive = None
        for assertion in all_assertions:
            if assertion.confidence > 0:
                if best_positive is None or assertion.confidence > best_positive.confidence:
                    best_positive = assertion
        if best_positive:
            claimed_name = best_positive.claimed_name

        return TrustResult(
            subject=subject,
            claimed_name=claimed_name,
            trust_score=trust_score,
            is_contested=is_contested,
            assertions=all_assertions,
            paths=all_paths,
        )

    def get_trusted_identities(
        self,
        min_score: float = 0.5,
        max_depth: int = 3,
    ) -> list[TrustResult]:
        """Get all identities with trust above threshold."""
        results = []
        for subject in self.assertions.keys():
            result = self.calculate_trust(subject, max_depth)
            if result.trust_score >= min_score and not result.is_contested:
                results.append(result)

        # Sort by trust score descending
        results.sort(key=lambda r: r.trust_score, reverse=True)
        return results


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
