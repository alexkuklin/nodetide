"""Email verification: prove control of an inbox, get a `low` assurance attestation.

Flow
  1. The holder proves it controls a key of the identity (an AuthAssertion bound
     to this node and to the claim) and reveals the claim document to us.
  2. We check the document against the commitment on the holder's sigchain and
     email a one-time code to the address.
  3. The holder returns the code; we issue an attestation for that claim.
We learn the address and salt for this one claim, which verifying it requires.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from nodetide.core.auth import choose_sigchain
from nodetide.core.claims import Attestation, ClaimDocument
from nodetide.core.identity import Sigchain
from nodetide.core.storage import Storage
from nodetide.verifiers.issuer import NodeIssuer
from nodetide.verifiers.mail import MailError, MailSender

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no I, L, O, 0, 1
CODE_LENGTH = 8
CODE_TTL = 900
MAX_ATTEMPTS = 5
MAX_PENDING = 1000

PER_ADDRESS = (3, 3600)   # starts per address per hour
PER_IDENTITY = (5, 3600)  # starts per identity per hour
GLOBAL = (60, 60)         # starts per minute, whole node


class VerificationError(Exception):
    """A verification step failed. `code` is machine readable."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class RateLimited(VerificationError):
    def __init__(self, message: str = "Too many verification requests, try again later"):
        super().__init__("rate_limited", message, 429)


class SlidingWindow:
    """Counts events per key within a time window."""

    def __init__(self, limit: int, seconds: int, clock: Callable[[], float]):
        self.limit, self.seconds, self.clock = limit, seconds, clock
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        events = self._events.setdefault(key, deque())
        while events and events[0] <= now - self.seconds:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True

    def cleanup(self) -> None:
        now = self.clock()
        for key in [k for k, v in self._events.items() if not v or v[-1] <= now - self.seconds]:
            del self._events[key]


@dataclass
class PendingEmail:
    verification_id: str
    identity: str
    claim_id: str
    address: str
    code_hash: str
    expires_at: int
    chain: Sigchain  # the holder's chain as checked at start (may not be stored on this node)
    attempts: int = 0


def _hash_code(verification_id: str, code: str) -> str:
    return hashlib.sha256(f"{verification_id}:{code}".encode()).hexdigest()


class EmailVerifier:
    method = "email_code"
    claim_type = "email"
    assurance = "low"

    def __init__(
        self,
        storage: Storage,
        issuer: NodeIssuer,
        sender: MailSender,
        clock: Callable[[], float] = time.time,
    ):
        self.storage, self.issuer, self.sender, self._clock = storage, issuer, sender, clock
        self._pending: dict[str, PendingEmail] = {}
        self._by_address = SlidingWindow(*PER_ADDRESS, clock)
        self._by_identity = SlidingWindow(*PER_IDENTITY, clock)
        self._global = SlidingWindow(*GLOBAL, clock)

    def _now(self) -> int:
        return int(self._clock())

    def cleanup(self) -> None:
        now = self._now()
        for vid in [v for v, p in self._pending.items() if p.expires_at < now]:
            del self._pending[vid]
        for window in (self._by_address, self._by_identity, self._global):
            window.cleanup()

    async def start(self, document: ClaimDocument, chain: Sigchain) -> tuple[str, int]:
        """Check the claim and email a code. Returns (verification_id, expires_at)."""
        if document.claim_type != self.claim_type:
            raise VerificationError("unsupported_claim_type", "This verifier only handles email claims")
        valid, err = chain.verify()
        if not valid or chain.identity_hash != document.identity:
            raise VerificationError("invalid_sigchain", err or "Sigchain does not match the identity")
        record = chain.get_claim(document.claim_id)
        if record is None:
            raise VerificationError("unknown_claim", "The identity has no such claim", 404)
        if not document.matches(record):
            raise VerificationError("claim_mismatch", "The document does not match the claim on the chain")
        status = record.status(self._now())
        if status != "active":
            raise VerificationError(f"claim_{status}", f"The claim is {status}", 409)

        self.cleanup()
        if len(self._pending) >= MAX_PENDING:
            raise RateLimited("The verifier is busy, try again later")
        address = str(document.value)
        # Count every attempt against all three limits, so no single check hides the others.
        allowed = [
            self._by_address.allow(address.lower()),
            self._by_identity.allow(document.identity),
            self._global.allow("all"),
        ]
        if not all(allowed):
            raise RateLimited()

        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
        verification_id = secrets.token_urlsafe(24)
        # A new request for the same claim replaces the older code.
        for vid in [v for v, p in self._pending.items()
                    if p.identity == document.identity and p.claim_id == document.claim_id]:
            del self._pending[vid]
        pending = PendingEmail(
            verification_id=verification_id,
            identity=document.identity,
            claim_id=document.claim_id,
            address=address,
            code_hash=_hash_code(verification_id, code),
            expires_at=self._now() + CODE_TTL,
            chain=chain,
        )
        self._pending[verification_id] = pending

        issuer_name = self.issuer.name or "Nodetide verifier"
        body = (
            f"{issuer_name} received a request to verify this email address for the "
            f"Nodetide identity {document.identity[:12]}...\n\n"
            f"Verification code: {code}\n\n"
            f"The code is valid for {CODE_TTL // 60} minutes. If you did not ask for this, "
            f"ignore this message; nothing will happen.\n"
        )
        try:
            await self.sender.send(address, f"{issuer_name}: your verification code", body)
        except MailError as e:
            del self._pending[verification_id]
            raise VerificationError("mail_failed", str(e), 503) from e
        return verification_id, pending.expires_at

    def confirm(self, verification_id: str, code: str) -> Attestation:
        """Check the code and issue the attestation."""
        pending = self._pending.get(verification_id) if isinstance(verification_id, str) else None
        if pending is None:
            raise VerificationError("unknown_verification", "Unknown or finished verification", 404)
        if self._now() > pending.expires_at:
            del self._pending[verification_id]
            raise VerificationError("expired", "The code has expired; start again", 410)

        pending.attempts += 1
        normalized = (code or "").strip().upper().replace(" ", "").replace("-", "")
        if not hmac.compare_digest(_hash_code(verification_id, normalized), pending.code_hash):
            remaining = MAX_ATTEMPTS - pending.attempts
            if remaining <= 0:
                del self._pending[verification_id]
                raise VerificationError("too_many_attempts", "Too many wrong codes; start again", 429)
            raise VerificationError("wrong_code", f"Wrong code, {remaining} attempts left", 401)

        del self._pending[verification_id]  # single use
        # Prefer the longer of what we stored and what the holder showed us at the start.
        chain, _ = choose_sigchain(self.storage.get_sigchain(pending.identity), pending.chain)
        record = chain.get_claim(pending.claim_id) if chain else None
        if chain is None or record is None or record.status(self._now()) != "active":
            raise VerificationError("claim_not_active", "The claim is no longer active", 409)

        attestation = self.issuer.issue(
            subject=pending.identity,
            record=record,
            chain_head=chain.head_hash or "",
            method=self.method,
            assurance=self.assurance,
        )
        self.storage.save_attestation(attestation.id, attestation.to_dict())
        return attestation
