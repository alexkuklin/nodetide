"""Phone verification by SMS: prove control of a number, get a `low` assurance attestation.

The service only queues the message (see sms.py); a gateway with a modem sends it. Which numbers it is willing to
send to is limited here by a pattern (default: Bulgarian mobile numbers) and, independently, by the gateway.
"""

from __future__ import annotations

import re
import time
from typing import Callable

from nodetide.core.storage import Storage
from nodetide.verifiers.email_verifier import CODE_TTL, CodeVerifier, PendingEmail, RateLimited, VerificationError
from nodetide.verifiers.issuer import NodeIssuer
from nodetide.verifiers.sms import FAILED, SENT, OutboxFull, SmsOutbox

DEFAULT_ALLOWED = r"^\+359[0-9]{9}$"
CODE_DIGITS = "0123456789"
SMS_TTL = 600


class PhoneVerifier(CodeVerifier):
    method = "sms_code"
    claim_type = "phone"
    assurance = "low"
    code_alphabet = CODE_DIGITS
    code_length = 6
    code_ttl = SMS_TTL
    per_address = (3, 3600)    # per number per hour
    per_identity = (3, 3600)   # per identity per hour
    global_limit = (10, 3600)  # SMS cost money: ten an hour, whole service

    def __init__(
        self,
        storage: Storage,
        issuer: NodeIssuer,
        outbox: SmsOutbox,
        allowed: str = DEFAULT_ALLOWED,
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(storage, issuer, clock)
        self.outbox = outbox
        self.allowed = re.compile(allowed)

    def _validate_value(self, value: str) -> None:
        if not self.allowed.fullmatch(value):
            raise VerificationError(
                "number_not_allowed", "This service only sends codes to numbers it is configured for", 422)

    async def _deliver(self, pending: PendingEmail, code: str) -> None:
        text = f"Nodetide code: {code}. Valid {self.code_ttl // 60} min. Ignore this if you did not ask for it."
        try:
            job = self.outbox.enqueue(pending.address, text, ttl=self.code_ttl)
        except OutboxFull:
            raise RateLimited("The SMS queue is full, try again later") from None
        pending.ref = job.id

    def delivery_status(self, verification_id: str) -> dict[str, str]:
        pending = self._pending.get(verification_id)
        if pending is None:
            raise VerificationError("unknown_verification", "Unknown or finished verification", 404)
        job = self.outbox.get(pending.ref)
        if job is None:
            return {"delivery": "unknown"}
        if job.state == SENT:
            return {"delivery": "sent"}
        if job.state == FAILED:
            return {"delivery": "failed", "reason": job.error}
        return {"delivery": "queued"}
