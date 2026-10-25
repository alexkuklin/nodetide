"""Environment configuration for the email verifier.

    (used by the standalone verification service, nodetide.verifiers.service)
    Email is on when NODETIDE_SMTP_HOST (or NODETIDE_EMAIL_DEV_LOG=1) is set. SMS is on when a gateway token is set:
    NODETIDE_SMS_GATEWAY_TOKEN        shared secret of the SMS gateway (24+ characters)
    NODETIDE_EIDAS_ANCHORS            directory of CA certificates: turns the eID notary on (also _REVOCATION=hard-fail|soft-fail|off)
    NODETIDE_EIDAS_NAME_MATCH         exact|transliterated|approximate: how loosely a legal name may match the certificate
    NODETIDE_PHONE_ALLOWED            regex of numbers codes may be sent to (default: Bulgarian mobile, ^\\+359[0-9]{9}$)
    NODETIDE_ISSUER_NAME          shown in emails and on the issuer identity
    NODETIDE_SMTP_HOST / _PORT / _USER / _PASSWORD / _SECURITY (starttls|ssl|none)
    NODETIDE_EMAIL_FROM           From address
    NODETIDE_EMAIL_DEV_LOG=1      development: log codes instead of sending mail
"""

from __future__ import annotations

import os

from nodetide.core.storage import Storage
import hashlib
import re

from nodetide.verifiers.email_verifier import EmailVerifier
from nodetide.verifiers.issuer import NodeIssuer
from nodetide.verifiers.mail import LogSender, MailSender, SMTPSender
from nodetide.verifiers.phone_verifier import DEFAULT_ALLOWED, PhoneVerifier
from nodetide.verifiers.sms import SmsOutbox


class VerifierConfigError(ValueError):
    pass


def smtp_configured() -> bool:
    return bool(os.environ.get("NODETIDE_SMTP_HOST")) or os.environ.get("NODETIDE_EMAIL_DEV_LOG") == "1"


def build_email_verifier(
    storage: Storage, audience: str | None, *, required: bool = False, issuer: NodeIssuer | None = None
) -> EmailVerifier | None:
    """None unless NODETIDE_EMAIL_VERIFIER=1 (or `required`, as the standalone service passes)."""
    if not required and os.environ.get("NODETIDE_EMAIL_VERIFIER") != "1":
        return None
    if not audience:
        raise VerifierConfigError("the verifier needs its public address (audience)")

    host = os.environ.get("NODETIDE_SMTP_HOST")
    sender: MailSender
    if host:
        from_addr = os.environ.get("NODETIDE_EMAIL_FROM")
        if not from_addr:
            raise VerifierConfigError("NODETIDE_SMTP_HOST needs NODETIDE_EMAIL_FROM")
        sender = SMTPSender(
            host=host,
            port=int(os.environ.get("NODETIDE_SMTP_PORT", "587")),
            username=os.environ.get("NODETIDE_SMTP_USER") or None,
            password=os.environ.get("NODETIDE_SMTP_PASSWORD") or None,
            from_addr=from_addr,
            security=os.environ.get("NODETIDE_SMTP_SECURITY", "starttls"),
        )
    elif os.environ.get("NODETIDE_EMAIL_DEV_LOG") == "1":
        sender = LogSender()
    else:
        raise VerifierConfigError(
            "the verifier needs NODETIDE_SMTP_HOST (or NODETIDE_EMAIL_DEV_LOG=1 for development)"
        )

    name = os.environ.get("NODETIDE_ISSUER_NAME", "Nodetide email verifier")
    return EmailVerifier(storage, issuer or NodeIssuer.load_or_create(storage, name), sender)


MIN_TOKEN_LENGTH = 24


def build_phone_verifier(storage: Storage, issuer: NodeIssuer) -> tuple[PhoneVerifier, SmsOutbox, bytes] | None:
    """SMS verification, if a gateway token is configured. Returns (verifier, queue, sha256 of the token)."""
    token = os.environ.get("NODETIDE_SMS_GATEWAY_TOKEN", "").strip()
    if not token:
        return None
    if len(token) < MIN_TOKEN_LENGTH:
        raise VerifierConfigError(f"NODETIDE_SMS_GATEWAY_TOKEN must be at least {MIN_TOKEN_LENGTH} characters")
    allowed = os.environ.get("NODETIDE_PHONE_ALLOWED") or DEFAULT_ALLOWED
    try:
        re.compile(allowed)
    except re.error as e:
        raise VerifierConfigError(f"NODETIDE_PHONE_ALLOWED is not a valid pattern: {e}") from e
    outbox = SmsOutbox()
    return PhoneVerifier(storage, issuer, outbox, allowed), outbox, hashlib.sha256(token.encode()).digest()


def build_eid_notary(issuer: NodeIssuer):
    """The eID notary, if trust anchors are configured (it refuses to start with an empty directory)."""
    from nodetide.eidas.verify import policy_from_env
    from nodetide.verifiers.eid_notary import EidNotary

    try:
        policy = policy_from_env()
    except (OSError, ValueError) as e:
        raise VerifierConfigError(f"eID trust anchors: {e}") from e
    if policy is None:
        return None
    leniency = os.environ.get("NODETIDE_EIDAS_NAME_MATCH", "transliterated")
    try:
        return EidNotary(issuer, policy, leniency)
    except ValueError as e:
        raise VerifierConfigError(str(e)) from e
