"""Environment configuration for the email verifier.

    NODETIDE_EMAIL_VERIFIER=1     turn it on (also needs NODETIDE_AUTH_AUDIENCE)
    NODETIDE_ISSUER_NAME          shown in emails and on the issuer identity
    NODETIDE_SMTP_HOST / _PORT / _USER / _PASSWORD / _SECURITY (starttls|ssl|none)
    NODETIDE_EMAIL_FROM           From address
    NODETIDE_EMAIL_DEV_LOG=1      development: log codes instead of sending mail
"""

from __future__ import annotations

import os

from nodetide.core.storage import Storage
from nodetide.verifiers.email_verifier import EmailVerifier
from nodetide.verifiers.issuer import NodeIssuer
from nodetide.verifiers.mail import LogSender, MailSender, SMTPSender


class VerifierConfigError(ValueError):
    pass


def build_email_verifier(storage: Storage, audience: str | None) -> EmailVerifier | None:
    if os.environ.get("NODETIDE_EMAIL_VERIFIER") != "1":
        return None
    if not audience:
        raise VerifierConfigError("NODETIDE_EMAIL_VERIFIER needs NODETIDE_AUTH_AUDIENCE")

    host = os.environ.get("NODETIDE_SMTP_HOST")
    sender: MailSender
    if host:
        from_addr = os.environ.get("NODETIDE_EMAIL_FROM")
        if not from_addr:
            raise VerifierConfigError("NODETIDE_SMTP_HOST needs NODETIDE_EMAIL_FROM")
        sender = SMTPSender(
            host=host,
            port=int(os.environ.get("NODETIDE_SMTP_PORT", "587")),
            username=os.environ.get("NODETIDE_SMTP_USER"),
            password=os.environ.get("NODETIDE_SMTP_PASSWORD"),
            from_addr=from_addr,
            security=os.environ.get("NODETIDE_SMTP_SECURITY", "starttls"),
        )
    elif os.environ.get("NODETIDE_EMAIL_DEV_LOG") == "1":
        sender = LogSender()
    else:
        raise VerifierConfigError(
            "NODETIDE_EMAIL_VERIFIER needs NODETIDE_SMTP_HOST (or NODETIDE_EMAIL_DEV_LOG=1 for development)"
        )

    name = os.environ.get("NODETIDE_ISSUER_NAME", "Nodetide email verifier")
    return EmailVerifier(storage, NodeIssuer.load_or_create(storage, name), sender)
