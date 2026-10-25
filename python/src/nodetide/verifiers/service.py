"""Standalone claim verification service (email codes, SMS codes through a gateway).

An independent party: its own process, its own storage, its own issuer identity. It shares nothing with
any node. A holder proves control of its identity, the service emails a one-time code, and on success it
issues an attestation signed by the service identity. Whether anyone trusts that identity is up to the
relying party (for the OIDC bridge: NODETIDE_OIDC_EMAIL_ISSUERS).

Environment
    NODETIDE_VERIFIER_URL            public https origin of this service (the audience of key-control proofs)
    NODETIDE_VERIFIER_HOME           state directory (database with the issuer keys); default ~/.nodetide-verifier
    NODETIDE_VERIFIER_PUBLISH_ISSUER file to write the issuer's identity hash to, for the operator to pin elsewhere
    NODETIDE_ISSUER_NAME, NODETIDE_SMTP_* , NODETIDE_EMAIL_FROM, NODETIDE_EMAIL_DEV_LOG    email, see verifiers.config
    NODETIDE_SMS_GATEWAY_TOKEN, NODETIDE_PHONE_ALLOWED                                      SMS, see verifiers.config

    python -m nodetide.verifiers.service [--host 0.0.0.0] [--port 4558]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import Iterable

from aiohttp import web

from nodetide.api.auth.challenges import ChallengeStore
from nodetide.api.auth.native import challenge_handler
from nodetide.api.verifiers import setup_verifier_routes
from nodetide.core.storage import Storage
from nodetide.verifiers.config import VerifierConfigError, build_email_verifier, build_phone_verifier, smtp_configured
from nodetide.verifiers.email_verifier import CodeVerifier
from nodetide.verifiers.issuer import NodeIssuer
from nodetide.verifiers.sms import SmsOutbox

logger = logging.getLogger("nodetide.verifier")


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "nodetide-verifier", "commit": os.environ.get("GIT_COMMIT", "dev")})


async def index(request: web.Request) -> web.Response:
    verifiers: dict[str, CodeVerifier] = request.app["verifiers"]
    issuer = request.app["issuer"]
    return web.json_response({
        "service": "nodetide-verifier",
        "name": issuer.name,
        "issuer": issuer.identity_hash,
        "claim_types": list(verifiers),
        "info": "/api/verify/issuer",
    })


async def _cleanup(app: web.Application) -> None:
    while True:
        await asyncio.sleep(60)
        for verifier in app["verifiers"].values():
            verifier.cleanup()
        app["challenge_store"].cleanup_expired()
        if app.get("sms_outbox") is not None:
            app["sms_outbox"].cleanup()


async def _start(app: web.Application) -> None:
    app["cleanup_task"] = asyncio.create_task(_cleanup(app))


async def _stop(app: web.Application) -> None:
    app["cleanup_task"].cancel()
    app["storage"].close()


def create_verifier_app(
    storage: Storage,
    verifiers: CodeVerifier | Iterable[CodeVerifier],
    audience: str,
    *,
    outbox: SmsOutbox | None = None,
    gateway_token_digest: bytes | None = None,
) -> web.Application:
    verifier_list = [verifiers] if isinstance(verifiers, CodeVerifier) else list(verifiers)
    app = web.Application()
    app["storage"] = storage
    app["verifiers"] = {v.claim_type: v for v in verifier_list}
    app["issuer"] = verifier_list[0].issuer
    app["auth_audience"] = audience.rstrip("/")
    app["challenge_store"] = ChallengeStore()
    if outbox is not None:
        app["sms_outbox"] = outbox
        app["gateway_token_digest"] = gateway_token_digest
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_post("/api/auth/challenge", challenge_handler)
    setup_verifier_routes(app)
    app.on_startup.append(_start)
    app.on_cleanup.append(_stop)
    return app


def publish_issuer(verifier: CodeVerifier | NodeIssuer, target: str | None) -> None:
    if target:
        issuer = getattr(verifier, "issuer", verifier)
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(issuer.identity_hash + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nodetide claim verification service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4558)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    audience = os.environ.get("NODETIDE_VERIFIER_URL", "")
    home = Path(os.environ.get("NODETIDE_VERIFIER_HOME") or Path.home() / ".nodetide-verifier")
    home.mkdir(parents=True, exist_ok=True)
    storage = Storage.open(home / "verifier.db")
    issuer = NodeIssuer.load_or_create(storage, os.environ.get("NODETIDE_ISSUER_NAME", "Nodetide verifier"))
    try:
        verifiers: list[CodeVerifier] = []
        email = build_email_verifier(storage, audience, required=True, issuer=issuer) if smtp_configured() else None
        if email is not None:
            verifiers.append(email)
        phone = build_phone_verifier(storage, issuer)
        outbox = digest = None
        if phone is not None:
            phone_verifier, outbox, digest = phone
            verifiers.append(phone_verifier)
        if not audience:
            raise VerifierConfigError("NODETIDE_VERIFIER_URL (the public address) is required")
        if not verifiers:
            raise VerifierConfigError("nothing to verify: set NODETIDE_SMTP_HOST (email) and/or NODETIDE_SMS_GATEWAY_TOKEN (SMS)")
    except VerifierConfigError as e:
        raise SystemExit(f"verifier configuration: {e}") from e
    publish_issuer(issuer, os.environ.get("NODETIDE_VERIFIER_PUBLISH_ISSUER"))
    logger.info("issuer %s (%s), audience %s, verifying: %s", issuer.identity_hash, issuer.name, audience,
                ", ".join(v.claim_type for v in verifiers))
    app = create_verifier_app(storage, verifiers, audience, outbox=outbox, gateway_token_digest=digest)
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
