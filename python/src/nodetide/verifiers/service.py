"""Standalone claim verification service.

An independent party: its own process, its own storage, its own issuer identity. It shares nothing with
any node. A holder proves control of its identity, the service emails a one-time code, and on success it
issues an attestation signed by the service identity. Whether anyone trusts that identity is up to the
relying party (for the OIDC bridge: NODETIDE_OIDC_EMAIL_ISSUERS).

Environment
    NODETIDE_VERIFIER_URL            public https origin of this service (the audience of key-control proofs)
    NODETIDE_VERIFIER_HOME           state directory (database with the issuer keys); default ~/.nodetide-verifier
    NODETIDE_VERIFIER_PUBLISH_ISSUER file to write the issuer's identity hash to, for the operator to pin elsewhere
    NODETIDE_ISSUER_NAME, NODETIDE_SMTP_* , NODETIDE_EMAIL_FROM, NODETIDE_EMAIL_DEV_LOG    see verifiers.config

    python -m nodetide.verifiers.service [--host 0.0.0.0] [--port 4558]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

from aiohttp import web

from nodetide.api.auth.challenges import ChallengeStore
from nodetide.api.auth.native import challenge_handler
from nodetide.api.verifiers import setup_verifier_routes
from nodetide.core.storage import Storage
from nodetide.verifiers.config import VerifierConfigError, build_email_verifier
from nodetide.verifiers.email_verifier import EmailVerifier

logger = logging.getLogger("nodetide.verifier")


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "nodetide-verifier", "commit": os.environ.get("GIT_COMMIT", "dev")})


async def index(request: web.Request) -> web.Response:
    verifier: EmailVerifier = request.app["email_verifier"]
    return web.json_response({
        "service": "nodetide-verifier",
        "name": verifier.issuer.name,
        "issuer": verifier.issuer.identity_hash,
        "info": "/api/verify/issuer",
    })


async def _cleanup(app: web.Application) -> None:
    while True:
        await asyncio.sleep(60)
        app["email_verifier"].cleanup()
        app["challenge_store"].cleanup_expired()


async def _start(app: web.Application) -> None:
    app["cleanup_task"] = asyncio.create_task(_cleanup(app))


async def _stop(app: web.Application) -> None:
    app["cleanup_task"].cancel()
    app["storage"].close()


def create_verifier_app(storage: Storage, verifier: EmailVerifier, audience: str) -> web.Application:
    app = web.Application()
    app["storage"] = storage
    app["email_verifier"] = verifier
    app["auth_audience"] = audience.rstrip("/")
    app["challenge_store"] = ChallengeStore()
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_post("/api/auth/challenge", challenge_handler)
    setup_verifier_routes(app)
    app.on_startup.append(_start)
    app.on_cleanup.append(_stop)
    return app


def publish_issuer(verifier: EmailVerifier, target: str | None) -> None:
    if target:
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(verifier.issuer.identity_hash + "\n")


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
    try:
        verifier = build_email_verifier(storage, audience, required=True)
    except VerifierConfigError as e:
        raise SystemExit(f"verifier configuration: {e}") from e
    assert verifier is not None
    publish_issuer(verifier, os.environ.get("NODETIDE_VERIFIER_PUBLISH_ISSUER"))
    logger.info("issuer %s (%s), audience %s", verifier.issuer.identity_hash, verifier.issuer.name, audience)
    web.run_app(create_verifier_app(storage, verifier, audience), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
