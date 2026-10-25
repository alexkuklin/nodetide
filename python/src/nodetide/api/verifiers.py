"""HTTP API of the node's claim verifiers (currently: email)."""

from __future__ import annotations

from aiohttp import web

from nodetide.api.auth.challenges import ChallengeStore
from nodetide.api.claims import error, read_object, resolve_chain
from nodetide.core.auth import CLOCK_SKEW, verify_assertion
from nodetide.core.claims import ClaimDocument, ClaimError
from nodetide.core.storage import Storage
from nodetide.verifiers import EmailVerifier, VerificationError

PURPOSE = "claim_verification"


async def issuer_info(request: web.Request) -> web.Response:
    """GET /verify/issuer - who issues attestations here, and for which claims."""
    verifier: EmailVerifier | None = request.app.get("email_verifier")
    if verifier is None:
        return error("not_configured", "This node does not verify claims", 404)
    return web.json_response({
        "issuer": verifier.issuer.identity_hash,
        "name": verifier.issuer.name,
        "audience": request.app.get("auth_audience"),
        "methods": [{
            "method": verifier.method,
            "claim_type": verifier.claim_type,
            "assurance": verifier.assurance,
            "start": "/api/verify/email/start",
            "confirm": "/api/verify/email/confirm",
        }],
    })


async def email_start(request: web.Request) -> web.Response:
    """POST /verify/email/start - {"document": {...}, "assertion": {...}, "sigchain": [...]?}

    The assertion is an AuthAssertion for this node's audience (challenge from
    /auth/challenge) whose signed claims bind it to this claim:
    {"purpose": "claim_verification", "claim_id": "<claim id>"}.
    """
    verifier: EmailVerifier | None = request.app.get("email_verifier")
    audience = request.app.get("auth_audience")
    if verifier is None or not audience:
        return error("not_configured", "Email verification is not enabled on this node", 501)

    storage: Storage = request.app["storage"]
    challenges: ChallengeStore = request.app["challenge_store"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data

    try:
        document = ClaimDocument.from_dict(data.get("document"))
    except ClaimError as e:
        return error("invalid_request", str(e), 400)
    assertion = data.get("assertion")
    if not isinstance(assertion, dict) or not isinstance(assertion.get("nonce"), str):
        return error("invalid_request", "An assertion with a nonce is required", 400)
    if assertion.get("identity") != document.identity:
        return error("invalid_request", "The assertion is for a different identity", 400)

    challenge = challenges.peek(assertion["nonce"])
    if challenge is None:
        return error("unknown_challenge", "Challenge is unknown, already used, or expired", 401)
    if challenge.aud != audience:
        return error("wrong_audience", "Challenge was not issued for this node", 401)

    chain, err = resolve_chain(storage, document.identity, data.get("sigchain"))
    if err is not None:
        return err

    result = verify_assertion(assertion, chain, expected_aud=audience)
    if result.ok and assertion["exp"] > challenge.expires_at + CLOCK_SKEW:
        return error("invalid_assertion", "Assertion outlives its challenge", 401)
    if not result.ok:
        if result.code == "unknown_chain_head":
            return error("stale_state", result.error or "Stale sigchain", 409, {"head_hash": chain.head_hash})
        return error(result.code or "invalid_assertion", result.error or "Invalid assertion", 401)
    if result.claims.get("purpose") != PURPOSE or result.claims.get("claim_id") != document.claim_id:
        return error("assertion_not_bound", "The assertion must be signed for this claim's verification", 401)
    if not challenges.consume(assertion["nonce"]):
        return error("unknown_challenge", "Challenge is unknown, already used, or expired", 401)

    try:
        verification_id, expires_at = await verifier.start(document, chain)
    except VerificationError as e:
        return error(e.code, e.message, e.status)
    return web.json_response({
        "verification_id": verification_id,
        "expires_at": expires_at,
        "message": "A verification code was sent to the address.",
    }, status=202)


async def email_confirm(request: web.Request) -> web.Response:
    """POST /verify/email/confirm - {"verification_id": "...", "code": "..."}"""
    verifier: EmailVerifier | None = request.app.get("email_verifier")
    if verifier is None:
        return error("not_configured", "Email verification is not enabled on this node", 501)
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    verification_id, code = data.get("verification_id"), data.get("code")
    if not isinstance(verification_id, str) or not isinstance(code, str) or len(code) > 32:
        return error("invalid_request", "verification_id and code are required", 400)
    try:
        attestation = verifier.confirm(verification_id, code)
    except VerificationError as e:
        return error(e.code, e.message, e.status)
    return web.json_response(
        {"attestation_id": attestation.id, "attestation": attestation.to_dict()}, status=201
    )


def setup_verifier_routes(app: web.Application) -> None:
    app.router.add_get("/api/verify/issuer", issuer_info)
    app.router.add_post("/api/verify/email/start", email_start)
    app.router.add_post("/api/verify/email/confirm", email_confirm)
