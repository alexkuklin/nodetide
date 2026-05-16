"""API route handlers."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

from nodetide.core.identity import (
    Sigchain,
    SigchainEvent,
    GenesisEvent,
    SocialRecoveryEvent,
)
from nodetide.core.storage import Storage
from nodetide.core.trust import TrustGraph, IdentityAssertion, TrustDelegation
from nodetide.api.models import (
    APIError,
    ErrorCode,
    CreateIdentityResponse,
    IdentityResponse,
    SubmitEventResponse,
    SigchainResponse,
    SessionResponse,
    RecoveryStatusResponse,
    TrustCalculationResponse,
    VerifyResponse,
)
from nodetide.api.auth import (
    SessionStore,
    RecoveryStore,
    verify_event_signature,
    verify_assertion_signature,
    verify_session_request,
    extract_bearer_token,
)


def error_response(error: ErrorCode, message: str, status: int, details: dict | None = None) -> web.Response:
    """Create an error response."""
    return web.json_response(
        APIError(error=error.value, message=message, code=status, details=details).to_dict(),
        status=status,
    )


# Identity routes

async def create_identity(request: web.Request) -> web.Response:
    """POST /identities - Create identity with genesis event."""
    storage: Storage = request.app["storage"]

    try:
        data = await request.json()
        event_data = data.get("event")
        if not event_data:
            logger.warning("create_identity: Missing event")
            return error_response(ErrorCode.INVALID_REQUEST, "Missing event", 400)

        if event_data.get("type") != "genesis":
            logger.warning(f"create_identity: Expected genesis, got {event_data.get('type')}")
            return error_response(ErrorCode.INVALID_REQUEST, "Expected genesis event", 400)

        # Verify self-signature
        logger.info("create_identity: verifying signature...")
        valid, err = verify_event_signature(event_data)
        if not valid:
            logger.warning(f"create_identity: signature verification failed: {err}")
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 400)

        # Parse event
        logger.info("create_identity: parsing event...")
        event = GenesisEvent._from_dict(event_data)

        # Create sigchain
        sigchain = Sigchain(events=[event])
        identity_hash = sigchain.identity_hash
        logger.info(f"create_identity: identity_hash={identity_hash}")

        # Verify sigchain
        logger.info("create_identity: verifying sigchain...")
        valid, err = sigchain.verify()
        if not valid:
            logger.warning(f"create_identity: sigchain verification failed: {err}")
            return error_response(ErrorCode.INVALID_SIGCHAIN, err or "Invalid sigchain", 400)

        # Save
        storage.save_sigchain(sigchain)

        return web.json_response(
            CreateIdentityResponse(
                identity_hash=identity_hash,
                accepted=True,
                event_hash=event.event_hash(),
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return error_response(ErrorCode.INVALID_REQUEST, str(e), 400)


async def list_identities(request: web.Request) -> web.Response:
    """GET /identities - List known identities."""
    storage: Storage = request.app["storage"]

    # Get all sigchains (local and remote)
    all_ids = storage.list_all_sigchains()
    local_ids = set(storage.list_local_identities())

    identities = []
    for identity_hash in all_ids:
        sigchain = storage.get_sigchain(identity_hash)
        if sigchain and sigchain.genesis:
            identities.append({
                "identity_hash": identity_hash,
                "name": sigchain.genesis.name,
                "type": sigchain.genesis.identity_type.value,
                "is_local": identity_hash in local_ids,
            })

    return web.json_response({"identities": identities})


async def get_identity(request: web.Request) -> web.Response:
    """GET /identities/{hash} - Get identity details."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    genesis = sigchain.genesis
    if not genesis:
        return error_response(ErrorCode.INVALID_SIGCHAIN, "Invalid sigchain - no genesis", 400)

    # Check if local
    local_ids = storage.list_local_identities()
    is_local = identity_hash in local_ids

    # Get devices
    devices = []
    for device in sigchain.get_active_devices():
        devices.append({
            "pubkey": device.pubkey,
            "encryption_pubkey": device.encryption_pubkey,
            "label": device.label,
            "capabilities": device.capabilities,
            "added_at": device.added_at,
            "expires": device.expires,
        })

    # Get recovery config
    recovery_event = sigchain.get_recovery_config()
    recovery = None
    if recovery_event:
        recovery = {
            "primary_trustees": recovery_event.primary_trustees,
            "primary_threshold": recovery_event.primary_threshold,
            "backup_trustees": recovery_event.backup_trustees,
            "backup_threshold": recovery_event.backup_threshold,
        }

    # Verify
    valid, _ = sigchain.verify()

    return web.json_response(
        IdentityResponse(
            identity_hash=identity_hash,
            name=genesis.name,
            identity_type=genesis.identity_type.value,
            created_at=genesis.timestamp,
            is_local=is_local,
            devices=devices,
            recovery=recovery,
            sigchain_length=len(sigchain.events),
            sigchain=sigchain.to_list(),
            verified=valid,
            master_pubkey=sigchain.get_current_master_key() or "",
        ).to_dict()
    )


async def get_sigchain(request: web.Request) -> web.Response:
    """GET /identities/{hash}/sigchain - Get full sigchain."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    return web.json_response(
        SigchainResponse(
            identity_hash=identity_hash,
            head_hash=sigchain.head_hash or "",
            length=len(sigchain.events),
            events=sigchain.to_list(),
        ).to_dict()
    )


async def submit_event(request: web.Request) -> web.Response:
    """POST /identities/{hash}/events - Submit a signed event."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    try:
        data = await request.json()
        event_data = data.get("event")

        if not event_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing event", 400)

        # Check prev hash
        if event_data.get("prev") != sigchain.head_hash:
            return error_response(
                ErrorCode.STALE_STATE,
                "prev hash mismatch - client has stale state",
                409,
                details={
                    "expected_prev": sigchain.head_hash,
                    "received_prev": event_data.get("prev"),
                },
            )

        # Verify signature
        valid, err = verify_event_signature(event_data, sigchain)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 400)

        # Parse and append event
        event = SigchainEvent.from_dict(event_data)
        sigchain.append(event)

        # Verify updated sigchain
        valid, err = sigchain.verify()
        if not valid:
            return error_response(ErrorCode.INVALID_SIGCHAIN, err or "Invalid sigchain after append", 400)

        # Handle device key storage if requested
        if data.get("store_device_key") and data.get("device_private_key_encrypted"):
            # TODO: Store encrypted device key
            pass

        # Save
        storage.save_sigchain(sigchain)

        return web.json_response(
            SubmitEventResponse(
                accepted=True,
                event_hash=event.event_hash(),
                sigchain_length=len(sigchain.events),
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return error_response(ErrorCode.INVALID_REQUEST, str(e), 400)


async def list_devices(request: web.Request) -> web.Response:
    """GET /identities/{hash}/devices - List devices."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    devices = []
    for device in sigchain.get_active_devices():
        devices.append({
            "pubkey": device.pubkey,
            "encryption_pubkey": device.encryption_pubkey,
            "label": device.label,
            "capabilities": device.capabilities,
            "added_at": device.added_at,
            "expires": device.expires,
        })

    return web.json_response({"devices": devices})


# Session routes

async def create_session(request: web.Request) -> web.Response:
    """POST /session - Create a session."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    try:
        data = await request.json()

        identity = data.get("identity")
        device_pubkey = data.get("device_pubkey")
        expires_in = data.get("expires_in", 3600)

        if not identity or not device_pubkey:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing identity or device_pubkey", 400)

        # Get sigchain
        sigchain = storage.get_sigchain(identity)
        if not sigchain:
            return error_response(ErrorCode.NOT_FOUND, f"Identity {identity} not found", 404)

        # Verify request signature
        valid, err = verify_session_request(data, sigchain)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 401)

        # Create session
        session = session_store.create(
            identity=identity,
            device_pubkey=device_pubkey,
            expires_in=expires_in,
        )

        return web.json_response(
            SessionResponse(
                token=session.token,
                expires_at=session.expires_at,
                identity=session.identity,
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def get_session(request: web.Request) -> web.Response:
    """GET /session - Check session status."""
    session_store: SessionStore = request.app["session_store"]

    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing or invalid token", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid or expired session", 401)

    return web.json_response({
        "identity": session.identity,
        "device_pubkey": session.device_pubkey,
        "expires_at": session.expires_at,
        "created_at": session.created_at,
    })


async def delete_session(request: web.Request) -> web.Response:
    """DELETE /session - Invalidate session."""
    session_store: SessionStore = request.app["session_store"]

    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing token", 401)

    if session_store.delete(token):
        return web.json_response({"deleted": True})
    else:
        return error_response(ErrorCode.NOT_FOUND, "Session not found", 404)


# Recovery routes

async def initiate_recovery(request: web.Request) -> web.Response:
    """POST /identities/{hash}/recovery/initiate - Start recovery."""
    storage: Storage = request.app["storage"]
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    recovery_config = sigchain.get_recovery_config()
    if not recovery_config:
        return error_response(ErrorCode.INVALID_REQUEST, "No recovery config set", 400)

    try:
        data = await request.json()

        new_pubkey = data.get("new_pubkey")
        new_encryption_pubkey = data.get("new_encryption_pubkey")
        initiated_by = data.get("initiated_by")

        if not new_pubkey or not new_encryption_pubkey:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing new keys", 400)

        # Verify initiator is a trustee
        all_trustees = recovery_config.primary_trustees + (recovery_config.backup_trustees or [])
        if initiated_by and initiated_by not in all_trustees:
            return error_response(ErrorCode.FORBIDDEN, "Initiator not a trustee", 403)

        # Create pending recovery
        recovery = recovery_store.create(
            identity=identity_hash,
            new_pubkey=new_pubkey,
            new_encryption_pubkey=new_encryption_pubkey,
            initiated_by=initiated_by or "unknown",
            threshold=recovery_config.primary_threshold,
            trustees=recovery_config.primary_trustees,
        )

        return web.json_response(
            RecoveryStatusResponse(
                recovery_id=recovery.recovery_id,
                identity=identity_hash,
                status="pending",
                threshold=recovery.threshold,
                collected=0,
                signatures=[],
                expires_at=recovery.expires_at,
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def submit_recovery_signature(request: web.Request) -> web.Response:
    """POST /identities/{hash}/recovery/{id}/sign - Submit trustee signature."""
    storage: Storage = request.app["storage"]
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]
    recovery_id = request.match_info["id"]

    recovery = recovery_store.get(recovery_id)
    if not recovery:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not found or expired", 404)

    if recovery.identity != identity_hash:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not for this identity", 404)

    try:
        data = await request.json()

        trustee_identity = data.get("trustee_identity")
        signature = data.get("signature")

        if not trustee_identity or not signature:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing trustee_identity or signature", 400)

        if trustee_identity not in recovery.trustees:
            return error_response(ErrorCode.FORBIDDEN, "Not a trustee for this identity", 403)

        # TODO: Verify trustee signature against their sigchain

        # Add signature
        recovery = recovery_store.add_signature(recovery_id, trustee_identity, signature)
        if not recovery:
            return error_response(ErrorCode.INVALID_REQUEST, "Failed to add signature", 400)

        # Check if threshold met
        if recovery.is_complete:
            # Create social recovery event
            sigchain = storage.get_sigchain(identity_hash)
            if sigchain:
                recovery_sigs = [
                    {"trustee_identity": t, "signature": s["signature"]}
                    for t, s in recovery.signatures.items()
                ]

                # Create the event (unsigned - signatures are from trustees)
                event = SocialRecoveryEvent(
                    type=SocialRecoveryEvent.__dataclass_fields__["type"].default,
                    timestamp=int(time.time()),
                    prev=sigchain.head_hash,
                    signature="",  # Not signed by master
                    signed_by=recovery.new_pubkey,  # New master key
                    new_pubkey=recovery.new_pubkey,
                    new_encryption_pubkey=recovery.new_encryption_pubkey,
                    recovery_signatures=recovery_sigs,
                )

                sigchain.append(event)
                storage.save_sigchain(sigchain)

                # Clean up recovery
                recovery_store.delete(recovery_id)

                return web.json_response(
                    RecoveryStatusResponse(
                        recovery_id=recovery_id,
                        identity=identity_hash,
                        status="complete",
                        threshold=recovery.threshold,
                        collected=recovery.collected,
                        signatures=[
                            {"trustee": t, "signed_at": s["signed_at"]}
                            for t, s in recovery.signatures.items()
                        ],
                        expires_at=recovery.expires_at,
                        new_master_pubkey=recovery.new_pubkey,
                        event_hash=event.event_hash(),
                    ).to_dict()
                )

        return web.json_response(
            RecoveryStatusResponse(
                recovery_id=recovery_id,
                identity=identity_hash,
                status="pending",
                threshold=recovery.threshold,
                collected=recovery.collected,
                signatures=[
                    {"trustee": t, "signed_at": s["signed_at"]}
                    for t, s in recovery.signatures.items()
                ],
                expires_at=recovery.expires_at,
            ).to_dict()
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def get_recovery_status(request: web.Request) -> web.Response:
    """GET /identities/{hash}/recovery/{id} - Check recovery status."""
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]
    recovery_id = request.match_info["id"]

    recovery = recovery_store.get(recovery_id)
    if not recovery:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not found or expired", 404)

    if recovery.identity != identity_hash:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not for this identity", 404)

    return web.json_response(
        RecoveryStatusResponse(
            recovery_id=recovery_id,
            identity=identity_hash,
            status="complete" if recovery.is_complete else "pending",
            threshold=recovery.threshold,
            collected=recovery.collected,
            signatures=[
                {"trustee": t, "signed_at": s["signed_at"]}
                for t, s in recovery.signatures.items()
            ],
            expires_at=recovery.expires_at,
        ).to_dict()
    )


async def list_pending_recoveries(request: web.Request) -> web.Response:
    """GET /identities/{hash}/recovery/pending - List pending recoveries."""
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]

    recoveries = recovery_store.get_for_identity(identity_hash)

    return web.json_response({
        "recoveries": [
            {
                "recovery_id": r.recovery_id,
                "status": "pending",
                "threshold": r.threshold,
                "collected": r.collected,
                "expires_at": r.expires_at,
            }
            for r in recoveries
        ]
    })


# Trust routes

async def create_assertion(request: web.Request) -> web.Response:
    """POST /trust/assertions - Create trust assertion."""
    storage: Storage = request.app["storage"]

    try:
        data = await request.json()
        assertion_data = data.get("assertion")

        if not assertion_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing assertion", 400)

        asserter = assertion_data.get("asserter")
        if not asserter:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing asserter", 400)

        # Get asserter's sigchain
        sigchain = storage.get_sigchain(asserter)
        if not sigchain:
            return error_response(ErrorCode.NOT_FOUND, f"Asserter {asserter} not found", 404)

        # Verify signature
        valid, err = verify_assertion_signature(assertion_data, sigchain)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 400)

        # Save assertion
        storage.save_trust_assertion(
            asserter_identity=assertion_data["asserter"],
            subject_identity=assertion_data["subject"],
            confidence=assertion_data["confidence"],
            timestamp=assertion_data["timestamp"],
            signature=assertion_data["signature"],
            claimed_name=assertion_data.get("claimed_name"),
            verification=assertion_data.get("verification"),
            note=assertion_data.get("note"),
        )

        return web.json_response({
            "accepted": True,
            "asserter": assertion_data["asserter"],
            "subject": assertion_data["subject"],
        }, status=201)

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def list_assertions(request: web.Request) -> web.Response:
    """GET /trust/assertions - Query assertions."""
    storage: Storage = request.app["storage"]

    subject = request.query.get("subject")
    if not subject:
        return error_response(ErrorCode.INVALID_REQUEST, "Missing subject parameter", 400)

    assertions = storage.get_trust_assertions(subject)

    return web.json_response({"assertions": assertions})


async def create_delegation(request: web.Request) -> web.Response:
    """POST /trust/delegations - Create trust delegation."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    # Check auth
    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing authorization", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid session", 401)

    try:
        data = await request.json()
        delegation_data = data.get("delegation")

        if not delegation_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing delegation", 400)

        # Delegation must be from the session identity
        if delegation_data.get("from_identity") != session.identity:
            return error_response(ErrorCode.FORBIDDEN, "Can only create delegations from your identity", 403)

        storage.save_trust_delegation(
            from_identity=delegation_data["from_identity"],
            to_identity=delegation_data["to_identity"],
            weight=delegation_data["weight"],
            timestamp=delegation_data.get("timestamp", int(time.time())),
            depth_limit=delegation_data.get("depth_limit"),
        )

        return web.json_response({
            "accepted": True,
            "from": delegation_data["from_identity"],
            "to": delegation_data["to_identity"],
        }, status=201)

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def list_delegations(request: web.Request) -> web.Response:
    """GET /trust/delegations - Query delegations."""
    storage: Storage = request.app["storage"]

    from_identity = request.query.get("from")
    if not from_identity:
        return error_response(ErrorCode.INVALID_REQUEST, "Missing 'from' parameter", 400)

    delegations = storage.get_trust_delegations(from_identity)

    return web.json_response({"delegations": delegations})


async def calculate_trust(request: web.Request) -> web.Response:
    """GET /trust/calculate/{hash} - Calculate transitive trust."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    subject = request.match_info["hash"]
    max_depth = int(request.query.get("max_depth", "3"))

    # Need a session to know whose perspective to use
    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Session required for trust calculation", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid session", 401)

    # Build trust graph
    graph = TrustGraph(my_identity=session.identity)

    # Load delegations (would need to traverse, simplified here)
    delegations = storage.get_trust_delegations(session.identity)
    for d in delegations:
        graph.add_delegation(TrustDelegation.from_dict(d))

    # Load assertions about subject
    assertions = storage.get_trust_assertions(subject)
    for a in assertions:
        graph.add_assertion(IdentityAssertion.from_dict(a))

    # Calculate
    result = graph.calculate_trust(subject, max_depth)

    return web.json_response(
        TrustCalculationResponse(
            subject=result.subject,
            claimed_name=result.claimed_name,
            trust_score=result.trust_score,
            is_contested=result.is_contested,
            paths=[
                {
                    "hops": p.hops,
                    "weights": p.weights,
                    "combined_score": p.combined_score,
                }
                for p in result.paths
            ],
            assertions=[a.to_dict() for a in result.assertions],
        ).to_dict()
    )


# Query routes

async def verify_sigchain(request: web.Request) -> web.Response:
    """POST /verify - Verify a sigchain."""
    try:
        data = await request.json()
        events_data = data.get("sigchain")

        if not events_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing sigchain", 400)

        sigchain = Sigchain.from_list(events_data)
        valid, err = sigchain.verify()

        if valid:
            return web.json_response(
                VerifyResponse(
                    valid=True,
                    identity_hash=sigchain.identity_hash,
                    events=len(sigchain.events),
                    current_master=sigchain.get_current_master_key(),
                    active_devices=len(sigchain.get_active_devices()),
                ).to_dict()
            )
        else:
            return web.json_response(
                VerifyResponse(valid=False, error=err).to_dict(),
                status=400,
            )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return web.json_response(
            VerifyResponse(valid=False, error=str(e)).to_dict(),
            status=400,
        )


async def lookup_identity(request: web.Request) -> web.Response:
    """GET /lookup/{hash} - Lookup identity."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)

    if sigchain:
        genesis = sigchain.genesis
        return web.json_response({
            "found": True,
            "identity_hash": identity_hash,
            "name": genesis.name if genesis else None,
            "type": genesis.identity_type.value if genesis else None,
            "sigchain_length": len(sigchain.events),
        })
    else:
        return web.json_response({
            "found": False,
            "identity_hash": identity_hash,
        })


def setup_routes(app: web.Application) -> None:
    """Setup all API routes."""

    # Identity routes
    app.router.add_post("/api/identities", create_identity)
    app.router.add_get("/api/identities", list_identities)
    app.router.add_get("/api/identities/{hash}", get_identity)
    app.router.add_get("/api/identities/{hash}/sigchain", get_sigchain)
    app.router.add_post("/api/identities/{hash}/events", submit_event)
    app.router.add_get("/api/identities/{hash}/devices", list_devices)

    # Session routes
    app.router.add_post("/api/session", create_session)
    app.router.add_get("/api/session", get_session)
    app.router.add_delete("/api/session", delete_session)

    # Recovery routes
    app.router.add_post("/api/identities/{hash}/recovery/initiate", initiate_recovery)
    app.router.add_post("/api/identities/{hash}/recovery/{id}/sign", submit_recovery_signature)
    app.router.add_get("/api/identities/{hash}/recovery/{id}", get_recovery_status)
    app.router.add_get("/api/identities/{hash}/recovery/pending", list_pending_recoveries)

    # Trust routes
    app.router.add_post("/api/trust/assertions", create_assertion)
    app.router.add_get("/api/trust/assertions", list_assertions)
    app.router.add_post("/api/trust/delegations", create_delegation)
    app.router.add_get("/api/trust/delegations", list_delegations)
    app.router.add_get("/api/trust/calculate/{hash}", calculate_trust)

    # Query routes
    app.router.add_post("/api/verify", verify_sigchain)
    app.router.add_get("/api/lookup/{hash}", lookup_identity)
