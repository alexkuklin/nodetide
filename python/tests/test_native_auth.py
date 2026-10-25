"""Tests for native SSO (AuthRequest / AuthAssertion)."""

from __future__ import annotations

import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.auth import (
    AUTH_DOMAIN,
    AuthRequest,
    canonical_json,
    create_assertion,
    signing_input,
    verify_assertion,
)
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.core.storage import Storage

AUD = "https://app.example.com"
NODE_AUD = "https://node.test"


def make_identity(caps=(DeviceCapability.AUTHENTICATE,)):
    """Identity with one device holding `caps`."""
    identity = Identity.create(name="alice")
    device, _ = identity.add_device("phone", capabilities=list(caps))
    return identity, device


def assertion_for(identity, device, aud=AUD, **kwargs):
    request = AuthRequest.new(aud=aud)
    assertion = create_assertion(
        request, identity.identity_hash, device, identity.sigchain.head_hash, **kwargs
    )
    return request, assertion


# --- core -------------------------------------------------------------------


def test_canonical_json_golden():
    """Same input/expected pair as golang/auth/auth_test.go; both must match byte for byte."""
    value = {"b": [1, 2, {"z": None, "a": True}], "a": 'é😀\x7f\n"', "c": -5}
    # "@" stands for a backslash, so no \u escape appears literally in this file.
    expected = '{"a":"@u00e9@ud83d@ude00@u007f@n@"","b":[1,2,{"a":true,"z":null}],"c":-5}'.replace(
        "@", chr(92)
    )
    assert canonical_json(value).decode("ascii") == expected


def test_valid_assertion():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert result.ok, result.error
    assert result.identity == identity.identity_hash
    assert result.device == device.verify_key.to_hex()


def test_claims_are_signed():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device, claims={"name": "alice"})
    assert verify_assertion(assertion, identity.sigchain, AUD).claims == {"name": "alice"}

    assertion["claims"] = {"name": "mallory"}
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "bad_signature"


def test_wrong_audience():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device, aud="https://evil.example.com")
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "wrong_audience"


def test_master_key_rejected():
    identity, _ = make_identity()
    request = AuthRequest.new(aud=AUD)
    assertion = create_assertion(
        request, identity.identity_hash, identity.local_keypair, identity.sigchain.head_hash
    )
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "device_not_authorized"


def test_device_without_authenticate_capability_rejected():
    identity, device = make_identity(caps=(DeviceCapability.SIGN_MESSAGES,))
    _, assertion = assertion_for(identity, device)
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "device_not_authorized"


def test_unknown_device_rejected():
    identity, _ = make_identity()
    other, other_device = make_identity()
    _, assertion = assertion_for(identity, other_device)
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "device_not_authorized"


def test_revoked_device_rejected():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    identity.revoke_device(device.verify_key.to_hex(), reason="lost")
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "device_not_authorized"


def test_unknown_chain_head_means_stale_chain():
    identity, device = make_identity()
    stale = Sigchain(events=list(identity.sigchain.events))
    identity.add_device("laptop")  # newer event the stale copy lacks
    _, assertion = assertion_for(identity, device)
    result = verify_assertion(assertion, stale, AUD)
    assert not result.ok and result.code == "unknown_chain_head"


def test_older_chain_head_is_fine():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    identity.add_device("laptop")  # chain grows after signing
    assert verify_assertion(assertion, identity.sigchain, AUD).ok


def test_identity_mismatch():
    identity, device = make_identity()
    other, _ = make_identity()
    _, assertion = assertion_for(identity, device)
    result = verify_assertion(assertion, other.sigchain, AUD)
    assert not result.ok


def test_expired_and_future():
    identity, device = make_identity()
    request = AuthRequest.new(aud=AUD)
    now = int(time.time())
    assertion = create_assertion(
        request, identity.identity_hash, device, identity.sigchain.head_hash, now=now
    )
    assert verify_assertion(assertion, identity.sigchain, AUD, now=now).ok
    late = verify_assertion(assertion, identity.sigchain, AUD, now=now + 3600)
    assert not late.ok and late.code == "expired"
    early = verify_assertion(assertion, identity.sigchain, AUD, now=now - 3600)
    assert not early.ok and early.code == "expired"


def test_signature_requires_domain_separation():
    """A signature over the bare JSON (no domain prefix) must not verify."""
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    body = {k: v for k, v in assertion.items() if k != "sig"}
    assert signing_input(assertion) == AUTH_DOMAIN + canonical_json(body)
    assertion["sig"] = device.sign_hex(canonical_json(body))
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "bad_signature"


@pytest.mark.parametrize("field", ["identity", "device", "aud", "nonce", "chain_head", "sig", "iat", "exp"])
def test_missing_fields(field):
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    del assertion[field]
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "invalid_assertion"


def test_malformed_signature_does_not_raise():
    identity, device = make_identity()
    _, assertion = assertion_for(identity, device)
    assertion["sig"] = "not-hex"
    result = verify_assertion(assertion, identity.sigchain, AUD)
    assert not result.ok and result.code == "bad_signature"


# --- HTTP -------------------------------------------------------------------


@pytest.fixture
async def client():
    storage = Storage.memory()
    app = create_app(storage=storage, auth_audience=NODE_AUD)
    async with TestClient(TestServer(app)) as c:
        c.storage = storage
        yield c


async def challenge(client, aud=None):
    body = {"aud": aud} if aud else {}
    resp = await client.post("/api/auth/challenge", json=body)
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def test_challenge_defaults_to_node_audience(client):
    request = await challenge(client)
    assert request["type"] == "AUTH_REQUEST"
    assert request["aud"] == NODE_AUD
    assert len(request["nonce"]) >= 22  # >= 128 bits base64url


async def test_challenge_validation(client):
    resp = await client.post("/api/auth/challenge", json={"aud": AUD, "callback": "https://evil.test/x"})
    assert resp.status == 400
    resp = await client.post("/api/auth/challenge", json={"aud": AUD, "claims": "name"})
    assert resp.status == 400
    resp = await client.post("/api/auth/challenge", json={"aud": AUD, "expires_in": 0})
    assert resp.status == 400
    resp = await client.post("/api/auth/challenge", data="{not json")
    assert resp.status == 400


async def test_verify_with_supplied_sigchain_and_replay(client):
    identity, device = make_identity()  # NOT in client.storage
    request = await challenge(client, aud=AUD)
    assertion = create_assertion(
        request, identity.identity_hash, device, identity.sigchain.head_hash
    )
    body = {"assertion": assertion, "sigchain": identity.sigchain.to_list()}

    resp = await client.post("/api/auth/verify", json=body)
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    assert data["valid"] is True
    assert data["identity"] == identity.identity_hash

    # Nonce is single use
    resp = await client.post("/api/auth/verify", json=body)
    assert resp.status == 401
    assert (await resp.json())["error"] == "unknown_challenge"


async def test_failed_verification_does_not_burn_nonce(client):
    identity, device = make_identity()
    request = await challenge(client, aud=AUD)
    good = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)
    bad = dict(good, sig="00" * 64)
    chain = identity.sigchain.to_list()

    resp = await client.post("/api/auth/verify", json={"assertion": bad, "sigchain": chain})
    assert resp.status == 401
    assert (await resp.json())["error"] == "bad_signature"

    resp = await client.post("/api/auth/verify", json={"assertion": good, "sigchain": chain})
    assert resp.status == 200


async def test_unknown_nonce(client):
    identity, device = make_identity()
    request = AuthRequest.new(aud=AUD)  # never registered with the node
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)
    resp = await client.post(
        "/api/auth/verify",
        json={"assertion": assertion, "sigchain": identity.sigchain.to_list()},
    )
    assert resp.status == 401
    assert (await resp.json())["error"] == "unknown_challenge"


async def test_verify_uses_stored_sigchain(client):
    identity, device = make_identity()
    client.storage.save_sigchain(identity.sigchain)
    request = await challenge(client, aud=AUD)
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)
    resp = await client.post("/api/auth/verify", json={"assertion": assertion})
    assert resp.status == 200


async def test_verify_unknown_identity_without_sigchain(client):
    identity, device = make_identity()
    request = await challenge(client, aud=AUD)
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)
    resp = await client.post("/api/auth/verify", json={"assertion": assertion})
    assert resp.status == 404


async def test_stale_stored_chain_returns_409(client):
    identity, device = make_identity()
    client.storage.save_sigchain(Sigchain(events=list(identity.sigchain.events)))
    identity.add_device("laptop")  # signer is ahead of the node
    request = await challenge(client, aud=AUD)
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)

    resp = await client.post("/api/auth/verify", json={"assertion": assertion})
    assert resp.status == 409
    assert (await resp.json())["error"] == "stale_state"

    # Supplying the newer chain resolves it
    resp = await client.post(
        "/api/auth/verify",
        json={"assertion": assertion, "sigchain": identity.sigchain.to_list()},
    )
    assert resp.status == 200


async def test_supplied_old_chain_cannot_hide_revocation(client):
    identity, device = make_identity()
    old_chain = identity.sigchain.to_list()
    old_head = identity.sigchain.head_hash
    identity.revoke_device(device.verify_key.to_hex(), reason="stolen")
    client.storage.save_sigchain(identity.sigchain)  # node knows the revocation

    request = await challenge(client, aud=AUD)
    assertion = create_assertion(request, identity.identity_hash, device, old_head)
    resp = await client.post(
        "/api/auth/verify", json={"assertion": assertion, "sigchain": old_chain}
    )
    assert resp.status == 401
    assert (await resp.json())["error"] == "device_not_authorized"


async def test_verify_rejects_assertion_for_other_audience(client):
    identity, device = make_identity()
    request = await challenge(client, aud=AUD)
    # Device signs for a different origin but reuses the nonce
    forged = create_assertion(
        dict(request, aud="https://evil.example.com"),
        identity.identity_hash,
        device,
        identity.sigchain.head_hash,
    )
    resp = await client.post(
        "/api/auth/verify",
        json={"assertion": forged, "sigchain": identity.sigchain.to_list()},
    )
    assert resp.status == 401
    assert (await resp.json())["error"] == "wrong_audience"


async def test_login_opens_session(client):
    identity, device = make_identity()
    client.storage.save_sigchain(identity.sigchain)
    request = await challenge(client)  # defaults to NODE_AUD
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)

    resp = await client.post("/api/auth/login", json={"assertion": assertion})
    assert resp.status == 201, await resp.text()
    data = await resp.json()
    assert data["identity"] == identity.identity_hash

    resp = await client.get("/api/session", headers={"Authorization": f"Bearer {data['token']}"})
    assert resp.status == 200
    assert (await resp.json())["identity"] == identity.identity_hash


async def test_login_rejects_challenge_for_other_audience(client):
    identity, device = make_identity()
    client.storage.save_sigchain(identity.sigchain)
    request = await challenge(client, aud=AUD)  # not this node
    assertion = create_assertion(request, identity.identity_hash, device, identity.sigchain.head_hash)
    resp = await client.post("/api/auth/login", json={"assertion": assertion})
    assert resp.status == 401
    assert (await resp.json())["error"] == "wrong_audience"


async def test_login_not_configured():
    app = create_app(storage=Storage.memory())
    async with TestClient(TestServer(app)) as c:
        resp = await c.post("/api/auth/login", json={"assertion": {}})
        assert resp.status == 501
