"""Tests for the OIDC bridge: any Nodetide identity can sign in."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from aiohttp import BasicAuth
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.auth import create_assertion
from nodetide.core.identity import DeviceCapability, Identity
from nodetide.core.storage import Storage
from nodetide.oidc import ConfigError, OIDCClient, OIDCConfig
from nodetide.oidc.fetcher import IdentityFetcher
from nodetide.oidc.netguard import GuardedResolver, is_public_ip, validate_source_url
from nodetide.oidc.provider import MSG_REAPPROVE, b64url

ISSUER = "https://bridge.test"
SPA_REDIRECT = "https://app.example.com/cb"
WEB_REDIRECT = "https://web.example.com/cb"
SECRET = "s3cret"
SEED = "https://seed.example.net"

SPA = OIDCClient("spa", "Demo SPA", (SPA_REDIRECT,))
WEB = OIDCClient("web", "Demo Web", (WEB_REDIRECT,), hashlib.sha256(SECRET.encode()).hexdigest())


def make_identity():
    identity = Identity.create(name="alice")
    device, _ = identity.add_device("phone", capabilities=[DeviceCapability.AUTHENTICATE])
    return identity, device


class FakeNetwork:
    """Stands in for other nodes: identity hash -> sigchain events."""

    def __init__(self):
        self.chains: dict[str, list[dict[str, Any]]] = {}
        self.calls: list[tuple[str, str]] = []
        self.online = True

    async def fetch(self, base_url: str, identity_hash: str):
        self.calls.append((base_url, identity_hash))
        if not self.online:
            raise ConnectionError("network down")
        return self.chains.get(identity_hash)

    def publish(self, identity: Identity) -> None:
        self.chains[identity.identity_hash] = identity.sigchain.to_list()


@dataclass
class Env:
    client: TestClient
    storage: Storage
    net: FakeNetwork
    provider: Any


@pytest.fixture
async def env():
    storage = Storage.memory()
    net = FakeNetwork()
    config = OIDCConfig(
        issuer=ISSUER,
        clients={SPA.client_id: SPA, WEB.client_id: WEB},
        seed_nodes=[SEED],
    )
    app = create_app(storage=storage, oidc_config=config, oidc_fetch=net.fetch)

    # Drive the fetcher by hand (run_once) instead of the background loop.
    async def no_background() -> None:
        return None

    app["oidc"].fetcher.start = no_background

    async with TestClient(TestServer(app)) as client:
        yield Env(client, storage, net, app["oidc"])


# --- helpers ------------------------------------------------------------------


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


async def start_login(env: Env, client_id="spa", redirect=SPA_REDIRECT, **extra):
    verifier, challenge = pkce()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": "openid profile",
        "state": "st-1",
        "nonce": "oidc-nonce-1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **extra,
    }
    resp = await env.client.get("/oidc/authorize", params=params, allow_redirects=False)
    assert resp.status == 302, await resp.text()
    path, _, secret = resp.headers["Location"].partition("#")
    assert path.startswith("/oidc/login/") and secret
    return path.rsplit("/", 1)[1], secret, verifier


async def get_status(env: Env, attempt_id: str, secret: str) -> dict[str, Any]:
    resp = await env.client.get(
        f"/oidc/login/{attempt_id}/status", headers={"X-Login-Secret": secret}
    )
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def sign(env: Env, attempt_id: str, identity: Identity, device, **kw) -> dict[str, Any]:
    resp = await env.client.get(f"/oidc/login/{attempt_id}/challenge")
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    return create_assertion(
        data["request"], identity.identity_hash, device, identity.sigchain.head_hash, **kw
    )


async def submit(env: Env, attempt_id: str, assertion, **extra):
    return await env.client.post(
        f"/oidc/login/{attempt_id}/assertion", json={"assertion": assertion, **extra}
    )


def code_from(status: dict[str, Any]) -> str:
    return parse_qs(urlsplit(status["redirect_to"]).query)["code"][0]


async def exchange(env: Env, code: str, verifier: str, client_id="spa", redirect=SPA_REDIRECT, **kw):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "client_id": client_id,
        "code_verifier": verifier,
    }
    return await env.client.post("/oidc/token", data=data, **kw)


async def decode_id_token(env: Env, id_token: str, audience="spa") -> dict[str, Any]:
    jwks = await (await env.client.get("/oidc/jwks.json")).json()
    assert jwt.get_unverified_header(id_token)["kid"] == jwks["keys"][0]["kid"]
    key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    return jwt.decode(id_token, key, algorithms=["RS256"], audience=audience, issuer=ISSUER)


async def login_known(env: Env, identity: Identity, device):
    """Complete a whole sign-in for an identity the node already knows."""
    attempt_id, secret, verifier = await start_login(env)
    assertion = await sign(env, attempt_id, identity, device)
    resp = await submit(env, attempt_id, assertion)
    assert resp.status == 200, await resp.text()
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "approved"
    return status, verifier


# --- discovery / authorize ------------------------------------------------------


async def test_discovery_and_jwks(env):
    doc = await (await env.client.get("/.well-known/openid-configuration")).json()
    assert doc["issuer"] == ISSUER
    assert doc["authorization_endpoint"] == f"{ISSUER}/oidc/authorize"
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert {"openid", "profile", "email", "phone"} <= set(doc["scopes_supported"])
    assert "verified_claims" in doc["claims_supported"]
    jwks = await (await env.client.get("/oidc/jwks.json")).json()
    assert jwks["keys"][0]["kty"] == "RSA" and jwks["keys"][0]["alg"] == "RS256"


async def test_authorize_never_redirects_to_unregistered_uri(env):
    _, challenge = pkce()
    base = {"response_type": "code", "scope": "openid", "code_challenge": challenge,
            "code_challenge_method": "S256"}
    for params in (
        {**base, "client_id": "nope", "redirect_uri": SPA_REDIRECT},
        {**base, "client_id": "spa", "redirect_uri": "https://evil.example.com/cb"},
        {**base, "client_id": "spa", "redirect_uri": SPA_REDIRECT + "/extra"},
    ):
        resp = await env.client.get("/oidc/authorize", params=params, allow_redirects=False)
        assert resp.status == 400
        assert "Location" not in resp.headers


async def test_authorize_errors_go_back_to_the_client(env):
    resp = await env.client.get(
        "/oidc/authorize",
        params={"client_id": "spa", "redirect_uri": SPA_REDIRECT, "response_type": "code",
                "scope": "openid", "state": "abc"},  # public client without PKCE
        allow_redirects=False,
    )
    assert resp.status == 302
    query = parse_qs(urlsplit(resp.headers["Location"]).query)
    assert query["error"] == ["invalid_request"] and query["state"] == ["abc"]

    _, challenge = pkce()
    resp = await env.client.get(
        "/oidc/authorize",
        params={"client_id": "spa", "redirect_uri": SPA_REDIRECT, "response_type": "token",
                "scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256"},
        allow_redirects=False,
    )
    assert parse_qs(urlsplit(resp.headers["Location"]).query)["error"] == ["unsupported_response_type"]

    resp = await env.client.get(
        "/oidc/authorize",
        params={"client_id": "spa", "redirect_uri": SPA_REDIRECT, "response_type": "code",
                "scope": "profile", "code_challenge": challenge, "code_challenge_method": "S256"},
        allow_redirects=False,
    )
    assert parse_qs(urlsplit(resp.headers["Location"]).query)["error"] == ["invalid_scope"]


async def test_login_page_and_status_secret(env):
    attempt_id, secret, _ = await start_login(env)
    page = await env.client.get(f"/oidc/login/{attempt_id}")
    assert page.status == 200
    assert "Demo SPA" in await page.text()
    assert "script-src 'nonce-" in page.headers["Content-Security-Policy"]
    assert page.headers["X-Frame-Options"] == "DENY"

    # The public id alone (what a QR code reveals) cannot read the result.
    for headers in ({}, {"X-Login-Secret": "wrong"}):
        resp = await env.client.get(f"/oidc/login/{attempt_id}/status", headers=headers)
        assert resp.status == 404
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "waiting" and "cancel_url" in status


# --- sign-in: identity already known --------------------------------------------


async def test_full_flow_known_identity(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)

    status, verifier = await login_known(env, identity, device)
    assert parse_qs(urlsplit(status["redirect_to"]).query)["state"] == ["st-1"]
    assert status["redirect_to"].startswith(SPA_REDIRECT + "?")

    resp = await exchange(env, code_from(status), verifier)
    assert resp.status == 200, await resp.text()
    tokens = await resp.json()
    assert tokens["token_type"] == "Bearer"

    claims = await decode_id_token(env, tokens["id_token"])
    assert claims["sub"] == identity.identity_hash
    assert claims["nonce"] == "oidc-nonce-1"
    assert claims["name"] == "alice" and claims["name_verified"] is False
    assert claims["nodetide_device"] == device.verify_key.to_hex()

    info = await env.client.get(
        "/oidc/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    # the display name from the identity's genesis is self-asserted, and is labelled as such
    assert (await info.json()) == {"sub": identity.identity_hash, "name": "alice", "name_verified": False}
    bad = await env.client.get("/oidc/userinfo", headers={"Authorization": "Bearer nope"})
    assert bad.status == 401


async def test_code_is_single_use(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    status, verifier = await login_known(env, identity, device)
    code = code_from(status)
    assert (await exchange(env, code, verifier)).status == 200
    resp = await exchange(env, code, verifier)
    assert resp.status == 400 and (await resp.json())["error"] == "invalid_grant"


async def test_pkce_and_redirect_uri_are_enforced(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)

    status, verifier = await login_known(env, identity, device)
    resp = await exchange(env, code_from(status), "x" * 43)  # wrong verifier
    assert (await resp.json())["error"] == "invalid_grant"

    status, verifier = await login_known(env, identity, device)
    resp = await exchange(env, code_from(status), verifier, redirect="https://evil.example.com/cb")
    assert (await resp.json())["error"] == "invalid_grant"


async def test_confidential_client_needs_its_secret(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    attempt_id, secret, verifier = await start_login(env, client_id="web", redirect=WEB_REDIRECT)
    await submit(env, attempt_id, await sign(env, attempt_id, identity, device))
    code = code_from(await get_status(env, attempt_id, secret))

    # Client authentication is checked before the code is touched.
    resp = await exchange(env, code, verifier, client_id="web", redirect=WEB_REDIRECT)
    assert resp.status == 401 and (await resp.json())["error"] == "invalid_client"
    resp = await exchange(
        env, code, verifier, client_id="web", redirect=WEB_REDIRECT, auth=BasicAuth("web", "wrong")
    )
    assert resp.status == 401

    resp = await exchange(
        env, code, verifier, client_id="web", redirect=WEB_REDIRECT, auth=BasicAuth("web", SECRET)
    )
    assert resp.status == 200, await resp.text()


async def test_assertion_cannot_be_replayed_or_reused(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    attempt_id, secret, _ = await start_login(env)
    assertion = await sign(env, attempt_id, identity, device)
    assert (await submit(env, attempt_id, assertion)).status == 200
    assert (await submit(env, attempt_id, assertion)).status == 409

    # Same assertion against a different attempt: nonce does not match.
    other_id, _, _ = await start_login(env)
    resp = await submit(env, other_id, assertion)
    assert resp.status == 401 and (await resp.json())["status"] == "unknown_challenge"


async def test_assertion_for_wrong_audience_is_rejected(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    attempt_id, _, _ = await start_login(env)
    challenge = await (await env.client.get(f"/oidc/login/{attempt_id}/challenge")).json()
    forged = create_assertion(
        dict(challenge["request"], aud="https://evil.example.com"),
        identity.identity_hash, device, identity.sigchain.head_hash,
    )
    resp = await submit(env, attempt_id, forged)
    assert resp.status == 401 and (await resp.json())["status"] == "wrong_audience"


async def test_repeated_rejections_fail_the_attempt(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    attempt_id, secret, _ = await start_login(env)
    assertion = await sign(env, attempt_id, identity, device)
    assertion["sig"] = "00" * 64
    for _ in range(5):
        assert (await submit(env, attempt_id, assertion)).status == 401
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "failed"
    assert "error=" in status["redirect_to"]


async def test_master_key_cannot_sign_in(env):
    identity, _ = make_identity()
    env.storage.save_sigchain(identity.sigchain)
    attempt_id, _, _ = await start_login(env)
    challenge = await (await env.client.get(f"/oidc/login/{attempt_id}/challenge")).json()
    assertion = create_assertion(
        challenge["request"], identity.identity_hash, identity.local_keypair,
        identity.sigchain.head_hash,
    )
    resp = await submit(env, attempt_id, assertion)
    assert resp.status == 401 and (await resp.json())["status"] == "device_not_authorized"


# --- sign-in: identity NOT known yet --------------------------------------------


async def test_supplied_sigchain_works_instantly_for_unknown_identity(env):
    identity, device = make_identity()  # never stored on the node
    attempt_id, secret, verifier = await start_login(env)
    assertion = await sign(env, attempt_id, identity, device)
    resp = await submit(env, attempt_id, assertion, sigchain=identity.sigchain.to_list())
    assert resp.status == 200, await resp.text()
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "approved"
    assert (await exchange(env, code_from(status), verifier)).status == 200
    assert env.net.calls == []  # no network needed


async def test_unknown_identity_is_scheduled_and_completes_after_fetch(env):
    identity, device = make_identity()
    attempt_id, secret, verifier = await start_login(env)
    assertion = await sign(env, attempt_id, identity, device)

    resp = await submit(env, attempt_id, assertion, hints=["https://alice-node.example.org"])
    assert resp.status == 202
    body = await resp.json()
    assert body["status"] == "fetching" and "doesn't know this identity" in body["message"]

    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "fetching"
    assert env.provider.fetcher.status(identity.identity_hash)["state"] == "pending"

    # The identity becomes reachable; the next fetch round completes the sign-in
    # without the user doing anything.
    env.net.publish(identity)
    assert await env.provider.fetcher.run_once() == 1

    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "approved"
    assert (await exchange(env, code_from(status), verifier)).status == 200
    assert env.storage.get_sigchain(identity.identity_hash) is not None
    assert env.provider.fetcher.status(identity.identity_hash)["state"] == "done"
    # hint and seed node were both candidates
    tried = {base for base, _ in env.net.calls}
    assert "https://alice-node.example.org" in tried


async def test_failed_for_now_message_then_success_on_retry(env):
    identity, device = make_identity()
    env.net.online = False
    attempt_id, secret, verifier = await start_login(env)
    await submit(env, attempt_id, await sign(env, attempt_id, identity, device))

    await env.provider.fetcher.run_once()
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "fetching"
    assert "failed for now" in status["message"]
    assert status["fetch"]["attempts"] == 1
    assert SEED in {base for base, _ in env.net.calls}  # seed nodes are consulted

    # Backoff: nothing is due yet.
    assert await env.provider.fetcher.run_once() == 0

    # Network returns; the retry (forced due) succeeds and finishes the sign-in.
    env.net.online = True
    env.net.publish(identity)
    with env.storage.transaction() as cur:
        cur.execute("UPDATE oidc_pending_fetches SET next_attempt_at = 0")
    assert await env.provider.fetcher.run_once() == 1
    assert (await get_status(env, attempt_id, secret))["status"] == "approved"


async def test_expired_approval_after_fetch_asks_to_approve_again(env):
    identity, device = make_identity()
    attempt_id, secret, verifier = await start_login(env)
    old = await sign(env, attempt_id, identity, device, now=int(time.time()) - 500)
    assert (await submit(env, attempt_id, old)).status == 202

    env.net.publish(identity)
    await env.provider.fetcher.run_once()

    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "waiting" and status["message"] == MSG_REAPPROVE

    # The identity is known now, so approving again is instant.
    fresh = await sign(env, attempt_id, identity, device)
    assert (await submit(env, attempt_id, fresh)).status == 200
    assert (await get_status(env, attempt_id, secret))["status"] == "approved"


async def test_stale_stored_chain_triggers_fetch_of_newer_one(env):
    identity, device = make_identity()
    env.storage.save_sigchain(identity.sigchain)  # node has the chain as of now
    identity.add_device("laptop")  # signer is ahead of the node

    attempt_id, secret, verifier = await start_login(env)
    resp = await submit(env, attempt_id, await sign(env, attempt_id, identity, device))
    assert resp.status == 202 and "out-of-date" in (await resp.json())["message"]

    env.net.publish(identity)
    await env.provider.fetcher.run_once()
    assert (await get_status(env, attempt_id, secret))["status"] == "approved"


async def test_revocation_known_to_node_beats_older_supplied_chain(env):
    identity, device = make_identity()
    old_chain = identity.sigchain.to_list()
    old_head = identity.sigchain.head_hash
    identity.revoke_device(device.verify_key.to_hex(), reason="stolen")
    env.storage.save_sigchain(identity.sigchain)

    attempt_id, _, _ = await start_login(env)
    challenge = await (await env.client.get(f"/oidc/login/{attempt_id}/challenge")).json()
    assertion = create_assertion(challenge["request"], identity.identity_hash, device, old_head)
    resp = await submit(env, attempt_id, assertion, sigchain=old_chain)
    assert resp.status == 401 and (await resp.json())["status"] == "device_not_authorized"


async def test_expired_attempt_reports_failed_for_now(env):
    identity, device = make_identity()
    attempt_id, secret, _ = await start_login(env)
    await submit(env, attempt_id, await sign(env, attempt_id, identity, device))  # fetching

    env.provider.attempts[attempt_id].expires_at = 0
    status = await get_status(env, attempt_id, secret)
    assert status["status"] == "expired" and "for now" in status["message"]
    query = parse_qs(urlsplit(status["redirect_to"]).query)
    assert query["error"] == ["temporarily_unavailable"] and query["state"] == ["st-1"]

    # The fetch keeps running in the background after the page gave up.
    assert env.provider.fetcher.status(identity.identity_hash)["state"] == "pending"


async def test_login_hint_warms_the_cache(env):
    identity, _ = make_identity()
    hint = f"{identity.identity_hash}@https://alice-node.example.org"
    await start_login(env, login_hint=hint)
    row = env.provider.fetcher.status(identity.identity_hash)
    assert row is not None and row["state"] == "pending"

    env.net.publish(identity)
    await env.provider.fetcher.run_once()
    assert env.storage.get_sigchain(identity.identity_hash) is not None
    assert ("https://alice-node.example.org", identity.identity_hash) in env.net.calls


# --- fetcher ----------------------------------------------------------------------


async def test_fetcher_rejects_a_chain_for_a_different_identity():
    storage = Storage.memory()
    net = FakeNetwork()
    wanted, _ = make_identity()
    other, _ = make_identity()
    net.chains[wanted.identity_hash] = other.sigchain.to_list()  # lies about who it is

    fetcher = IdentityFetcher(storage, seed_nodes=[SEED], fetch=net.fetch)
    assert fetcher.schedule(wanted.identity_hash)
    await fetcher.run_once()
    assert storage.get_sigchain(wanted.identity_hash) is None
    assert storage.get_sigchain(other.identity_hash) is None
    assert fetcher.status(wanted.identity_hash)["attempts"] == 1


async def test_fetcher_rejects_tampered_chain():
    storage = Storage.memory()
    net = FakeNetwork()
    identity, _ = make_identity()
    events = identity.sigchain.to_list()
    events[1]["label"] = "evil"  # breaks the master's signature
    net.chains[identity.identity_hash] = events

    fetcher = IdentityFetcher(storage, seed_nodes=[SEED], fetch=net.fetch)
    fetcher.schedule(identity.identity_hash)
    await fetcher.run_once()
    assert storage.get_sigchain(identity.identity_hash) is None


async def test_fetcher_persists_across_restart():
    storage = Storage.memory()
    net = FakeNetwork()
    identity, _ = make_identity()

    first = IdentityFetcher(storage, seed_nodes=[SEED], fetch=net.fetch)
    first.schedule(identity.identity_hash)

    # "Restart": a new instance over the same database still has the work queued.
    net.publish(identity)
    second = IdentityFetcher(storage, seed_nodes=[SEED], fetch=net.fetch)
    assert await second.run_once() == 1
    assert storage.get_sigchain(identity.identity_hash) is not None


async def test_fetcher_input_validation():
    storage = Storage.memory()
    fetcher = IdentityFetcher(storage, fetch=FakeNetwork().fetch)
    assert not fetcher.schedule("not-a-hash")
    assert not fetcher.schedule("../../etc/passwd")

    identity, _ = make_identity()
    assert fetcher.schedule(
        identity.identity_hash,
        hints=[
            "http://127.0.0.1:4557",
            "http://169.254.169.254/latest/meta-data",
            "http://localhost/",
            "file:///etc/passwd",
            "ftp://example.com",
            "https://user:pw@example.com",
            "https://good.example.org/ignored/path",
        ],
    )
    with storage.transaction() as cur:
        cur.execute("SELECT hints FROM oidc_pending_fetches")
        hints = json.loads(cur.fetchone()["hints"])
    assert hints == ["https://good.example.org"]


# --- network guard -----------------------------------------------------------------


@pytest.mark.parametrize("addr,expected", [
    ("8.8.8.8", True),
    ("2606:4700:4700::1111", True),
    ("127.0.0.1", False),
    ("10.0.0.5", False),
    ("192.168.1.1", False),
    ("172.16.0.1", False),
    ("169.254.169.254", False),
    ("100.64.0.1", False),
    ("0.0.0.0", False),
    ("::1", False),
    ("fe80::1", False),
    ("fc00::1", False),
    ("::ffff:127.0.0.1", False),
    ("not-an-ip", False),
])
def test_is_public_ip(addr, expected):
    assert is_public_ip(addr) is expected


def test_validate_source_url():
    assert validate_source_url("https://node.example.org/") == "https://node.example.org"
    assert validate_source_url("http://node.example.org:8080/x?y=1") == "http://node.example.org:8080"
    assert validate_source_url("http://127.0.0.1") is None
    assert validate_source_url("http://[::1]:80") is None
    assert validate_source_url("http://foo.localhost") is None
    assert validate_source_url("gopher://example.org") is None
    assert validate_source_url("https://a:b@example.org") is None
    assert validate_source_url("https://example.org:99999") is None
    assert validate_source_url("x" * 600) is None
    # Development override
    assert validate_source_url("http://127.0.0.1:4557", allow_private=True) == "http://127.0.0.1:4557"


async def test_guarded_resolver_refuses_loopback_names():
    with pytest.raises(OSError):
        await GuardedResolver().resolve("localhost", 80)


# --- configuration -------------------------------------------------------------------


def test_issuer_must_be_https():
    with pytest.raises(ConfigError):
        OIDCConfig(issuer="http://bridge.example.com", clients={})
    OIDCConfig(issuer="https://bridge.example.com/", clients={})
    OIDCConfig(issuer="http://localhost:4557", clients={})


def test_clients_file_validation(tmp_path):
    def load(entries):
        path = tmp_path / "clients.json"
        path.write_text(json.dumps(entries))
        return OIDCConfig.load_clients(path)

    ok = load([{"client_id": "a", "redirect_uris": ["https://a.example.com/cb"]}])
    assert ok["a"].is_public and ok["a"].name == "a"

    with pytest.raises(ConfigError):
        load([{"client_id": "a", "redirect_uris": ["http://a.example.com/cb"]}])  # insecure
    with pytest.raises(ConfigError):
        load([{"client_id": "a", "redirect_uris": []}])
    with pytest.raises(ConfigError):
        load([{"client_id": "a", "redirect_uris": ["https://a.example.com/cb"],
               "client_secret_sha256": "short"}])
    with pytest.raises(ConfigError):
        load([{"client_id": "a", "redirect_uris": ["https://a.example.com/cb"]},
              {"client_id": "a", "redirect_uris": ["https://b.example.com/cb"]}])
