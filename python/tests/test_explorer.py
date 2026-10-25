"""Tests for the read-only explorer API and its static UI."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.crypto import hash_json
from nodetide.core.identity import DeviceCapability, Identity, IdentityType
from nodetide.core.storage import Storage
from nodetide.messaging.message import PublicMessage

REPO_WEB = Path(__file__).resolve().parents[2] / "web"
XSS = '<script>alert(1)</script> & "quotes"'


def save_message(storage: Storage, message: PublicMessage, message_type: str = "public") -> str:
    bundle = message.to_dict()
    message_hash = hash_json(bundle)
    storage.save_message(
        message_hash=message_hash,
        bundle_json=json.dumps(bundle),
        sender_identity=message.sender,
        recipient_identity=None,
        message_type=message_type,
        created_at=message.created_at,
        received_at=message.created_at + 1,
    )
    return message_hash


class World:
    """A small, deterministic population of identities and public data."""

    def __init__(self, storage: Storage):
        self.storage = storage

        self.bob = Identity.create(name="Bob")
        self.carol = Identity.create(name="Carol")
        self.stranger = Identity.create(name="Not stored")  # never saved

        self.alice = Identity.create(name="Alice")
        self.phone, _ = self.alice.add_device("phone", capabilities=[DeviceCapability.AUTHENTICATE])
        self.laptop, _ = self.alice.add_device("laptop")
        self.alice.revoke_device(self.laptop.verify_key.to_hex(), reason="lost")
        self.alice.set_recovery([self.bob.identity_hash, self.carol.identity_hash], 2)
        self.alice.set_distribution_points(["https://alice-node.example.org"])
        self.alice.rotate_master()

        for identity in (self.alice, self.bob, self.carol):
            storage.save_sigchain(identity.sigchain)

        keypair = self.alice.local_keypair
        self.msg_xss = save_message(storage, PublicMessage.create(
            keypair, self.alice.identity_hash, {"content_type": "text/plain", "body": XSS}))
        self.msg_long = save_message(storage, PublicMessage.create(
            keypair, self.alice.identity_hash, {"content_type": "text/plain", "body": "x" * 1000}))

        # Signature does not match: body changed after signing.
        forged = PublicMessage.create(
            self.bob.local_keypair, self.bob.identity_hash, {"body": "original"})
        forged.content = {"body": "tampered"}
        self.msg_forged = save_message(storage, forged)

        self.msg_stranger = save_message(storage, PublicMessage.create(
            self.stranger.local_keypair, self.stranger.identity_hash, {"body": "who am i"}))

        private = PublicMessage.create(
            self.alice.local_keypair, self.alice.identity_hash, {"body": "SECRET PRIVATE TEXT"})
        self.msg_private = save_message(storage, private, message_type="private")

        now = int(time.time())
        storage.save_trust_delegation(self.bob.identity_hash, self.carol.identity_hash, 0.8, now)
        storage.save_trust_delegation(
            self.carol.identity_hash, self.alice.identity_hash, 0.6, now - 5,
            depth_limit=1, scope=["email", "legal_name"])
        storage.add_relayed_identity(
            self.stranger.identity_hash, distribution_points=["https://far-away.example.org"])


@pytest.fixture
async def env():
    storage = Storage.memory()
    world = World(storage)
    app = create_app(storage=storage)
    async with TestClient(TestServer(app)) as client:
        client.world = world
        client.storage = storage
        yield client


async def get(client: TestClient, path: str, status: int = 200, **params):
    resp = await client.get(path, params=params)
    assert resp.status == status, await resp.text()
    return await resp.json()


# --- overview / lists ---------------------------------------------------------------


async def test_stats(env):
    stats = await get(env, "/api/explorer/stats")
    assert stats["identities"] == 3
    assert stats["events"] == 7 + 1 + 1  # alice's chain, bob, carol
    assert stats["public_messages"] == 4  # the private one is not counted
    assert stats["trust_delegations"] == 2
    assert stats["relayed_identities"] == 1
    assert stats["event_types"]["genesis"] == 3
    assert stats["event_types"]["add_device"] == 2
    assert stats["last_event_at"] >= stats["first_event_at"]


async def test_identities_list_search_sort_and_paging(env):
    w = env.world
    data = await get(env, "/api/explorer/identities")
    assert data["total"] == 3 and len(data["items"]) == 3
    alice = next(i for i in data["items"] if i["identity_hash"] == w.alice.identity_hash)
    assert alice["name"] == "Alice" and alice["event_count"] == 7

    by_name = await get(env, "/api/explorer/identities", q="ali")
    assert [i["name"] for i in by_name["items"]] == ["Alice"]

    by_prefix = await get(env, "/api/explorer/identities", q=w.bob.identity_hash[:10].upper())
    assert [i["name"] for i in by_prefix["items"]] == ["Bob"]

    page = await get(env, "/api/explorer/identities", limit=2, offset=0, sort="name")
    assert [i["name"] for i in page["items"]] == ["Alice", "Bob"] and page["total"] == 3
    page = await get(env, "/api/explorer/identities", limit=2, offset=2, sort="name")
    assert [i["name"] for i in page["items"]] == ["Carol"]

    by_events = await get(env, "/api/explorer/identities", sort="events")
    assert by_events["items"][0]["name"] == "Alice"


async def test_search_wildcards_are_not_wildcards(env):
    for q in ("%", "_", "A%", "\\"):
        data = await get(env, "/api/explorer/identities", q=q)
        assert data["total"] == 0, q
        assert (await get(env, "/api/explorer/search", q=q))["results"] == []


async def test_bad_parameters_are_rejected(env):
    for params in ({"limit": "0"}, {"limit": "101"}, {"limit": "abc"}, {"offset": "-1"}):
        await get(env, "/api/explorer/identities", status=400, **params)
    await get(env, "/api/explorer/events", status=400, identity="not-a-hash")
    await get(env, "/api/explorer/events", status=400, type="x'; DROP TABLE messages;--")
    await get(env, "/api/explorer/messages", status=400, sender="zz")
    await get(env, "/api/explorer/identities", status=400, q="x" * 101)


# --- identity detail ------------------------------------------------------------------


async def test_identity_detail(env):
    w = env.world
    d = await get(env, f"/api/explorer/identities/{w.alice.identity_hash}")
    assert d["name"] == "Alice" and d["verified"] is True and d["verify_error"] is None
    assert d["event_count"] == 7 and len(d["events"]) == 7
    assert d["master_pubkey"] == w.alice.sigchain.get_current_master_key()
    assert d["distribution_points"] == ["https://alice-node.example.org"]

    assert [k["via"] for k in d["master_history"]] == ["genesis", "rotate_master"]

    by_label = {dev["label"]: dev for dev in d["devices"]}
    assert by_label["phone"]["status"] == "active"
    assert by_label["laptop"]["status"] == "revoked" and by_label["laptop"]["revoke_reason"] == "lost"
    assert by_label["Genesis key"]["role"] == "genesis" and by_label["Genesis key"]["is_master"] is False

    trustees = {t["name"] for t in d["recovery"]["primary_trustees"]}
    assert trustees == {"Bob", "Carol"} and d["recovery"]["primary_threshold"] == 2

    assert d["counts"]["public_messages"] == 2
    assert d["counts"]["delegations_to"] == 1

    types = [e["type"] for e in d["events"]]
    assert types == ["genesis", "add_device", "add_device", "revoke_device",
                     "set_recovery", "set_distribution", "rotate_master"]
    assert d["events"][1]["summary"] == 'Added device "phone"'


async def test_identity_detail_not_found(env):
    await get(env, "/api/explorer/identities/" + "0" * 64, status=404)
    await get(env, "/api/explorer/identities/not-a-hash", status=404)
    # known to the relay table but without a sigchain: nothing to show
    await get(env, f"/api/explorer/identities/{env.world.stranger.identity_hash}", status=404)


async def test_relay_info_on_identity(env):
    w = env.world
    env.storage.save_sigchain(w.stranger.sigchain)
    d = await get(env, f"/api/explorer/identities/{w.stranger.identity_hash}")
    assert d["relay"]["distribution_points"] == ["https://far-away.example.org"]


# --- events ---------------------------------------------------------------------------------


async def test_events_feed_and_filters(env):
    w = env.world
    everything = await get(env, "/api/explorer/events", limit=100)
    assert everything["total"] == 9

    only_alice = await get(env, "/api/explorer/events", identity=w.alice.identity_hash)
    assert only_alice["total"] == 7
    indexes = [e["index"] for e in only_alice["items"]]
    assert indexes == sorted(indexes, reverse=True)  # newest first within a chain
    assert all(e["identity_name"] == "Alice" for e in only_alice["items"])

    devices = await get(env, "/api/explorer/events", type="add_device")
    assert devices["total"] == 2 and {e["type"] for e in devices["items"]} == {"add_device"}


async def test_event_detail_links_neighbours(env):
    w = env.world
    detail = await get(env, f"/api/explorer/identities/{w.alice.identity_hash}")
    events = detail["events"]
    middle = events[3]

    e = await get(env, f"/api/explorer/events/{middle['event_hash']}")
    assert e["index"] == 3 and e["chain_length"] == 7
    assert e["prev_hash"] == events[2]["event_hash"] and e["next_hash"] == events[4]["event_hash"]
    assert e["raw"]["type"] == "revoke_device" and e["identity_name"] == "Alice"

    first = await get(env, f"/api/explorer/events/{events[0]['event_hash']}")
    assert first["prev_hash"] is None
    last = await get(env, f"/api/explorer/events/{events[-1]['event_hash']}")
    assert last["next_hash"] is None

    await get(env, "/api/explorer/events/" + "f" * 64, status=404)


# --- messages ----------------------------------------------------------------------------------


async def test_messages_list_is_public_only(env):
    w = env.world
    data = await get(env, "/api/explorer/messages", limit=100)
    hashes = {m["message_hash"] for m in data["items"]}
    assert w.msg_private not in hashes and data["total"] == 4
    assert "SECRET PRIVATE TEXT" not in json.dumps(data)

    mine = await get(env, "/api/explorer/messages", sender=w.alice.identity_hash)
    assert {m["message_hash"] for m in mine["items"]} == {w.msg_xss, w.msg_long}
    assert all(m["sender_name"] == "Alice" for m in mine["items"])


async def test_message_preview_is_clipped_but_detail_is_full(env):
    w = env.world
    data = await get(env, "/api/explorer/messages", sender=w.alice.identity_hash)
    long_item = next(m for m in data["items"] if m["message_hash"] == w.msg_long)
    assert len(long_item["preview"]) <= 280 and long_item["truncated"] is True

    detail = await get(env, f"/api/explorer/messages/{w.msg_long}")
    assert len(detail["text"]) == 1000


async def test_message_content_is_returned_verbatim_as_data(env):
    # The API never HTML-escapes or interprets content; the UI must render it as text.
    detail = await get(env, f"/api/explorer/messages/{env.world.msg_xss}")
    assert detail["text"] == XSS and detail["content_type"] == "text/plain"


async def test_message_signature_status(env):
    w = env.world
    assert (await get(env, f"/api/explorer/messages/{w.msg_xss}"))["signature_status"] == "valid"
    assert (await get(env, f"/api/explorer/messages/{w.msg_forged}"))["signature_status"] == "invalid"
    assert (await get(env, f"/api/explorer/messages/{w.msg_stranger}"))["signature_status"] == "unknown_sender"


async def test_private_message_is_not_found(env):
    await get(env, f"/api/explorer/messages/{env.world.msg_private}", status=404)
    await get(env, "/api/explorer/messages/" + "a" * 64, status=404)


# --- trust ---------------------------------------------------------------------------------------


async def test_trust_delegations_list_and_filters(env):
    w = env.world
    data = await get(env, "/api/explorer/trust/delegations")
    assert data["total"] == 2
    scoped = next(d for d in data["items"] if d["scope"])
    assert scoped["scope"] == ["email", "legal_name"] and scoped["depth_limit"] == 1
    assert (scoped["from_name"], scoped["to_name"]) == ("Carol", "Alice")
    plain = next(d for d in data["items"] if not d["scope"])
    assert (plain["from_name"], plain["to_name"], plain["weight"]) == ("Bob", "Carol", 0.8)

    assert (await get(env, "/api/explorer/trust/delegations", to=w.alice.identity_hash))["total"] == 1
    assert (await get(env, "/api/explorer/trust/delegations", **{"from": w.bob.identity_hash}))["total"] == 1
    assert (await get(env, "/api/explorer/trust/delegations", to=w.bob.identity_hash))["total"] == 0
    assert (await env.get("/api/explorer/trust/assertions")).status == 404  # removed


# --- search ----------------------------------------------------------------------------------------


async def test_search_by_name_and_hashes(env):
    w = env.world

    r = (await get(env, "/api/explorer/search", q="carol"))["results"]
    assert [(x["kind"], x["id"]) for x in r] == [("identity", w.carol.identity_hash)]

    r = (await get(env, "/api/explorer/search", q=w.alice.identity_hash))["results"]
    kinds = {(x["kind"], x["id"]) for x in r}
    assert ("identity", w.alice.identity_hash) in kinds
    # the genesis event hash equals the identity hash, so it is also an event
    assert ("event", w.alice.identity_hash) in kinds

    r = (await get(env, "/api/explorer/search", q=w.msg_xss[:12]))["results"]
    assert ("message", w.msg_xss) in {(x["kind"], x["id"]) for x in r}

    head = w.alice.sigchain.head_hash
    r = (await get(env, "/api/explorer/search", q=head))["results"]
    assert ("event", head) in {(x["kind"], x["id"]) for x in r}

    assert (await get(env, "/api/explorer/search", q="no such thing"))["results"] == []
    assert (await get(env, "/api/explorer/search", q=""))["results"] == []


async def test_search_does_not_find_private_messages(env):
    r = (await get(env, "/api/explorer/search", q=env.world.msg_private))["results"]
    assert not any(x["kind"] == "message" for x in r)


# --- network -----------------------------------------------------------------------------------------


async def test_network_standard_node(env):
    data = await get(env, "/api/explorer/network")
    assert data["mode"] == "standard" and data["polling"] is None
    assert len(data["relayed"]) == 1
    entry = data["relayed"][0]
    assert entry["known"] is False and entry["distribution_points"] == ["https://far-away.example.org"]


async def test_network_relay_node():
    class FakePoller:
        async def start(self): pass
        async def stop(self): pass
        def get_status(self):
            return {"running": True, "suspended": False, "poll_interval": 300}

    storage = Storage.memory()
    app = create_app(storage=storage)
    app["relay_poller"] = FakePoller()
    async with TestClient(TestServer(app)) as client:
        data = await get(client, "/api/explorer/network")
    assert data["mode"] == "relay" and data["polling"]["poll_interval"] == 300


# --- index maintenance -------------------------------------------------------------------------------------


async def test_index_follows_new_events(env):
    w = env.world
    before = (await get(env, "/api/explorer/stats"))["events"]
    w.bob.add_device("tablet")
    env.storage.save_sigchain(w.bob.sigchain)  # same code path as submitting an event
    stats = await get(env, "/api/explorer/stats")
    assert stats["events"] == before + 1
    bob = await get(env, f"/api/explorer/identities/{w.bob.identity_hash}")
    assert bob["event_count"] == 2
    listed = next(i for i in (await get(env, "/api/explorer/identities"))["items"]
                  if i["identity_hash"] == w.bob.identity_hash)
    assert listed["event_count"] == 2 and listed["device_count"] == 2


async def test_reindex_rebuilds_from_sigchains(env):
    with env.storage.transaction() as cur:
        cur.execute("DELETE FROM explorer_events")
        cur.execute("DELETE FROM explorer_identities")
    assert (await get(env, "/api/explorer/stats"))["identities"] == 0
    env.storage.reindex_explorer()
    stats = await get(env, "/api/explorer/stats")
    assert stats["identities"] == 3 and stats["events"] == 9


def test_existing_database_is_backfilled_on_open(tmp_path):
    path = tmp_path / "old.db"
    storage = Storage.open(path)
    identity = Identity.create(name="Legacy")
    storage.save_sigchain(identity.sigchain)
    with storage.transaction() as cur:  # what a pre-explorer database looks like
        cur.execute("DELETE FROM explorer_events")
        cur.execute("DELETE FROM explorer_identities")
    storage.close()

    reopened = Storage.open(path)
    with reopened.transaction() as cur:
        cur.execute("SELECT name FROM explorer_identities")
        assert [r["name"] for r in cur.fetchall()] == ["Legacy"]
    reopened.close()


# --- privacy ------------------------------------------------------------------------------------------------------


async def test_no_secrets_in_any_response(env):
    """Secret keys of identities this node controls must never appear."""
    w = env.world
    secret_identity = Identity.create(name="Node owner")
    env.storage.save_local_identity(secret_identity, is_default=True)
    secrets_ = [
        secret_identity.local_keypair.signing_key.to_hex(),
        secret_identity.local_keypair.encryption_key.to_hex(),
    ]

    paths = [
        "/api/explorer/stats",
        "/api/explorer/identities?limit=100",
        f"/api/explorer/identities/{secret_identity.identity_hash}",
        f"/api/explorer/identities/{w.alice.identity_hash}",
        "/api/explorer/events?limit=100",
        "/api/explorer/messages?limit=100",
        "/api/explorer/trust/delegations",
        "/api/explorer/network",
        f"/api/explorer/search?q={secret_identity.identity_hash[:8]}",
    ]
    for path in paths:
        resp = await env.get(path)
        body = await resp.text()
        for secret in secrets_:
            assert secret not in body, (path, "leaked a secret key")


async def test_api_is_read_only(env):
    for method in (env.post, env.put, env.delete):
        resp = await method("/api/explorer/identities")
        assert resp.status in (404, 405)


async def test_api_allows_cross_origin_reads(env):
    resp = await env.get("/api/explorer/stats", headers={"Origin": "https://other.example"})
    assert resp.headers["Access-Control-Allow-Origin"] == "*"


async def test_explorer_can_be_disabled(monkeypatch):
    monkeypatch.setenv("NODETIDE_EXPLORER", "0")
    app = create_app(storage=Storage.memory(), web_root=REPO_WEB)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/api/explorer/stats")).status == 404
        assert (await client.get("/explorer/", allow_redirects=False)).status == 404


# --- static UI -----------------------------------------------------------------------------------------------------------


@pytest.fixture
async def ui():
    app = create_app(storage=Storage.memory(), web_root=REPO_WEB)
    async with TestClient(TestServer(app)) as client:
        yield client


async def test_ui_is_served_with_a_strict_csp(ui):
    resp = await ui.get("/explorer", allow_redirects=False)
    assert resp.status == 302 and resp.headers["Location"] == "/explorer/"

    resp = await ui.get("/explorer/")
    assert resp.status == 200
    page = await resp.text()
    assert "/explorer/explorer.js" in page and "/explorer/explorer.css" in page
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    assert resp.headers["X-Frame-Options"] == "DENY"

    for asset, kind in (("explorer.js", "javascript"), ("explorer.css", "css")):
        resp = await ui.get(f"/explorer/{asset}")
        assert resp.status == 200 and kind in resp.headers["Content-Type"]


async def test_ui_assets_cannot_escape_the_directory(ui):
    for path in ("/explorer/..%2Findex.html", "/explorer/%2e%2e/index.html",
                 "/explorer/.hidden", "/explorer/nope.js", "/explorer/sub/x"):
        resp = await ui.get(path, allow_redirects=False)
        assert resp.status in (404, 400), path


def test_ui_never_uses_innerhtml_or_eval():
    """Hostile names and message bodies must only ever be inserted as text."""
    source = (REPO_WEB / "explorer" / "explorer.js").read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in source, banned
    page = (REPO_WEB / "explorer" / "index.html").read_text()
    assert " style=" not in page and "onclick=" not in page  # allowed by the CSP only if absent


# --- claims and attestations -------------------------------------------------------------------------------


class ClaimsWorld:
    """Alice with three claims: one published and attested, one private, one revoked."""

    def __init__(self, storage: Storage, alice: Identity):
        from nodetide.core.claims import Attestation, ClaimDocument

        self.alice = alice
        self.docs = {
            "published": ClaimDocument.create(alice.identity_hash, "legal_name", {"given_name": "Alice", "family_name": "Public"}),
            "private": ClaimDocument.create(alice.identity_hash, "email", "private-address@example.com"),
            "revoked": ClaimDocument.create(alice.identity_hash, "phone", "+359881234567"),
        }
        for doc in self.docs.values():
            alice.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
        alice.revoke_claim(self.docs["revoked"].claim_id, reason="new number")
        storage.save_sigchain(alice.sigchain)

        self.issuer = Identity.create(identity_type=IdentityType.ORGANIZATION, name="Acme Verifier")
        signer, _ = self.issuer.add_device("signer", capabilities=[DeviceCapability.SIGN_IDENTITY])
        storage.save_sigchain(self.issuer.sigchain)
        record = alice.sigchain.get_claim(self.docs["private"].claim_id)
        self.attestation = Attestation.issue(
            self.issuer.identity_hash, signer, alice.identity_hash, record,
            alice.sigchain.head_hash, "email_code", "low")
        storage.save_attestation(self.attestation.id, self.attestation.to_dict())
        d = self.docs["published"]
        storage.save_claim_document(alice.identity_hash, d.claim_id, d.claim_type, d.value, d.salt, int(time.time()))


@pytest.fixture
async def claims_env(env):
    env.claims = ClaimsWorld(env.storage, env.world.alice)
    return env



async def test_identity_page_lists_claims_and_hides_unpublished_values(claims_env):
    env, w = claims_env, claims_env.claims
    detail = await get(env, f"/api/explorer/identities/{w.alice.identity_hash}")
    by_type = {c["claim_type"]: c for c in detail["claims"]}
    assert set(by_type) == {"legal_name", "email", "phone"}

    assert by_type["legal_name"]["published"] and by_type["legal_name"]["value"]["family_name"] == "Public"
    assert not by_type["email"]["published"] and by_type["email"]["value"] is None
    assert by_type["email"]["commitment"] == w.docs["private"].commitment
    assert by_type["phone"]["status"] == "revoked" and by_type["phone"]["revoke_reason"] == "new number"

    att = by_type["email"]["attestations"][0]
    assert att["issuer_name"] == "Acme Verifier" and att["assurance"] == "low" and not att["revoked"]


async def test_no_private_claim_value_or_salt_in_any_explorer_response(claims_env):
    env, w = claims_env, claims_env.claims
    secrets = ["private-address@example.com", "+359881234567", w.docs["private"].salt, w.docs["revoked"].salt]
    for path in (
        f"/api/explorer/identities/{w.alice.identity_hash}", "/api/explorer/events?limit=100",
        "/api/explorer/attestations", "/api/explorer/stats", "/api/explorer/search?q=private",
        f"/api/explorer/search?q={w.docs['private'].commitment[:10]}",
    ):
        body = await (await env.get(path)).text()
        for secret in secrets:
            assert secret not in body, (path, secret)


async def test_attestations_listing_and_filters(claims_env):
    env, w = claims_env, claims_env.claims
    data = await get(env, "/api/explorer/attestations")
    assert data["total"] == 1
    item = data["items"][0]
    assert item["subject_name"] == "Alice" and item["issuer_name"] == "Acme Verifier"
    assert item["claim_type"] == "email" and item["expired"] is False and item["revoked"] is False

    assert (await get(env, "/api/explorer/attestations", issuer=w.issuer.identity_hash))["total"] == 1
    assert (await get(env, "/api/explorer/attestations", subject=w.issuer.identity_hash))["total"] == 0
    assert (await get(env, "/api/explorer/attestations", claim_type="phone"))["total"] == 0
    await get(env, "/api/explorer/attestations", status=400, subject="nope")
    assert (await get(env, "/api/explorer/stats"))["attestations"] == 1


async def test_claim_events_have_readable_summaries(claims_env):
    env, w = claims_env, claims_env.claims
    detail = await get(env, f"/api/explorer/identities/{w.alice.identity_hash}")
    summaries = [e["summary"] for e in detail["events"]]
    assert "Made a legal_name claim" in summaries
    assert any(s.startswith("Revoked claim ") and "new number" in s for s in summaries)
    assert (await get(env, "/api/explorer/events", type="add_claim"))["total"] == 3


async def test_revoked_attestation_is_flagged(claims_env):
    from nodetide.core.claims import AttestationRevocation

    env, w = claims_env, claims_env.claims
    row = env.storage.get_node_issuer()  # none: the fixture's issuer is a plain identity
    assert row is None
    rev = AttestationRevocation(w.attestation.id, w.issuer.identity_hash, "ab" * 32, "mistake", int(time.time()), "cd" * 64)
    env.storage.save_attestation_revocation(w.attestation.id, rev.to_dict())
    item = (await get(env, "/api/explorer/attestations"))["items"][0]
    assert item["revoked"] is True and item["revoke_reason"] == "mistake"
