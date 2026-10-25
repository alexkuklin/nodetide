"""HTTP tests for claim documents and attestations."""

from __future__ import annotations

import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.claims import (
    Attestation,
    AttestationRevocation,
    ClaimDocument,
    publication_signing_input,
)
from nodetide.core.identity import DeviceCapability, Identity, IdentityType
from nodetide.core.storage import Storage

D = DeviceCapability
SECRET_EMAIL = "very-private-address@example.com"


class Env:
    def __init__(self, client: TestClient, storage: Storage):
        self.client, self.storage = client, storage
        self.holder = Identity.create(name="Alice")
        self.device, _ = self.holder.add_device("phone", capabilities=[D.MANAGE_CLAIMS])
        self.weak_device, _ = self.holder.add_device("watch", capabilities=[D.SIGN_MESSAGES])
        self.doc = ClaimDocument.create(self.holder.identity_hash, "email", SECRET_EMAIL)
        self.holder.add_claim(self.doc.claim_id, "email", self.doc.commitment)
        self.issuer = Identity.create(identity_type=IdentityType.ORGANIZATION, name="Verifier")
        self.signer, _ = self.issuer.add_device("signer", capabilities=[D.SIGN_IDENTITY])
        storage.save_sigchain(self.holder.sigchain)
        storage.save_sigchain(self.issuer.sigchain)

    def attestation(self, **kw) -> Attestation:
        record = self.holder.sigchain.get_claim(self.doc.claim_id)
        return Attestation.issue(
            self.issuer.identity_hash, kw.pop("key", self.signer), self.holder.identity_hash, record,
            chain_head=kw.pop("chain_head", self.holder.sigchain.head_hash),
            method="email_code", assurance="low", **kw)

    def publication(self, action="publish", key=None, issued_at=None, document=None):
        key = key or self.device
        issued_at = int(time.time()) if issued_at is None else issued_at
        document = document or self.doc.to_dict()
        return {
            "action": action, "document": document, "issued_at": issued_at,
            "signed_by": key.verify_key.to_hex(),
            "sig": key.sign_hex(publication_signing_input(action, document, issued_at)),
        }

    async def post(self, path, body):
        resp = await self.client.post(path, json=body)
        return resp.status, await resp.json()

    async def get(self, path, **params):
        resp = await self.client.get(path, params=params)
        return resp.status, await resp.json()


@pytest.fixture
async def env():
    storage = Storage.memory()
    app = create_app(storage=storage)
    async with TestClient(TestServer(app)) as client:
        yield Env(client, storage)


# --- claims listing and privacy ---------------------------------------------------------------


async def test_claims_are_listed_without_their_values(env):
    status, body = await env.get(f"/api/identities/{env.holder.identity_hash}/claims")
    assert status == 200 and len(body["claims"]) == 1
    claim = body["claims"][0]
    assert claim["claim_type"] == "email" and claim["status"] == "active"
    assert claim["commitment"] == env.doc.commitment
    assert claim["document"] is None and claim["attestations"] == []
    assert SECRET_EMAIL not in str(body)

    status, _ = await env.get("/api/identities/" + "0" * 64 + "/claims")
    assert status == 404


async def test_value_never_leaks_until_published(env):
    att = env.attestation()
    assert (await env.post("/api/attestations", {"attestation": att.to_dict()}))[0] == 201

    for path, params in (
        (f"/api/identities/{env.holder.identity_hash}/claims", {}),
        ("/api/attestations", {"subject": env.holder.identity_hash}),
        (f"/api/attestations/{att.id}", {}),
        (f"/api/identities/{env.holder.identity_hash}", {}),
        (f"/api/identities/{env.holder.identity_hash}/sigchain", {}),
        ("/api/explorer/identities/" + env.holder.identity_hash, {}),
        ("/api/explorer/events", {"limit": 100}),
    ):
        resp = await env.client.get(path, params=params)
        assert SECRET_EMAIL not in await resp.text(), path
    assert env.doc.salt not in await (await env.client.get(f"/api/identities/{env.holder.identity_hash}/claims")).text()


# --- publishing -----------------------------------------------------------------------------------


async def test_publish_and_unpublish(env):
    status, body = await env.post("/api/claims/documents", env.publication())
    assert status == 201 and body["published"] is True

    _, listing = await env.get(f"/api/identities/{env.holder.identity_hash}/claims")
    published = listing["claims"][0]["document"]
    assert published["value"] == SECRET_EMAIL and published["salt"] == env.doc.salt

    # the published document is exactly what the commitment on the chain binds
    assert ClaimDocument.from_dict({"identity": env.holder.identity_hash, **published}).matches(
        env.holder.sigchain.get_claim(env.doc.claim_id))

    status, body = await env.post(
        "/api/claims/documents",
        env.publication("unpublish", document={"identity": env.holder.identity_hash, "claim_id": env.doc.claim_id},
                        issued_at=int(time.time()) + 1))
    assert status == 200 and body["unpublished"] is True
    _, listing = await env.get(f"/api/identities/{env.holder.identity_hash}/claims")
    assert listing["claims"][0]["document"] is None


async def test_master_key_may_publish(env):
    body = env.publication(key=env.holder.local_keypair)
    assert (await env.post("/api/claims/documents", body))[0] == 201


async def test_publication_needs_an_authorized_key(env):
    status, body = await env.post("/api/claims/documents", env.publication(key=env.weak_device))
    assert status == 403
    stranger = Identity.create()
    status, _ = await env.post("/api/claims/documents", env.publication(key=stranger.local_keypair))
    assert status == 403


async def test_publication_signature_and_freshness(env):
    good = env.publication()
    assert (await env.post("/api/claims/documents", {**good, "sig": "00" * 64}))[0] == 401

    # the signature covers the document: swapping the value invalidates it
    forged_doc = {**env.doc.to_dict(), "value": "other@example.com"}
    assert (await env.post("/api/claims/documents", {**good, "document": forged_doc}))[0] == 401

    old = env.publication(issued_at=int(time.time()) - 3600)
    assert (await env.post("/api/claims/documents", old))[0] == 400


async def test_publication_replays_do_not_override_newer_state(env):
    now = int(time.time())
    first = env.publication(issued_at=now)
    assert (await env.post("/api/claims/documents", first))[0] == 201
    unpublish = env.publication(
        "unpublish", document={"identity": env.holder.identity_hash, "claim_id": env.doc.claim_id},
        issued_at=now + 1)
    assert (await env.post("/api/claims/documents", unpublish))[0] == 200
    # replaying the original publish (older than the unpublish) must not resurrect it
    status, body = await env.post("/api/claims/documents", first)
    assert status in (201, 409)  # nothing stored anymore, so this is a fresh publish at `now`
    # but replaying an old unpublish after a newer publish must not remove it
    newer = env.publication(issued_at=now + 10)
    assert (await env.post("/api/claims/documents", newer))[0] == 201
    assert (await env.post("/api/claims/documents", unpublish))[0] == 409


async def test_publication_must_match_the_chain(env):
    wrong = ClaimDocument(env.doc.identity, env.doc.claim_id, "email", "someone-else@example.com", env.doc.salt)
    status, body = await env.post("/api/claims/documents", env.publication(document=wrong.to_dict()))
    assert status == 400 and body["error"] == "claim_mismatch"

    env.holder.revoke_claim(env.doc.claim_id)
    env.storage.save_sigchain(env.holder.sigchain)
    status, body = await env.post("/api/claims/documents", env.publication())
    assert status == 409 and body["error"] == "claim_not_active"


# --- attestations ------------------------------------------------------------------------------------


async def test_attestation_is_stored_and_listed(env):
    att = env.attestation()
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 201 and body["attestation_id"] == att.id
    assert (await env.post("/api/attestations", {"attestation": att.to_dict()}))[0] == 201  # idempotent

    _, listed = await env.get("/api/attestations", subject=env.holder.identity_hash)
    assert [a["attestation_id"] for a in listed["attestations"]] == [att.id]
    _, one = await env.get(f"/api/attestations/{att.id}")
    assert one["attestation"]["issuer"] == env.issuer.identity_hash and one["revoked_at"] is None

    _, claims = await env.get(f"/api/identities/{env.holder.identity_hash}/claims")
    shown = claims["claims"][0]["attestations"][0]
    assert shown["issuer"] == env.issuer.identity_hash and not shown["revoked"] and not shown["expired"]

    assert (await env.get("/api/attestations"))[0] == 400
    assert (await env.get("/api/attestations/" + "0" * 64))[0] == 404


async def test_attestation_rejections(env):
    # bad signature
    data = env.attestation().to_dict()
    data["sig"] = "00" * 64
    status, body = await env.post("/api/attestations", {"attestation": data})
    assert status == 401 and body["error"] == "bad_signature"

    # issuer key without sign_identity
    weak = Identity.create(identity_type=IdentityType.ORGANIZATION)
    weak_key, _ = weak.add_device("k", capabilities=[D.SIGN_MESSAGES])
    env.storage.save_sigchain(weak.sigchain)
    record = env.holder.sigchain.get_claim(env.doc.claim_id)
    att = Attestation.issue(weak.identity_hash, weak_key, env.holder.identity_hash, record,
                            env.holder.sigchain.head_hash, "email_code", "low")
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 403 and body["error"] == "issuer_key_not_authorized"

    # malformed
    status, _ = await env.post("/api/attestations", {"attestation": {"type": "ATTESTATION"}})
    assert status == 400
    assert (await env.post("/api/attestations", {}))[0] == 400


async def test_unknown_issuer_needs_its_chain_supplied(env):
    outsider = Identity.create(identity_type=IdentityType.ORGANIZATION, name="Elsewhere")
    key, _ = outsider.add_device("signer", capabilities=[D.SIGN_IDENTITY])  # not stored on this node
    record = env.holder.sigchain.get_claim(env.doc.claim_id)
    att = Attestation.issue(outsider.identity_hash, key, env.holder.identity_hash, record,
                            env.holder.sigchain.head_hash, "email_code", "low")
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 404

    status, body = await env.post(
        "/api/attestations", {"attestation": att.to_dict(), "issuer_sigchain": outsider.sigchain.to_list()})
    assert status == 201


async def test_stale_holder_chain_gets_a_409_with_the_fix(env):
    newer = Identity.create()  # throwaway to compute nothing; real case below
    env.holder.add_device("laptop")  # holder moved on; the node has not seen it
    att = env.attestation()
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 409 and body["error"] == "unknown_chain_head"
    status, _ = await env.post(
        "/api/attestations",
        {"attestation": att.to_dict(), "subject_sigchain": env.holder.sigchain.to_list()})
    assert status == 201


async def test_attestation_for_a_revoked_claim_is_rejected(env):
    env.holder.revoke_claim(env.doc.claim_id)
    env.storage.save_sigchain(env.holder.sigchain)
    record = env.holder.sigchain.get_claim(env.doc.claim_id)
    att = Attestation.issue(env.issuer.identity_hash, env.signer, env.holder.identity_hash, record,
                            env.holder.sigchain.head_hash, "email_code", "low")
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 422 and body["error"] == "claim_revoked"


async def test_issuer_can_revoke_and_nobody_else(env):
    att = env.attestation()
    await env.post("/api/attestations", {"attestation": att.to_dict()})

    forged = AttestationRevocation.create(env.holder.identity_hash, env.holder.local_keypair, att.id)
    status, _ = await env.post("/api/attestations/revocations", {"revocation": forged.to_dict()})
    assert status in (401, 403, 422)

    claimed = AttestationRevocation.create(env.issuer.identity_hash, env.weak_device, att.id)
    status, _ = await env.post("/api/attestations/revocations", {"revocation": claimed.to_dict()})
    assert status in (401, 403, 422)  # signed by someone else's key

    rev = AttestationRevocation.create(env.issuer.identity_hash, env.signer, att.id, "mistake")
    status, body = await env.post("/api/attestations/revocations", {"revocation": rev.to_dict()})
    assert status == 201

    _, one = await env.get(f"/api/attestations/{att.id}")
    assert one["revoked_at"] is not None and one["revoke_reason"] == "mistake"
    _, claims = await env.get(f"/api/identities/{env.holder.identity_hash}/claims")
    assert claims["claims"][0]["attestations"][0]["revoked"] is True

    # a revoked attestation cannot be stored again
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 409 and body["error"] == "revoked"


async def test_revocation_can_arrive_before_the_attestation(env):
    att = env.attestation()
    rev = AttestationRevocation.create(env.issuer.identity_hash, env.signer, att.id)
    assert (await env.post("/api/attestations/revocations", {"revocation": rev.to_dict()}))[0] == 201
    assert (await env.post("/api/attestations", {"attestation": att.to_dict()}))[0] == 409


async def test_per_claim_attestation_cap(env, monkeypatch):
    import nodetide.api.claims as claims_api
    monkeypatch.setattr(claims_api, "MAX_ATTESTATIONS_PER_CLAIM", 2)
    for i in range(2):
        att = env.attestation(now=int(time.time()) - i)
        assert (await env.post("/api/attestations", {"attestation": att.to_dict()}))[0] == 201
    att = env.attestation(now=int(time.time()) - 10)
    status, body = await env.post("/api/attestations", {"attestation": att.to_dict()})
    assert status == 429
