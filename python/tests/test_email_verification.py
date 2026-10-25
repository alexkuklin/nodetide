"""End-to-end tests of email claim verification."""

from __future__ import annotations

import re
import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.auth import create_assertion
from nodetide.core.claims import Attestation, ClaimDocument, verify_attestation
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.core.storage import Storage
from nodetide.verifiers import EmailVerifier, NodeIssuer
from nodetide.verifiers import email_verifier as ev
from nodetide.verifiers.mail import MemorySender

D = DeviceCapability
AUD = "https://node.test"
ADDRESS = "alice-private@example.com"


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


class World:
    def __init__(self, client: TestClient, storage: Storage, sender: MemorySender, verifier, clock):
        self.client, self.storage, self.sender, self.verifier, self.clock = client, storage, sender, verifier, clock
        self.holder = Identity.create(name="Alice")
        self.device, _ = self.holder.add_device("phone", capabilities=[D.AUTHENTICATE])
        self.doc = self.new_claim(ADDRESS)
        storage.save_sigchain(self.holder.sigchain)

    def new_claim(self, address, claim_type="email") -> ClaimDocument:
        doc = ClaimDocument.create(self.holder.identity_hash, claim_type, address)
        self.holder.add_claim(doc.claim_id, claim_type, doc.commitment)
        return doc

    async def post(self, path, body):
        resp = await self.client.post(path, json=body)
        return resp.status, await resp.json()

    async def challenge(self, aud=None):
        _, request = await self.post("/api/auth/challenge", {"aud": aud} if aud else {})
        return request

    async def assertion(self, doc=None, purpose="claim_verification", request=None, bind=True):
        doc = doc or self.doc
        request = request or await self.challenge()
        claims = {"purpose": purpose, "claim_id": doc.claim_id} if bind else None
        return create_assertion(
            request, self.holder.identity_hash, self.device, self.holder.sigchain.head_hash,
            claims=claims)  # real time: only the verifier's own windows use the fake clock

    async def start(self, doc=None, assertion=None, **extra):
        doc = doc or self.doc
        assertion = assertion or await self.assertion(doc)
        return await self.post("/api/verify/email/start", {"document": doc.to_dict(), "assertion": assertion, **extra})

    def last_code(self) -> str:
        return re.search(r"Verification code: ([A-Z0-9]+)", self.sender.outbox[-1]["body"]).group(1)

    async def verify_fully(self):
        status, started = await self.start()
        assert status == 202, started
        return await self.post("/api/verify/email/confirm",
                               {"verification_id": started["verification_id"], "code": self.last_code()})


@pytest.fixture
async def world():
    storage = Storage.memory()
    clock = Clock()
    sender = MemorySender()
    verifier = EmailVerifier(storage, NodeIssuer.load_or_create(storage, "Test Verifier"), sender, clock=clock)
    app = create_app(storage=storage, auth_audience=AUD, email_verifier=verifier)
    async with TestClient(TestServer(app)) as client:
        yield World(client, storage, sender, verifier, clock)


# --- the happy path ---------------------------------------------------------------------------------------


async def test_full_flow_issues_a_verifiable_attestation(world):
    status, body = await world.verify_fully()
    assert status == 201, body
    att = Attestation.from_dict(body["attestation"])
    assert att.method == "email_code" and att.assurance == "low" and att.subject == world.holder.identity_hash
    assert att.evidence == {}  # the address is not repeated in the attestation

    issuer_chain = world.storage.get_sigchain(att.issuer)
    assert verify_attestation(att, world.holder.sigchain, issuer_chain).ok

    # it is stored and shows up on the claim, without the address
    resp = await world.client.get(f"/api/identities/{world.holder.identity_hash}/claims")
    text = await resp.text()
    claim = (await resp.json())["claims"][0]
    assert claim["attestations"][0]["attestation_id"] == att.id
    assert ADDRESS not in text


async def test_the_mail_contains_a_code_and_nothing_sensitive(world):
    status, _ = await world.start()
    assert status == 202
    mail = world.sender.outbox[0]
    assert mail["to"] == ADDRESS and "Test Verifier" in mail["subject"]
    assert re.fullmatch(r"[A-HJKMNP-Z2-9]{8}", world.last_code())
    assert world.holder.identity_hash not in mail["body"]  # only a short prefix
    assert world.doc.salt not in mail["body"]


async def test_code_entry_is_forgiving(world):
    _, started = await world.start()
    code = world.last_code()
    messy = f" {code[:4].lower()}-{code[4:].lower()} "
    status, _ = await world.post("/api/verify/email/confirm", {"verification_id": started["verification_id"], "code": messy})
    assert status == 201


async def test_issuer_endpoint_describes_the_verifier(world):
    resp = await world.client.get("/api/verify/issuer")
    info = await resp.json()
    assert info["issuer"] == world.verifier.issuer.identity_hash and info["audience"] == AUD
    assert info["methods"][0]["claim_type"] == "email" and info["methods"][0]["assurance"] == "low"


# --- proof of key control ---------------------------------------------------------------------------------


async def test_assertion_must_be_bound_to_this_claim(world):
    other = world.new_claim("second@example.com")
    world.storage.save_sigchain(world.holder.sigchain)
    for assertion in (
        await world.assertion(bind=False),
        await world.assertion(purpose="login"),
        await world.assertion(doc=other),  # bound to a different claim
    ):
        status, body = await world.start(assertion=assertion)
        assert status == 401 and body["error"] == "assertion_not_bound"
    assert world.sender.outbox == []


async def test_nobody_else_can_start_verification_for_my_claim(world):
    mallory = Identity.create()
    mallory_device, _ = mallory.add_device("phone", capabilities=[D.AUTHENTICATE])
    request = await world.challenge()
    assertion = create_assertion(
        request, world.holder.identity_hash, mallory_device, world.holder.sigchain.head_hash,
        claims={"purpose": "claim_verification", "claim_id": world.doc.claim_id})
    status, body = await world.start(assertion=assertion)
    assert status == 401 and body["error"] == "device_not_authorized"
    assert world.sender.outbox == []


async def test_challenges_are_single_use_and_audience_bound(world):
    request = await world.challenge()
    assertion = await world.assertion(request=request)
    assert (await world.start(assertion=assertion))[0] == 202
    status, body = await world.start(assertion=assertion)  # replay
    assert status == 401 and body["error"] == "unknown_challenge"

    foreign = await world.challenge(aud="https://elsewhere.test")
    status, body = await world.start(assertion=await world.assertion(request=foreign))
    assert status == 401 and body["error"] == "wrong_audience"


async def test_unknown_identity_needs_its_chain_and_is_not_stored(world):
    stranger = Identity.create(name="Bob")
    device, _ = stranger.add_device("phone", capabilities=[D.AUTHENTICATE])
    doc = ClaimDocument.create(stranger.identity_hash, "email", "bob@example.com")
    stranger.add_claim(doc.claim_id, "email", doc.commitment)

    request = await world.challenge()
    assertion = create_assertion(
        request, stranger.identity_hash, device, stranger.sigchain.head_hash,
        claims={"purpose": "claim_verification", "claim_id": doc.claim_id})
    status, _ = await world.post("/api/verify/email/start", {"document": doc.to_dict(), "assertion": assertion})
    assert status == 404

    request = await world.challenge()
    assertion = create_assertion(
        request, stranger.identity_hash, device, stranger.sigchain.head_hash,
        claims={"purpose": "claim_verification", "claim_id": doc.claim_id})
    status, started = await world.post(
        "/api/verify/email/start",
        {"document": doc.to_dict(), "assertion": assertion, "sigchain": stranger.sigchain.to_list()})
    assert status == 202
    status, body = await world.post(
        "/api/verify/email/confirm",
        {"verification_id": started["verification_id"], "code": world.last_code()})
    assert status == 201 and body["attestation"]["subject"] == stranger.identity_hash
    assert world.storage.get_sigchain(stranger.identity_hash) is None  # we did not adopt it


# --- the claim itself -------------------------------------------------------------------------------------------


async def test_document_must_match_the_commitment(world):
    wrong = ClaimDocument(world.doc.identity, world.doc.claim_id, "email", "someone-else@example.com", world.doc.salt)
    status, body = await world.start(doc=wrong, assertion=await world.assertion(world.doc))
    assert status == 400 and body["error"] == "claim_mismatch"
    assert world.sender.outbox == []


async def test_only_email_claims_are_handled_here(world):
    phone = world.new_claim("+359881234567", "phone")
    world.storage.save_sigchain(world.holder.sigchain)
    status, body = await world.start(doc=phone, assertion=await world.assertion(phone))
    assert status == 400 and body["error"] == "unsupported_claim_type"


async def test_revoked_or_unknown_claims_are_refused(world):
    world.holder.revoke_claim(world.doc.claim_id)
    world.storage.save_sigchain(world.holder.sigchain)
    status, body = await world.start()
    assert status == 409 and body["error"] == "claim_revoked"

    ghost = ClaimDocument.create(world.holder.identity_hash, "email", "ghost@example.com")  # never put on chain
    status, body = await world.start(doc=ghost, assertion=await world.assertion(ghost))
    assert status == 404 and body["error"] == "unknown_claim"


async def test_claim_revoked_between_start_and_confirm(world):
    _, started = await world.start()
    world.holder.revoke_claim(world.doc.claim_id)
    world.storage.save_sigchain(world.holder.sigchain)
    status, body = await world.post(
        "/api/verify/email/confirm", {"verification_id": started["verification_id"], "code": world.last_code()})
    assert status == 409 and body["error"] == "claim_not_active"


# --- codes -------------------------------------------------------------------------------------------------------


async def test_wrong_codes_run_out(world):
    _, started = await world.start()
    vid, real = started["verification_id"], world.last_code()
    for attempt in range(ev.MAX_ATTEMPTS - 1):
        status, body = await world.post("/api/verify/email/confirm", {"verification_id": vid, "code": "WRONG123"})
        assert status == 401 and body["error"] == "wrong_code"
    status, body = await world.post("/api/verify/email/confirm", {"verification_id": vid, "code": "WRONG123"})
    assert status == 429 and body["error"] == "too_many_attempts"
    # the correct code no longer works: the verification is gone
    status, body = await world.post("/api/verify/email/confirm", {"verification_id": vid, "code": real})
    assert status == 404


async def test_codes_are_single_use_and_expire(world):
    _, started = await world.start()
    vid, code = started["verification_id"], world.last_code()
    assert (await world.post("/api/verify/email/confirm", {"verification_id": vid, "code": code}))[0] == 201
    assert (await world.post("/api/verify/email/confirm", {"verification_id": vid, "code": code}))[0] == 404

    _, started = await world.start()
    world.clock.now += ev.CODE_TTL + 1
    status, body = await world.post(
        "/api/verify/email/confirm", {"verification_id": started["verification_id"], "code": world.last_code()})
    assert status == 410 and body["error"] == "expired"


async def test_a_new_request_replaces_the_old_code(world):
    _, first = await world.start()
    first_code = world.last_code()
    _, second = await world.start()
    status, _ = await world.post("/api/verify/email/confirm", {"verification_id": first["verification_id"], "code": first_code})
    assert status == 404
    status, _ = await world.post("/api/verify/email/confirm", {"verification_id": second["verification_id"], "code": world.last_code()})
    assert status == 201


async def test_bad_confirm_requests(world):
    for body in ({}, {"verification_id": 5, "code": "X"}, {"verification_id": "x" * 10, "code": "y" * 40}):
        assert (await world.post("/api/verify/email/confirm", body))[0] == 400
    assert (await world.post("/api/verify/email/confirm", {"verification_id": "nope", "code": "ABCDEFGH"}))[0] == 404


# --- abuse limits ------------------------------------------------------------------------------------------------------


async def test_per_address_rate_limit(world):
    for _ in range(ev.PER_ADDRESS[0]):
        assert (await world.start())[0] == 202
    status, body = await world.start()
    assert status == 429 and body["error"] == "rate_limited"
    assert len(world.sender.outbox) == ev.PER_ADDRESS[0]  # no extra mail was sent

    world.clock.now += ev.PER_ADDRESS[1] + 1
    assert (await world.start())[0] == 202


async def test_per_identity_rate_limit(world):
    docs = [world.new_claim(f"user{i}@example.com") for i in range(ev.PER_IDENTITY[0] + 1)]
    world.storage.save_sigchain(world.holder.sigchain)
    for doc in docs[: ev.PER_IDENTITY[0]]:
        assert (await world.start(doc=doc, assertion=await world.assertion(doc)))[0] == 202
    status, body = await world.start(doc=docs[-1], assertion=await world.assertion(docs[-1]))
    assert status == 429


async def test_mail_failure_is_reported_and_leaves_nothing_behind(world):
    world.sender.fail = True
    status, body = await world.start()
    assert status == 503 and body["error"] == "mail_failed"
    assert world.verifier._pending == {}
    world.sender.fail = False
    assert (await world.start())[0] == 202


# --- issuer ------------------------------------------------------------------------------------------------------------

def test_issuer_survives_restart():
    storage = Storage.memory()
    first = NodeIssuer.load_or_create(storage, "Verifier")
    again = NodeIssuer.load_or_create(storage, "Different name is ignored")
    assert again.identity_hash == first.identity_hash and again.name == "Verifier"
    assert again.device_key.to_hex() == first.device_key.to_hex()

    holder = Identity.create()
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment)
    att = first.issue(holder.identity_hash, holder.sigchain.get_claim(doc.claim_id), holder.sigchain.head_hash,
                      "email_code", "low")
    assert verify_attestation(att, holder.sigchain, storage.get_sigchain(again.identity_hash)).ok


def test_issuer_signs_with_a_device_not_the_master():
    storage = Storage.memory()
    issuer = NodeIssuer.load_or_create(storage, "Verifier")
    chain = storage.get_sigchain(issuer.identity_hash)
    assert chain.verify() == (True, None)
    assert issuer.device_key.verify_key.to_hex() != chain.get_current_master_key()
    active = {d.pubkey: d for d in chain.get_active_devices()}
    assert D.SIGN_IDENTITY.value in active[issuer.device_key.verify_key.to_hex()].capabilities


async def test_verification_is_off_unless_configured():
    app = create_app(storage=Storage.memory(), auth_audience=AUD)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/api/verify/issuer")).status == 404
        assert (await client.post("/api/verify/email/start", json={})).status == 501
        assert (await client.post("/api/verify/email/confirm", json={})).status == 501


def test_environment_configuration(monkeypatch):
    from nodetide.verifiers.config import VerifierConfigError, build_email_verifier

    storage = Storage.memory()
    monkeypatch.delenv("NODETIDE_EMAIL_VERIFIER", raising=False)
    assert build_email_verifier(storage, AUD) is None

    monkeypatch.setenv("NODETIDE_EMAIL_VERIFIER", "1")
    with pytest.raises(VerifierConfigError):
        build_email_verifier(storage, None)  # no audience
    with pytest.raises(VerifierConfigError):
        build_email_verifier(storage, AUD)  # no SMTP, no dev log

    monkeypatch.setenv("NODETIDE_SMTP_HOST", "smtp.example.com")
    with pytest.raises(VerifierConfigError):
        build_email_verifier(storage, AUD)  # no From address
    monkeypatch.setenv("NODETIDE_EMAIL_FROM", "verify@example.com")
    verifier = build_email_verifier(storage, AUD)
    assert verifier.sender.host == "smtp.example.com" and verifier.sender.security == "starttls"

    monkeypatch.delenv("NODETIDE_SMTP_HOST")
    monkeypatch.setenv("NODETIDE_EMAIL_DEV_LOG", "1")
    assert build_email_verifier(Storage.memory(), AUD) is not None
