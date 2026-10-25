"""SMS code verification: the service queues messages, a gateway (token-protected) fetches and reports them."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.core.auth import create_assertion
from nodetide.core.claims import Attestation, ClaimDocument, verify_attestation
from nodetide.core.identity import DeviceCapability, Identity
from nodetide.core.storage import Storage
from nodetide.verifiers import NodeIssuer, PhoneVerifier, SmsOutbox
from nodetide.verifiers.service import create_verifier_app

AUD = "https://verifier.test"
TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
NUMBER = "+359881234567"


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


class World:
    def __init__(self, client, verifier, outbox, clock):
        self.client, self.verifier, self.outbox, self.clock = client, verifier, outbox, clock
        self.holder = Identity.create(name="Alice")
        self.device, _ = self.holder.add_device("phone", capabilities=[DeviceCapability.AUTHENTICATE])
        self.doc = self.new_claim(NUMBER)

    def new_claim(self, number) -> ClaimDocument:
        doc = ClaimDocument.create(self.holder.identity_hash, "phone", number)
        self.holder.add_claim(doc.claim_id, "phone", doc.commitment)
        return doc

    async def post(self, path, body, headers=None):
        resp = await self.client.post(path, json=body, headers=headers)
        return resp.status, await resp.json()

    async def start(self, doc=None):
        doc = doc or self.doc
        _, request = await self.post("/api/auth/challenge", {})
        assertion = create_assertion(request, self.holder.identity_hash, self.device, self.holder.sigchain.head_hash,
                                     claims={"purpose": "claim_verification", "claim_id": doc.claim_id})
        return await self.post("/api/verify/phone/start", {
            "document": doc.to_dict(), "assertion": assertion, "sigchain": self.holder.sigchain.to_list()})

    async def gateway_fetch(self, wait=0):
        resp = await self.client.get(f"/api/gateway/sms/pending?wait={wait}", headers=AUTH)
        return (await resp.json())["messages"]


@pytest.fixture
async def world():
    storage, clock, outbox = Storage.memory(), Clock(), SmsOutbox()
    outbox._clock = clock
    verifier = PhoneVerifier(storage, NodeIssuer.load_or_create(storage, "Test Verifier"), outbox, clock=clock)
    app = create_verifier_app(storage, verifier, AUD, outbox=outbox,
                              gateway_token_digest=hashlib.sha256(TOKEN.encode()).digest())
    async with TestClient(TestServer(app)) as client:
        yield World(client, verifier, outbox, clock)


def code_in(text: str) -> str:
    return re.search(r"code: ([0-9]{6})", text).group(1)


async def test_full_flow_through_the_gateway(world):
    status, started = await world.start()
    assert status == 202, started
    vid = started["verification_id"]
    assert (await (await world.client.get(f"/api/verify/phone/{vid}/status")).json()) == {"delivery": "queued"}

    messages = await world.gateway_fetch()
    assert len(messages) == 1 and messages[0]["to"] == NUMBER
    text = messages[0]["text"]
    assert text.isascii() and len(text) <= 160 and world.holder.identity_hash not in text

    status, _ = await world.post(f"/api/gateway/sms/{messages[0]['id']}/result", {"status": "sent"}, AUTH)
    assert status == 200
    assert (await (await world.client.get(f"/api/verify/phone/{vid}/status")).json()) == {"delivery": "sent"}

    status, body = await world.post("/api/verify/phone/confirm", {"verification_id": vid, "code": code_in(text)})
    assert status == 201, body
    att = Attestation.from_dict(body["attestation"])
    assert att.method == "sms_code" and att.assurance == "low" and att.evidence == {}
    assert verify_attestation(att, world.holder.sigchain, world.verifier.issuer.identity.sigchain).ok
    assert NUMBER not in str(body)


async def test_numbers_outside_the_mask_are_never_queued(world):
    other = world.new_claim("+441234567890")
    status, body = await world.start(other)
    assert status == 422 and body["error"] == "number_not_allowed"
    assert await world.gateway_fetch() == []


async def test_gateway_endpoints_need_the_token(world):
    for headers in (None, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic " + TOKEN}):
        resp = await world.client.get("/api/gateway/sms/pending?wait=0", headers=headers)
        assert resp.status == 401
        status, _ = await world.post("/api/gateway/sms/x/result", {"status": "sent"}, headers)
        assert status == 401


async def test_without_a_configured_gateway_the_endpoints_do_not_exist():
    storage = Storage.memory()
    outbox = SmsOutbox()
    verifier = PhoneVerifier(storage, NodeIssuer.load_or_create(storage, "V"), outbox)
    app = create_verifier_app(storage, verifier, AUD)  # no outbox, no token
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/api/gateway/sms/pending", headers=AUTH)).status == 404


async def test_long_poll_wakes_up_when_a_message_is_queued(world):
    poll = asyncio.create_task(world.gateway_fetch(wait=5))
    await asyncio.sleep(0.2)
    assert not poll.done()
    status, _ = await world.start()
    assert status == 202
    messages = await asyncio.wait_for(poll, 3)
    assert len(messages) == 1


async def test_long_poll_times_out_with_nothing(world):
    started = time.monotonic()
    assert await world.gateway_fetch(wait=0.3) == []
    assert 0.2 < time.monotonic() - started < 3


async def test_an_unreported_message_comes_back_then_fails(world):
    _, started = await world.start()
    first = await world.gateway_fetch()
    assert len(first) == 1
    assert await world.gateway_fetch() == []  # leased
    world.clock.now += 200  # the lease ran out
    again = await world.gateway_fetch()
    assert [m["id"] for m in again] == [first[0]["id"]]
    world.clock.now += 200
    assert await world.gateway_fetch() == []  # two attempts is all it gets
    status = await (await world.client.get(f"/api/verify/phone/{started['verification_id']}/status")).json()
    assert status == {"delivery": "failed", "reason": "gateway_no_answer"}


async def test_a_rejection_is_visible_to_the_person(world):
    _, started = await world.start()
    message = (await world.gateway_fetch())[0]
    status, _ = await world.post(f"/api/gateway/sms/{message['id']}/result",
                                 {"status": "rejected", "reason": "limit_reached"}, AUTH)
    assert status == 200
    status = await (await world.client.get(f"/api/verify/phone/{started['verification_id']}/status")).json()
    assert status == {"delivery": "failed", "reason": "limit_reached"}
    # unknown and repeated reports are refused
    assert (await world.post(f"/api/gateway/sms/{message['id']}/result", {"status": "sent"}, AUTH))[0] == 404
    assert (await world.post("/api/gateway/sms/nope/result", {"status": "sent"}, AUTH))[0] == 404
    assert (await world.post("/api/gateway/sms/x/result", {"status": "maybe"}, AUTH))[0] == 400


async def test_wrong_codes_and_rate_limits_apply_to_sms_too(world):
    _, started = await world.start()
    status, body = await world.post("/api/verify/phone/confirm", {"verification_id": started["verification_id"], "code": "000000"})
    assert status == 401 and body["error"] == "wrong_code"
    for _ in range(2):
        assert (await world.start())[0] == 202
    status, body = await world.start()
    assert status == 429 and body["error"] == "rate_limited"  # three per number per hour


async def test_issuer_info_lists_the_phone_method(world):
    info = await (await world.client.get("/api/verify/issuer")).json()
    assert [m["claim_type"] for m in info["methods"]] == ["phone"] and info["methods"][0]["method"] == "sms_code"


def test_environment_configuration(monkeypatch):
    from nodetide.verifiers.config import VerifierConfigError, build_phone_verifier

    storage = Storage.memory()
    issuer = NodeIssuer.load_or_create(storage, "V")
    monkeypatch.delenv("NODETIDE_SMS_GATEWAY_TOKEN", raising=False)
    assert build_phone_verifier(storage, issuer) is None
    monkeypatch.setenv("NODETIDE_SMS_GATEWAY_TOKEN", "short")
    with pytest.raises(VerifierConfigError):
        build_phone_verifier(storage, issuer)
    monkeypatch.setenv("NODETIDE_SMS_GATEWAY_TOKEN", TOKEN)
    monkeypatch.setenv("NODETIDE_PHONE_ALLOWED", "(")
    with pytest.raises(VerifierConfigError):
        build_phone_verifier(storage, issuer)
    monkeypatch.setenv("NODETIDE_PHONE_ALLOWED", r"^\+3598[0-9]{8}$")
    verifier, outbox, digest = build_phone_verifier(storage, issuer)
    assert digest == hashlib.sha256(TOKEN.encode()).digest()
    assert verifier.allowed.fullmatch("+359881234567") and not verifier.allowed.fullmatch("+359981234567")
