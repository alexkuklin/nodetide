"""The eID notary: reads the certificate privately and issues attestations without it, only for the claims listed."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import logging
import time
from datetime import date, datetime, timezone

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.core.auth import create_assertion
from nodetide.core.claims import Attestation, ClaimDocument, ClaimError, normalize_value, verify_attestation
from nodetide.core.identity import DeviceCapability, Identity
from nodetide.core.storage import Storage
from nodetide.eidas.certs import _EGN_WEIGHTS, cert_birthdate, egn_birthdate
from nodetide.eidas.cms import create_cades_detached
from nodetide.eidas.notary_statement import build_notary_statement, parse_notary_statement
from nodetide.eidas.statement import StatementError
from nodetide.eidas.validate import TrustStore
from nodetide.eidas.verify import EidasPolicy
from nodetide.verifiers import NodeIssuer
from nodetide.verifiers.eid_notary import EidNotary
from nodetide.verifiers.service import create_verifier_app
from tests import pki

AUD = "https://notary.test"
NAME = {"given_name": "Maria", "family_name": "Ivanova"}


def egn_for(born: date) -> str:
    month = born.month + (40 if born.year >= 2000 else 0)
    prefix = f"{born.year % 100:02d}{month:02d}{born.day:02d}123"
    check = sum(w * int(d) for w, d in zip(_EGN_WEIGHTS, prefix)) % 11
    return prefix + str(check if check < 10 else 0)


ADULT_BORN = date(1985, 6, 15)
CHILD_BORN = date.today().replace(year=date.today().year - 10)


class World:
    def __init__(self, client, notary, issuer, egn):
        self.client, self.notary, self.issuer, self.egn = client, notary, issuer, egn
        self.holder = Identity.create(name="Maria")
        self.device, _ = self.holder.add_device("phone", capabilities=[DeviceCapability.AUTHENTICATE])
        self.docs = {
            "legal_name": self._claim("legal_name", NAME),
            "birthdate": self._claim("birthdate", ADULT_BORN.isoformat()),
            "age_over_18": self._claim("age_over_18", True),
        }

    def _claim(self, claim_type, value) -> ClaimDocument:
        doc = ClaimDocument.create(self.holder.identity_hash, claim_type, value)
        self.holder.add_claim(doc.claim_id, claim_type, doc.commitment)
        return doc

    def statement(self, types=("legal_name",), notary=None, signed_on=None, valid_days=30) -> str:
        signed_on = signed_on or int(time.time())
        return build_notary_statement(
            self.holder.identity_hash, notary or self.issuer.identity_hash, self.holder.sigchain.head_hash,
            signed_on, signed_on + valid_days * 86400,
            [(self.docs[t].claim_id, t, self.docs[t].commitment) for t in types])

    def sign(self, text: str, signer=None) -> bytes:
        parsed = parse_notary_statement(text)
        return create_cades_detached(text.encode(), signer or self.signer,
                                     datetime.fromtimestamp(parsed.signed_on, tz=timezone.utc))

    async def submit(self, text, der, types=None, purpose="eid_attestation", bound_to=None, docs=None):
        request = await (await self.client.post("/api/auth/challenge", json={})).json()
        assertion = create_assertion(
            request, self.holder.identity_hash, self.device, self.holder.sigchain.head_hash,
            claims={"purpose": purpose, "statement_sha256": hashlib.sha256((bound_to or text).encode()).hexdigest()})
        types = types or [c[1] for c in parse_notary_statement(text).claims]
        body = {"statement": text, "signature": base64.b64encode(der).decode(),
                "documents": docs if docs is not None else [self.docs[t].to_dict() for t in types],
                "assertion": assertion, "sigchain": self.holder.sigchain.to_list()}
        resp = await self.client.post("/api/verify/eid/attest", json=body)
        return resp.status, await resp.json()


async def make_world(egn: str, trusted_root=True, **cert_kw):
    root = pki.make_ca("Test Root CA", path_length=1)
    inter = pki.make_ca("Test Qualified CA", parent=root, path_length=0)
    leaf = pki.make_signer_cert(inter, serial=f"PNOBG-{egn}", **cert_kw)
    other = pki.make_ca("Unrelated Root")
    policy = EidasPolicy(TrustStore([root.asn1 if trusted_root else other.asn1]), revocation_mode="off")
    storage = Storage.memory()
    issuer = NodeIssuer.load_or_create(storage, "Test Notary")
    notary = EidNotary(issuer, policy)
    app = create_verifier_app(storage, [], AUD, notary=notary)
    client = TestClient(TestServer(app))
    await client.start_server()
    world = World(client, notary, issuer, egn)
    world.signer = pki.SoftwareSigner(leaf, extra_chain=[inter])
    world.leaf = leaf
    return world


@pytest.fixture
async def world():
    w = await make_world(egn_for(ADULT_BORN))
    yield w
    await w.client.close()


# --- the point of it all ------------------------------------------------------------------------------------


async def test_attestations_contain_neither_certificate_nor_id_number_nor_unlisted_claims(world):
    text = world.statement(("legal_name", "age_over_18"))
    status, body = await world.submit(text, world.sign(text))
    assert status == 201, body
    attestations = [Attestation.from_dict(a) for a in body["attestations"]]
    assert sorted(a.claim_type for a in attestations) == ["age_over_18", "legal_name"]  # no birthdate: not listed
    issuer_chain = world.issuer.identity.sigchain
    for att in attestations:
        assert att.method == "eidas_notary" and att.assurance == "high" and att.proof is None
        assert att.evidence == {"source": "eidas_qes", "qscd": True}
        assert att.issuer == world.issuer.identity_hash and att.subject == world.holder.identity_hash
        assert verify_attestation(att, world.holder.sigchain, issuer_chain).ok
    raw = str(body)
    cert_b64 = base64.b64encode(world.leaf.cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)).decode()
    for secret in (world.egn, "PNOBG", cert_b64[:60], ADULT_BORN.isoformat(), "1985", "Ivanova", "Maria"):
        assert secret not in raw


async def test_birthdate_is_attested_only_when_the_person_listed_it(world):
    text = world.statement(("legal_name", "birthdate"))
    status, body = await world.submit(text, world.sign(text))
    assert status == 201
    assert sorted(a["claim_type"] for a in body["attestations"]) == ["birthdate", "legal_name"]


async def test_the_certificate_is_never_logged(world, caplog):
    caplog.set_level(logging.DEBUG)
    text = world.statement(("legal_name", "birthdate"))
    await world.submit(text, world.sign(text))
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert world.egn not in logged and "PNOBG" not in logged and ADULT_BORN.isoformat() not in logged


async def test_issuer_info_announces_the_notary(world):
    info = await (await world.client.get("/api/verify/issuer")).json()
    method = next(m for m in info["methods"] if m["method"] == "eidas_notary")
    assert method["claim_types"] == ["legal_name", "birthdate", "age_over_18"] and method["assurance"] == "high"


# --- the notary does not take anyone's word for it -----------------------------------------------------------------


async def test_a_statement_for_another_notary_is_refused(world):
    text = world.statement(notary="f" * 64)
    status, body = await world.submit(text, world.sign(text))
    assert status == 422 and body["error"] == "wrong_notary"


async def test_an_untrusted_certificate_is_refused():
    w = await make_world(egn_for(ADULT_BORN), trusted_root=False)
    try:
        text = w.statement()
        status, body = await w.submit(text, w.sign(text))
        assert status == 422 and body["error"] == "untrusted_certificate"
    finally:
        await w.client.close()


async def test_a_name_that_is_not_on_the_certificate_is_refused(world):
    world.docs["legal_name"] = world._claim("legal_name", {"given_name": "Petar", "family_name": "Georgiev"})
    text = world.statement()
    status, body = await world.submit(text, world.sign(text))
    assert status == 422 and body["error"] == "name_mismatch"


async def test_a_wrong_birthdate_is_refused(world):
    world.docs["birthdate"] = world._claim("birthdate", "1985-06-16")
    text = world.statement(("birthdate",))
    status, body = await world.submit(text, world.sign(text))
    assert status == 422 and body["error"] == "birthdate_mismatch"


async def test_under_18_cannot_claim_to_be_over_18():
    w = await make_world(egn_for(CHILD_BORN))
    try:
        text = w.statement(("age_over_18",))
        status, body = await w.submit(text, w.sign(text))
        assert status == 422 and body["error"] == "not_over_18"
    finally:
        await w.client.close()


async def test_a_certificate_without_a_birth_date_cannot_attest_one():
    w = await make_world("0000000000")  # valid checksum, but not a date
    try:
        text = w.statement(("birthdate",))
        status, body = await w.submit(text, w.sign(text))
        assert status == 422 and body["error"] == "birthdate_unavailable"
        text = w.statement(("legal_name",))  # the name alone still works
        assert (await w.submit(text, w.sign(text)))[0] == 201
    finally:
        await w.client.close()


async def test_the_request_must_be_bound_to_this_exact_statement(world):
    text = world.statement(("legal_name",))
    other = world.statement(("legal_name", "birthdate"))
    status, body = await world.submit(text, world.sign(text), bound_to=other)
    assert status == 401 and body["error"] == "assertion_not_bound"
    status, body = await world.submit(text, world.sign(text), purpose="claim_verification")
    assert status == 401 and body["error"] == "assertion_not_bound"


async def test_a_signature_over_something_else_is_refused(world):
    text = world.statement()
    status, body = await world.submit(text, world.sign(world.statement(("legal_name", "birthdate"))))
    assert status == 400 and body["error"] == "invalid_signature"


async def test_old_statements_are_not_accepted(world):
    text = world.statement(signed_on=int(time.time()) - 5 * 86400, valid_days=30)
    status, body = await world.submit(text, world.sign(text))
    assert status == 422 and body["error"] == "stale_statement"


async def test_documents_must_be_the_claims_on_the_chain(world):
    text = world.statement()
    real = world.docs["legal_name"]
    forged = ClaimDocument(real.identity, real.claim_id, "legal_name", {"given_name": "Maria", "family_name": "Petrova"}, real.salt)
    status, body = await world.submit(text, world.sign(text), docs=[forged.to_dict()])
    assert status == 400 and body["error"] == "claim_mismatch"


async def test_a_challenge_cannot_be_reused(world):
    text = world.statement()
    der = world.sign(text)
    request = await (await world.client.post("/api/auth/challenge", json={})).json()
    assertion = create_assertion(request, world.holder.identity_hash, world.device, world.holder.sigchain.head_hash,
                                 claims={"purpose": "eid_attestation", "statement_sha256": hashlib.sha256(text.encode()).hexdigest()})
    body = {"statement": text, "signature": base64.b64encode(der).decode(),
            "documents": [world.docs["legal_name"].to_dict()], "assertion": assertion, "sigchain": world.holder.sigchain.to_list()}
    assert (await world.client.post("/api/verify/eid/attest", json=body)).status == 201
    assert (await world.client.post("/api/verify/eid/attest", json=body)).status == 401


# --- the pieces -------------------------------------------------------------------------------------------


def test_egn_decoding_and_checksum():
    assert egn_birthdate(egn_for(date(1985, 6, 15))) == date(1985, 6, 15)
    assert egn_birthdate(egn_for(date(2004, 2, 1))) == date(2004, 2, 1)
    body = "2512011235"
    assert egn_birthdate(body) == date(1925, 12, 1)
    assert egn_birthdate(body[:-1] + "0") is None          # wrong checksum
    assert egn_birthdate("9902290000") is None             # no 29 February 1999
    assert egn_birthdate("12345") is None and egn_birthdate("abcdefghij") is None


def test_the_birth_date_is_read_from_the_certificate_serial():
    ca = pki.make_ca("CA")
    leaf = pki.make_signer_cert(ca, serial=f"PNOBG-{egn_for(date(1990, 4, 23))}")
    assert cert_birthdate(leaf.asn1) == date(1990, 4, 23)
    foreign = pki.make_signer_cert(ca, serial="PNOGR-1234567890")
    assert cert_birthdate(foreign.asn1) is None


def test_new_claim_types_are_normalised():
    assert normalize_value("birthdate", " 1990-04-23 ") == "1990-04-23"
    assert normalize_value("age_over_18", True) is True
    for bad in ("1990-4-23", "1990-02-30", "2999-01-01", "1700-01-01", 19900423, None):
        with pytest.raises(ClaimError):
            normalize_value("birthdate", bad)
    for bad in (False, "true", 1, None):
        with pytest.raises(ClaimError):
            normalize_value("age_over_18", bad)


def test_notary_statement_is_canonical_and_closed():
    a, b = "a" * 64, "b" * 64
    claims = [("claim-id-0123456789", "legal_name", "c" * 64), ("claim-id-9876543210", "age_over_18", "d" * 64)]
    text = build_notary_statement(a, b, a, 1_700_000_000, 1_700_086_400, claims)
    parsed = parse_notary_statement(text)
    assert parsed.text() == text and parsed.notary == b and [c[1] for c in parsed.claims] == ["legal_name", "age_over_18"]
    assert "ONLY the claims listed" in text
    for bad_claims in ([("claim-id-0123456789", "email", "c" * 64)], [], claims + claims, [claims[0]] * 2,
                       [(f"claim-id-{i:010d}", "birthdate", "c" * 64) for i in range(6)]):
        with pytest.raises(StatementError):
            build_notary_statement(a, b, a, 1, 2, bad_claims)
    for mutate in (lambda t: t + "\n", lambda t: t.replace("\n", "\r\n"), lambda t: t.replace("v1", "v2"),
                   lambda t: t.replace("ONLY", "also"), lambda t: " " + t):
        with pytest.raises(StatementError):
            parse_notary_statement(mutate(text))


# --- through the bridge ----------------------------------------------------------------------------------------


async def test_the_bridge_releases_what_the_person_listed_and_nothing_else(world):
    """Notary attestations (no certificate) are accepted by a bridge that pins the notary, and only for those claims."""
    from nodetide.oidc.config import OIDCConfig
    from nodetide.oidc.handlers import default_claim_rules
    from nodetide.core.relying_party import evaluate_claim

    text = world.statement(("legal_name", "age_over_18"))
    status, body = await world.submit(text, world.sign(text))
    assert status == 201
    config = OIDCConfig(issuer="https://bridge.test", clients={}, notary_issuers=[world.issuer.identity_hash])
    rules = default_claim_rules({}, config)
    by_type = {a["claim_type"]: Attestation.from_dict(a) for a in body["attestations"]}
    for claim_type, att in by_type.items():
        verdict = evaluate_claim(rules[claim_type], world.docs[claim_type], att, world.holder.sigchain,
                                 world.issuer.identity.sigchain)
        assert verdict.claim is not None, verdict
    assert "birthdate" not in by_type
    # an unpinned bridge believes none of it
    other = default_claim_rules({}, OIDCConfig(issuer="https://bridge.test", clients={}, notary_issuers=["c" * 64]))
    verdict = evaluate_claim(other["legal_name"], world.docs["legal_name"], by_type["legal_name"],
                             world.holder.sigchain, world.issuer.identity.sigchain)
    assert verdict.claim is None
