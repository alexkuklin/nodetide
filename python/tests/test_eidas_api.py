"""HTTP tests: relying parties verify attestations with POST /api/claims/verify."""

from __future__ import annotations

import copy

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.claims import PROOF_VERIFIERS, Attestation, AttestationRevocation, ClaimDocument
from nodetide.core.identity import DeviceCapability, Identity, IdentityType
from nodetide.core.storage import Storage
from nodetide.eidas.issue import build_eidas_attestation
from tests.test_eidas import World

D = DeviceCapability


@pytest.fixture
async def setup():
    w = World()
    storage = Storage.memory()
    app = create_app(storage=storage, eidas_policy=w.policy)
    try:
        async with TestClient(TestServer(app)) as client:
            yield w, client, storage
    finally:
        PROOF_VERIFIERS.pop("eidas_qes", None)  # registration is process-global


async def verify(client, body):
    resp = await client.post("/api/claims/verify", json=body)
    return resp.status, await resp.json()


async def test_proof_attestation_verifies_with_the_holders_chain(setup):
    w, client, storage = setup
    att = w.attest()
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": w.holder.sigchain.to_list()})
    assert status == 200, body
    assert body["valid"] is True and body["method"] == "eidas_qes" and body["assurance"] == "high"
    assert body["issuer"] is None and body["value_checked"] is False


async def test_disclosed_name_is_checked_against_the_certificate(setup):
    w, client, storage = setup
    att, chain = w.attest(), w.holder.sigchain.to_list()
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": chain,
                                         "document": w.doc.to_dict()})
    assert status == 200 and body["value_checked"] is True and body["name_match"] == "exact"

    other = ClaimDocument(w.doc.identity, w.doc.claim_id, "legal_name",
                          {"given_name": "Petar", "family_name": "Ivanova"}, w.doc.salt)
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": chain,
                                         "document": other.to_dict()})
    assert status == 422 and body["code"] == "claim_mismatch"  # wrong value: the commitment differs


async def test_name_mismatch_with_a_matching_commitment(setup):
    w, client, storage = setup
    # The holder commits to a name that is not the certificate holder's name.
    doc = ClaimDocument.create(w.holder.identity_hash, "legal_name", {"given_name": "Petar", "family_name": "Petrov"})
    w.holder.add_claim(doc.claim_id, "legal_name", doc.commitment)
    att = build_eidas_attestation(w.holder.sigchain, w.holder.sigchain.get_claim(doc.claim_id), w.signer)
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": w.holder.sigchain.to_list(),
                                         "document": doc.to_dict()})
    assert status == 422 and body["code"] == "name_mismatch"
    # without the document, the attestation alone cannot reveal the mismatch, which is why
    # relying parties must always check the disclosed value
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": w.holder.sigchain.to_list()})
    assert status == 200 and body["value_checked"] is False


async def test_proofs_are_never_stored_or_published(setup):
    w, client, storage = setup
    att = w.attest()
    resp = await client.post("/api/attestations", json={"attestation": att.to_dict(),
                                                        "subject_sigchain": w.holder.sigchain.to_list()})
    assert resp.status == 422 and (await resp.json())["error"] == "proof_not_publishable"
    await verify(client, {"attestation": att.to_dict(), "subject_sigchain": w.holder.sigchain.to_list(),
                          "document": w.doc.to_dict()})
    assert storage.list_attestations(subject=w.holder.identity_hash) == []
    assert storage.get_sigchain(w.holder.identity_hash) is None  # the supplied chain was not adopted


async def test_failures_are_reported_with_codes(setup):
    w, client, storage = setup
    att = w.attest()
    chain = w.holder.sigchain.to_list()

    tampered = copy.deepcopy(att.to_dict())
    tampered["commitment"] = "d" * 64
    status, body = await verify(client, {"attestation": tampered, "subject_sigchain": chain})
    assert status == 422 and body["valid"] is False and body["code"] in ("claim_mismatch", "statement_mismatch")

    w.holder.add_device("laptop")  # newer chain state the attestation does not know... but this is older
    status, body = await verify(client, {"attestation": att.to_dict()})
    assert status == 404  # chain neither stored nor supplied

    untrusted = World()
    status, body = await verify(client, {"attestation": untrusted.attest().to_dict(),
                                         "subject_sigchain": untrusted.holder.sigchain.to_list()})
    assert status == 422 and body["code"] == "untrusted_certificate"

    status, _ = await verify(client, {"attestation": {"type": "ATTESTATION"}})
    assert status == 400
    status, _ = await verify(client, {})
    assert status == 400


async def test_stale_holder_chain_is_a_409(setup):
    w, client, storage = setup
    stale = w.holder.sigchain.to_list()
    w.holder.add_device("laptop")
    att = w.attest()  # signed against the newer head
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": stale})
    assert status == 409 and body["code"] == "unknown_chain_head"
    status, body = await verify(client, {"attestation": att.to_dict(), "subject_sigchain": w.holder.sigchain.to_list()})
    assert status == 200


async def test_issued_attestations_verify_too_and_revocation_is_honoured(setup):
    w, client, storage = setup
    holder = Identity.create(name="Alice")
    doc = ClaimDocument.create(holder.identity_hash, "email", "alice@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment)
    issuer = Identity.create(identity_type=IdentityType.ORGANIZATION)
    signer, _ = issuer.add_device("signer", capabilities=[D.SIGN_IDENTITY])
    storage.save_sigchain(holder.sigchain)
    storage.save_sigchain(issuer.sigchain)
    att = Attestation.issue(issuer.identity_hash, signer, holder.identity_hash,
                            holder.sigchain.get_claim(doc.claim_id), holder.sigchain.head_hash, "email_code", "low")

    status, body = await verify(client, {"attestation": att.to_dict(), "document": doc.to_dict()})
    assert status == 200 and body["issuer"] == issuer.identity_hash and body["value_checked"] is True

    rev = AttestationRevocation.create(issuer.identity_hash, signer, att.id, "mistake")
    assert (await client.post("/api/attestations/revocations", json={"revocation": rev.to_dict()})).status == 201
    status, body = await verify(client, {"attestation": att.to_dict()})
    assert status == 409 and body["code"] == "revoked"


async def test_verification_is_off_for_proofs_without_anchors():
    w = World()
    app = create_app(storage=Storage.memory())  # no eidas_policy, no NODETIDE_EIDAS_ANCHORS
    async with TestClient(TestServer(app)) as client:
        status, body = await verify(client, {"attestation": w.attest().to_dict(),
                                             "subject_sigchain": w.holder.sigchain.to_list()})
        assert status == 422 and body["code"] == "unsupported_method"


def test_policy_from_environment(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from nodetide.eidas.verify import policy_from_env
    from tests import pki

    monkeypatch.delenv("NODETIDE_EIDAS_ANCHORS", raising=False)
    assert policy_from_env() is None
    (tmp_path / "root.pem").write_bytes(pki.make_ca("Root").cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("NODETIDE_EIDAS_ANCHORS", str(tmp_path))
    policy = policy_from_env()
    assert len(policy.store.anchors) == 1 and policy.revocation_mode == "hard-fail"
    monkeypatch.setenv("NODETIDE_EIDAS_REVOCATION", "nonsense")
    with pytest.raises(ValueError):
        policy_from_env()
