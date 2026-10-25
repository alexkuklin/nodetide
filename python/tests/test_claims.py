"""Tests for claims on the sigchain, commitments, attestations and trust delegation."""

from __future__ import annotations

import time

import pytest

from nodetide.core.claims import (
    Attestation,
    AttestationRevocation,
    ClaimDocument,
    ClaimError,
    compute_commitment,
    normalize_value,
    verify_attestation,
    verify_revocation,
)
from nodetide.core.identity import DeviceCapability, Identity, IdentityType, Sigchain
from nodetide.core.storage import Storage
from nodetide.core.trust import TrustDelegation, TrustGraph

D = DeviceCapability


def holder_with_claim(claim_type="email", value="alice@example.com"):
    holder = Identity.create(name="Alice")
    doc = ClaimDocument.create(holder.identity_hash, claim_type, value)
    holder.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
    return holder, doc


def make_issuer(caps=(D.SIGN_IDENTITY,)):
    issuer = Identity.create(identity_type=IdentityType.ORGANIZATION, name="Verifier Inc")
    device, _ = issuer.add_device("signer", capabilities=list(caps))
    return issuer, device


def issue(issuer, device, holder, doc, **kw):
    record = holder.sigchain.get_claim(doc.claim_id)
    return Attestation.issue(
        issuer.identity_hash, device, holder.identity_hash, record,
        chain_head=kw.pop("chain_head", holder.sigchain.head_hash),
        method=kw.pop("method", "email_code"), assurance=kw.pop("assurance", "low"), **kw)


# --- values and commitments ------------------------------------------------------------


@pytest.mark.parametrize("claim_type,raw,expected", [
    ("email", "  Alice@Example.COM ", "Alice@example.com"),
    ("email", "bob@BÜCHER.example", "bob@xn--bcher-kva.example"),
    ("phone", "+359 88 123-4567", "+359881234567"),
    ("phone", "+1 (415) 555.0100", "+14155550100"),
    ("legal_name", {"given_name": " Мария ", "family_name": "Иванова"},
     {"given_name": "Мария", "family_name": "Иванова"}),
])
def test_normalize_value(claim_type, raw, expected):
    assert normalize_value(claim_type, raw) == expected


@pytest.mark.parametrize("claim_type,raw", [
    ("email", "no-at-sign"), ("email", "a@b"), ("email", "a b@example.com"), ("email", 5),
    ("email", "a@-bad.example"), ("phone", "0881234567"), ("phone", "+0123456789"),
    ("phone", "+123"), ("legal_name", "Alice"), ("legal_name", {"given_name": "A"}),
    ("legal_name", {"given_name": "A", "family_name": "B", "extra": "x"}),
    ("legal_name", {"given_name": "", "family_name": "B"}),
    ("nonsense", "x"), ("x-Bad:Type", "x"),
])
def test_normalize_rejects(claim_type, raw):
    with pytest.raises(ClaimError):
        normalize_value(claim_type, raw)


def test_unicode_is_normalized_before_hashing():
    composed = "é"  # é as one code point
    decomposed = "é"
    a = normalize_value("legal_name", {"given_name": composed, "family_name": "X"})
    b = normalize_value("legal_name", {"given_name": decomposed, "family_name": "X"})
    assert a == b


def test_commitment_known_answers():
    """Pinned test vectors: another implementation must produce exactly these."""
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert compute_commitment("claim-id-0123456789", "email", salt, "alice@example.com") == (
        "1128902e28663ab251eb8b6a1eebb1ef3e392b19b9068cecbe724b338b318251"
    )
    name = {"given_name": "Мария", "family_name": "Иванова"}
    assert compute_commitment("claim-id-0123456789", "legal_name", salt, name) == (
        "9e79db383f30f69fb0be0bb76dd4e94849e0dd998d6bc51ebee761d02f1e0f9a"
    )


def test_commitment_depends_on_everything():
    salt = bytes(range(16))
    base = compute_commitment("claim-id-0123456789", "email", salt, "a@example.com")
    assert base == compute_commitment("claim-id-0123456789", "email", salt, " a@Example.COM ")  # domain case, spaces
    assert base != compute_commitment("claim-id-0123456780", "email", salt, "a@example.com")
    assert base != compute_commitment("claim-id-0123456789", "email", bytes(16), "a@example.com")
    assert base != compute_commitment("claim-id-0123456789", "email", salt, "b@example.com")
    assert base != compute_commitment("claim-id-0123456789", "x-acme:email", salt, "a@example.com")


def test_document_roundtrip_and_validation():
    holder, doc = holder_with_claim()
    again = ClaimDocument.from_dict(doc.to_dict())
    assert again.commitment == doc.commitment
    for broken in ({**doc.to_dict(), "salt": "zz"}, {**doc.to_dict(), "claim_id": "short"},
                   {**doc.to_dict(), "identity": "nope"}, {**doc.to_dict(), "value": "bad"}):
        with pytest.raises(ClaimError):
            ClaimDocument.from_dict(broken)
    with pytest.raises(ClaimError):
        ClaimDocument.from_dict({"identity": doc.identity})


def test_document_matches_only_its_own_record():
    holder, doc = holder_with_claim()
    record = holder.sigchain.get_claim(doc.claim_id)
    assert doc.matches(record)
    other = ClaimDocument(doc.identity, doc.claim_id, doc.claim_type, "other@example.com", doc.salt)
    assert not other.matches(record)
    assert not doc.matches(None)


# --- claim events on the chain --------------------------------------------------------------


def test_claim_lifecycle_on_chain():
    holder, doc = holder_with_claim()
    record = holder.sigchain.get_claim(doc.claim_id)
    assert record.claim_type == "email" and record.status() == "active"
    assert holder.sigchain.verify() == (True, None)

    holder.revoke_claim(doc.claim_id, reason="changed address")
    record = holder.sigchain.get_claim(doc.claim_id)
    assert record.status() == "revoked" and record.revoke_reason == "changed address"
    assert holder.sigchain.verify() == (True, None)


def test_claim_expiry():
    holder = Identity.create()
    doc = ClaimDocument.create(holder.identity_hash, "phone", "+359881234567")
    holder.add_claim(doc.claim_id, "phone", doc.commitment, expires=int(time.time()) + 100)
    record = holder.sigchain.get_claim(doc.claim_id)
    assert record.status() == "active" and record.status(int(time.time()) + 200) == "expired"


def test_chain_roundtrips_through_serialization_and_storage():
    holder, doc = holder_with_claim()
    again = Sigchain.from_list(holder.sigchain.to_list())
    assert again.verify() == (True, None) and again.head_hash == holder.sigchain.head_hash
    storage = Storage.memory()
    storage.save_sigchain(holder.sigchain)
    assert storage.get_sigchain(holder.identity_hash).get_claim(doc.claim_id).commitment == doc.commitment


def test_device_with_manage_claims_may_add_claims():
    holder = Identity.create()
    device, _ = holder.add_device("phone", capabilities=[D.MANAGE_CLAIMS])
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment, signer=device)
    holder.revoke_claim(doc.claim_id, signer=device)
    assert holder.sigchain.verify() == (True, None)


def test_device_without_manage_claims_is_rejected():
    holder = Identity.create()
    device, _ = holder.add_device("phone", capabilities=[D.SIGN_MESSAGES])
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment, signer=device)
    ok, err = holder.sigchain.verify()
    assert not ok and "manage claims" in err


def test_unknown_and_revoked_devices_are_rejected():
    holder = Identity.create()
    stranger = Identity.create()
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment, signer=stranger.local_keypair)
    assert not holder.sigchain.verify()[0]

    holder = Identity.create()
    device, _ = holder.add_device("phone", capabilities=[D.MANAGE_CLAIMS])
    holder.revoke_device(device.verify_key.to_hex())
    holder.add_claim(doc.claim_id, "email", doc.commitment, signer=device)
    assert not holder.sigchain.verify()[0]


def test_old_master_cannot_add_claims_after_rotation():
    holder = Identity.create()
    old = holder.local_keypair
    holder.rotate_master()
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment, signer=old)
    assert not holder.sigchain.verify()[0]


def test_duplicate_and_orphan_claim_events_are_rejected():
    holder, doc = holder_with_claim()
    holder.add_claim(doc.claim_id, "email", doc.commitment)  # same id again
    assert "duplicate" in holder.sigchain.verify()[1]

    holder, doc = holder_with_claim()
    holder.revoke_claim("never-existed-0123456789")
    assert "unknown claim" in holder.sigchain.verify()[1]

    holder, doc = holder_with_claim()
    holder.revoke_claim(doc.claim_id)
    holder.revoke_claim(doc.claim_id)
    assert "already revoked" in holder.sigchain.verify()[1]


def test_tampered_claim_event_breaks_the_chain():
    holder, doc = holder_with_claim()
    events = holder.sigchain.to_list()
    events[1]["commitment"] = "0" * 64
    assert not Sigchain.from_list(events).verify()[0]


# --- attestations ----------------------------------------------------------------------------------


def test_valid_attestation():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    assert verify_attestation(att, holder.sigchain, issuer.sigchain).ok
    assert Attestation.from_dict(att.to_dict()).id == att.id  # stable content id


def test_attestation_needs_the_issuers_chain():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    check = verify_attestation(att, holder.sigchain, None)
    assert not check.ok and check.code == "unknown_issuer"
    other, _ = make_issuer()
    check = verify_attestation(att, holder.sigchain, other.sigchain)
    assert not check.ok and check.code == "issuer_mismatch"


def test_issuer_master_key_and_wrong_capability_are_rejected():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, issuer.local_keypair, holder, doc)
    assert verify_attestation(att, holder.sigchain, issuer.sigchain).code == "issuer_key_not_authorized"

    weak_issuer, weak_device = make_issuer(caps=(D.SIGN_MESSAGES,))
    att = issue(weak_issuer, weak_device, holder, doc)
    assert verify_attestation(att, holder.sigchain, weak_issuer.sigchain).code == "issuer_key_not_authorized"


def test_revoked_issuer_device_invalidates_its_attestations():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    issuer.revoke_device(device.verify_key.to_hex(), reason="key leaked")
    assert verify_attestation(att, holder.sigchain, issuer.sigchain).code == "issuer_key_not_authorized"


@pytest.mark.parametrize("field,value", [
    ("assurance", "high"), ("method", "manual"), ("evidence", {"extra": 1}),
    ("expires_at", 2**40), ("chain_head", "f" * 64),
])
def test_any_tampering_breaks_the_signature(field, value):
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    data = issue(issuer, device, holder, doc).to_dict()
    data[field] = value
    try:
        att = Attestation.from_dict(data)
    except ClaimError:
        return  # rejected even earlier
    check = verify_attestation(att, holder.sigchain, issuer.sigchain)
    assert not check.ok and check.code in ("bad_signature", "unknown_chain_head")


def test_attestation_for_a_different_commitment_is_rejected():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    data = issue(issuer, device, holder, doc).to_dict()
    other_doc = ClaimDocument(doc.identity, doc.claim_id, "email", "mallory@example.com", doc.salt)
    data["commitment"] = other_doc.commitment
    check = verify_attestation(Attestation.from_dict(data), holder.sigchain, issuer.sigchain)
    assert check.code == "claim_mismatch"


def test_attestation_stops_counting_when_claim_is_revoked_or_expired():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    assert verify_attestation(att, holder.sigchain, issuer.sigchain).ok
    assert verify_attestation(att, holder.sigchain, issuer.sigchain, now=att.expires_at + 1).code == "expired"
    holder.revoke_claim(doc.claim_id)
    check = verify_attestation(att, holder.sigchain, issuer.sigchain)
    assert not check.ok and check.code == "claim_revoked"


def test_unknown_claim_and_wrong_subject():
    holder, doc = holder_with_claim()
    other, other_doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    assert verify_attestation(att, other.sigchain, issuer.sigchain).code == "subject_mismatch"
    data = att.to_dict()
    data["claim_id"] = other_doc.claim_id
    check = verify_attestation(Attestation.from_dict(data), holder.sigchain, issuer.sigchain)
    assert check.code == "unknown_claim"


def test_stale_subject_chain_is_reported_not_rejected_outright():
    holder, doc = holder_with_claim()
    stale = Sigchain(events=list(holder.sigchain.events))
    holder.add_device("laptop")  # the issuer saw this newer state
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    check = verify_attestation(att, stale, issuer.sigchain)
    assert check.code == "unknown_chain_head"
    assert verify_attestation(att, holder.sigchain, issuer.sigchain).ok


def test_attestation_structure_validation():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    good = issue(issuer, device, holder, doc).to_dict()
    for broken in (
        {**good, "assurance": "ultra"}, {**good, "claim_type": "nonsense"},
        {**good, "expires_at": good["issued_at"]}, {**good, "type": "OTHER"},
        {**good, "evidence": {"x": 1.5}}, {k: v for k, v in good.items() if k != "sig"},
        {**good, "subject": "short"}, {**good, "proof": {"a": 1}},
    ):
        with pytest.raises(ClaimError):
            Attestation.from_dict(broken)


def test_attestation_revocation():
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    rev = AttestationRevocation.create(issuer.identity_hash, device, att.id, "claim was wrong")
    assert verify_revocation(AttestationRevocation.from_dict(rev.to_dict()), issuer.sigchain).ok

    forged = AttestationRevocation.create(issuer.identity_hash, holder.local_keypair, att.id)
    assert not verify_revocation(forged, issuer.sigchain).ok
    tampered = AttestationRevocation.from_dict({**rev.to_dict(), "attestation_id": "a" * 64})
    assert verify_revocation(tampered, issuer.sigchain).code == "bad_signature"


def test_domain_separation_between_object_kinds():
    """An attestation signature must not verify as a revocation, or vice versa."""
    holder, doc = holder_with_claim()
    issuer, device = make_issuer()
    att = issue(issuer, device, holder, doc)
    rev = AttestationRevocation.create(issuer.identity_hash, device, att.id)
    assert att.signing_input()[:19] != rev.signing_input()[:19]
    assert not device.verify_key.verify_hex(rev.signing_input(), att.sig)


# --- trust delegation -----------------------------------------------------------------------------------


def graph(*delegations):
    g = TrustGraph(my_identity="me")
    for d in delegations:
        g.add_delegation(TrustDelegation(*d[:3], **(d[3] if len(d) > 3 else {})))
    return g


def test_trust_paths_multiply_and_best_wins():
    g = graph(("me", "a", 0.6), ("a", "issuer", 0.9), ("me", "c", 0.8), ("c", "issuer", 0.7))
    result = g.calculate_trust("issuer")
    assert result.trust_score == pytest.approx(0.56)
    assert len(result.paths) == 2 and result.paths[0].combined_score >= result.paths[1].combined_score


def test_trust_scope_filters_delegations():
    g = graph(("me", "issuer", 0.9, {"scope": ["email"]}))
    assert g.calculate_trust("issuer", "email").trust_score == pytest.approx(0.9)
    assert g.calculate_trust("issuer", "legal_name").trust_score == 0.0
    assert g.calculate_trust("issuer").trust_score == pytest.approx(0.9)  # no claim type asked


def test_trust_depth_limits():
    chain = [("me", "a", 1.0), ("a", "b", 1.0), ("b", "issuer", 1.0)]
    assert graph(*chain).calculate_trust("issuer", max_depth=3).trust_score == 1.0
    assert graph(*chain).calculate_trust("issuer", max_depth=2).trust_score == 0.0
    # a delegation's depth_limit caps how far trust continues beyond its delegate
    limited = [("me", "a", 1.0, {"depth_limit": 1}), ("a", "b", 1.0), ("b", "issuer", 1.0)]
    assert graph(*limited).calculate_trust("issuer", max_depth=5).trust_score == 0.0
    assert graph(*limited).calculate_trust("b", max_depth=5).trust_score == 1.0


def test_trust_cycles_and_self():
    g = graph(("me", "a", 1.0), ("a", "me", 1.0), ("a", "a", 1.0))
    assert g.calculate_trust("nobody").trust_score == 0.0
    assert g.calculate_trust("me").trust_score == 1.0


def test_delegation_validation_and_storage_roundtrip():
    with pytest.raises(ValueError):
        TrustDelegation("a", "b", 1.5)
    with pytest.raises(ValueError):
        TrustDelegation("a", "b", 0.5, scope=["ok", 3])
    storage = Storage.memory()
    storage.save_trust_delegation("a", "b", 0.7, 1, depth_limit=2, scope=["email"])
    storage.save_trust_delegation("a", "c", 0.2, 1)
    rows = {r["to_identity"]: r for r in storage.get_trust_delegations("a")}
    assert rows["b"]["scope"] == ["email"] and rows["b"]["depth_limit"] == 2
    assert rows["c"]["scope"] is None
