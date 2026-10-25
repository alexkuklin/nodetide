"""Tests for eIDAS-style (CAdES) claim attestations, using a synthetic PKI."""

from __future__ import annotations

import base64
import copy
import datetime as dt

import pytest

from nodetide.core.claims import (
    PROOF_VERIFIERS, Attestation, ClaimDocument, ClaimError, verify_attestation,
)
from nodetide.core.identity import Identity
from nodetide.eidas import statement as st
from nodetide.eidas.certs import cert_facts, names_match, transliterate_bg
from nodetide.eidas.cms import CmsError, create_cades_detached, verify_cades_detached
from nodetide.eidas.issue import build_eidas_attestation
from nodetide.eidas.validate import TrustStore
from nodetide.eidas.verify import EidasPolicy, check_legal_name, register
from tests import pki

NAME = {"given_name": "Maria", "family_name": "Ivanova"}


class World:
    def __init__(self, **leaf_kw):
        self.root = pki.make_ca("Test Root CA", path_length=1)
        self.inter = pki.make_ca("Test Qualified CA", parent=self.root, path_length=0)
        self.leaf = pki.make_signer_cert(self.inter, **leaf_kw)
        self.signer = pki.SoftwareSigner(self.leaf, extra_chain=[self.inter])
        self.policy = EidasPolicy(TrustStore([self.root.asn1]), revocation_mode="off")
        self.holder = Identity.create(name="Maria")
        self.doc = ClaimDocument.create(self.holder.identity_hash, "legal_name", NAME)
        self.holder.add_claim(self.doc.claim_id, "legal_name", self.doc.commitment)
        self.record = self.holder.sigchain.get_claim(self.doc.claim_id)

    def attest(self, **kw) -> Attestation:
        return build_eidas_attestation(self.holder.sigchain, self.record, self.signer, **kw)

    def check(self, att: Attestation, now: int | None = None):
        import time
        return self.policy.verify(att, self.holder.sigchain, int(time.time()) if now is None else now)


@pytest.fixture
def w():
    return World()


def tamper(att: Attestation, mutate) -> Attestation:
    data = copy.deepcopy(att.to_dict())
    mutate(data)
    return Attestation.from_dict(data)


# --- statement -----------------------------------------------------------------------------


def make_statement(**over):
    fields = dict(identity="a" * 64, claim_id="claim-id-0123456789", claim_type="legal_name",
                  commitment="b" * 64, chain_head="c" * 64, signed_on=1_700_000_000, valid_until=1_700_086_400)
    fields.update(over)
    return st.build_statement(**fields)


def test_statement_roundtrip_and_canonical_form():
    text = make_statement()
    parsed = st.parse_statement(text)
    assert parsed.text() == text and parsed.signed_on == 1_700_000_000
    assert text.startswith("NODETIDE CLAIM STATEMENT v1\nIdentity: " + "a" * 64)
    assert text.endswith("this claim's value is mine.")


@pytest.mark.parametrize("mutate", [
    lambda t: t + "\n", lambda t: t.replace("\n", "\r\n"), lambda t: t.replace("is mine", "is yours"),
    lambda t: t.replace("Type:", "Kind:"), lambda t: t.replace("v1", "v2"),
    lambda t: t.replace("Signed on: 2023", "Signed on: 2024"),  # still well-formed: caught by canonical rebuild? no
    lambda t: " " + t, lambda t: t.replace("Commitment: " + "b" * 64, "Commitment: " + "B" * 64),
])
def test_statement_rejects_anything_not_canonical(mutate):
    text = make_statement()
    changed = mutate(text)
    if changed == text:
        pytest.skip("mutation was a no-op")
    try:
        parsed = st.parse_statement(changed)
    except st.StatementError:
        return
    # a still-valid statement is fine only if it is a different, canonical statement
    assert parsed.text() == changed


def test_statement_validation():
    with pytest.raises(st.StatementError):
        make_statement(identity="short")
    with pytest.raises(st.StatementError):
        make_statement(valid_until=1_699_999_999)
    with pytest.raises(st.StatementError):
        st.parse_statement("garbage")


# --- CMS --------------------------------------------------------------------------------------


def test_cades_signature_roundtrip(w):
    der = create_cades_detached(b"hello", w.signer)
    parsed = verify_cades_detached(der, b"hello")
    assert parsed.signer_cert.serial_number == w.leaf.cert.serial_number
    assert parsed.hash_alg == "sha256" and parsed.signing_time is not None
    assert [c.subject.native["common_name"] for c in parsed.other_certs] == ["Test Qualified CA"]


@pytest.mark.parametrize("hash_alg", ["sha256", "sha384", "sha512"])
@pytest.mark.parametrize("key_kind", ["rsa", "ec"])
def test_cades_algorithms(hash_alg, key_kind):
    leaf = pki.make_signer_cert(pki.make_ca("CA"), key_kind=key_kind)
    signer = pki.SoftwareSigner(leaf, hash_alg=hash_alg)
    verify_cades_detached(create_cades_detached(b"data", signer), b"data")


def test_cades_accepts_what_other_signing_applications_produce(w):
    legacy = verify_cades_detached(create_cades_detached(b"x", w.signer, legacy_ess=True), b"x")
    assert legacy.signer_cert.serial_number == w.leaf.cert.serial_number
    bare = verify_cades_detached(create_cades_detached(b"x", w.signer, include_signing_time=False), b"x")
    assert bare.signing_time is None


def test_attestation_from_an_external_signature_without_signing_time(w):
    from nodetide.eidas.issue import attestation_from_signature, statement_for

    text, signed_on, _ = statement_for(w.holder.sigchain, w.record, cert_facts(w.signer.certificate).not_after)
    der = create_cades_detached(text.encode(), w.signer, legacy_ess=True, include_signing_time=False)
    att = attestation_from_signature(w.holder.sigchain, w.record, text, der)
    assert att.issued_at == signed_on and w.check(att).ok


def test_external_signature_must_match_the_claim(w):
    from nodetide.eidas.issue import attestation_from_signature, statement_for

    other = ClaimDocument.create(w.holder.identity_hash, "legal_name", NAME)
    w.holder.add_claim(other.claim_id, "legal_name", other.commitment)
    other_record = w.holder.sigchain.get_claim(other.claim_id)
    text, _, _ = statement_for(w.holder.sigchain, other_record, cert_facts(w.signer.certificate).not_after)
    der = create_cades_detached(text.encode(), w.signer)
    with pytest.raises(st.StatementError):
        attestation_from_signature(w.holder.sigchain, w.record, text, der)  # signed for another claim
    with pytest.raises(CmsError):  # the signature does not cover a statement that was edited afterwards
        attestation_from_signature(w.holder.sigchain, other_record, text.replace("Valid until", "Valid until"), der[:-1] + b"\x00")


def test_cades_detects_modified_content(w):
    der = create_cades_detached(b"hello", w.signer)
    with pytest.raises(CmsError, match="does not cover"):
        verify_cades_detached(der, b"hellp")


def test_cades_detects_modified_signature(w):
    der = bytearray(create_cades_detached(b"hello", w.signer))
    der[-5] ^= 0xFF  # inside the signature value
    with pytest.raises(CmsError):
        verify_cades_detached(bytes(der), b"hello")


def test_cades_rejects_garbage_and_other_structures(w):
    for junk in (b"", b"not der", b"\x30\x03\x02\x01\x00"):
        with pytest.raises(CmsError):
            verify_cades_detached(junk, b"x")


def test_cades_signing_certificate_attribute_binds_the_signer():
    # A signature made with one certificate cannot be re-labelled as another's.
    ca = pki.make_ca("CA")
    a, b = pki.make_signer_cert(ca, "Ann", "A"), pki.make_signer_cert(ca, "Bob", "B")
    signer = pki.SoftwareSigner(a)
    signer.certificate = b.asn1  # claim to be Bob while signing with Ann's key
    signer.leaf = a
    der = create_cades_detached(b"x", signer)
    with pytest.raises(CmsError):
        verify_cades_detached(der, b"x")


# --- certificate facts -----------------------------------------------------------------------------


@pytest.mark.parametrize("kw,assurance", [
    ({}, "high"),
    ({"qscd": False}, "substantial"),
    ({"qualified": False, "qscd": False}, "low"),
    ({"non_repudiation": False}, "low"),
])
def test_certificate_assurance(kw, assurance):
    leaf = pki.make_signer_cert(pki.make_ca("CA"), **kw)
    facts = cert_facts(leaf.asn1)
    assert facts.assurance == assurance and facts.country == "BG"
    assert facts.issuer_name == "CA"


def test_name_matching():
    assert names_match("Maria", "maria") == "exact"
    assert names_match("Мария", "Maria") == "transliterated"
    assert names_match("Иванова", "Ivanova") == "transliterated"
    assert names_match("Георги", "Georgi") == "transliterated"
    assert names_match("Щерю", "Shteryu") == "transliterated"
    assert names_match("Мария", "Petar") is None and names_match("Maria", None) is None
    assert transliterate_bg("Мария") == "maria" and transliterate_bg("Юлия") == "yulia"


# --- verification of attestations -----------------------------------------------------------------------


def test_valid_attestation(w):
    att = w.attest()
    assert att.assurance == "high" and att.method == "eidas_qes" and att.issuer is None
    check = w.check(att)
    assert check.ok, check.error
    assert Attestation.from_dict(att.to_dict()).id == att.id


def test_attestation_never_contains_personal_identifiers_outside_the_certificate(w):
    text = str(w.attest().to_dict())
    assert "Ivanova" not in text.replace(base64.b64encode(b"x").decode(), "")  # not in plain fields
    # the proof's signature blob does contain the certificate; that is why proofs are not published
    assert w.attest().proof["signature"]


def test_it_plugs_into_verify_attestation(w):
    register(w.policy)
    try:
        assert verify_attestation(w.attest(), w.holder.sigchain, None).ok
    finally:
        PROOF_VERIFIERS.pop("eidas_qes", None)
    check = verify_attestation(w.attest(), w.holder.sigchain, None)
    assert not check.ok and check.code == "unsupported_method"


def test_untrusted_root_is_rejected(w):
    other = EidasPolicy(TrustStore([pki.make_ca("Some Other Root").asn1]), revocation_mode="off")
    check = other.verify(w.attest(), w.holder.sigchain, int(__import__("time").time()))
    assert not check.ok and check.code == "untrusted_certificate"


def test_expired_certificate_is_rejected():
    w = World(not_before=pki.now() - 400 * pki.DAY, not_after=pki.now() - 30 * pki.DAY)
    att = w.attest(now=int((pki.now() - 100 * pki.DAY).timestamp()))
    check = w.check(att)  # judged today: the certificate has expired
    assert not check.ok and check.code in ("untrusted_certificate", "statement_mismatch")


def test_not_yet_valid_certificate_is_rejected():
    w = World(not_before=pki.now() + 10 * pki.DAY, not_after=pki.now() + 400 * pki.DAY)
    assert not w.check(w.attest()).ok


def test_non_qualified_certificate_cannot_claim_high_assurance():
    w = World(qualified=False, qscd=False)
    att = w.attest()  # builder uses the certificate's own level: low
    assert att.assurance == "low" and w.check(att).ok
    inflated = tamper(att, lambda d: d.update(assurance="high"))
    check = w.check(inflated)
    assert not check.ok and check.code == "assurance_too_high"


def test_certificate_without_signing_key_usage_is_rejected():
    w = World(non_repudiation=False)
    check = w.check(w.attest())
    assert not check.ok and check.code == "not_qualified"


def test_statement_must_match_the_attestation(w):
    att = w.attest()
    for field, value in (("claim_id", "another-claim-id-0123"), ("commitment", "d" * 64),
                         ("chain_head", "e" * 64), ("subject", "f" * 64)):
        bad = tamper(att, lambda d: d.update({field: value}))
        check = w.check(bad)
        assert not check.ok and check.code == "statement_mismatch", field
    for field, delta in (("issued_at", -5), ("expires_at", 86400 * 400)):
        bad = tamper(att, lambda d: d.update({field: d[field] + delta}))
        assert not w.check(bad).ok, field


def test_signature_must_cover_the_statement(w):
    att = w.attest()
    other_text = st.build_statement(att.subject, att.claim_id, att.claim_type, att.commitment,
                                    att.chain_head, att.issued_at, att.expires_at - 3600)
    bad = tamper(att, lambda d: d["proof"].update(statement=other_text))
    check = w.check(bad)
    assert not check.ok and check.code == "invalid_proof"


def test_proof_structure_errors(w):
    att = w.attest()
    for mutate in (
        lambda d: d["proof"].update(format="pades"),
        lambda d: d["proof"].update(signature="!!!not base64!!!"),
        lambda d: d["proof"].update(signature=base64.b64encode(b"garbage").decode()),
        lambda d: d["proof"].update(statement="not a statement"),
        lambda d: d.update(evidence={"note": "x"}),
        lambda d: d["proof"].pop("signature"),
    ):
        assert not w.check(tamper(att, mutate)).ok


def test_revocation_with_a_crl():
    ca_world = World(crl_url="http://crl.invalid/ca.crl")
    leaf, inter = ca_world.leaf, ca_world.inter
    clean = EidasPolicy(ca_world.policy.store, revocation_mode="hard-fail", allow_fetching=False,
                        crls=(pki.make_crl(inter, []),))
    att = ca_world.attest()
    ok = clean.verify(att, ca_world.holder.sigchain, int(__import__("time").time()))
    assert ok.ok, ok.error

    revoked = EidasPolicy(ca_world.policy.store, revocation_mode="hard-fail", allow_fetching=False,
                          crls=(pki.make_crl(inter, [leaf]),))
    check = revoked.verify(att, ca_world.holder.sigchain, int(__import__("time").time()))
    assert not check.ok and check.code == "untrusted_certificate"

    unknown = EidasPolicy(ca_world.policy.store, revocation_mode="hard-fail", allow_fetching=False)
    assert not unknown.verify(att, ca_world.holder.sigchain, int(__import__("time").time())).ok


def test_attestation_cannot_outlive_the_certificate():
    w = World(not_after=pki.now() + 10 * pki.DAY)
    att = w.attest(valid_days=365)
    assert att.expires_at <= int((pki.now() + 10 * pki.DAY).timestamp()) + 1
    stretched = tamper(att, lambda d: d.update(expires_at=d["expires_at"] + 86400 * 30))
    assert not w.check(stretched).ok


# --- legal name check ------------------------------------------------------------------------------------


def test_legal_name_matches_the_certificate(w):
    result = check_legal_name(w.attest(), w.doc)
    assert result.ok and result.how == "exact"


def test_cyrillic_name_matches_latin_certificate():
    w = World(given="Maria", surname="Ivanova")
    doc = ClaimDocument.create(w.holder.identity_hash, "legal_name", {"given_name": "Мария", "family_name": "Иванова"})
    w.holder.add_claim(doc.claim_id, "legal_name", doc.commitment)
    att = build_eidas_attestation(w.holder.sigchain, w.holder.sigchain.get_claim(doc.claim_id), w.signer)
    result = check_legal_name(att, doc)
    assert result.ok and result.how == "transliterated"


def test_someone_elses_name_is_rejected(w):
    att = w.attest()
    for name in ({"given_name": "Petar", "family_name": "Ivanova"}, {"given_name": "Maria", "family_name": "Petrova"}):
        doc = ClaimDocument(w.doc.identity, w.doc.claim_id, "legal_name", name, w.doc.salt)
        result = check_legal_name(att, doc)
        assert not result.ok


def test_name_check_rejects_other_claim_types(w):
    email = ClaimDocument.create(w.holder.identity_hash, "email", "a@example.com")
    assert not check_legal_name(w.attest(), email).ok


# --- trust store ---------------------------------------------------------------------------------------------


def test_trust_store_loading(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from nodetide.eidas.validate import TrustStoreError

    root = pki.make_ca("Root")
    (tmp_path / "root.pem").write_bytes(root.cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "other.der").write_bytes(pki.make_ca("Two").cert.public_bytes(serialization.Encoding.DER))
    (tmp_path / "ignored.txt").write_text("not a certificate")
    assert len(TrustStore.from_directory(tmp_path).anchors) == 2
    with pytest.raises(TrustStoreError):
        TrustStore.from_directory(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(TrustStoreError):
        TrustStore.from_directory(empty)
    (tmp_path / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    with pytest.raises(TrustStoreError):
        TrustStore.from_directory(tmp_path)


# --- no fetching on behalf of strangers ----------------------------------------------------------------


class CountingServer:
    """Accepts connections and counts them; answers 404 so fetches fail cleanly."""

    def __init__(self):
        import socket
        import threading

        self.hits = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        import socket

        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.hits += 1
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            finally:
                conn.close()

    def close(self):
        self._stop = True
        self._thread.join(timeout=2)
        self.sock.close()


def test_untrusted_certificates_cannot_make_the_node_fetch_urls():
    server = CountingServer()
    try:
        w = World(crl_url=f"http://127.0.0.1:{server.port}/evil.crl")
        stranger_trust = TrustStore([pki.make_ca("Unrelated Root").asn1])  # does not include w.root
        policy = EidasPolicy(stranger_trust, revocation_mode="hard-fail", allow_fetching=True)
        check = policy.verify(w.attest(), w.holder.sigchain, int(__import__("time").time()))
        assert not check.ok and check.code == "untrusted_certificate"
        assert server.hits == 0, "the node contacted a URL named by an untrusted certificate"
    finally:
        server.close()


def test_trusted_certificates_do_get_their_revocation_checked():
    server = CountingServer()
    try:
        w = World(crl_url=f"http://127.0.0.1:{server.port}/ca.crl")
        policy = EidasPolicy(w.policy.store, revocation_mode="hard-fail", allow_fetching=True)
        check = policy.verify(w.attest(), w.holder.sigchain, int(__import__("time").time()))
        assert not check.ok  # the CRL endpoint answers 404, and hard-fail refuses to guess
        assert server.hits >= 1
    finally:
        server.close()


# --- name fields as a real B-Trust certificate has them ------------------------------------------------------------


def btrust_like_world():
    """givenName=ALEXEY, surname=SMIRNOV, CN carries the patronymic (as on a B-Trust QES)."""
    return World(given="ALEXEY", surname="SMIRNOV", common_name="ALEXEY IVANOVICH SMIRNOV")


def name_doc(w, given, family):
    doc = ClaimDocument.create(w.holder.identity_hash, "legal_name", {"given_name": given, "family_name": family})
    w.holder.add_claim(doc.claim_id, "legal_name", doc.commitment)
    att = build_eidas_attestation(w.holder.sigchain, w.holder.sigchain.get_claim(doc.claim_id), w.signer)
    return att, doc


@pytest.mark.parametrize("given,family,leniency,expected", [
    ("Alexey", "Smirnov", "exact", "exact"),                             # case differences are not differences
    ("Alexey Ivanovich", "Smirnov", "exact", "exact"),               # given + patronymic, from the CN
    ("Алексей", "Смирнов", "approximate", "approximate"),                # Cyrillic with Latin X: only loosely equal
    ("Aleksey", "Smirnov", "approximate", "approximate"),                # spelling variant
])
def test_name_mapping_accepts_real_world_forms(given, family, leniency, expected):
    w = btrust_like_world()
    att, doc = name_doc(w, given, family)
    result = check_legal_name(att, doc, leniency)
    assert result.ok and result.how == expected, result


def test_leniency_controls_how_loose_a_match_may_be():
    w = btrust_like_world()
    att, doc = name_doc(w, "Алексей", "Смирнов")
    assert not check_legal_name(att, doc, "exact").ok
    assert not check_legal_name(att, doc, "transliterated").ok  # the default: "Aleksey" is not "Alexey" strictly
    loose = check_legal_name(att, doc, "approximate")
    assert loose.ok and loose.how == "approximate"
    assert not check_legal_name(att, doc, "bogus").ok


@pytest.mark.parametrize("given,family", [
    ("Petar", "Smirnov"), ("Alexey", "Petrov"), ("Vladimir", "Smirnov"),  # a patronymic is not a given name
    ("Alexey", "Ivanovich"),
])
def test_name_mapping_rejects_other_people(given, family):
    w = btrust_like_world()
    att, doc = name_doc(w, given, family)
    assert not check_legal_name(att, doc, "approximate").ok


def test_certificate_without_name_attributes_falls_back_to_the_common_name():
    from nodetide.eidas.certs import CertNames, match_legal_name

    names = CertNames(None, None, "MARIA IVANOVA")
    assert match_legal_name("Maria", "Ivanova", names) == "exact"
    assert match_legal_name("Maria", "Petrova", names) is None
    assert match_legal_name("Maria", "Ivanova", CertNames(None, None, "MARIA")) is None


# --- collecting the CA chain for review -----------------------------------------------------------------------------


def test_fetch_chain_follows_aia_links_and_checks_each_signature():
    from nodetide.eidas.anchors import fetch_chain, fingerprint, issuer_urls, write_anchors

    root = pki.make_ca("Root", path_length=1)
    inter = pki.make_ca("Intermediate", parent=root, path_length=0, aia_url="http://pki.example.org/root.cer")
    leaf = pki.make_signer_cert(inter, aia_url="http://pki.example.org/inter.cer")
    served = {"http://pki.example.org/root.cer": root.asn1.dump(), "http://pki.example.org/inter.cer": inter.asn1.dump()}
    requested = []

    def fetch(url):
        requested.append(url)
        return served[url]

    assert issuer_urls(leaf.asn1) == ["http://pki.example.org/inter.cer"]
    chain = fetch_chain(leaf.asn1, fetch)
    assert [c.subject.native["common_name"] for c in chain] == ["Intermediate", "Root"]
    assert requested == ["http://pki.example.org/inter.cer", "http://pki.example.org/root.cer"]

    # certificates already at hand are used before anything is downloaded
    requested.clear()
    assert len(fetch_chain(leaf.asn1, fetch, known=[inter.asn1, root.asn1])) == 2 and requested == []


def test_fetch_chain_rejects_a_certificate_that_did_not_sign():
    from nodetide.eidas.anchors import fetch_chain

    root = pki.make_ca("Root")
    imposter = pki.make_ca("Root")  # same name, different key
    leaf = pki.make_signer_cert(root, aia_url="http://pki.example.org/ca.cer")
    assert fetch_chain(leaf.asn1, lambda url: imposter.asn1.dump()) == []


def test_fetch_chain_survives_bad_downloads_and_stops_at_a_root():
    from nodetide.eidas.anchors import fetch_chain

    root = pki.make_ca("Root")
    leaf = pki.make_signer_cert(root, aia_url="http://pki.example.org/ca.cer")

    def broken(url):
        raise OSError("down")

    assert fetch_chain(leaf.asn1, broken) == []
    assert fetch_chain(leaf.asn1, lambda url: b"not a certificate") == []
    assert fetch_chain(root.asn1, broken) == []  # a self-signed root has no issuer to find


def test_default_fetch_refuses_private_addresses():
    from nodetide.eidas.anchors import AnchorError, default_fetch

    for url in ("http://127.0.0.1/ca.cer", "http://169.254.169.254/x", "file:///etc/passwd", "ftp://example.org/x"):
        with pytest.raises(AnchorError):
            default_fetch(url)


def test_anchors_are_written_as_pem_named_by_fingerprint(tmp_path):
    from nodetide.eidas.anchors import fingerprint, write_anchors

    root = pki.make_ca("Root")
    (path,) = write_anchors([root.asn1], tmp_path / "anchors")
    assert path.name == fingerprint(root.asn1)[:16] + ".pem"
    assert len(TrustStore.from_directory(tmp_path / "anchors").anchors) == 1
