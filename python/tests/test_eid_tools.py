"""Tests for the PKCS#11 signer (against a fake token) and the claim / eid CLI."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from nodetide.cli.main import cli
from nodetide.core.claims import ClaimDocument
from nodetide.core.identity import Identity
from nodetide.eidas.cms import create_cades_detached, verify_cades_detached
from nodetide.eidas.issue import build_eidas_attestation
from nodetide.eidas.pkcs11 import Pkcs11Error, Pkcs11Signer, find_module
from tests import pki
from tests.test_eidas import NAME, World

PIN = "4242-secret"


# --- a fake PKCS#11 stack ----------------------------------------------------------------------------------


class FakePk11:
    CKF_SERIAL_SESSION = 4
    CKA_CLASS, CKA_VALUE, CKA_ID, CKA_LABEL = 0, 0x11, 0x102, 3
    CKO_CERTIFICATE, CKO_PRIVATE_KEY = 1, 3
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS = 0x40, 0x41, 0x42
    CKM_RSA_PKCS, CKM_ECDSA = 1, 0x1041
    CKR_MECHANISM_INVALID, CKR_PIN_INCORRECT, CKR_PIN_LOCKED = 0x70, 0xA0, 0xA4
    CKR_USER_NOT_LOGGED_IN, CKR_USER_ALREADY_LOGGED_IN = 0x101, 0x100

    class PyKCS11Error(Exception):
        def __init__(self, value):
            super().__init__(f"PKCS#11 error {value}")
            self.value = value

    class Mechanism:
        def __init__(self, mechanism, param):
            self.mechanism = mechanism

    def __init__(self, certs, token_hashes=True):
        """certs: list of (asn1 cert DER, key id bytes, label, private key or None)."""
        self.certs, self.token_hashes = certs, token_hashes
        self.signed_with: list[int] = []
        outer = self

        class Lib:
            def load(self, path):
                outer.loaded = path

            def getSlotList(self, tokenPresent=True):
                return [0] if outer.certs is not None else []

            def openSession(self, slot, flags):
                return FakeSession(outer)

        self.PyKCS11Lib = Lib


class FakeSession:
    def __init__(self, pk11: FakePk11):
        self.pk11, self.logged_in = pk11, False

    def findObjects(self, template):
        template = dict(template)
        if template[0] == self.pk11.CKO_CERTIFICATE:
            return [("cert", i) for i in range(len(self.pk11.certs))]
        keys = [("key", i) for i, c in enumerate(self.pk11.certs) if c[3] is not None]
        if self.pk11.CKA_ID in template:
            wanted = bytes(template[self.pk11.CKA_ID])
            keys = [k for k in keys if self.pk11.certs[k[1]][1] == wanted]
        return keys

    def getAttributeValue(self, obj, attrs, allAsBinary=False):
        kind, index = obj
        der, key_id, label, _ = self.pk11.certs[index]
        values = {self.pk11.CKA_VALUE: der, self.pk11.CKA_ID: key_id, self.pk11.CKA_LABEL: label.encode()}
        return [values[a] for a in attrs]

    def login(self, pin):
        if pin != PIN:
            raise self.pk11.PyKCS11Error(self.pk11.CKR_PIN_INCORRECT)
        self.logged_in = True

    def logout(self):
        self.logged_in = False

    def closeSession(self):
        pass

    def sign(self, key, data, mechanism):
        if not self.logged_in:
            raise self.pk11.PyKCS11Error(self.pk11.CKR_USER_NOT_LOGGED_IN)
        private = self.pk11.certs[key[1]][3]
        m = mechanism.mechanism
        self.pk11.signed_with.append(m)
        names = {self.pk11.CKM_SHA256_RSA_PKCS: hashes.SHA256, self.pk11.CKM_SHA384_RSA_PKCS: hashes.SHA384,
                 self.pk11.CKM_SHA512_RSA_PKCS: hashes.SHA512}
        if m in names:
            if not self.pk11.token_hashes:
                raise self.pk11.PyKCS11Error(self.pk11.CKR_MECHANISM_INVALID)
            return list(private.sign(data, padding.PKCS1v15(), names[m]()))
        if m == self.pk11.CKM_RSA_PKCS:  # data is a DigestInfo: sign its digest
            digest = data[-32:]
            return list(private.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())))
        if m == self.pk11.CKM_ECDSA:  # data is the digest; answer in raw r||s form
            der = private.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            r, s = utils.decode_dss_signature(der)
            return list(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        raise self.pk11.PyKCS11Error(self.pk11.CKR_MECHANISM_INVALID)


def token_for(world: World, *, with_auth_cert=True, token_hashes=True, ec_key=False):
    ca = world.inter
    signing = world.leaf
    if ec_key:
        signing = pki.make_signer_cert(ca, key_kind="ec")
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    certs = [(der(signing.cert), b"\x01", "Signature", signing.key),
             (der(ca.cert), b"\xca", "CA", None),
             (der(world.root.cert), b"\xff", "Root", None)]
    if with_auth_cert:
        auth = pki.make_signer_cert(ca, non_repudiation=False)
        certs.insert(0, (der(auth.cert), b"\x02", "Authentication", auth.key))
    return FakePk11(certs, token_hashes), signing


# --- the signer -----------------------------------------------------------------------------------------------


def test_signer_selects_the_signing_certificate_and_builds_the_chain():
    world = World()
    pk11, _ = token_for(world)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pk11=pk11)
    assert signer.entry.label == "Signature" and signer.entry.usable_for_signing
    assert [c.subject.native["common_name"] for c in signer.chain] == ["Test Qualified CA"]  # no root


def test_a_token_signature_produces_a_valid_attestation():
    world = World()
    pk11, _ = token_for(world)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pin=PIN, pk11=pk11)
    att = build_eidas_attestation(world.holder.sigchain, world.record, signer)
    assert world.check(att).ok
    assert pk11.signed_with == [pk11.CKM_SHA256_RSA_PKCS]


def test_signer_falls_back_when_the_token_cannot_hash():
    world = World()
    pk11, _ = token_for(world, token_hashes=False)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pin=PIN, pk11=pk11)
    att = build_eidas_attestation(world.holder.sigchain, world.record, signer)
    assert world.check(att).ok
    assert pk11.signed_with == [pk11.CKM_SHA256_RSA_PKCS, pk11.CKM_RSA_PKCS]


def test_signer_with_an_ec_key():
    world = World()
    pk11, leaf = token_for(world, ec_key=True)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pin=PIN, pk11=pk11)
    der = create_cades_detached(b"data", signer)
    assert verify_cades_detached(der, b"data").signer_cert.serial_number == leaf.cert.serial_number


def test_wrong_pin_is_reported_without_echoing_it():
    world = World()
    pk11, _ = token_for(world)
    with pytest.raises(Pkcs11Error) as info:
        Pkcs11Signer.for_certificate("/fake/module.so", pin="9999-wrong", pk11=pk11)
    assert "incorrect PIN" in str(info.value) and "9999" not in str(info.value)


def test_pin_is_not_kept_after_login():
    world = World()
    pk11, _ = token_for(world)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pin=PIN, pk11=pk11)
    assert signer._pin is None and PIN not in repr(vars(signer))


def test_signing_without_login_explains_the_per_signature_pin_case():
    world = World()
    pk11, _ = token_for(world)
    signer = Pkcs11Signer.for_certificate("/fake/module.so", pk11=pk11)
    with pytest.raises(Pkcs11Error, match="not logged in"):
        signer.sign(b"x")


def test_certificate_choice_errors():
    world = World()
    pk11, _ = token_for(world)
    with pytest.raises(Pkcs11Error, match="cannot be used for signing"):
        Pkcs11Signer.for_certificate("/fake/module.so", entry_index=0, pk11=pk11)  # the authentication cert

    no_signing = FakePk11([(c[0], c[1], c[2], c[3]) for c in token_for(World(), with_auth_cert=True)[0].certs[:1]])
    with pytest.raises(Pkcs11Error, match="no certificate usable"):
        Pkcs11Signer.for_certificate("/fake/module.so", pk11=no_signing)

    empty = FakePk11(None)
    with pytest.raises(Pkcs11Error, match="No token found"):
        Pkcs11Signer.for_certificate("/fake/module.so", pk11=empty)
    with pytest.raises(Pkcs11Error, match="Slot 5"):
        Pkcs11Signer.for_certificate("/fake/module.so", slot=5, pk11=pk11)


def test_module_discovery(tmp_path, monkeypatch):
    module = tmp_path / "libfake.so"
    module.write_bytes(b"")
    assert find_module(str(module)) == str(module)
    monkeypatch.setenv("NODETIDE_PKCS11_MODULE", str(module))
    assert find_module() == str(module)
    monkeypatch.delenv("NODETIDE_PKCS11_MODULE")
    monkeypatch.setattr("nodetide.eidas.pkcs11.CANDIDATE_MODULES", ())
    with pytest.raises(Pkcs11Error, match="No PKCS#11 module"):
        find_module(str(tmp_path / "missing.so"))


# --- the CLI ------------------------------------------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def run(*args, input=None):
    result = CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)
    return result


def test_claim_lifecycle_in_the_cli(home):
    assert run("identity", "create", "--name", "Maria").exit_code == 0
    result = run("claim", "add", "--type", "legal_name", "--given", "Maria", "--family", "Ivanova")
    assert result.exit_code == 0, result.output
    claim_id = result.output.split()[1]

    files = list((home / ".nodetide" / "claims").glob("*.json"))
    assert [f.stem for f in files] == [claim_id]
    assert oct(files[0].stat().st_mode & 0o777) == "0o600"
    assert json.loads(files[0].read_text())["value"] == NAME

    listing = run("claim", "list").output
    assert claim_id in listing and "legal_name" in listing and "active" in listing and "held" in listing

    exported = json.loads(run("claim", "export", claim_id).output)
    assert exported["claim_id"] == claim_id

    assert run("claim", "revoke", claim_id, "--reason", "test").exit_code == 0
    assert "revoked" in run("claim", "list").output


def test_claim_add_validates(home):
    run("identity", "create", "--name", "Maria")
    assert run("claim", "add", "--type", "email", "--email", "not-an-address").exit_code != 0
    assert run("claim", "add", "--type", "phone").exit_code != 0
    assert run("claim", "add", "--type", "legal_name", "--given", "Maria").exit_code != 0


def test_claim_commands_need_an_identity(home):
    result = run("claim", "list")
    assert result.exit_code != 0 and "No default identity" in result.output


def test_full_eid_flow_with_an_external_signing_application(home, tmp_path):
    """statement -> (sign with your own eID application) -> attach -> verify."""
    from cryptography.hazmat.primitives import serialization

    world = World()
    run("identity", "create", "--name", "Maria")
    claim_id = run("claim", "add", "--type", "legal_name", "--given", "Maria", "--family", "Ivanova").output.split()[1]

    statement_path = tmp_path / "statement.txt"
    result = run("eid", "statement", claim_id, "--out", str(statement_path))
    assert result.exit_code == 0, result.output
    raw = statement_path.read_bytes()
    assert raw.startswith(b"NODETIDE CLAIM STATEMENT v1\n") and not raw.endswith(b"\n")

    # the "provider's application" signs the file bytes
    der = create_cades_detached(raw, world.signer, legacy_ess=True)
    signature_path = tmp_path / "statement.txt.p7s"
    signature_path.write_bytes(der)

    attestation_path = tmp_path / "attestation.json"
    result = run("eid", "attach", claim_id, str(statement_path), str(signature_path), "--out", str(attestation_path))
    assert result.exit_code == 0, result.output
    assert "personal identifiers" in result.output and "high" in result.output
    assert oct(attestation_path.stat().st_mode & 0o777) == "0o600"

    chain_out = run("eid", "chain", str(attestation_path)).output
    assert "Test Qualified CA" in chain_out and "sha256" in chain_out

    anchors = tmp_path / "anchors"
    anchors.mkdir()
    (anchors / "root.pem").write_bytes(world.root.cert.public_bytes(serialization.Encoding.PEM))
    document = tmp_path / "doc.json"
    run("claim", "export", claim_id, "--out", str(document))
    result = run("eid", "verify", str(attestation_path), "--anchors", str(anchors),
                 "--document", str(document), "--revocation", "off")
    assert result.exit_code == 0, result.output
    assert "valid" in result.output and "matches (exact)" in result.output

    # trusting a different root makes the same file fail
    other = tmp_path / "other"
    other.mkdir()
    (other / "root.pem").write_bytes(pki.make_ca("Other").cert.public_bytes(serialization.Encoding.PEM))
    result = run("eid", "verify", str(attestation_path), "--anchors", str(other), "--revocation", "off")
    assert result.exit_code != 0 and "untrusted_certificate" in result.output


def test_attach_rejects_a_signature_over_something_else(home, tmp_path):
    world = World()
    run("identity", "create", "--name", "Maria")
    claim_id = run("claim", "add", "--type", "legal_name", "--given", "Maria", "--family", "Ivanova").output.split()[1]
    statement = tmp_path / "s.txt"
    run("eid", "statement", claim_id, "--out", str(statement))
    signature = tmp_path / "s.p7s"
    signature.write_bytes(create_cades_detached(b"some other document", world.signer))
    result = run("eid", "attach", claim_id, str(statement), str(signature))
    assert result.exit_code != 0 and "does not cover" in result.output

    signature.write_bytes(b"garbage")
    assert run("eid", "attach", claim_id, str(statement), str(signature)).exit_code != 0


def test_eid_sign_with_a_fake_token_never_asks_for_the_pin_on_the_command_line(home, tmp_path, monkeypatch):
    world = World()
    pk11, _ = token_for(world)
    monkeypatch.setattr("nodetide.eidas.pkcs11._load_pykcs11", lambda: pk11)
    module = tmp_path / "libfake.so"
    module.write_bytes(b"")

    run("identity", "create", "--name", "Maria")
    claim_id = run("claim", "add", "--type", "legal_name", "--given", "Maria", "--family", "Ivanova").output.split()[1]
    out = tmp_path / "att.json"

    declined = run("eid", "sign", claim_id, "--module", str(module), "--out", str(out), input="n\n")
    assert declined.exit_code != 0 and not out.exists()  # nothing is signed without confirmation
    assert "NODETIDE CLAIM STATEMENT v1" in declined.output  # the person saw what they would sign

    result = run("eid", "sign", claim_id, "--module", str(module), "--out", str(out), input=f"y\n{PIN}\n")
    assert result.exit_code == 0, result.output
    assert PIN not in result.output and out.exists()

    bad = run("eid", "sign", claim_id, "--module", str(module), "--out", str(tmp_path / "x.json"), input="y\nwrong-pin\n")
    assert bad.exit_code != 0 and "incorrect PIN" in bad.output and "wrong-pin" not in bad.output
