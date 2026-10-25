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
from nodetide.eidas.pkcs11 import Pkcs11Error, Pkcs11Token, find_module
from tests import pki
from tests.test_eidas import NAME, World

# --- a fake PKCS#11 stack (two slots, hidden keys, per-signature PIN) ----------------------------------------


AUTH_PIN, SIGN_PIN = "1111", "2222-secret"


class FakeSlot:
    def __init__(self, label, pin, certs=(), keys=(), flags=0, min_pin=4, max_pin=16, attempts=3):
        self.label, self.pin, self.certs, self.keys = label, pin, list(certs), list(keys)
        self.flags, self.min_pin, self.max_pin, self.attempts = flags, min_pin, max_pin, attempts


class FakePk11:
    CKF_SERIAL_SESSION = 4
    CKF_LOGIN_REQUIRED, CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED = 4, 0x10000, 0x20000, 0x40000
    CKA_CLASS, CKA_VALUE, CKA_ID, CKA_LABEL, CKA_MODULUS, CKA_ALWAYS_AUTHENTICATE = 0, 0x11, 0x102, 3, 0x120, 0x202
    CKO_CERTIFICATE, CKO_PRIVATE_KEY = 1, 3
    CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS = 0x40, 0x41, 0x42
    CKM_RSA_PKCS, CKM_ECDSA = 1, 0x1041
    CKR_OK, CKR_MECHANISM_INVALID, CKR_PIN_INCORRECT, CKR_PIN_LOCKED = 0, 0x70, 0xA0, 0xA4
    CKR_USER_NOT_LOGGED_IN, CKR_USER_ALREADY_LOGGED_IN, CKR_ATTRIBUTE_TYPE_INVALID = 0x101, 0x100, 0x12
    CKU_CONTEXT_SPECIFIC = 2
    ckbytelist = list

    class PyKCS11Error(Exception):
        def __init__(self, value):
            super().__init__(f"PKCS#11 error {value}")
            self.value = value

    class Mechanism:
        def __init__(self, mechanism, param):
            self.mechanism = mechanism

        def to_native(self):
            return self.mechanism

    def __init__(self, slots, token_hashes=True):
        self.slots, self.token_hashes = slots, token_hashes
        self.signed_with: list[int] = []
        self.pins_tried: list[tuple[int, str]] = []
        outer = self

        class Info:
            def __init__(self, slot):
                s = outer.slots[slot]
                self.label, self.manufacturerID, self.model = s.label.ljust(32), "Fake", "IDPrime"
                self.ulMinPinLen, self.ulMaxPinLen = s.min_pin, s.max_pin
                self.flags = s.flags | outer.CKF_LOGIN_REQUIRED

        class Lib:
            def load(self, path):
                outer.loaded = path

            def getSlotList(self, tokenPresent=True):
                return sorted(outer.slots)

            def getTokenInfo(self, slot):
                return Info(slot)

            def openSession(self, slot, flags):
                return FakeSession(outer, slot)

        self.PyKCS11Lib = Lib


class FakeLow:
    """The C_* calls PyKCS11 exposes through session.lib."""

    def __init__(self, session):
        self.s = session
        self.key = None
        self.context_ok = False

    def C_SignInit(self, handle, mechanism, key):
        self.key, self.mechanism, self.context_ok = key, mechanism, False
        self.s.pk11.signed_with.append(mechanism)  # one entry per signing operation
        return 0

    def C_Login(self, handle, user_type, pin):
        pk = self.s.pk11
        assert user_type == pk.CKU_CONTEXT_SPECIFIC and self.key is not None
        pin = "".join(pin) if isinstance(pin, list) and pin and isinstance(pin[0], str) else pin
        pin = pin if isinstance(pin, str) else bytes(pin).decode()
        pk.pins_tried.append((self.s.slot, pin))
        if pin != self.s.fake.pin:
            return pk.CKR_PIN_INCORRECT
        self.context_ok = True
        return 0

    def C_Sign(self, handle, data, signature):
        pk, (private, always) = self.s.pk11, self.s.key_material(self.key)
        if always and not self.context_ok:
            return pk.CKR_USER_NOT_LOGGED_IN
        m, data = self.mechanism, bytes(data)
        if m in (pk.CKM_SHA256_RSA_PKCS, pk.CKM_SHA384_RSA_PKCS, pk.CKM_SHA512_RSA_PKCS):
            if not pk.token_hashes:
                return pk.CKR_MECHANISM_INVALID
            hash_cls = {pk.CKM_SHA256_RSA_PKCS: hashes.SHA256, pk.CKM_SHA384_RSA_PKCS: hashes.SHA384,
                        pk.CKM_SHA512_RSA_PKCS: hashes.SHA512}[m]
            out = private.sign(data, padding.PKCS1v15(), hash_cls())
        elif m == pk.CKM_RSA_PKCS:  # data is a DigestInfo: sign its digest
            out = private.sign(data[-32:], padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        elif m == pk.CKM_ECDSA:
            r, s2 = utils.decode_dss_signature(private.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
            out = r.to_bytes(32, "big") + s2.to_bytes(32, "big")
        else:
            return pk.CKR_MECHANISM_INVALID
        signature[:] = list(out)
        return 0


class FakeSession:
    def __init__(self, pk11: FakePk11, slot: int):
        self.pk11, self.slot, self.fake = pk11, slot, pk11.slots[slot]
        self.logged_in = False
        self.session = ("handle", slot)
        self.lib = FakeLow(self)

    def key_material(self, key):
        _, index = key
        return self.fake.keys[index][1], self.fake.keys[index][2]

    def findObjects(self, template):
        template = dict(template)
        if template[self.pk11.CKA_CLASS] == self.pk11.CKO_CERTIFICATE:
            return [("cert", i) for i in range(len(self.fake.certs))]
        if not self.logged_in:  # private keys are hidden until login
            return []
        keys = [("key", i) for i in range(len(self.fake.keys))]
        if self.pk11.CKA_ID in template:
            wanted = bytes(template[self.pk11.CKA_ID])
            keys = [k for k in keys if self.fake.keys[k[1]][0] == wanted]
        return keys

    def getAttributeValue(self, obj, attrs, allAsBinary=False):
        kind, index = obj
        pk = self.pk11
        if kind == "cert":
            der, key_id, label = self.fake.certs[index]
            values = {pk.CKA_VALUE: der, pk.CKA_ID: key_id, pk.CKA_LABEL: label.encode()}
        else:
            key_id, private, always = self.fake.keys[index]
            numbers = private.public_key().public_numbers()
            modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big") if hasattr(numbers, "n") else b""
            values = {pk.CKA_ID: key_id, pk.CKA_MODULUS: modulus, pk.CKA_ALWAYS_AUTHENTICATE: always}
        return [values[a] for a in attrs]

    def login(self, pin):
        pk = self.pk11
        pk.pins_tried.append((self.slot, pin))
        if self.fake.attempts <= 0:
            raise pk.PyKCS11Error(pk.CKR_PIN_LOCKED)
        if pin != self.fake.pin:
            self.fake.attempts -= 1
            raise pk.PyKCS11Error(pk.CKR_PIN_INCORRECT)
        self.logged_in = True

    def logout(self):
        self.logged_in = False

    def closeSession(self):
        pass


def der_of(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def fake_card(world: World, *, always_authenticate=True, token_hashes=True, ec_key=False,
              key_on_signature_slot=True, key_id_matches=True, sign_flags=0):
    """A B-Trust-like card: slot 0 (authentication PIN) shows the certificates; the qualified
    signing key appears only after logging in to slot 16 (digital signature PIN)."""
    signing = pki.make_signer_cert(world.inter, key_kind="ec") if ec_key else world.leaf
    certs = [(der_of(signing.cert), b"SIGN-CERT", "Signature certificate"),
             (der_of(world.inter.cert), b"CA", "Operational CA")]
    key = (b"SIGN-CERT" if key_id_matches else b"OTHER", signing.key, always_authenticate)
    auth_slot = FakeSlot("Card 3072 bits", AUTH_PIN, certs=certs)
    sign_slot = FakeSlot("Card 3072 bits (Dig", SIGN_PIN, certs=[], keys=[key], flags=sign_flags)
    if not key_on_signature_slot:
        auth_slot.keys, sign_slot.keys = [key], []
    return FakePk11({0: auth_slot, 16: sign_slot}, token_hashes), signing


def make_provider(*pins):
    """A PIN callback answering from a script; records every request."""
    answers, asked = list(pins), []

    def provider(reason: str) -> str:
        asked.append(reason)
        return answers.pop(0)

    provider.asked = asked
    return provider


def signer_for(world, pk11, provider, slot=16, hash_alg="sha256"):
    token = Pkcs11Token("/fake/module.so", pk11=pk11)
    return token.signer(token.choose_certificate(), slot, provider, hash_alg)


# --- the token layer -------------------------------------------------------------------------------------------


def test_slots_and_certificates_are_readable_without_any_pin():
    world = World()
    pk11, _ = fake_card(world)
    token = Pkcs11Token("/fake/module.so", pk11=pk11)
    slots = {s.slot: s for s in token.slots()}
    assert not slots[0].looks_like_signature_slot and slots[16].looks_like_signature_slot
    assert (slots[16].min_pin, slots[16].max_pin) == (4, 16) and not slots[16].pin_locked

    certs = token.certificates()
    assert [c.subject for c in certs] == ["Maria Ivanova", "Test Qualified CA"]
    signing = token.choose_certificate()
    assert signing.slot == 0 and signing.facts.assurance == "high" and signing.usable_for_signing
    assert pk11.pins_tried == []  # nothing was sent to the card


def test_pin_state_flags_are_reported():
    world = World()
    pk11, _ = fake_card(world, sign_flags=FakePk11.CKF_USER_PIN_FINAL_TRY | FakePk11.CKF_USER_PIN_COUNT_LOW)
    info = {s.slot: s for s in Pkcs11Token("/fake", pk11=pk11).slots()}[16]
    assert info.pin_final_try and info.pin_count_low and not info.pin_locked


def test_certificate_choice_errors():
    world = World()
    pk11, _ = fake_card(world)
    token = Pkcs11Token("/fake/module.so", pk11=pk11)
    with pytest.raises(Pkcs11Error, match="cannot be used for signing"):
        token.choose_certificate(1)  # the CA certificate
    with pytest.raises(Pkcs11Error, match="cannot be used for signing"):
        token.choose_certificate(99)
    with pytest.raises(Pkcs11Error, match="Slot 5"):
        token.slot_info(5)
    with pytest.raises(Pkcs11Error, match="No token found"):
        Pkcs11Token("/fake", pk11=FakePk11({}))
    ca_only = FakePk11({0: FakeSlot("c", "1", certs=[(der_of(world.inter.cert), b"CA", "CA")])})
    with pytest.raises(Pkcs11Error, match="no certificate usable"):
        Pkcs11Token("/fake", pk11=ca_only).choose_certificate()


def test_chain_excludes_the_root():
    world = World()
    pk11, _ = fake_card(world)
    signer = signer_for(world, pk11, make_provider())
    assert [c.subject.native["common_name"] for c in signer.chain] == ["Test Qualified CA"]


# --- signing -----------------------------------------------------------------------------------------------------


def test_signature_with_the_per_signature_pin_makes_a_valid_attestation():
    world = World()
    pk11, _ = fake_card(world, always_authenticate=True)
    provider = make_provider(SIGN_PIN, SIGN_PIN)
    signer = signer_for(world, pk11, provider)
    signer.login()
    att = build_eidas_attestation(world.holder.sigchain, world.record, signer)
    signer.close()
    assert world.check(att).ok
    assert len(provider.asked) == 2 and "authorise this signature" in provider.asked[1]
    assert pk11.signed_with == [pk11.CKM_SHA256_RSA_PKCS]


def test_key_without_per_signature_pin_asks_only_once():
    world = World()
    pk11, _ = fake_card(world, always_authenticate=False)
    provider = make_provider(SIGN_PIN)
    signer = signer_for(world, pk11, provider)
    signer.login()
    assert world.check(build_eidas_attestation(world.holder.sigchain, world.record, signer)).ok
    assert len(provider.asked) == 1


def test_wrong_pin_is_tried_exactly_once_and_never_echoed():
    world = World()
    pk11, _ = fake_card(world)
    provider = make_provider("0000-wrong", SIGN_PIN)  # the second answer must never be used
    signer = signer_for(world, pk11, provider)
    with pytest.raises(Pkcs11Error) as info:
        signer.login()
    assert "incorrect PIN" in str(info.value) and "0000-wrong" not in str(info.value)
    assert len(provider.asked) == 1 and pk11.pins_tried == [(16, "0000-wrong")]
    assert pk11.slots[16].attempts == 2  # one retry spent, no automatic second guess


def test_wrong_per_signature_pin_aborts_without_a_signature():
    world = World()
    pk11, _ = fake_card(world, always_authenticate=True)
    signer = signer_for(world, pk11, make_provider(SIGN_PIN, "bad-second"))
    signer.login()
    with pytest.raises(Pkcs11Error, match="incorrect PIN"):
        signer.sign(b"data")


def test_pin_length_is_checked_before_it_reaches_the_card():
    world = World()
    pk11, _ = fake_card(world)
    for pin in ("123", "x" * 17):
        with pytest.raises(Pkcs11Error, match="4 to 16 characters"):
            signer_for(world, pk11, make_provider(pin)).login()
    assert pk11.pins_tried == [] and pk11.slots[16].attempts == 3


def test_locked_pin_is_refused_before_asking_for_it():
    world = World()
    pk11, _ = fake_card(world, sign_flags=FakePk11.CKF_USER_PIN_LOCKED)
    provider = make_provider(SIGN_PIN)
    with pytest.raises(Pkcs11Error, match="locked"):
        signer_for(world, pk11, provider).login()
    assert provider.asked == []


def test_key_on_the_other_slot_is_reported_not_guessed():
    world = World()
    pk11, _ = fake_card(world, key_on_signature_slot=True)
    provider = make_provider(AUTH_PIN)
    signer = signer_for(world, pk11, provider, slot=0)  # the user chose the authentication slot
    with pytest.raises(Pkcs11Error, match="other slot"):
        signer.login()
    assert pk11.pins_tried == [(0, AUTH_PIN)]  # it did not go on to try slot 16


def test_signing_requires_login():
    world = World()
    pk11, _ = fake_card(world)
    with pytest.raises(Pkcs11Error, match="Not logged in"):
        signer_for(world, pk11, make_provider()).sign(b"x")


def test_key_is_found_by_modulus_when_ids_differ():
    world = World()
    pk11, _ = fake_card(world, key_id_matches=False, always_authenticate=False)
    signer = signer_for(world, pk11, make_provider(SIGN_PIN))
    signer.login()
    assert world.check(build_eidas_attestation(world.holder.sigchain, world.record, signer)).ok


def test_signer_falls_back_when_the_token_cannot_hash():
    world = World()
    pk11, _ = fake_card(world, token_hashes=False, always_authenticate=False)
    signer = signer_for(world, pk11, make_provider(SIGN_PIN))
    signer.login()
    assert world.check(build_eidas_attestation(world.holder.sigchain, world.record, signer)).ok
    assert pk11.signed_with == [pk11.CKM_SHA256_RSA_PKCS, pk11.CKM_RSA_PKCS]


def test_signer_with_an_ec_key():
    world = World()
    pk11, leaf = fake_card(world, ec_key=True, always_authenticate=False)
    token = Pkcs11Token("/fake/module.so", pk11=pk11)
    entry = next(c for c in token.certificates() if c.usable_for_signing)
    signer = token.signer(entry, 16, make_provider(SIGN_PIN))
    signer.login()
    der = create_cades_detached(b"data", signer)
    assert verify_cades_detached(der, b"data").signer_cert.serial_number == leaf.cert.serial_number


def test_no_pin_survives_in_the_signer():
    world = World()
    pk11, _ = fake_card(world, always_authenticate=False)
    signer = signer_for(world, pk11, make_provider(SIGN_PIN))
    signer.login()
    assert SIGN_PIN not in repr(vars(signer))


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


def cli_card(monkeypatch, tmp_path, **kw):
    world = World()
    pk11, _ = fake_card(world, **kw)
    monkeypatch.setattr("nodetide.eidas.pkcs11._load_pykcs11", lambda: pk11)
    module = tmp_path / "libfake.so"
    module.write_bytes(b"")
    return world, pk11, str(module)


def new_claim(tmp_path):
    run("identity", "create", "--name", "Maria")
    return run("claim", "add", "--type", "legal_name", "--given", "Maria", "--family", "Ivanova").output.split()[1]


def test_eid_tokens_lists_slots_certificates_and_pin_state(home, tmp_path, monkeypatch):
    world, pk11, module = cli_card(monkeypatch, tmp_path, sign_flags=FakePk11.CKF_USER_PIN_COUNT_LOW)
    out = run("eid", "tokens", "--module", module).output
    assert "slot 0:" in out and "slot 16:" in out and "digital signature PIN" in out
    assert "some PIN attempts already failed" in out and "assurance high" in out
    assert pk11.pins_tried == []  # listing never touches a PIN


def test_eid_sign_walks_through_slot_statement_and_pins(home, tmp_path, monkeypatch):
    world, pk11, module = cli_card(monkeypatch, tmp_path)
    claim_id = new_claim(tmp_path)
    out_file = tmp_path / "att.json"

    # decline at the confirmation: the statement was shown, nothing was signed, no PIN was tried
    declined = run("eid", "sign", claim_id, "--module", module, "--out", str(out_file), input="16\nn\n")
    assert declined.exit_code != 0 and not out_file.exists() and pk11.pins_tried == []
    assert "NODETIDE CLAIM STATEMENT v1" in declined.output and "slot 16" in declined.output

    # slot 16 is proposed by default (press enter); the key needs the PIN twice
    result = run("eid", "sign", claim_id, "--module", module, "--out", str(out_file),
                 input=f"\ny\n{SIGN_PIN}\n{SIGN_PIN}\n")
    assert result.exit_code == 0, result.output
    assert SIGN_PIN not in result.output and out_file.exists()
    assert [p for _, p in pk11.pins_tried] == [SIGN_PIN, SIGN_PIN]
    assert "assurance:   high" in result.output


def test_eid_sign_warns_before_the_last_pin_attempt(home, tmp_path, monkeypatch):
    world, pk11, module = cli_card(monkeypatch, tmp_path, sign_flags=FakePk11.CKF_USER_PIN_FINAL_TRY)
    claim_id = new_claim(tmp_path)
    out = tmp_path / "att.json"
    refused = run("eid", "sign", claim_id, "--module", module, "--slot", "16", "--out", str(out), input="n\n")
    assert refused.exit_code != 0 and "ONE PIN attempt" in refused.output and pk11.pins_tried == []

    ok = run("eid", "sign", claim_id, "--module", module, "--slot", "16", "--out", str(out),
             input=f"y\ny\n{SIGN_PIN}\n{SIGN_PIN}\n")
    assert ok.exit_code == 0 and out.exists()


def test_eid_sign_refuses_a_locked_slot_without_asking_for_a_pin(home, tmp_path, monkeypatch):
    world, pk11, module = cli_card(monkeypatch, tmp_path, sign_flags=FakePk11.CKF_USER_PIN_LOCKED)
    claim_id = new_claim(tmp_path)
    result = run("eid", "sign", claim_id, "--module", module, "--slot", "16")
    assert result.exit_code != 0 and "locked" in result.output and pk11.pins_tried == []


def test_eid_sign_wrong_pin_costs_one_attempt_and_is_not_echoed(home, tmp_path, monkeypatch):
    world, pk11, module = cli_card(monkeypatch, tmp_path)
    claim_id = new_claim(tmp_path)
    result = run("eid", "sign", claim_id, "--module", module, "--slot", "16",
                 "--out", str(tmp_path / "x.json"), input="y\nwrong-pin-1\nwrong-pin-2\n")
    assert result.exit_code != 0 and "incorrect PIN" in result.output
    assert "wrong-pin" not in result.output.replace("Token PIN", "")  # never echoed back
    assert len(pk11.pins_tried) == 1 and pk11.slots[16].attempts == 2


def test_nodetide_home_redirects_the_cli_data_directory(tmp_path, monkeypatch):
    elsewhere = tmp_path / "isolated"
    monkeypatch.setenv("HOME", str(tmp_path / "real-home"))
    monkeypatch.setenv("NODETIDE_HOME", str(elsewhere))
    assert run("identity", "create", "--name", "Isolated").exit_code == 0
    run("claim", "add", "--type", "email", "--email", "a@example.com")
    assert (elsewhere / "nodetide.db").exists() and list((elsewhere / "claims").glob("*.json"))
    assert not (tmp_path / "real-home" / ".nodetide").exists()  # the real data directory was never touched
