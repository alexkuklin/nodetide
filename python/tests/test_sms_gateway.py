"""The SMS gateway script (tools/sms-gateway/sms_gateway.py): safety checks happen on the modem side."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import re
import sys
import types
import urllib.error
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.core.storage import Storage
from nodetide.verifiers import NodeIssuer, PhoneVerifier, SmsOutbox
from nodetide.verifiers.service import create_verifier_app

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "sms-gateway" / "sms_gateway.py"
spec = importlib.util.spec_from_file_location("sms_gateway", SCRIPT)
gw = importlib.util.module_from_spec(spec)
sys.modules["sms_gateway"] = gw
spec.loader.exec_module(gw)

NUMBER = "+359881234567"
TOKEN = "g" * 32


class FakeClient:
    def __init__(self):
        self.reports: list[tuple[str, str, str]] = []

    def report(self, message_id, status, reason=""):
        self.reports.append((message_id, status, reason))


class FakeModem:
    def __init__(self, fail=False):
        self.sent: list[tuple[str, str]] = []
        self.fail = fail

    def send(self, number, text):
        if self.fail:
            raise gw.ModemError("no network")
        self.sent.append((number, text))


def make(tmp_path, **kw):
    limits = gw.Limits(re.compile(kw.pop("allow", gw.DEFAULT_ALLOW)), **kw)
    ledger = gw.Ledger(tmp_path / "ledger.json", limits.window)
    return gw.Policy(limits, ledger), ledger


def msg(i="m1", to=NUMBER, text="Nodetide code: 123456. Valid 10 min.", expires=None):
    return {"id": i, "to": to, "text": text, **({"expires_at": expires} if expires else {})}


# --- policy ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("number", [
    "+359881234567", "+359 88 123 4567", "0881234567", "+441234567890", "+35988123456", "+3598812345678",
    "+359881234567\n", '+359881234567"', "", None, 359881234567,
])
def test_only_numbers_matching_the_mask_pass(tmp_path, number):
    policy, _ = make(tmp_path)
    expected = None if number == "+359881234567" else "number_not_allowed"
    assert policy.check(number, "Nodetide code: 123456.", 1000.0) == expected


@pytest.mark.parametrize("text", ["", "x" * 161, "café", "line\nbreak", "stop\x1a", "esc\x1b[", "\r", None])
def test_text_must_be_short_plain_printable_ascii(tmp_path, text):
    policy, _ = make(tmp_path)
    assert policy.check(NUMBER, text, 1000.0) == "bad_text"


def test_count_limit_is_a_rolling_window_and_persists(tmp_path):
    policy, ledger = make(tmp_path, max_sms=3, window=100, max_per_number=99)
    for i in range(3):
        assert policy.check(NUMBER, "ok", 1000.0 + i) is None
        ledger.record(NUMBER, f"m{i}", 1000.0 + i)
    assert policy.check(NUMBER, "ok", 1050.0) == "limit_reached"
    # a restart does not reset it
    policy2, ledger2 = make(tmp_path, max_sms=3, window=100, max_per_number=99)
    assert ledger2.count(1050.0) == 3 and policy2.check(NUMBER, "ok", 1050.0) == "limit_reached"
    # the window rolls: the first send ages out
    assert policy2.check(NUMBER, "ok", 1101.5) is None


def test_per_number_limit(tmp_path):
    policy, ledger = make(tmp_path, max_sms=10, max_per_number=2)
    for i in range(2):
        ledger.record(NUMBER, f"m{i}", 1000.0)
    assert policy.check(NUMBER, "ok", 1001.0) == "number_limit_reached"
    assert policy.check("+359887654321", "ok", 1001.0) is None


def test_the_ledger_keeps_hashes_not_numbers_and_is_private(tmp_path):
    _, ledger = make(tmp_path)
    ledger.record(NUMBER, "m1", 1000.0)
    raw = (tmp_path / "ledger.json").read_text()
    assert NUMBER not in raw and "881234567" not in raw
    assert oct((tmp_path / "ledger.json").stat().st_mode & 0o777) == "0o600"


def test_a_damaged_ledger_stops_the_gateway_instead_of_resetting_the_limits(tmp_path):
    (tmp_path / "ledger.json").write_text("{not json")
    with pytest.raises(SystemExit):
        gw.Ledger(tmp_path / "ledger.json", 100)


# --- processing -----------------------------------------------------------------------------------------------


def test_a_good_message_is_sent_counted_and_reported(tmp_path):
    policy, ledger = make(tmp_path)
    client, modem = FakeClient(), FakeModem()
    assert gw.process(msg(), policy, ledger, modem, client, now=lambda: 1000.0) == "sent"
    assert modem.sent == [(NUMBER, "Nodetide code: 123456. Valid 10 min.")]
    assert client.reports == [("m1", "sent", "")] and ledger.count(1000.0) == 1


def test_a_refused_message_never_reaches_the_modem(tmp_path):
    policy, ledger = make(tmp_path)
    client, modem = FakeClient(), FakeModem()
    assert gw.process(msg(to="+441234567890"), policy, ledger, modem, client, now=lambda: 1000.0) == "number_not_allowed"
    assert modem.sent == [] and client.reports == [("m1", "rejected", "number_not_allowed")] and ledger.count(1000.0) == 0


def test_the_limit_stops_the_eleventh_message(tmp_path):
    policy, ledger = make(tmp_path, max_sms=10, max_per_number=100)
    client, modem = FakeClient(), FakeModem()
    results = [gw.process(msg(f"m{i}"), policy, ledger, modem, client, now=lambda: 1000.0) for i in range(12)]
    assert results[:10] == ["sent"] * 10 and results[10:] == ["limit_reached"] * 2
    assert len(modem.sent) == 10


def test_a_failed_send_still_counts_so_a_flaky_modem_cannot_exceed_the_limit(tmp_path):
    policy, ledger = make(tmp_path)
    client = FakeClient()
    assert gw.process(msg(), policy, ledger, FakeModem(fail=True), client, now=lambda: 1000.0) == "failed"
    assert client.reports == [("m1", "failed", "modem_error")] and ledger.count(1000.0) == 1


def test_an_offered_again_message_is_not_sent_twice(tmp_path):
    policy, ledger = make(tmp_path)
    client, modem = FakeClient(), FakeModem()
    gw.process(msg(), policy, ledger, modem, client, now=lambda: 1000.0)
    assert gw.process(msg(), policy, ledger, modem, client, now=lambda: 1001.0) == "duplicate"
    assert len(modem.sent) == 1 and client.reports[-1] == ("m1", "sent", "duplicate_suppressed")


def test_expired_messages_are_not_sent(tmp_path):
    policy, ledger = make(tmp_path)
    client, modem = FakeClient(), FakeModem()
    assert gw.process(msg(expires=900), policy, ledger, modem, client, now=lambda: 1000.0) == "expired"
    assert modem.sent == [] and client.reports == [("m1", "rejected", "expired")]


# --- the AT protocol (scripted fake serial port) -------------------------------------------------------------


class FakeSerial:
    script: dict[bytes, bytes] = {}
    instances: list["FakeSerial"] = []

    def __init__(self, device, baud, timeout=None, write_timeout=None):
        self.written: list[bytes] = []
        self._out = b""
        FakeSerial.instances.append(self)

    def write(self, data):
        self.written.append(data)
        for key, reply in FakeSerial.script.items():
            if data == key or (key == b"*TEXT*" and data.endswith(b"\x1a")):
                self._out += reply
                return

    def flush(self):
        pass

    def reset_input_buffer(self):
        self._out = b""

    def read(self, n):
        chunk, self._out = self._out[:n], self._out[n:]
        return chunk


OK = b"\r\nOK\r\n"


@pytest.fixture
def fake_serial(monkeypatch):
    module = types.ModuleType("serial")
    module.Serial = FakeSerial
    monkeypatch.setitem(sys.modules, "serial", module)
    FakeSerial.instances.clear()
    FakeSerial.script = {
        b"ATE0\r": OK, b"AT+CPIN?\r": b"\r\n+CPIN: READY\r\n" + OK, b"AT+CMGF=1\r": OK, b'AT+CSCS="GSM"\r': OK,
        f'AT+CMGS="{NUMBER}"\r'.encode(): b"\r\n> ", b"*TEXT*": b"\r\n+CMGS: 7\r\n" + OK,
    }
    return FakeSerial


def test_at_modem_sends_text_mode_sms(fake_serial):
    modem = gw.AtModem("/dev/ttyFAKE")
    modem.send(NUMBER, "Nodetide code: 123456.")
    written = fake_serial.instances[0].written
    assert b'AT+CMGS="+359881234567"\r' in written and written[-1] == b"Nodetide code: 123456.\x1a"


def test_at_modem_reports_a_refusal(fake_serial):
    fake_serial.script[b"*TEXT*"] = b"\r\n+CMS ERROR: 330\r\n"
    modem = gw.AtModem("/dev/ttyFAKE")
    with pytest.raises(gw.ModemError):
        modem.send(NUMBER, "hello")


def test_at_modem_refuses_anything_that_could_inject_commands(fake_serial):
    modem = gw.AtModem("/dev/ttyFAKE")
    for number, text in ((NUMBER + '"\rAT+CMGD=1', "x"), (NUMBER, "a\x1ab"), (NUMBER, "a\rb"), ("0881234567", "x")):
        with pytest.raises(gw.ModemError):
            modem.send(number, text)
    assert not any(b"CMGD" in w for w in fake_serial.instances[0].written)


def test_a_sim_that_wants_a_pin_is_not_guessed_at(fake_serial):
    fake_serial.script[b"AT+CPIN?\r"] = b"\r\n+CPIN: SIM PIN\r\n" + OK
    with pytest.raises(SystemExit):
        gw.AtModem("/dev/ttyFAKE")
    assert not any(w.startswith(b"AT+CPIN=") for w in fake_serial.instances[0].written)


# --- the server side of the conversation ------------------------------------------------------------------------


def test_the_token_never_travels_over_plain_http_to_a_remote_host():
    with pytest.raises(SystemExit):
        gw.Client("http://verifier.example.org", TOKEN)
    gw.Client("http://localhost:4558", TOKEN)
    gw.Client("https://verifier.example.org", TOKEN)


async def test_against_the_real_service(tmp_path):
    from nodetide.core.auth import create_assertion
    from nodetide.core.claims import ClaimDocument
    from nodetide.core.identity import DeviceCapability, Identity

    storage, outbox = Storage.memory(), SmsOutbox()
    verifier = PhoneVerifier(storage, NodeIssuer.load_or_create(storage, "V"), outbox)
    digest = hashlib.sha256(TOKEN.encode()).digest()
    app = create_verifier_app(storage, verifier, "https://v.test", outbox=outbox, gateway_token_digest=digest)
    async with TestClient(TestServer(app)) as http:
        holder = Identity.create(name="A")
        device, _ = holder.add_device("p", capabilities=[DeviceCapability.AUTHENTICATE])
        doc = ClaimDocument.create(holder.identity_hash, "phone", NUMBER)
        holder.add_claim(doc.claim_id, "phone", doc.commitment)
        request = await (await http.post("/api/auth/challenge", json={})).json()
        assertion = create_assertion(request, holder.identity_hash, device, holder.sigchain.head_hash,
                                     claims={"purpose": "claim_verification", "claim_id": doc.claim_id})
        resp = await http.post("/api/verify/phone/start", json={
            "document": doc.to_dict(), "assertion": assertion, "sigchain": holder.sigchain.to_list()})
        vid = (await resp.json())["verification_id"]

        policy, ledger = make(tmp_path)
        client = gw.Client(str(http.make_url("")).rstrip("/"), TOKEN)
        modem = FakeModem()
        await asyncio.to_thread(gw.run, client, policy, ledger, modem, 0, True, lambda: False)

        assert len(modem.sent) == 1 and modem.sent[0][0] == NUMBER
        status = await (await http.get(f"/api/verify/phone/{vid}/status")).json()
        assert status == {"delivery": "sent"}

        # a wrong token is a hard stop, not a retry loop
        bad = gw.Client(str(http.make_url("")).rstrip("/"), "wrong" * 8)
        with pytest.raises(SystemExit):
            await asyncio.to_thread(gw.run, bad, policy, ledger, modem, 0, True, lambda: False)
