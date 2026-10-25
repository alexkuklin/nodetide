#!/usr/bin/env python3
"""Nodetide SMS gateway: sends verification codes through a USB modem.

Runs next to the modem (for example on a home server behind NAT). It only makes outbound HTTPS requests: it
long-polls the verification service for queued messages, sends each one over the modem with AT commands, and
reports the outcome. Nothing connects to it.

Safety is enforced HERE, whatever the server asks for:
  * the destination must match a mask (default: Bulgarian mobile numbers, ^\\+359[0-9]{9}$)
  * at most N messages per rolling window (default 10 per 24 h), counted when a send is attempted, success or not
  * at most M messages per destination number per window (default 3)
  * the text must be plain printable ASCII, at most 160 characters (so it cannot smuggle modem control characters)
  * a message id is never sent twice, even if the server offers it again
  * expired messages are not sent
A refused message is reported back as "rejected" with a reason code; the person just sees that no SMS came.

    SMS_GATEWAY_TOKEN=... ./sms_gateway.py --server https://nt-verifier.example.org --device /dev/ttyUSB0

The token is read from the environment (or --token-file), never from the command line.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

DEFAULT_ALLOW = r"^\+359[0-9]{9}$"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
log = logging.getLogger("sms-gateway")


# --- policy -------------------------------------------------------------------------------------------------------


@dataclass
class Limits:
    allow: re.Pattern[str]
    max_sms: int = 10
    window: int = 24 * 3600
    max_per_number: int = 3
    max_length: int = 160


def mask(number: str) -> str:
    return number[:4] + "*" * max(len(number) - 8, 0) + number[-4:] if len(number) > 8 else "***"


class Ledger:
    """What was sent, kept on disk so limits survive restarts. Numbers are stored as short hashes."""

    KEEP_IDS = 7 * 24 * 3600

    def __init__(self, path: Path, window: int):
        self.path, self.window = path, window
        self.sends: list[list[Any]] = []  # [timestamp, number hash]
        self.done: dict[str, float] = {}
        if path.exists():
            try:
                data = json.loads(path.read_text())
                self.sends, self.done = list(data.get("sends", [])), dict(data.get("done", {}))
            except (OSError, ValueError) as e:
                raise SystemExit(f"cannot read the ledger {path}: {e} (fix or remove it; removing it resets the limits)")

    @staticmethod
    def _h(number: str) -> str:
        return hashlib.sha256(number.encode()).hexdigest()[:16]

    def _recent(self, now: float) -> list[list[Any]]:
        return [s for s in self.sends if s[0] > now - self.window]

    def count(self, now: float) -> int:
        return len(self._recent(now))

    def count_number(self, number: str, now: float) -> int:
        h = self._h(number)
        return sum(1 for s in self._recent(now) if s[1] == h)

    def seen(self, message_id: str) -> bool:
        return message_id in self.done

    def record(self, number: str, message_id: str, now: float) -> None:
        self.sends = self._recent(now) + [[now, self._h(number)]]
        self.done = {k: v for k, v in self.done.items() if v > now - self.KEEP_IDS}
        self.done[message_id] = now
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"sends": self.sends, "done": self.done}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


class Policy:
    def __init__(self, limits: Limits, ledger: Ledger):
        self.limits, self.ledger = limits, ledger

    def check(self, number: Any, text: Any, now: float) -> str | None:
        """None if the message may be sent, else a short reason code."""
        lim = self.limits
        if not isinstance(number, str) or not lim.allow.fullmatch(number):
            return "number_not_allowed"
        if (not isinstance(text, str) or not text or len(text) > lim.max_length
                or not text.isascii() or not text.isprintable()):
            return "bad_text"
        if self.ledger.count(now) >= lim.max_sms:
            return "limit_reached"
        if self.ledger.count_number(number, now) >= lim.max_per_number:
            return "number_limit_reached"
        return None


# --- modems -------------------------------------------------------------------------------------------------------


class ModemError(Exception):
    pass


class DryRunModem:
    """Sends nothing. With a file, appends what would have been sent (the text holds the code: testing only)."""

    def __init__(self, sink: Path | None = None):
        self.sink = sink

    def send(self, number: str, text: str) -> None:
        log.info("DRY RUN: would send %d characters to %s", len(text), mask(number))
        if self.sink is not None:
            self.sink.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.sink, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps({"to": number, "text": text}) + "\n")

    def status(self) -> dict[str, str]:
        return {"modem": "dry run"}


class AtModem:
    """A GSM modem on a serial port, text-mode SMS (AT+CMGF=1)."""

    def __init__(self, device: str, baud: int = 115200, pin: str | None = None, send_timeout: float = 60.0):
        try:
            import serial  # pyserial
        except ImportError:
            raise SystemExit("pyserial is needed for a real modem:  pip install pyserial") from None
        self.ser = serial.Serial(device, baud, timeout=0.5, write_timeout=5)
        self.send_timeout = send_timeout
        self._init(pin)

    def _write(self, data: bytes) -> None:
        self.ser.write(data)
        self.ser.flush()

    def _read_until(self, tokens: tuple[str, ...], timeout: float) -> str:
        deadline, buf = time.monotonic() + timeout, ""
        while time.monotonic() < deadline:
            chunk = self.ser.read(256)
            if chunk:
                buf += chunk.decode("ascii", "replace")
                if any(t in buf for t in tokens):
                    return buf
        raise ModemError(f"modem did not answer in time (got {buf!r})")

    def command(self, cmd: str, timeout: float = 5.0) -> str:
        self.ser.reset_input_buffer()
        self._write(cmd.encode("ascii") + b"\r")
        reply = self._read_until(("\r\nOK\r\n", "ERROR"), timeout)
        if "ERROR" in reply:
            raise ModemError(f"{cmd.split('=')[0]} failed: {reply.strip()!r}")
        return reply

    def _init(self, pin: str | None) -> None:
        self.command("ATE0")
        state = self.command("AT+CPIN?")
        if "SIM PIN" in state:
            if not pin:
                raise SystemExit("the SIM asks for a PIN: pass --sim-pin-file (a wrong PIN can lock the SIM, so it is not retried)")
            self.command(f'AT+CPIN="{pin}"', 10)
            time.sleep(3)
        elif "READY" not in state:
            raise SystemExit(f"the SIM is not ready: {state.strip()!r}")
        self.command("AT+CMGF=1")
        self.command('AT+CSCS="GSM"')

    def status(self) -> dict[str, str]:
        out = {}
        for key, cmd in (("signal", "AT+CSQ"), ("operator", "AT+COPS?"), ("registration", "AT+CREG?")):
            try:
                out[key] = " ".join(self.command(cmd).split()).replace(" OK", "")
            except ModemError as e:
                out[key] = f"error: {e}"
        return out

    def send(self, number: str, text: str) -> None:
        # defence in depth: the policy already checked, but these end up inside a modem command
        if not re.fullmatch(r"\+[0-9]{6,15}", number) or not text.isascii() or not text.isprintable():
            raise ModemError("refusing to send: unsafe characters")
        self.ser.reset_input_buffer()
        self._write(f'AT+CMGS="{number}"\r'.encode("ascii"))
        self._read_until((">",), 10)
        self._write(text.encode("ascii") + b"\x1a")
        reply = self._read_until(("\r\nOK\r\n", "ERROR"), self.send_timeout)
        if "ERROR" in reply or "+CMGS:" not in reply:
            raise ModemError(f"the modem refused the message: {reply.strip()!r}")


# --- the server ---------------------------------------------------------------------------------------------------


class Client:
    def __init__(self, base: str, token: str, allow_insecure_http: bool = False):
        parts = urlsplit(base)
        if parts.scheme != "https" and not (parts.scheme == "http" and (parts.hostname in LOOPBACK or allow_insecure_http)):
            raise SystemExit("the server address must be https:// (the token travels with every request)")
        self.base, self.token = base.rstrip("/"), token

    def _request(self, method: str, path: str, body: dict | None, timeout: float) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": "nodetide-sms-gateway"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")

    def pending(self, wait: int, limit: int = 5) -> list[dict[str, Any]]:
        return self._request("GET", f"/api/gateway/sms/pending?wait={wait}&max={limit}", None, wait + 15).get("messages", [])

    def report(self, message_id: str, status: str, reason: str = "") -> None:
        last: Exception | None = None
        for attempt in range(4):
            try:
                self._request("POST", f"/api/gateway/sms/{message_id}/result", {"status": status, "reason": reason}, 15)
                return
            except urllib.error.HTTPError as e:
                if e.code == 404:  # already reported or expired: nothing more to do
                    return
                last = e
            except (urllib.error.URLError, OSError, ValueError) as e:
                last = e
            time.sleep(2 ** attempt)
        log.error("could not report %s as %s: %s", message_id[:6], status, last)


# --- the loop -----------------------------------------------------------------------------------------------------


def process(message: dict[str, Any], policy: Policy, ledger: Ledger, modem: Any, client: Any,
            now: Callable[[], float] = time.time) -> str:
    """Handle one queued message. Returns what happened: sent | duplicate | failed | <reason it was refused>."""
    message_id, number, text = str(message.get("id", "")), message.get("to"), message.get("text")
    if not message_id:
        return "bad_message"
    if ledger.seen(message_id):
        client.report(message_id, "sent", "duplicate_suppressed")
        return "duplicate"
    expires = message.get("expires_at")
    if isinstance(expires, (int, float)) and expires <= now():
        client.report(message_id, "rejected", "expired")
        return "expired"
    reason = policy.check(number, text, now())
    if reason:
        log.warning("refused a message to %s: %s", mask(str(number)), reason)
        client.report(message_id, "rejected", reason)
        return reason
    ledger.record(number, message_id, now())  # counted before the attempt, so a flaky modem cannot exceed the limits
    try:
        modem.send(number, text)
    except ModemError as e:
        log.error("sending to %s failed: %s", mask(number), e)
        client.report(message_id, "failed", "modem_error")
        return "failed"
    log.info("sent a message to %s (%d of %d in this window)", mask(number), ledger.count(now()), policy.limits.max_sms)
    client.report(message_id, "sent")
    return "sent"


def run(client: Client, policy: Policy, ledger: Ledger, modem: Any, wait: int, once: bool, stop: Callable[[], bool]) -> None:
    failures = 0
    while not stop():
        try:
            messages = client.pending(0 if once else wait)
            failures = 0
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise SystemExit("the server rejected the gateway token") from None
            failures += 1
            log.error("server answered %s", e.code)
            messages = []
        except (urllib.error.URLError, OSError, ValueError) as e:
            failures += 1
            log.error("cannot reach the server: %s", e)
            messages = []
        for message in messages:
            process(message, policy, ledger, modem, client)
        if once:
            return
        if failures:
            time.sleep(min(60, 2 ** min(failures, 6)))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Send Nodetide verification codes through a USB modem")
    p.add_argument("--server", default=os.environ.get("SMS_GATEWAY_SERVER"), help="verification service address (https://...)")
    p.add_argument("--token-file", help="file holding the gateway token (default: $SMS_GATEWAY_TOKEN)")
    p.add_argument("--device", default=os.environ.get("SMS_GATEWAY_DEVICE"), help="modem serial port, e.g. /dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--sim-pin-file", help="file holding the SIM PIN, if the SIM asks for one")
    p.add_argument("--allow", default=DEFAULT_ALLOW, help=f"regex every destination must fully match (default {DEFAULT_ALLOW})")
    p.add_argument("--max-sms", type=int, default=10, help="messages allowed per window (default 10)")
    p.add_argument("--window-hours", type=float, default=24, help="length of the rolling window (default 24)")
    p.add_argument("--max-per-number", type=int, default=3, help="messages per destination per window (default 3)")
    p.add_argument("--max-length", type=int, default=160)
    p.add_argument("--state", default=str(Path.home() / ".nodetide-sms-gateway" / "ledger.json"))
    p.add_argument("--poll-wait", type=int, default=25, help="long-poll seconds (the server allows up to 30)")
    p.add_argument("--dry-run", action="store_true", help="do everything except sending: log instead of using the modem")
    p.add_argument("--dry-run-file", help="with --dry-run: append each message that would be sent to this file (testing)")
    p.add_argument("--once", action="store_true", help="fetch and process what is queued now, then exit")
    p.add_argument("--selftest-modem", action="store_true", help="print the modem's SIM, signal and network state, then exit")
    p.add_argument("--allow-insecure-http", action="store_true", help="accept a plain http:// server (never over the internet)")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    pin = Path(args.sim_pin_file).read_text().strip() if args.sim_pin_file else None
    if args.dry_run:
        modem: Any = DryRunModem(Path(args.dry_run_file) if args.dry_run_file else None)
    else:
        if not args.device:
            raise SystemExit("--device is required (or use --dry-run)")
        modem = AtModem(args.device, args.baud, pin)
    if args.selftest_modem:
        for key, value in modem.status().items():
            print(f"{key}: {value}")
        return

    token = Path(args.token_file).read_text().strip() if args.token_file else os.environ.get("SMS_GATEWAY_TOKEN", "").strip()
    if not args.server or not token:
        raise SystemExit("--server and the token (SMS_GATEWAY_TOKEN or --token-file) are required")
    try:
        allow = re.compile(args.allow)
    except re.error as e:
        raise SystemExit(f"--allow is not a valid pattern: {e}") from None

    window = int(args.window_hours * 3600)
    ledger = Ledger(Path(args.state), window)
    policy = Policy(Limits(allow, args.max_sms, window, args.max_per_number, args.max_length), ledger)
    client = Client(args.server, token, args.allow_insecure_http)
    log.info("gateway up: destinations %s, at most %d per %gh (%d already used), %d per number, server %s%s",
             args.allow, args.max_sms, args.window_hours, ledger.count(time.time()), args.max_per_number, client.base,
             ", DRY RUN" if args.dry_run else "")

    stopping = False

    def _stop(*_: Any) -> None:
        nonlocal stopping
        stopping = True
        log.info("stopping after the current request")

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    run(client, policy, ledger, modem, args.poll_wait, args.once, lambda: stopping)


if __name__ == "__main__":
    main()
