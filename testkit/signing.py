#!/usr/bin/env python3
"""Signing testkit: try the eID claim-signing flow safely, with your own card or without one.

Everything it creates lives in .testkit/ (git-ignored) and uses its own isolated Nodetide
data directory, so your real ~/.nodetide is never touched. The token PIN is only ever typed
at the prompt of `nodetide eid sign`: this script never sees, stores or logs it.

    ./testkit/run setup        create the test environment (once)
    ./testkit/run selftest     prove the signing code works, no card needed
    ./testkit/run token        show your card's slots, PIN state and certificates (no PIN)
    ./testkit/run claim        create a throwaway identity and a legal-name claim
    ./testkit/run sign         sign it with your card (asks for the PIN)
    ./testkit/run anchors      fetch the CA chain for review, then save the ones you confirm
    ./testkit/run verify       verify the attestation as a relying party would
    ./testkit/run report       a summary with no personal data, safe to paste anywhere
    ./testkit/run clean        delete the attestation and test identity (--all: everything)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "python"
HOME = Path(os.environ.get("TESTKIT_HOME", ROOT / ".testkit")).resolve()
VENV = HOME / "venv"
DATA = HOME / "data"           # NODETIDE_HOME for the isolated identity
OUT = HOME / "out"             # attestation, claim document (personal data!)
ANCHORS = HOME / "anchors"
STATE = HOME / "state.json"
ATTESTATION = OUT / "attestation.json"
CLAIM_DOC = OUT / "claim.json"

SIGNING_TESTS = ["tests/test_eidas.py", "tests/test_eid_tools.py", "tests/test_eidas_api.py", "tests/test_claims.py",
                 "tests/test_testkit.py"]


def venv_python() -> Path:
    """The test environment's interpreter ($TESTKIT_PYTHON overrides it, for the kit's own tests)."""
    return Path(os.environ["TESTKIT_PYTHON"]) if os.environ.get("TESTKIT_PYTHON") else VENV / "bin" / "python"


def say(message: str = "") -> None:
    print(message, flush=True)


def fail(message: str) -> "NoReturn":  # noqa: F821
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(state: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2))


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def nodetide(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    """Run the nodetide CLI in the test environment with the isolated data directory.

    Interactive by default: stdin/stdout stay attached to the terminal, which is how the
    PIN prompt reaches you directly.
    """
    if not venv_python().exists():
        fail("the test environment is missing: run ./testkit/run setup")
    env = {**os.environ, "NODETIDE_HOME": str(private_dir(DATA)), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([str(venv_python()), "-m", "nodetide.cli.main", *args], env=env,
                          capture_output=capture, text=True)


# --- setup / selftest ------------------------------------------------------------------------------


def cmd_setup(args) -> None:
    if sys.version_info < (3, 11):
        fail("Python 3.11 or newer is required")
    HOME.mkdir(parents=True, exist_ok=True)
    if not venv_python().exists():
        say("creating the virtualenv ...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    say("installing nodetide and the test tools ...")
    pip = [str(venv_python()), "-m", "pip", "install", "-q"]
    subprocess.run([*pip, "-e", f"{PY_DIR}[dev]"], check=True)
    if subprocess.run([*pip, f"{PY_DIR}[eid]"], stderr=subprocess.DEVNULL).returncode != 0:
        say("warning: PyKCS11 could not be installed, so `sign` and `token` cannot use a card here.")
    say("ready. Next: ./testkit/run selftest")


def cmd_selftest(args) -> None:
    """The signing code against a synthetic CA and a fake card: no hardware, no personal data."""
    if not venv_python().exists():
        fail("run ./testkit/run setup first")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(PY_DIR / "src"), str(PY_DIR)]), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run([str(venv_python()), "-m", "pytest", *SIGNING_TESTS, "-q", "-p", "no:cacheprovider", "-W", "ignore",
                           *args.pytest_args], cwd=PY_DIR, env=env)
    if proc.returncode == 0:
        say("\nselftest passed: the signing code works. Real-card steps next: token, claim, sign.")
    raise SystemExit(proc.returncode)


# --- the real card ------------------------------------------------------------------------------------


def cmd_token(args) -> None:
    extra = ["--module", args.module] if args.module else []
    raise SystemExit(nodetide("eid", "tokens", *extra).returncode)


def cmd_claim(args) -> None:
    state = load_state()
    if state.get("claim_id") and not args.force:
        fail(f"a claim already exists ({state['claim_id']}). Use --force to make a new one, or `clean` first.")
    if not (DATA / "nodetide.db").exists():
        created = nodetide("identity", "create", "--name", "Signing testkit", capture=True)
        if created.returncode:
            fail(created.stderr or created.stdout)
    proc = nodetide("claim", "add", "--type", "legal_name", "--given", args.given, "--family", args.family, capture=True)
    if proc.returncode:
        fail(proc.stderr or proc.stdout)
    claim_id = proc.stdout.split()[1]
    OUT.mkdir(parents=True, exist_ok=True)
    os.chmod(OUT, 0o700)
    nodetide("claim", "export", claim_id, "--out", str(CLAIM_DOC), capture=True)
    save_state({"claim_id": claim_id})
    say(f"Claim {claim_id} created in the isolated test identity.")
    say("The name you entered must match your certificate (see `token`). Next: ./testkit/run sign")


def need_claim() -> str:
    claim_id = load_state().get("claim_id")
    if not claim_id:
        fail("no claim yet: run ./testkit/run claim --given NAME --family SURNAME")
    return claim_id


def cmd_sign(args) -> None:
    claim_id = need_claim()
    private_dir(OUT)
    cmd = ["eid", "sign", claim_id, "--out", str(ATTESTATION), "--valid-days", str(args.valid_days)]
    for flag, value in (("--module", args.module), ("--slot", args.slot), ("--cert", args.cert)):
        if value is not None:
            cmd += [flag, str(value)]
    say("The next step talks to your card. Read what it shows before you type the PIN.")
    say("A wrong PIN costs one of the card's few attempts and is never retried.\n")
    code = nodetide(*cmd).returncode
    if code == 0:
        os.chmod(ATTESTATION, 0o600)
        say("\nNext: ./testkit/run anchors   (then verify, report)")
    raise SystemExit(code)


def cmd_anchors(args) -> None:
    need_claim()
    if not ATTESTATION.exists():
        fail("no attestation yet: run ./testkit/run sign")
    raise SystemExit(nodetide("eid", "anchors", str(ATTESTATION), "--out", str(private_dir(ANCHORS))).returncode)


def cmd_verify(args) -> None:
    need_claim()
    if not ATTESTATION.exists():
        fail("no attestation yet: run ./testkit/run sign")
    if not ANCHORS.exists() or not any(ANCHORS.iterdir()):
        fail("no trust anchors yet: run ./testkit/run anchors")
    raise SystemExit(nodetide("eid", "verify", str(ATTESTATION), "--anchors", str(ANCHORS),
                              "--document", str(CLAIM_DOC), "--revocation", args.revocation).returncode)


# --- report ---------------------------------------------------------------------------------------------------


REPORT_CODE = r'''
import json, sys, time
from pathlib import Path
from nodetide.cli.main import data_dir
from nodetide.core.claims import Attestation, ClaimDocument
from nodetide.core.storage import Storage
from nodetide.eidas.certs import cert_facts
from nodetide.eidas.validate import TrustStore
from nodetide.eidas.verify import EidasPolicy, check_legal_name, inspect_proof

attestation_path, claim_path, anchors, revocation, leniency = sys.argv[1:6]
att = Attestation.from_dict(json.loads(Path(attestation_path).read_text()))
doc = ClaimDocument.from_dict(json.loads(Path(claim_path).read_text()))
chain = Storage.open(data_dir() / "nodetide.db").get_default_identity().sigchain
summary = inspect_proof(att)
f = summary.facts
key = summary.cades.signer_cert.public_key
now = int(time.time())

def outcome(mode):
    store = TrustStore.from_directory(anchors)
    check = EidasPolicy(store, revocation_mode=mode).verify(att, chain, now)
    return "OK" if check.ok else f"FAIL ({check.code})"

name = check_legal_name(att, doc, leniency)
print("Signing testkit report (contains no names or ID numbers)")
print(f"  method / assurance claimed : {att.method} / {att.assurance}")
print(f"  signature covers statement : OK (checked while reading the proof)")
print(f"  certificate                : qualified={f.qualified} qscd={f.qscd} signs_documents={f.non_repudiation} "
      f"key={key.algorithm}-{key.bit_size}")
print(f"  certificate assurance      : {f.assurance}")
print(f"  issuing CA / country       : {f.issuer_name} / {f.country}")
print(f"  certificate validity       : {f.not_before:%Y-%m-%d} .. {f.not_after:%Y-%m-%d}")
print(f"  signing time in signature  : {summary.cades.signing_time}")
print(f"  attestation valid until    : {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(att.expires_at))}")
print(f"  chain to saved anchors     : {outcome('off')}")
print(f"  with revocation ({revocation:9}): {outcome(revocation)}")
print(f"  claimed name vs certificate: {'match ' + str(name.how) if name.ok else 'NO MATCH (' + str(name.reason) + ')'}")
print(f"  accepted at leniency       : {leniency}")
'''


def cmd_report(args) -> None:
    need_claim()
    for path, hint in ((ATTESTATION, "sign"), (CLAIM_DOC, "claim")):
        if not path.exists():
            fail(f"missing {path.name}: run ./testkit/run {hint}")
    if not ANCHORS.exists() or not any(ANCHORS.iterdir()):
        fail("no trust anchors yet: run ./testkit/run anchors")
    env = {**os.environ, "NODETIDE_HOME": str(DATA), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run([str(venv_python()), "-c", REPORT_CODE, str(ATTESTATION), str(CLAIM_DOC), str(ANCHORS),
                           args.revocation, args.leniency], env=env)
    raise SystemExit(proc.returncode)


def cmd_clean(args) -> None:
    targets = [OUT, ANCHORS, DATA, STATE]
    if args.all:
        targets.append(VENV)
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
    say("removed the test identity, attestation and claim document" + (" and the virtualenv" if args.all else "") + ".")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("setup", help="create the test environment").set_defaults(fn=cmd_setup)
    p = sub.add_parser("selftest", help="run the signing tests (no card needed)")
    p.add_argument("pytest_args", nargs="*", help="extra pytest arguments, e.g. -k name")
    p.set_defaults(fn=cmd_selftest)

    p = sub.add_parser("token", help="show slots, PIN state and certificates (needs no PIN)")
    p.add_argument("--module", help="PKCS#11 module (default: auto-detect)")
    p.set_defaults(fn=cmd_token)

    p = sub.add_parser("claim", help="create the test identity and a legal-name claim")
    p.add_argument("--given", required=True, help="given name as it appears on your certificate")
    p.add_argument("--family", required=True, help="family name as it appears on your certificate")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_claim)

    p = sub.add_parser("sign", help="sign the claim with your card")
    p.add_argument("--module")
    p.add_argument("--slot", type=int, help="slot whose PIN you will type (see `token`)")
    p.add_argument("--cert", type=int, help="certificate number from `token`")
    p.add_argument("--valid-days", type=int, default=7)
    p.set_defaults(fn=cmd_sign)

    sub.add_parser("anchors", help="fetch and review the CA chain, save the ones you confirm").set_defaults(fn=cmd_anchors)

    p = sub.add_parser("verify", help="verify the attestation against the saved anchors")
    p.add_argument("--revocation", choices=["hard-fail", "soft-fail", "off"], default="hard-fail")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("report", help="summary without personal data")
    p.add_argument("--revocation", choices=["hard-fail", "soft-fail", "off"], default="hard-fail")
    p.add_argument("--leniency", choices=["exact", "transliterated", "approximate"], default="transliterated")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("clean", help="delete the test identity and attestation")
    p.add_argument("--all", action="store_true", help="also delete the virtualenv")
    p.set_defaults(fn=cmd_clean)

    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
