"""The signing testkit script itself, driven end to end with a synthetic CA instead of a card."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from nodetide.cli.main import data_dir  # noqa: F401  (import check: the kit relies on it)
from nodetide.core.storage import Storage
from nodetide.eidas.issue import build_eidas_attestation
from tests.test_eidas import World

KIT = Path(__file__).resolve().parents[2] / "testkit" / "signing.py"


@pytest.fixture
def kit(tmp_path):
    home = tmp_path / "kit-home"
    env = {**os.environ, "TESTKIT_HOME": str(home), "TESTKIT_PYTHON": sys.executable,
           "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(tmp_path / "real-home")}

    def run(*args, input=None):
        return subprocess.run([sys.executable, str(KIT), *args], env=env, input=input, capture_output=True, text=True)

    run.home = home
    run.real_home = tmp_path / "real-home"
    return run


def test_steps_refuse_to_run_out_of_order(kit):
    for step in ("sign", "anchors", "verify", "report"):
        result = kit(step)
        assert result.returncode != 0 and "run ./testkit/run" in result.stderr, step


def test_claim_creates_an_isolated_identity_and_never_touches_the_real_home(kit):
    result = kit("claim", "--given", "Maria", "--family", "Ivanova")
    assert result.returncode == 0, result.stderr
    assert (kit.home / "data" / "nodetide.db").exists() and (kit.home / "out" / "claim.json").exists()
    assert oct((kit.home / "out").stat().st_mode & 0o777) == "0o700"
    assert not kit.real_home.exists() or not (kit.real_home / ".nodetide").exists()

    again = kit("claim", "--given", "Maria", "--family", "Ivanova")
    assert again.returncode != 0 and "already exists" in again.stderr
    assert kit("claim", "--given", "Maria", "--family", "Ivanova", "--force").returncode == 0


def test_full_pipeline_with_a_synthetic_certificate_and_a_report_without_names(kit):
    assert kit("claim", "--given", "Maria", "--family", "Ivanova").returncode == 0
    claim_id = json.loads((kit.home / "state.json").read_text())["claim_id"]

    # what `sign` would have written, made with the synthetic qualified certificate
    world = World()
    identity = Storage.open(kit.home / "data" / "nodetide.db").get_default_identity()
    attestation = build_eidas_attestation(identity.sigchain, identity.sigchain.get_claim(claim_id), world.signer)
    (kit.home / "out" / "attestation.json").write_text(json.dumps(attestation.to_dict()))
    anchors = kit.home / "anchors"
    anchors.mkdir()
    (anchors / "root.pem").write_bytes(world.root.cert.public_bytes(serialization.Encoding.PEM))

    verified = kit("verify", "--revocation", "off")
    assert verified.returncode == 0, verified.stderr + verified.stdout
    assert "valid" in verified.stdout and "matches (exact)" in verified.stdout

    report = kit("report", "--revocation", "off")
    assert report.returncode == 0, report.stderr
    out = report.stdout
    assert "qualified=True qscd=True" in out and "key=rsa-2048" in out
    assert "chain to saved anchors     : OK" in out and "match exact" in out
    assert "Test Qualified CA" in out  # the CA is not personal data
    for personal in ("Maria", "Ivanova", "PNOBG", attestation.subject, claim_id):
        assert personal not in out, f"the report leaked {personal!r}"

    # trusting some other root changes the verdict
    for pem in anchors.iterdir():
        pem.unlink()
    from tests import pki
    (anchors / "other.pem").write_bytes(pki.make_ca("Unrelated").cert.public_bytes(serialization.Encoding.PEM))
    assert kit("verify", "--revocation", "off").returncode != 0
    assert "FAIL (untrusted_certificate)" in kit("report", "--revocation", "off").stdout


def test_clean_removes_everything_personal(kit):
    kit("claim", "--given", "Maria", "--family", "Ivanova")
    (kit.home / "out" / "attestation.json").write_text("{}")
    assert kit("clean").returncode == 0
    for name in ("out", "data", "anchors", "state.json"):
        assert not (kit.home / name).exists(), name
