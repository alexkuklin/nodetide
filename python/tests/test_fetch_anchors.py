"""deploy/test/fetch-anchors.py: published links with pinned fingerprints, cross-checked against the trusted list."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from nodetide.eidas.validate import PathError, TrustStore, validate_signer_chain
from tests import pki

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "test" / "fetch-anchors.py"
spec = importlib.util.spec_from_file_location("fetch_anchors", SCRIPT)
fa = importlib.util.module_from_spec(spec)
sys.modules["fetch_anchors"] = fa
spec.loader.exec_module(fa)

URL = "https://ca.example.org/repository/Qualified.crt"
TL_URL = "https://regulator.example.org/TSL.xml"


def der_of(ca) -> bytes:
    return ca.cert.public_bytes(serialization.Encoding.DER)


def trusted_list(*services) -> bytes:
    """services: (der, type, status)"""
    parts = "".join(
        f"""<TSPService><ServiceInformation>
<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/{kind}</ServiceTypeIdentifier>
<ServiceName><Name xml:lang="en">svc</Name></ServiceName>
<ServiceDigitalIdentity><DigitalId><X509Certificate>{base64.b64encode(der).decode()}</X509Certificate></DigitalId></ServiceDigitalIdentity>
<ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/{status}</ServiceStatus>
</ServiceInformation></TSPService>""" for der, kind, status in services)
    return f'<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><TrustServiceProviderList><TrustServiceProvider><TSPServices>{parts}</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>'.encode()


class Net:
    def __init__(self, files: dict[str, bytes]):
        self.files = files

    def __call__(self, url: str) -> bytes:
        if url not in self.files:
            raise OSError(f"unreachable: {url}")
        return self.files[url]


@pytest.fixture
def ca():
    return pki.make_ca("Test Qualified CA", path_length=0)


def config(ca, pin=None, tl=True):
    return {"trusted_list": TL_URL if tl else None, "anchors": [
        {"name": "Test Qualified CA", "url": URL, "sha256": pin or hashlib.sha256(der_of(ca)).hexdigest()}]}


def test_a_matching_download_is_written_as_pem(tmp_path, ca):
    logs = []
    net = Net({URL: der_of(ca), TL_URL: trusted_list((der_of(ca), "CA/QC", "granted"))})
    assert fa.run(config(ca), tmp_path, net, strict=True, log=logs.append) == 0
    written = list(tmp_path.glob("fetched-*.pem"))
    assert len(written) == 1 and written[0].read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert TrustStore.from_directory(tmp_path).anchors[0].dump() == der_of(ca)
    assert any("granted QC" in line for line in logs)


def test_pem_downloads_are_accepted_too(tmp_path, ca):
    net = Net({URL: fa.to_pem(der_of(ca)).encode()})
    assert fa.run(config(ca, tl=False), tmp_path, net) == 0 and len(list(tmp_path.iterdir())) == 1


def test_a_download_that_is_not_the_pinned_certificate_is_refused(tmp_path, ca):
    imposter = pki.make_ca("Test Qualified CA", path_length=0)  # same name, other key
    net = Net({URL: der_of(imposter)})
    assert fa.run(config(ca, tl=False), tmp_path, net) == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("junk", [b"", b"<html>moved</html>", b"\x30" + b"\x00" * 10])
def test_things_that_are_not_certificates_are_refused(tmp_path, ca, junk):
    assert fa.run(config(ca, tl=False), tmp_path, Net({URL: junk})) == 1 and list(tmp_path.iterdir()) == []


def test_only_https_links_are_fetched():
    with pytest.raises(fa.AnchorError):
        fa.default_fetch("http://ca.example.org/ca.crt")
    with pytest.raises(fa.AnchorError):
        fa.default_fetch("file:///etc/passwd")


@pytest.mark.parametrize("status", ["withdrawn", "recognisedatnationallevel", "deprecatedatnationallevel"])
def test_a_ca_the_trusted_list_does_not_grant_is_rejected_in_strict_mode(tmp_path, ca, status):
    net = Net({URL: der_of(ca), TL_URL: trusted_list((der_of(ca), "CA/QC", status))})
    assert fa.run(config(ca), tmp_path, net, strict=True) == 1 and list(tmp_path.iterdir()) == []
    assert fa.run(config(ca), tmp_path, net, strict=False) == 0  # without --strict it is only reported


def test_a_certificate_missing_from_the_trusted_list_is_rejected_in_strict_mode(tmp_path, ca):
    other = pki.make_ca("Other CA")
    net = Net({URL: der_of(ca), TL_URL: trusted_list((der_of(other), "CA/QC", "granted"))})
    assert fa.run(config(ca), tmp_path, net, strict=True) == 1


def test_one_certificate_backing_several_services_is_granted_if_any_is_a_granted_qc(tmp_path, ca):
    """B-Trust's list has the same CA certificate as a QC, a registration and an identity service."""
    der = der_of(ca)
    net = Net({URL: der, TL_URL: trusted_list((der, "RA/nothavingPKIid", "recognisedatnationallevel"), (der, "CA/QC", "granted"),
                                               (der, "Certstatus/OCSP", "granted"))})
    assert fa.run(config(ca), tmp_path, net, strict=True) == 0


def test_an_unreachable_trusted_list_does_not_block_pinned_certificates(tmp_path, ca):
    logs = []
    assert fa.run(config(ca), tmp_path, Net({URL: der_of(ca)}), strict=True, log=logs.append) == 0
    assert any("could not read the trusted list" in line for line in logs)


def test_certificates_the_list_no_longer_names_are_removed_but_other_files_are_not(tmp_path, ca):
    (tmp_path / "fetched-0123456789abcdef.pem").write_text("old")
    (tmp_path / "mine.pem").write_text("operator's own")
    assert fa.run(config(ca, tl=False), tmp_path, Net({URL: der_of(ca)})) == 0
    names = sorted(p.name for p in tmp_path.iterdir())
    assert "fetched-0123456789abcdef.pem" not in names and "mine.pem" in names


def test_a_failed_run_keeps_what_was_there(tmp_path, ca):
    assert fa.run(config(ca, tl=False), tmp_path, Net({URL: der_of(ca)})) == 0
    before = sorted(p.name for p in tmp_path.iterdir())
    assert fa.run(config(ca, pin="0" * 64, tl=False), tmp_path, Net({URL: der_of(ca)})) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_the_published_list_is_well_formed():
    import json

    data = json.loads((SCRIPT.parent / "trust-anchors.json").read_text())
    assert data["trusted_list"].startswith("https://")
    for entry in data["anchors"]:
        assert entry["url"].startswith("https://") and len(entry["sha256"]) == 64 and int(entry["sha256"], 16) >= 0


def test_an_intermediate_ca_can_be_the_trust_anchor():
    """The trusted list grants the qualified CA itself, not its root: that certificate must work as the anchor."""
    root = pki.make_ca("Root", path_length=1)
    inter = pki.make_ca("Operational Qualified CA", parent=root, path_length=0)
    leaf = pki.make_signer_cert(inter)
    store = TrustStore([inter.asn1])
    validate_signer_chain(leaf.asn1, [], store, int(time.time()), "off")
    stranger = pki.make_ca("Other Operational CA", parent=root, path_length=0)
    with pytest.raises(PathError):
        validate_signer_chain(pki.make_signer_cert(stranger).asn1, [], store, int(time.time()), "off")
