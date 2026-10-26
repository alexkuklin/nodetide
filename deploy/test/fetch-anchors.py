#!/usr/bin/env python3
"""Fetch the eID trust anchors listed in trust-anchors.json.

The list holds LINKS to where the certificate authorities publish their certificates, each with the SHA-256 fingerprint
it must have. A download is refused unless it matches, so a hijacked mirror or a changed file cannot slip in; the pins
were checked against the EU trusted list of the country (a service of type QC with status "granted"). Every run repeats
that check against the live trusted list when it can be reached and stops if a pinned certificate is no longer granted
(--strict), because a withdrawn CA must not be trusted.

    ./fetch-anchors.py [--out anchors] [--strict]        # then docker compose up -d verifier

The files are written as fetched-<fingerprint>.pem; ones written by an earlier run that the list no longer names are removed.
Nothing else in the output directory is touched. Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import textwrap
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
MAX_BYTES = 200_000
TL = "{http://uri.etsi.org/02231/v2#}"


class AnchorError(Exception):
    pass


def default_fetch(url: str) -> bytes:
    if not url.lower().startswith("https://"):
        raise AnchorError(f"{url}: only https links are fetched")
    request = urllib.request.Request(url, headers={"User-Agent": "nodetide-fetch-anchors"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(10_000_000 if url.endswith(".xml") else MAX_BYTES + 1)
    if len(data) > (10_000_000 if url.endswith(".xml") else MAX_BYTES):
        raise AnchorError(f"{url}: download is too large")
    return data


def to_der(data: bytes) -> bytes:
    """A certificate as DER, given PEM or DER."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        body = data.split(b"-----BEGIN CERTIFICATE-----", 1)[1].split(b"-----END CERTIFICATE-----", 1)[0]
        data = base64.b64decode(b"".join(body.split()), validate=True)
    if len(data) < 64 or data[0] != 0x30:
        raise AnchorError("not a DER certificate")
    return data


def to_pem(der: bytes) -> str:
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64)) + "\n-----END CERTIFICATE-----\n"


def trusted_list_services(xml_bytes: bytes) -> dict[str, list[tuple[str, str, str]]]:
    """sha256 of every service certificate in a trusted list -> its services (name, short type, short status).

    One certificate can back several services (qualified certificates, registration, identity proofing).
    """
    ns = {"t": TL[1:-1]}
    found: dict[str, list[tuple[str, str, str]]] = {}
    for info in ET.fromstring(xml_bytes).iter(TL + "ServiceInformation"):
        kind = (info.findtext("t:ServiceTypeIdentifier", namespaces=ns) or "").rsplit("/", 1)[-1]
        status = (info.findtext("t:ServiceStatus", namespaces=ns) or "").rsplit("/", 1)[-1]
        name = info.findtext("t:ServiceName/t:Name", namespaces=ns) or ""
        for cert in info.iter(TL + "X509Certificate"):
            try:
                found.setdefault(hashlib.sha256(base64.b64decode(cert.text or "")).hexdigest(), []).append((name, kind, status))
            except ValueError:
                continue
    return found


def run(config: dict, out: Path, fetch: Callable[[str], bytes] = default_fetch, strict: bool = False,
        log: Callable[[str], None] = print) -> int:
    problems = 0
    entries = config.get("anchors", [])
    if not entries:
        raise AnchorError("the list has no anchors")
    out.mkdir(parents=True, exist_ok=True)

    services: dict[str, list[tuple[str, str, str]]] | None = None
    if config.get("trusted_list"):
        try:
            services = trusted_list_services(fetch(config["trusted_list"]))
        except Exception as e:  # unreachable or malformed: the pins still protect, say so
            log(f"warning: could not read the trusted list ({type(e).__name__}); relying on the pinned fingerprints only")

    wanted: set[str] = set()
    for entry in entries:
        name, pin = entry["name"], entry["sha256"].lower()
        try:
            der = to_der(fetch(entry["url"]))
        except Exception as e:
            log(f"FAIL  {name}: {e}")
            problems += 1
            continue
        actual = hashlib.sha256(der).hexdigest()
        if actual != pin:
            log(f"FAIL  {name}: fingerprint {actual} is not the pinned {pin} (refusing it)")
            problems += 1
            continue
        status, trusted = "not checked", True
        if services is not None:
            hits = services.get(actual, [])
            if any(kind.endswith("QC") and state == "granted" for _, kind, state in hits):
                status = "trusted list: granted QC"
            else:
                status = "NOT a granted QC service in the trusted list" + (
                    f" (listed as: {', '.join(f'{k}/{s}' for _, k, s in hits)})" if hits else "")
                trusted = not strict
        if not trusted:
            log(f"FAIL  {name}: {status}; a CA the list does not grant must not be trusted")
            problems += 1
            continue
        target = out / f"fetched-{actual[:16]}.pem"
        target.write_text(to_pem(der))
        wanted.add(target.name)
        log(f"ok    {name}  sha256={actual[:16]}...  [{status}]")

    for old in out.glob("fetched-*.pem"):
        if old.name not in wanted and problems == 0:
            old.unlink()
            log(f"removed {old.name} (no longer in the list)")
    return problems


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Fetch the eID trust anchors listed in trust-anchors.json")
    parser.add_argument("--list", default=str(HERE / "trust-anchors.json"))
    parser.add_argument("--out", default=str(HERE / "anchors"))
    parser.add_argument("--strict", action="store_true", help="fail unless every anchor is a granted QC service in the trusted list")
    args = parser.parse_args(argv)
    try:
        problems = run(json.loads(Path(args.list).read_text()), Path(args.out), strict=args.strict)
    except (OSError, ValueError, KeyError, AnchorError) as e:
        raise SystemExit(f"cannot use the anchor list: {e}") from None
    if problems:
        raise SystemExit(f"{problems} problem(s); the trust anchors were NOT updated where it failed")
    print(f"done: {args.out}")


if __name__ == "__main__":
    main()
