"""Collect the CA certificates behind a signer certificate, for the operator to review and trust.

A qualified certificate names where its issuer's certificate can be downloaded
(Authority Information Access). This follows those links up the chain so the
operator can compare the fingerprints with the ones the provider publishes and
only then save them as trust anchors. Fetching a certificate proves nothing by
itself: trust comes from the operator's check of the fingerprints.
"""

from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path
from typing import Callable

from asn1crypto import pem, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from nodetide.oidc.netguard import validate_source_url

MAX_CERT_BYTES = 200_000
MAX_DEPTH = 6
_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class AnchorError(Exception):
    pass


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.dump()).hexdigest()


def issuer_urls(cert: x509.Certificate) -> list[str]:
    """http(s) locations of the issuer's certificate, from the AIA extension."""
    urls = []
    for access in cert.authority_information_access_value or []:
        if access["access_method"].native == "ca_issuers":
            location = access["access_location"]
            if location.name == "uniform_resource_identifier":
                urls.append(location.native)
    return [u for u in urls if u.lower().startswith(("http://", "https://"))]


def default_fetch(url: str, allow_private: bool = False) -> bytes:
    if validate_source_url(url, allow_private) is None:
        raise AnchorError(f"refusing to fetch {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "nodetide-eid-anchors"})
    with urllib.request.urlopen(request, timeout=15) as response:
        data = response.read(MAX_CERT_BYTES + 1)
    if len(data) > MAX_CERT_BYTES:
        raise AnchorError("certificate download is too large")
    return data


def parse_certificate(data: bytes) -> x509.Certificate:
    if pem.detect(data):
        data = pem.unarmor(data)[2]
    return x509.Certificate.load(data)


def signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Did `issuer`'s key produce `cert`'s signature?"""
    if cert.issuer != issuer.subject:
        return False
    key = serialization.load_der_public_key(issuer.public_key.dump())
    hash_cls = _HASHES.get(cert.hash_algo)
    if hash_cls is None:
        return False
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert["signature_value"].native, cert["tbs_certificate"].dump(), padding.PKCS1v15(), hash_cls())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert["signature_value"].native, cert["tbs_certificate"].dump(), ec.ECDSA(hash_cls()))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def fetch_chain(
    cert: x509.Certificate,
    fetch: Callable[[str], bytes] = default_fetch,
    known: list[x509.Certificate] | None = None,
) -> list[x509.Certificate]:
    """Issuer certificates above `cert`, nearest first, each checked to have signed the one below.

    `known` are certificates already at hand (for example inside the signature); they are
    used before anything is downloaded.
    """
    chain: list[x509.Certificate] = []
    current, pool = cert, list(known or [])
    for _ in range(MAX_DEPTH):
        if current.issuer == current.subject:
            break  # a self-signed root: the top of the chain
        parent = next((c for c in pool if signed_by(current, c)), None)
        if parent is None:
            for url in issuer_urls(current):
                try:
                    candidate = parse_certificate(fetch(url))
                except Exception:
                    continue
                if signed_by(current, candidate):
                    parent = candidate
                    break
        if parent is None:
            break
        chain.append(parent)
        current = parent
    return chain


def write_anchors(certs: list[x509.Certificate], directory: str | Path) -> list[Path]:
    """Save certificates as PEM files named by fingerprint. Returns the paths."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for cert in certs:
        path = out / f"{fingerprint(cert)[:16]}.pem"
        path.write_bytes(pem.armor("CERTIFICATE", cert.dump()))
        written.append(path)
    return written
