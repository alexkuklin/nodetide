"""Certificate path validation against operator-supplied trust anchors."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Coroutine, Iterable

from asn1crypto import pem, x509
from pyhanko_certvalidator import CertificateValidator, ValidationContext


class TrustStoreError(ValueError):
    pass


@dataclass
class TrustStore:
    """Root (and optionally intermediate) CA certificates the operator trusts for QES.

    For qualified signatures these come from the EU trusted lists
    (https://eidas.ec.europa.eu/efda/tl-browser): the qualified trust service
    providers' CA certificates, per member state.
    """

    anchors: list[x509.Certificate] = field(default_factory=list)

    @classmethod
    def from_directory(cls, path: str | Path) -> TrustStore:
        directory = Path(path)
        if not directory.is_dir():
            raise TrustStoreError(f"{directory} is not a directory")
        anchors: list[x509.Certificate] = []
        for file in sorted(directory.iterdir()):
            if file.suffix.lower() not in (".pem", ".crt", ".cer", ".der"):
                continue
            data = file.read_bytes()
            try:
                if pem.detect(data):
                    anchors.extend(x509.Certificate.load(der) for _, _, der in pem.unarmor(data, multiple=True))
                else:
                    anchors.append(x509.Certificate.load(data))
            except Exception as e:
                raise TrustStoreError(f"cannot read certificate {file.name}: {type(e).__name__}") from None
        if not anchors:
            raise TrustStoreError(f"no certificates found in {directory}")
        return cls(anchors)


class PathError(Exception):
    """The certificate is not valid or not trusted."""


def run_blocking(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run a coroutine to completion from sync code, even inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _validate(
    cert: x509.Certificate,
    others: Iterable[x509.Certificate],
    store: TrustStore,
    moment: datetime,
    revocation_mode: str,
    allow_fetching: bool,
    crls: Iterable[bytes] = (),
) -> None:
    context = ValidationContext(
        trust_roots=store.anchors,
        other_certs=list(others),
        moment=moment,
        allow_fetching=allow_fetching,
        crls=list(crls) or None,
        revocation_mode=revocation_mode,
    )
    validator = CertificateValidator(cert, intermediate_certs=list(others), validation_context=context)
    await validator.async_validate_usage({"non_repudiation"})


def validate_signer_chain(
    cert: x509.Certificate,
    others: Iterable[x509.Certificate],
    store: TrustStore,
    now: int,
    revocation_mode: str = "hard-fail",
    allow_fetching: bool = True,
    crls: Iterable[bytes] = (),
) -> None:
    """Raise PathError unless `cert` chains to a trust anchor and is valid (and, depending
    on revocation_mode, not revoked) at `now`.

    revocation_mode: "hard-fail" (revocation status must be known), "soft-fail"
    (check if available) or "off" (no revocation information is consulted).

    Two phases, because the certificate comes from a stranger and names URLs
    (OCSP, CRL, issuer): first trust is established with NO network access, so a
    fake certificate cannot make this node fetch anything; only a certificate
    that already chains to an operator-supplied anchor gets its revocation
    information fetched, from URLs a real CA put there.
    """
    moment = datetime.fromtimestamp(now, tz=timezone.utc)
    others = list(others)
    try:
        run_blocking(_validate(cert, others, store, moment, "soft-fail", False, ()))
        if revocation_mode != "off":
            run_blocking(_validate(cert, others, store, moment, revocation_mode, allow_fetching, crls))
    except Exception as e:
        # Messages from the validator describe certificates, not secrets; keep them short.
        raise PathError(f"{type(e).__name__}: {str(e)[:200]}") from None
