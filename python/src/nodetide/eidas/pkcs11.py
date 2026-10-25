"""Sign with a certificate on a PKCS#11 token (smart card / USB eID token).

The private key never leaves the token: we send it the bytes to sign. The PIN
is passed straight to the token driver and is never stored, logged or put in an
error message.

Needs the optional dependency PyKCS11 (pip install 'nodetide[eid]') and the
token vendor's PKCS#11 module, e.g. OpenSC's opensc-pkcs11 or the vendor's own
middleware library.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from asn1crypto import algos, x509

from nodetide.eidas.certs import CertFacts, cert_facts

CANDIDATE_MODULES = (
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
    "/usr/local/lib/libIDPrimePKCS11.dylib",
    "/usr/local/lib/libeToken.dylib",
    "/Library/bit4id/pkcs11/libbit4ipki.dylib",
    "/usr/local/lib/libbit4ipki.dylib",
)

# DER prefixes of DigestInfo, for tokens that only offer raw RSA PKCS#1 v1.5 (CKM_RSA_PKCS)
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class Pkcs11Error(Exception):
    """Token, module or signing problem (never contains the PIN)."""


def find_module(explicit: str | None = None) -> str:
    """The PKCS#11 module to use: explicit path, $NODETIDE_PKCS11_MODULE, or a known location."""
    for candidate in (explicit, os.environ.get("NODETIDE_PKCS11_MODULE"), *CANDIDATE_MODULES):
        if candidate and Path(candidate).is_file():
            return candidate
    raise Pkcs11Error(
        "No PKCS#11 module found. Install your eID vendor's middleware (or OpenSC) and pass "
        "--module /path/to/library, or set NODETIDE_PKCS11_MODULE."
    )


def _load_pykcs11() -> Any:
    try:
        import PyKCS11
    except ImportError:
        raise Pkcs11Error("PyKCS11 is not installed: pip install 'nodetide[eid]'") from None
    return PyKCS11


@dataclass
class TokenCertificate:
    """A certificate found on a token, with its private key's identifier."""

    index: int
    label: str
    key_id: bytes
    certificate: x509.Certificate
    facts: CertFacts
    has_private_key: bool

    @property
    def subject(self) -> str:
        return str(self.certificate.subject.native.get("common_name") or "(no common name)")

    @property
    def usable_for_signing(self) -> bool:
        return self.has_private_key and self.facts.non_repudiation


class Pkcs11Signer:
    """A Signer (see nodetide.eidas.cms) backed by a token certificate."""

    def __init__(self, session: Any, pk11: Any, entry: TokenCertificate, chain: list[x509.Certificate],
                 hash_alg: str = "sha256", pin: str | None = None, key: Any = None):
        self._session, self._pk11, self._pin = session, pk11, pin
        self.entry, self.certificate, self.chain, self.hash_alg = entry, entry.certificate, chain, hash_alg
        self._key = key

    # --- discovery ---------------------------------------------------------------

    @classmethod
    def open_session(cls, module: str, slot: int | None = None, pk11: Any = None) -> tuple[Any, Any, list[TokenCertificate], Any]:
        """Open the token and list its certificates. Returns (pk11, session, certs, lib)."""
        pk11 = pk11 or _load_pykcs11()
        lib = pk11.PyKCS11Lib()
        try:
            lib.load(module)
            slots = lib.getSlotList(tokenPresent=True)
        except pk11.PyKCS11Error as e:
            raise Pkcs11Error(f"cannot use the PKCS#11 module: {e}") from None
        if not slots:
            raise Pkcs11Error("No token found. Is the card/USB token inserted and the reader recognised?")
        if slot is None:
            slot = slots[0]
        elif slot not in slots:
            raise Pkcs11Error(f"Slot {slot} has no token (available: {list(slots)})")
        try:
            session = lib.openSession(slot, pk11.CKF_SERIAL_SESSION)
        except pk11.PyKCS11Error as e:
            raise Pkcs11Error(f"cannot open a session on slot {slot}: {e}") from None
        return pk11, session, cls._certificates(pk11, session), lib

    @staticmethod
    def _certificates(pk11: Any, session: Any) -> list[TokenCertificate]:
        key_ids = set()
        for obj in session.findObjects([(pk11.CKA_CLASS, pk11.CKO_PRIVATE_KEY)]):
            (key_id,) = session.getAttributeValue(obj, [pk11.CKA_ID], allAsBinary=True)
            key_ids.add(bytes(key_id))
        found: list[TokenCertificate] = []
        for obj in session.findObjects([(pk11.CKA_CLASS, pk11.CKO_CERTIFICATE)]):
            value, key_id, label = session.getAttributeValue(
                obj, [pk11.CKA_VALUE, pk11.CKA_ID, pk11.CKA_LABEL], allAsBinary=True)
            try:
                cert = x509.Certificate.load(bytes(value))
            except Exception:
                continue
            found.append(TokenCertificate(
                index=len(found), label=bytes(label).decode("utf-8", "replace"), key_id=bytes(key_id),
                certificate=cert, facts=cert_facts(cert), has_private_key=bytes(key_id) in key_ids,
            ))
        return found

    @classmethod
    def build_chain(cls, leaf: x509.Certificate, candidates: list[x509.Certificate]) -> list[x509.Certificate]:
        """Intermediate CA certificates from the token that lead from `leaf` towards a root."""
        chain: list[x509.Certificate] = []
        current = leaf
        while current.issuer != current.subject:
            parent = next(
                (c for c in candidates if c.subject == current.issuer and c not in chain and c is not current),
                None,
            )
            if parent is None or parent.subject == parent.issuer:
                break  # the root is the verifier's trust anchor, not ours to send
            chain.append(parent)
            current = parent
        return chain

    @classmethod
    def for_certificate(cls, module: str, entry_index: int | None = None, slot: int | None = None,
                        pin: str | None = None, hash_alg: str = "sha256", pk11: Any = None) -> Pkcs11Signer:
        pk11, session, certs, _ = cls.open_session(module, slot, pk11)
        usable = [c for c in certs if c.usable_for_signing]
        if entry_index is not None:
            entry = next((c for c in certs if c.index == entry_index), None)
            if entry is None or not entry.usable_for_signing:
                raise Pkcs11Error("That certificate cannot be used for signing documents")
        elif len(usable) == 1:
            entry = usable[0]
        elif not usable:
            raise Pkcs11Error("The token has no certificate usable for signing documents")
        else:
            raise Pkcs11Error("Several signing certificates found; choose one with --cert")
        chain = cls.build_chain(entry.certificate, [c.certificate for c in certs])
        signer = cls(session, pk11, entry, chain, hash_alg, pin)
        if pin is not None:
            signer.login(pin)
        return signer

    # --- signing -----------------------------------------------------------------------

    def login(self, pin: str) -> None:
        pk11 = self._pk11
        try:
            self._session.login(pin)
        except pk11.PyKCS11Error as e:
            if getattr(e, "value", None) == getattr(pk11, "CKR_USER_ALREADY_LOGGED_IN", object()):
                return
            raise Pkcs11Error(_describe(pk11, e, "PIN rejected or token locked")) from None
        self._pin = None  # the token holds the login now; do not keep the PIN around

    def _private_key(self) -> Any:
        if self._key is None:
            pk11 = self._pk11
            keys = self._session.findObjects(
                [(pk11.CKA_CLASS, pk11.CKO_PRIVATE_KEY), (pk11.CKA_ID, tuple(self.entry.key_id))])
            if not keys:
                raise Pkcs11Error("The token does not expose the private key for this certificate")
            self._key = keys[0]
        return self._key

    def sign(self, data: bytes) -> bytes:
        """Signature over `data` as required for a CMS signer: RSA PKCS#1 v1.5 or ECDSA (DER)."""
        pk11, key, alg = self._pk11, self._private_key(), self.hash_alg
        try:
            if self.certificate.public_key.algorithm == "rsa":
                mechanism = getattr(pk11, f"CKM_{alg.upper()}_RSA_PKCS")
                try:
                    return bytes(self._session.sign(key, data, pk11.Mechanism(mechanism, None)))
                except pk11.PyKCS11Error as e:
                    if getattr(e, "value", None) != getattr(pk11, "CKR_MECHANISM_INVALID", object()):
                        raise
                # The token cannot hash: do it here and send the DigestInfo for raw RSA.
                digest_info = _DIGEST_INFO[alg] + hashlib.new(alg, data).digest()
                return bytes(self._session.sign(key, digest_info, pk11.Mechanism(pk11.CKM_RSA_PKCS, None)))
            if self.certificate.public_key.algorithm == "ec":
                raw = bytes(self._session.sign(
                    key, hashlib.new(alg, data).digest(), pk11.Mechanism(pk11.CKM_ECDSA, None)))
                return algos.DSASignature.from_p1363(raw).dump()
        except pk11.PyKCS11Error as e:
            raise Pkcs11Error(_describe(pk11, e, "the token refused to sign")) from None
        raise Pkcs11Error("Unsupported key type on the token")

    def close(self) -> None:
        try:
            self._session.logout()
        except Exception:
            pass
        try:
            self._session.closeSession()
        except Exception:
            pass


def _describe(pk11: Any, error: Exception, fallback: str) -> str:
    """A short message for a PKCS#11 error that cannot contain a PIN."""
    code = getattr(error, "value", None)
    names = {
        getattr(pk11, "CKR_PIN_INCORRECT", None): "incorrect PIN",
        getattr(pk11, "CKR_PIN_LOCKED", None): "the PIN is locked (too many wrong attempts)",
        getattr(pk11, "CKR_PIN_LEN_RANGE", None): "the PIN has an invalid length",
        getattr(pk11, "CKR_USER_NOT_LOGGED_IN", None): "not logged in (this key may need the PIN for every signature)",
        getattr(pk11, "CKR_TOKEN_NOT_PRESENT", None): "the token was removed",
    }
    return f"{fallback}: {names.get(code, f'PKCS#11 error {code}')}"
