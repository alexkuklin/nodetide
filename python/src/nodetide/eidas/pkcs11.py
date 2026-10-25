"""Sign with a certificate on a PKCS#11 token (smart card / USB eID token).

The private key never leaves the token: we send it the bytes to sign.

PINs
  * A PIN is requested through a callback at the moment it is needed, passed
    straight to the token driver, and never stored, logged or put in an error.
  * A PIN is tried at most once per run. A wrong PIN costs one of the card's few
    retries, so nothing here retries or guesses, and the token's retry flags are
    exposed so the caller can warn before the last attempt.
  * Cards such as the B-Trust / Gemalto IDPrime expose several slots, each with
    its own PIN (authentication vs. digital signature). Choosing the slot is the
    caller's job; this module never tries other slots on its own.
  * Qualified signing keys usually demand the PIN again for every signature
    (CKA_ALWAYS_AUTHENTICATE); that is handled with a context-specific login.

Needs the optional dependency PyKCS11 (pip install 'nodetide[eid]') and the
token vendor's PKCS#11 module (SafeNet/IDPrime middleware, OpenSC, ...).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from asn1crypto import algos, x509

from nodetide.eidas.certs import CertFacts, cert_facts

CANDIDATE_MODULES = (
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/libIDPrimePKCS11.dylib",
    "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
    "/usr/local/lib/libeToken.dylib",
    "/usr/lib/libIDPrimePKCS11.so",
    "/usr/lib/libeToken.so",
    "/Library/bit4id/pkcs11/libbit4ipki.dylib",
    "/usr/local/lib/libbit4ipki.dylib",
)

# DER prefixes of DigestInfo, for tokens that only offer raw RSA PKCS#1 v1.5 (CKM_RSA_PKCS)
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

PinProvider = Callable[[str], str]  # reason ("PIN for slot 16 ...") -> PIN


class Pkcs11Error(Exception):
    """Token, module or signing problem (never contains a PIN)."""


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


@dataclass(frozen=True)
class SlotInfo:
    """A token slot and its PIN state (read without logging in)."""

    slot: int
    label: str
    manufacturer: str
    model: str
    min_pin: int
    max_pin: int
    login_required: bool
    pin_locked: bool       # the PIN is blocked; it must be unblocked with the PUK
    pin_final_try: bool    # ONE attempt left: a wrong PIN locks the card
    pin_count_low: bool    # some attempts have already failed

    @property
    def looks_like_signature_slot(self) -> bool:
        """Cards label the digital-signature slot "... (Digital Signature)" (often cut to "(Dig")."""
        return "(dig" in self.label.lower() or "signature" in self.label.lower()


@dataclass
class TokenCertificate:
    """A certificate found on a token."""

    index: int
    slot: int
    label: str
    key_id: bytes
    certificate: x509.Certificate
    facts: CertFacts

    @property
    def subject(self) -> str:
        return str(self.certificate.subject.native.get("common_name") or "(no common name)")

    @property
    def usable_for_signing(self) -> bool:
        # The private key stays hidden until login, so only the certificate can be judged here.
        return self.facts.non_repudiation


class Pkcs11Token:
    """A loaded PKCS#11 module: slots and certificates, all readable without a PIN."""

    def __init__(self, module: str, pk11: Any = None):
        self.pk11 = pk11 or _load_pykcs11()
        self.module = module
        self.lib = self.pk11.PyKCS11Lib()
        try:
            self.lib.load(module)
            self._slot_ids = list(self.lib.getSlotList(tokenPresent=True))
        except self.pk11.PyKCS11Error as e:
            raise Pkcs11Error(f"cannot use the PKCS#11 module: {e}") from None
        if not self._slot_ids:
            raise Pkcs11Error("No token found. Is the card/USB token inserted and the reader recognised?")

    def slots(self) -> list[SlotInfo]:
        pk11, result = self.pk11, []
        for slot in self._slot_ids:
            info = self.lib.getTokenInfo(slot)
            flags = info.flags
            result.append(SlotInfo(
                slot=slot,
                label=info.label.strip(),
                manufacturer=info.manufacturerID.strip(),
                model=info.model.strip(),
                min_pin=info.ulMinPinLen,
                max_pin=info.ulMaxPinLen,
                login_required=bool(flags & pk11.CKF_LOGIN_REQUIRED),
                pin_locked=bool(flags & pk11.CKF_USER_PIN_LOCKED),
                pin_final_try=bool(flags & pk11.CKF_USER_PIN_FINAL_TRY),
                pin_count_low=bool(flags & pk11.CKF_USER_PIN_COUNT_LOW),
            ))
        return result

    def slot_info(self, slot: int) -> SlotInfo:
        for info in self.slots():
            if info.slot == slot:
                return info
        raise Pkcs11Error(f"Slot {slot} has no token (available: {self._slot_ids})")

    def certificates(self) -> list[TokenCertificate]:
        """Certificates on every slot (they are public objects), de-duplicated."""
        pk11, found, seen = self.pk11, [], set()
        for slot in self._slot_ids:
            try:
                session = self.lib.openSession(slot, pk11.CKF_SERIAL_SESSION)
            except pk11.PyKCS11Error:
                continue
            try:
                for obj in session.findObjects([(pk11.CKA_CLASS, pk11.CKO_CERTIFICATE)]):
                    value, key_id, label = session.getAttributeValue(
                        obj, [pk11.CKA_VALUE, pk11.CKA_ID, pk11.CKA_LABEL], allAsBinary=True)
                    der = bytes(value)
                    if der in seen:
                        continue
                    try:
                        cert = x509.Certificate.load(der)
                    except Exception:
                        continue
                    seen.add(der)
                    found.append(TokenCertificate(
                        index=len(found), slot=slot, label=bytes(label).decode("utf-8", "replace"),
                        key_id=bytes(key_id), certificate=cert, facts=cert_facts(cert),
                    ))
            finally:
                session.closeSession()
        return found

    @staticmethod
    def build_chain(leaf: x509.Certificate, candidates: list[x509.Certificate]) -> list[x509.Certificate]:
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

    def choose_certificate(self, index: int | None = None) -> TokenCertificate:
        certs = self.certificates()
        usable = [c for c in certs if c.usable_for_signing]
        if index is not None:
            entry = next((c for c in certs if c.index == index), None)
            if entry is None or not entry.usable_for_signing:
                raise Pkcs11Error("That certificate cannot be used for signing documents")
            return entry
        if not usable:
            raise Pkcs11Error("The token has no certificate usable for signing documents")
        qualified = [c for c in usable if c.facts.qualified]
        if len(qualified) == 1:
            return qualified[0]
        if len(usable) == 1:
            return usable[0]
        raise Pkcs11Error("Several signing certificates found; choose one with --cert")

    def signer(self, entry: TokenCertificate, slot: int, pin_provider: PinProvider,
               hash_alg: str = "sha256") -> Pkcs11Signer:
        """A signer for `entry` that logs in to `slot` (the slot holding the signing key)."""
        chain = self.build_chain(entry.certificate, [c.certificate for c in self.certificates()])
        return Pkcs11Signer(self, self.slot_info(slot), entry, chain, pin_provider, hash_alg)


class Pkcs11Signer:
    """A Signer (see nodetide.eidas.cms) backed by a token key. Call login() before signing."""

    def __init__(self, token: Pkcs11Token, slot: SlotInfo, entry: TokenCertificate,
                 chain: list[x509.Certificate], pin_provider: PinProvider, hash_alg: str = "sha256"):
        self._token, self._pk11 = token, token.pk11
        self.slot, self.entry, self.certificate = slot, entry, entry.certificate
        self.chain, self.hash_alg, self._pin_provider = chain, hash_alg, pin_provider
        self._session: Any = None
        self._key: Any = None
        self._always_authenticate = False

    # --- login -------------------------------------------------------------------------

    def _ask_pin(self, reason: str) -> str:
        pin = self._pin_provider(reason)
        if not self.slot.min_pin <= len(pin) <= self.slot.max_pin:
            # reject locally: it would not reach the card, but it would waste the user's time
            raise Pkcs11Error(
                f"The PIN must be {self.slot.min_pin} to {self.slot.max_pin} characters long")
        return pin

    def login(self) -> None:
        """Log in to the slot (one attempt) and locate the signing key. Raises Pkcs11Error."""
        pk11, slot = self._pk11, self.slot
        if slot.pin_locked:
            raise Pkcs11Error(f"The PIN of slot {slot.slot} is locked; unblock it with your PUK first")
        self._session = self._token.lib.openSession(slot.slot, pk11.CKF_SERIAL_SESSION)
        pin = self._ask_pin(f"PIN for slot {slot.slot} ({slot.label})")
        try:
            self._session.login(pin)
        except pk11.PyKCS11Error as e:
            if getattr(e, "value", None) != getattr(pk11, "CKR_USER_ALREADY_LOGGED_IN", object()):
                self.close()
                raise Pkcs11Error(_describe(pk11, e, "login failed")) from None
        finally:
            del pin  # drop our reference; the token holds the login now
        self._key = self._find_key()
        if self._key is None:
            self.close()
            raise Pkcs11Error(
                f"Logged in, but slot {slot.slot} holds no private key for this certificate. "
                "The signing key is probably on the other slot (with its own PIN); choose it with --slot."
            )
        try:
            (flag,) = self._session.getAttributeValue(self._key, [pk11.CKA_ALWAYS_AUTHENTICATE], allAsBinary=False)
            self._always_authenticate = bool(flag)
        except pk11.PyKCS11Error:
            self._always_authenticate = False  # attribute not supported: plain session login suffices

    def _find_key(self) -> Any:
        pk11, session = self._pk11, self._session
        wanted_class = (pk11.CKA_CLASS, pk11.CKO_PRIVATE_KEY)
        by_id = session.findObjects([wanted_class, (pk11.CKA_ID, tuple(self.entry.key_id))])
        if by_id:
            return by_id[0]
        # Some cards give the key and the certificate different ids: match on the RSA modulus.
        if self.certificate.public_key.algorithm == "rsa":
            modulus = int(self.certificate.public_key["public_key"].parsed["modulus"].native)
            width = (modulus.bit_length() + 7) // 8
            want = modulus.to_bytes(width, "big")
            for key in session.findObjects([wanted_class]):
                (found,) = session.getAttributeValue(key, [pk11.CKA_MODULUS], allAsBinary=True)
                if bytes(found) == want:
                    return key
        return None

    # --- signing -------------------------------------------------------------------------

    def _raw_sign(self, mechanism: Any, data: bytes) -> bytes:
        """C_SignInit, optional context-specific login, C_Sign (what Session.sign cannot do)."""
        pk11, session = self._pk11, self._session
        low, handle = session.lib, session.session
        native = mechanism.to_native()
        signature, payload = pk11.ckbytelist(), pk11.ckbytelist(data)
        rv = low.C_SignInit(handle, native, self._key)
        if rv != pk11.CKR_OK:
            raise pk11.PyKCS11Error(rv)
        if self._always_authenticate:
            pin = self._ask_pin(f"PIN to authorise this signature (slot {self.slot.slot})")
            try:
                rv = low.C_Login(handle, pk11.CKU_CONTEXT_SPECIFIC, pk11.ckbytelist(pin))
            finally:
                del pin
            if rv != pk11.CKR_OK:
                raise pk11.PyKCS11Error(rv)
        for _ in range(2):  # first call reports the size, second returns the signature
            rv = low.C_Sign(handle, payload, signature)
            if rv != pk11.CKR_OK:
                raise pk11.PyKCS11Error(rv)
        return bytes(signature)

    def sign(self, data: bytes) -> bytes:
        """Signature over `data` as required for a CMS signer: RSA PKCS#1 v1.5 or ECDSA (DER)."""
        pk11, alg = self._pk11, self.hash_alg
        if self._key is None:
            raise Pkcs11Error("Not logged in")
        try:
            if self.certificate.public_key.algorithm == "rsa":
                try:
                    return self._raw_sign(pk11.Mechanism(getattr(pk11, f"CKM_{alg.upper()}_RSA_PKCS"), None), data)
                except pk11.PyKCS11Error as e:
                    if getattr(e, "value", None) != getattr(pk11, "CKR_MECHANISM_INVALID", object()):
                        raise
                # The token cannot hash: do it here and send the DigestInfo for raw RSA.
                digest_info = _DIGEST_INFO[alg] + hashlib.new(alg, data).digest()
                return self._raw_sign(pk11.Mechanism(pk11.CKM_RSA_PKCS, None), digest_info)
            if self.certificate.public_key.algorithm == "ec":
                raw = self._raw_sign(pk11.Mechanism(pk11.CKM_ECDSA, None), hashlib.new(alg, data).digest())
                return algos.DSASignature.from_p1363(raw).dump()
        except pk11.PyKCS11Error as e:
            raise Pkcs11Error(_describe(pk11, e, "the token refused to sign")) from None
        raise Pkcs11Error("Unsupported key type on the token")

    def close(self) -> None:
        session, self._session, self._key = self._session, None, None
        if session is None:
            return
        for step in (session.logout, session.closeSession):
            try:
                step()
            except Exception:
                pass


def _describe(pk11: Any, error: Exception, fallback: str) -> str:
    """A short message for a PKCS#11 error that cannot contain a PIN."""
    code = getattr(error, "value", None)
    names = {
        getattr(pk11, "CKR_PIN_INCORRECT", None): "incorrect PIN",
        getattr(pk11, "CKR_PIN_LOCKED", None): "the PIN is now locked (too many wrong attempts)",
        getattr(pk11, "CKR_PIN_LEN_RANGE", None): "the PIN has an invalid length",
        getattr(pk11, "CKR_USER_NOT_LOGGED_IN", None): "not logged in",
        getattr(pk11, "CKR_TOKEN_NOT_PRESENT", None): "the token was removed",
        getattr(pk11, "CKR_FUNCTION_CANCELED", None): "the operation was cancelled",
    }
    return f"{fallback}: {names.get(code, f'PKCS#11 error {code}')}"
