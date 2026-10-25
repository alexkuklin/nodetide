"""What a signer certificate says: qualified status, QSCD, key usage, names.

QCStatements follow ETSI EN 319 412-5; the statement ids below are the ones that
decide whether a certificate is a qualified certificate for electronic
signatures created on a qualified signature creation device.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import core, x509

QC_STATEMENTS_OID = "1.3.6.1.5.5.7.1.3"
QC_COMPLIANCE = "0.4.0.1862.1.1"
QC_SSCD = "0.4.0.1862.1.4"
QC_TYPE = "0.4.0.1862.1.6"
QC_TYPE_ESIGN = "0.4.0.1862.1.6.1"

ASSURANCE_ORDER = {"low": 0, "substantial": 1, "high": 2}


class QCStatement(core.Sequence):
    _fields = [
        ("statement_id", core.ObjectIdentifier),
        ("statement_info", core.Any, {"optional": True}),
    ]


class QCStatements(core.SequenceOf):
    _child_spec = QCStatement


class QcTypes(core.SequenceOf):
    _child_spec = core.ObjectIdentifier


@dataclass(frozen=True)
class CertFacts:
    qualified: bool        # carries the QcCompliance statement
    qscd: bool             # private key is on a qualified signature creation device
    esign: bool            # qualified for electronic signatures (default when QcType is absent)
    non_repudiation: bool  # keyUsage contentCommitment
    not_after: datetime
    not_before: datetime
    country: str | None
    issuer_name: str       # CA's common name (not personal data)

    @property
    def assurance(self) -> str:
        """The assurance this certificate can support (the signer's identity proofing aside)."""
        if not self.non_repudiation:
            return "low"
        if self.qualified and self.esign and self.qscd:
            return "high"
        if self.qualified and self.esign:
            return "substantial"
        return "low"


def _extension(cert: x509.Certificate, oid: str):
    for ext in cert["tbs_certificate"]["extensions"] or []:
        if ext["extn_id"].dotted == oid:
            return ext
    return None


def cert_facts(cert: x509.Certificate) -> CertFacts:
    qualified = qscd = False
    esign = True  # ETSI: an absent QcType means electronic signature
    ext = _extension(cert, QC_STATEMENTS_OID)
    if ext is not None:
        statements = QCStatements.load(ext["extn_value"].contents)
        for statement in statements:
            oid = statement["statement_id"].dotted
            if oid == QC_COMPLIANCE:
                qualified = True
            elif oid == QC_SSCD:
                qscd = True
            elif oid == QC_TYPE:
                types = statement["statement_info"].parse(QcTypes)
                esign = QC_TYPE_ESIGN in {t.dotted for t in types}

    usage = cert.key_usage_value.native if cert.key_usage_value is not None else []
    validity = cert["tbs_certificate"]["validity"]
    subject = cert.subject.native
    return CertFacts(
        qualified=qualified,
        qscd=qscd,
        esign=esign,
        non_repudiation="non_repudiation" in usage,
        not_after=validity["not_after"].native,
        not_before=validity["not_before"].native,
        country=subject.get("country_name"),
        issuer_name=str(cert.issuer.native.get("common_name") or cert.issuer.human_friendly),
    )


@dataclass(frozen=True)
class CertNames:
    """Name fields of a signer certificate, as qualified CAs actually issue them.

    Typically givenName and surname are present and the common name is the full
    name, possibly with a middle name or patronymic ("ALEXEY IVANOVICH SMIRNOV").
    """

    given: str | None
    surname: str | None
    common_name: str | None

    def _surname(self) -> str:
        if self.surname:
            return self.surname.strip()
        parts = (self.common_name or "").split()
        return parts[-1] if len(parts) > 1 else ""

    def given_candidates(self) -> list[str]:
        """Acceptable readings of a given name: givenName, and the CN minus the surname."""
        candidates = [self.given] if self.given else []
        cn, surname = (self.common_name or "").strip(), self._surname()
        if cn and surname and _fold(cn).endswith(_fold(surname)):
            rest = cn[: len(cn) - len(surname)].strip()
            if rest and rest not in candidates:
                candidates.append(rest)
        return candidates

    def family_candidates(self) -> list[str]:
        surname = self._surname()
        return [surname] if surname else []


def cert_names(cert: x509.Certificate) -> CertNames:
    subject = cert.subject.native
    return CertNames(subject.get("given_name"), subject.get("surname"), subject.get("common_name"))


def signer_names(cert: x509.Certificate) -> tuple[str | None, str | None]:
    """(given name, surname) from the certificate subject, if present."""
    names = cert_names(cert)
    return names.given, names.surname


# Bulgarian "Streamlined System" (Law on the Transliteration, 2009), used because
# qualified certificates often carry the Latin spelling of a Cyrillic name.
_BG = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ж": "zh", "з": "z", "и": "i",
    "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s",
    "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sht",
    "ъ": "a", "ь": "y", "ю": "yu", "я": "ya",
}

MATCH_STRENGTH = {"exact": 0, "transliterated": 1, "approximate": 2}


def _fold(text: str) -> str:
    return unicodedata.normalize("NFC", text).strip().casefold()


def transliterate_bg(text: str) -> str:
    folded = _fold(text)
    out = "".join(_BG.get(ch, ch) for ch in folded)
    # a final "-ия" is "-ia" in the official system
    if folded.endswith("ия") and out.endswith("iya"):
        out = out[:-3] + "ia"
    return out


def _loose(text: str) -> str:
    """Spelling-insensitive key: Latin spellings of one name differ in x/ks, j/y, ia/ya, ..."""
    out = transliterate_bg(text)
    for old, new in (("x", "ks"), ("j", "y"), ("w", "v"), ("ya", "ia"), ("yu", "iu"), ("ye", "e"),
                     ("ii", "i"), ("yy", "y"), ("iy", "y"), ("ey", "ei"), ("ay", "ai"), ("oy", "oi")):
        out = out.replace(old, new)
    out = "".join(ch for ch in out if ch.isalpha())
    return "".join(ch for i, ch in enumerate(out) if i == 0 or ch != out[i - 1])  # double letters


def names_match(claimed: str, certified: str | None) -> str | None:
    """How a claimed name part relates to the certificate's: exact | transliterated | approximate | None."""
    if not certified:
        return None
    if _fold(claimed) == _fold(certified):
        return "exact"
    if transliterate_bg(claimed) == _fold(certified) or _fold(claimed) == transliterate_bg(certified):
        return "transliterated"
    if _loose(claimed) and _loose(claimed) == _loose(certified):
        return "approximate"
    return None


def match_legal_name(given: str, family: str, names: CertNames) -> str | None:
    """The weakest match strength needed for both name parts to agree, or None."""
    firsts = [m for m in (names_match(given, c) for c in names.given_candidates()) if m]
    lasts = [m for m in (names_match(family, c) for c in names.family_candidates()) if m]
    if not firsts or not lasts:
        return None
    best_first = min(firsts, key=MATCH_STRENGTH.__getitem__)
    best_last = min(lasts, key=MATCH_STRENGTH.__getitem__)
    return max(best_first, best_last, key=MATCH_STRENGTH.__getitem__)
