"""Verification of `eidas_qes` attestations: a CAdES signature over a claim statement."""

from __future__ import annotations

import base64
import binascii
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nodetide.core.claims import PROOF_VERIFIERS, Attestation, Check, ClaimDocument
from nodetide.core.identity import Sigchain
from nodetide.eidas.certs import ASSURANCE_ORDER, CertFacts, cert_facts, names_match, signer_names
from nodetide.eidas.cms import CmsError, ParsedCades, verify_cades_detached
from nodetide.eidas.statement import Statement, StatementError, parse_statement
from nodetide.eidas.validate import PathError, TrustStore, validate_signer_chain

METHOD = "eidas_qes"
FORMAT = "cades-detached"
MAX_SIGNATURE_BYTES = 256 * 1024
SIGNING_TIME_TOLERANCE = 600


@dataclass
class ProofSummary:
    """What a proof says, with the cryptography checked but trust NOT yet evaluated."""

    statement: Statement
    cades: ParsedCades
    facts: CertFacts


def _decode_proof(att: Attestation) -> tuple[str, bytes]:
    proof = att.proof or {}
    if proof.get("format") != FORMAT:
        raise CmsError(f"unsupported proof format: {proof.get('format')!r}")
    statement, signature = proof.get("statement"), proof.get("signature")
    if not isinstance(statement, str) or not isinstance(signature, str):
        raise CmsError("proof needs a statement and a signature")
    if len(signature) > MAX_SIGNATURE_BYTES * 4 // 3 + 8:
        raise CmsError("signature is too large")
    try:
        der = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        raise CmsError("signature is not valid base64") from None
    return statement, der


def inspect_proof(att: Attestation) -> ProofSummary:
    """Parse a proof and verify the signature itself. Raises CmsError/StatementError."""
    statement_text, der = _decode_proof(att)
    statement = parse_statement(statement_text)
    cades = verify_cades_detached(der, statement_text.encode("utf-8"))
    return ProofSummary(statement, cades, cert_facts(cades.signer_cert))


@dataclass
class EidasPolicy:
    """How strictly this node judges qualified-signature proofs."""

    store: TrustStore
    revocation_mode: str = "hard-fail"  # hard-fail | soft-fail | off
    allow_fetching: bool = True         # fetch OCSP/CRL and missing intermediates
    crls: tuple[bytes, ...] = ()

    def verify(self, att: Attestation, subject_chain: Sigchain, now: int) -> Check:
        if att.method != METHOD:
            return Check.fail("unsupported_method", f"Not an {METHOD} attestation")
        if att.evidence:
            return Check.fail("invalid_proof", "Proof-based attestations carry no evidence")
        try:
            summary = inspect_proof(att)
        except StatementError as e:
            return Check.fail("invalid_proof", f"Statement: {e}")
        except CmsError as e:
            return Check.fail("invalid_proof", str(e))

        s, facts = summary.statement, summary.facts
        if (s.identity, s.claim_id, s.claim_type, s.commitment, s.chain_head) != (
            att.subject, att.claim_id, att.claim_type, att.commitment, att.chain_head,
        ):
            return Check.fail("statement_mismatch", "The signed statement is about a different claim")
        if s.signed_on != att.issued_at or att.expires_at > s.valid_until:
            return Check.fail("statement_mismatch", "Attestation dates do not match the signed statement")
        if att.expires_at > int(facts.not_after.timestamp()):
            return Check.fail("statement_mismatch", "Attestation outlives the signer's certificate")
        signing_time = summary.cades.signing_time
        # Optional in CAdES-BES; when present it must agree with the statement.
        if signing_time is not None and abs(int(signing_time.timestamp()) - s.signed_on) > SIGNING_TIME_TOLERANCE:
            return Check.fail("invalid_proof", "Signing time does not match the statement")

        if not facts.non_repudiation:
            return Check.fail("not_qualified", "The certificate is not for signing documents")
        if ASSURANCE_ORDER[att.assurance] > ASSURANCE_ORDER[facts.assurance]:
            return Check.fail(
                "assurance_too_high",
                f"The certificate supports at most {facts.assurance!r} assurance",
            )

        try:
            validate_signer_chain(
                summary.cades.signer_cert, summary.cades.other_certs, self.store, now,
                self.revocation_mode, self.allow_fetching, self.crls,
            )
        except PathError as e:
            return Check.fail("untrusted_certificate", str(e))
        return Check(True)


def register(policy: EidasPolicy) -> None:
    """Make verify_attestation understand eidas_qes proofs, judged by `policy`."""
    PROOF_VERIFIERS[METHOD] = policy.verify


def policy_from_env() -> EidasPolicy | None:
    """NODETIDE_EIDAS_ANCHORS=<directory of PEM/DER CA certificates> enables the verifier.

    NODETIDE_EIDAS_REVOCATION=hard-fail|soft-fail|off (default hard-fail).
    """
    anchors = os.environ.get("NODETIDE_EIDAS_ANCHORS")
    if not anchors:
        return None
    mode = os.environ.get("NODETIDE_EIDAS_REVOCATION", "hard-fail")
    if mode not in ("hard-fail", "soft-fail", "off"):
        raise ValueError("NODETIDE_EIDAS_REVOCATION must be hard-fail, soft-fail or off")
    return EidasPolicy(TrustStore.from_directory(Path(anchors)), revocation_mode=mode)


@dataclass
class NameCheck:
    ok: bool
    how: str | None = None  # exact | transliterated
    reason: str | None = None


def check_legal_name(att: Attestation, document: ClaimDocument) -> NameCheck:
    """Does the disclosed legal name match the names in the signer's certificate?"""
    if att.claim_type != "legal_name" or document.claim_type != "legal_name":
        return NameCheck(False, reason="Not a legal_name claim")
    try:
        summary = inspect_proof(att)
    except (CmsError, StatementError) as e:
        return NameCheck(False, reason=str(e))
    given, surname = signer_names(summary.cades.signer_cert)
    value: dict[str, Any] = document.value
    first = names_match(value["given_name"], given)
    last = names_match(value["family_name"], surname)
    if first is None or last is None:
        return NameCheck(False, reason="The name does not match the signer's certificate")
    return NameCheck(True, "exact" if first == last == "exact" else "transliterated")
