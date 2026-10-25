"""Turn a signer (PKCS#11 token or software key) and a claim into an eidas_qes attestation."""

from __future__ import annotations

import base64
import time

from nodetide.core.claims import Attestation
from nodetide.core.identity import ClaimRecord, Sigchain
from nodetide.eidas.certs import cert_facts
from nodetide.eidas.cms import Signer, create_cades_detached, verify_cades_detached
from nodetide.eidas.statement import StatementError, build_statement, parse_statement
from nodetide.eidas.verify import FORMAT, METHOD
from datetime import datetime, timezone

DEFAULT_VALID_DAYS = 90


def statement_for(
    chain: Sigchain, record: ClaimRecord, signer_not_after: datetime,
    valid_days: int = DEFAULT_VALID_DAYS, now: int | None = None,
) -> tuple[str, int, int]:
    """(statement text, signed_on, valid_until) for this claim at the chain's current head."""
    signed_on = int(time.time()) if now is None else now
    valid_until = min(signed_on + valid_days * 86400, int(signer_not_after.timestamp()))
    text = build_statement(
        chain.identity_hash or "", record.claim_id, record.claim_type, record.commitment,
        chain.head_hash or "", signed_on, valid_until,
    )
    return text, signed_on, valid_until


def attestation_from_signature(
    chain: Sigchain, record: ClaimRecord, statement_text: str, der: bytes
) -> Attestation:
    """Wrap an existing detached CAdES signature over `statement_text` as an attestation.

    Raises StatementError/CmsError if the statement is malformed, does not match
    this claim and chain, or the signature does not cover it. Trust in the
    certificate is decided later, by whoever verifies the attestation.
    """
    statement = parse_statement(statement_text)
    if (statement.identity, statement.claim_id, statement.claim_type, statement.commitment) != (
        chain.identity_hash, record.claim_id, record.claim_type, record.commitment,
    ):
        raise StatementError("the statement is about a different claim")
    if not any(e.event_hash() == statement.chain_head for e in chain.events):
        raise StatementError("the statement names a sigchain state this chain does not have")

    parsed = verify_cades_detached(der, statement_text.encode("utf-8"))
    facts = cert_facts(parsed.signer_cert)
    attestation = Attestation(
        subject=statement.identity,
        claim_id=record.claim_id,
        claim_type=record.claim_type,
        commitment=record.commitment,
        method=METHOD,
        assurance=facts.assurance,
        issued_at=statement.signed_on,
        expires_at=min(statement.valid_until, int(facts.not_after.timestamp())),
        chain_head=statement.chain_head,
        proof={"format": FORMAT, "statement": statement_text,
               "signature": base64.b64encode(der).decode("ascii")},
    )
    return Attestation.from_dict(attestation.to_dict())


def build_eidas_attestation(
    chain: Sigchain,
    record: ClaimRecord,
    signer: Signer,
    valid_days: int = DEFAULT_VALID_DAYS,
    now: int | None = None,
) -> Attestation:
    """Sign the claim statement with `signer` and wrap the signature as an attestation."""
    facts = cert_facts(signer.certificate)
    text, signed_on, _ = statement_for(chain, record, facts.not_after, valid_days, now)
    der = create_cades_detached(
        text.encode("utf-8"), signer, datetime.fromtimestamp(signed_on, tz=timezone.utc)
    )
    return attestation_from_signature(chain, record, text, der)
