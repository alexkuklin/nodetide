"""eID notary: reads a person's qualified-signature certificate so nobody else has to.

The person signs a notary statement (eidas/notary_statement.py) with their eID card and sends the signature, which
embeds the certificate and so the personal ID number, to THIS service only (the statement names it, and the
request is bound to the person's identity key). The notary

  1. checks the signature and the certificate chain against its own trust anchors,
  2. compares each listed claim with what the certificate says,
  3. issues one separate attestation per listed claim, signed by the service identity.

The attestations hold no certificate and no ID number, and they exist only for the claims the person listed: a
person who leaves "birthdate" out of the statement gets no birthdate attestation, and the notary never learns more
than it has to forget. The certificate is held in memory for the length of the request and never stored or logged.
"""

from __future__ import annotations

import asyncio
import time
from datetime import date, datetime, timezone
from typing import Callable

from nodetide.core.claims import Attestation, ClaimDocument
from nodetide.core.identity import Sigchain
from nodetide.eidas.certs import MATCH_STRENGTH, cert_birthdate, cert_facts, cert_names, match_legal_name
from nodetide.eidas.cms import CmsError, verify_cades_detached
from nodetide.eidas.notary_statement import NotaryStatement, parse_notary_statement
from nodetide.eidas.statement import StatementError
from nodetide.eidas.validate import PathError, validate_signer_chain
from nodetide.eidas.verify import SIGNING_TIME_TOLERANCE, EidasPolicy
from nodetide.verifiers.email_verifier import SlidingWindow, VerificationError
from nodetide.verifiers.issuer import NodeIssuer

METHOD = "eidas_notary"
MAX_STATEMENT_AGE = 3 * 86400   # a statement is for now, not for a file that has been lying around
ATTESTATION_DAYS = 90
PER_IDENTITY = (5, 3600)
GLOBAL = (30, 3600)
ADULT_YEARS = 18


def _years_between(born: date, today: date) -> int:
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


class EidNotary:
    claim_types = ("legal_name", "birthdate", "age_over_18")

    def __init__(
        self,
        issuer: NodeIssuer,
        policy: EidasPolicy,
        name_leniency: str = "transliterated",
        clock: Callable[[], float] = time.time,
    ):
        if name_leniency not in MATCH_STRENGTH:
            raise ValueError(f"unknown name leniency {name_leniency!r}")
        self.issuer, self.policy, self.name_leniency, self._clock = issuer, policy, name_leniency, clock
        self._by_identity = SlidingWindow(*PER_IDENTITY, clock)
        self._global = SlidingWindow(*GLOBAL, clock)

    def cleanup(self) -> None:
        self._by_identity.cleanup()
        self._global.cleanup()

    def describe(self) -> dict[str, object]:
        return {"method": METHOD, "claim_types": list(self.claim_types), "assurance": "high",
                "attest": "/api/verify/eid/attest"}

    async def attest(
        self, statement_text: str, signature: bytes, documents: list[ClaimDocument], chain: Sigchain
    ) -> list[Attestation]:
        now = int(self._clock())
        try:
            statement = parse_notary_statement(statement_text)
        except StatementError as e:
            raise VerificationError("invalid_statement", f"Statement: {e}") from None
        self._check_statement(statement, chain, now)
        if not (self._by_identity.allow(statement.identity) and self._global.allow("all")):
            raise VerificationError("rate_limited", "Too many requests, try again later", 429)

        try:
            parsed = verify_cades_detached(signature, statement_text.encode("utf-8"))
        except CmsError as e:
            raise VerificationError("invalid_signature", str(e)) from None
        facts = cert_facts(parsed.signer_cert)
        if parsed.signing_time is not None and abs(int(parsed.signing_time.timestamp()) - statement.signed_on) > SIGNING_TIME_TOLERANCE:
            raise VerificationError("invalid_signature", "Signing time does not match the statement")
        if not facts.non_repudiation:
            raise VerificationError("not_qualified", "The certificate is not for signing documents", 422)
        try:  # may fetch revocation data over the network: keep it off the event loop
            await asyncio.to_thread(
                validate_signer_chain, parsed.signer_cert, parsed.other_certs, self.policy.store, now,
                self.policy.revocation_mode, self.policy.allow_fetching, self.policy.crls)
        except PathError as e:
            raise VerificationError("untrusted_certificate", str(e), 422) from None

        by_id = {d.claim_id: d for d in documents}
        born = None
        out: list[Attestation] = []
        lifetime = min(ATTESTATION_DAYS * 86400, statement.valid_until - now, int(facts.not_after.timestamp()) - now)
        if lifetime <= 0:
            raise VerificationError("expired", "The statement or the certificate has expired", 422)
        for claim_id, claim_type, _ in statement.claims:
            record = chain.get_claim(claim_id)
            document = by_id.get(claim_id)
            if record is None or document is None or not document.matches(record):
                raise VerificationError("claim_mismatch", f"The document for claim {claim_id[:8]} does not match the chain")
            if record.status(now) != "active":
                raise VerificationError(f"claim_{record.status(now)}", "A listed claim is not active", 409)
            if claim_type == "legal_name":
                value = document.value
                how = match_legal_name(value["given_name"], value["family_name"], cert_names(parsed.signer_cert))
                if how is None or MATCH_STRENGTH[how] > MATCH_STRENGTH[self.name_leniency]:
                    raise VerificationError("name_mismatch", "The name does not match the certificate", 422)
            else:
                born = born or cert_birthdate(parsed.signer_cert)
                if born is None:
                    raise VerificationError("birthdate_unavailable", "This certificate does not state a date of birth", 422)
                if claim_type == "birthdate" and born.isoformat() != document.value:
                    raise VerificationError("birthdate_mismatch", "The birth date does not match the certificate", 422)
                if claim_type == "age_over_18" and _years_between(born, datetime.fromtimestamp(now, timezone.utc).date()) < ADULT_YEARS:
                    raise VerificationError("not_over_18", "The certificate holder is under 18", 422)
            out.append(self.issuer.issue(
                subject=statement.identity, record=record, chain_head=statement.chain_head, method=METHOD,
                assurance=facts.assurance, evidence={"source": "eidas_qes", "qscd": facts.qscd}, lifetime=lifetime))
        return out

    def _check_statement(self, statement: NotaryStatement, chain: Sigchain, now: int) -> None:
        if statement.notary != self.issuer.identity_hash:
            raise VerificationError("wrong_notary", "This statement names a different notary", 422)
        if statement.identity != chain.identity_hash:
            raise VerificationError("invalid_statement", "The statement is about a different identity")
        if not any(e.event_hash() == statement.chain_head for e in chain.events):
            raise VerificationError("invalid_statement", "The statement names a sigchain state this chain does not have")
        if statement.signed_on > now + SIGNING_TIME_TOLERANCE or now - statement.signed_on > MAX_STATEMENT_AGE:
            raise VerificationError("stale_statement", "The statement is not from the last few days; sign a fresh one", 422)
        if statement.valid_until <= now:
            raise VerificationError("expired", "The statement has expired", 422)
