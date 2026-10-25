"""The statement a person signs with their eID to ask ONE notary to attest SOME of their claims.

Unlike the single-claim statement it names the notary (so a copy that leaks cannot be used with anyone else) and
lists exactly the claims to attest, so what may be revealed is decided by what the person signs. It is
human readable and strictly canonical, like the single-claim statement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nodetide.eidas.statement import StatementError, format_time, parse_time

HEADER = "NODETIDE NOTARY STATEMENT v1"
FOOTER = (
    "By signing I ask the notary above to attest ONLY the claims listed here. It may read my\n"
    "certificate for that purpose only, and must not keep it or pass it on."
)
NOTARIZABLE = ("legal_name", "birthdate", "age_over_18")
MAX_CLAIMS = 5
_HASH = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


@dataclass(frozen=True)
class NotaryStatement:
    identity: str
    notary: str
    chain_head: str
    signed_on: int
    valid_until: int
    claims: tuple[tuple[str, str, str], ...]  # (claim id, claim type, commitment), sorted by claim id

    def text(self) -> str:
        return build_notary_statement(
            self.identity, self.notary, self.chain_head, self.signed_on, self.valid_until, self.claims)


def build_notary_statement(
    identity: str, notary: str, chain_head: str, signed_on: int, valid_until: int,
    claims: tuple[tuple[str, str, str], ...] | list[tuple[str, str, str]],
) -> str:
    for name, value in (("identity", identity), ("notary", notary), ("chain_head", chain_head)):
        if not _HASH.match(value):
            raise StatementError(f"invalid {name}")
    if valid_until <= signed_on:
        raise StatementError("valid_until must be after signed_on")
    if not 1 <= len(claims) <= MAX_CLAIMS:
        raise StatementError(f"between 1 and {MAX_CLAIMS} claims")
    ordered = sorted(claims)
    if len({c[0] for c in ordered}) != len(ordered):
        raise StatementError("a claim is listed twice")
    lines = [
        HEADER, f"Identity: {identity}", f"Notary: {notary}", f"Chain head: {chain_head}",
        f"Signed on: {format_time(signed_on)}", f"Valid until: {format_time(valid_until)}",
    ]
    for claim_id, claim_type, commitment in ordered:
        if not _CLAIM_ID.match(claim_id) or claim_type not in NOTARIZABLE or not _HASH.match(commitment):
            raise StatementError(f"invalid claim line for {claim_id!r}")
        lines.append(f"Claim: {claim_id} {claim_type} {commitment}")
    lines.append(FOOTER)
    return "\n".join(lines)


def parse_notary_statement(text: str) -> NotaryStatement:
    if not isinstance(text, str) or len(text) > 4096:
        raise StatementError("statement must be a short string")
    lines = text.split("\n")
    if len(lines) < 9 or lines[0] != HEADER:
        raise StatementError("not a Nodetide notary statement")
    fields: dict[str, str] = {}
    for key, line in zip(("Identity", "Notary", "Chain head", "Signed on", "Valid until"), lines[1:6]):
        if not line.startswith(f"{key}: "):
            raise StatementError(f"expected {key!r}")
        fields[key] = line[len(key) + 2:]
    claims = []
    for line in lines[6:-2]:
        parts = line.split(" ")
        if len(parts) != 4 or parts[0] != "Claim:":
            raise StatementError("malformed claim line")
        claims.append((parts[1], parts[2], parts[3]))
    try:
        statement = NotaryStatement(
            fields["Identity"], fields["Notary"], fields["Chain head"],
            parse_time(fields["Signed on"]), parse_time(fields["Valid until"]), tuple(claims))
        canonical = statement.text()
    except StatementError:
        raise
    except ValueError as e:
        raise StatementError(str(e)) from None
    if canonical != text:
        raise StatementError("statement is not in canonical form")
    return statement
