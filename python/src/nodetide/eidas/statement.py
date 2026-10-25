"""The plain-text statement a person signs with their eID.

It is deliberately human readable (a signing application can show it as is) and
strictly canonical: parse_statement accepts only text that build_statement could
have produced, so there is exactly one valid encoding of any set of fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

HEADER = "NODETIDE CLAIM STATEMENT v1"
FOOTER = (
    "By signing I confirm that I control the Nodetide identity above and that\n"
    "this claim's value is mine."
)
_ORDER = ("Identity", "Claim", "Type", "Commitment", "Chain head", "Signed on", "Valid until")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_TYPE = re.compile(r"^(?:[a-z_]{1,32}|x-[a-z0-9]{1,32}:[a-z0-9_]{1,48})$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class StatementError(ValueError):
    """The text is not a valid Nodetide claim statement."""


def format_time(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> int:
    if not _TIME.match(text):
        raise StatementError("malformed timestamp")
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


@dataclass(frozen=True)
class Statement:
    identity: str
    claim_id: str
    claim_type: str
    commitment: str
    chain_head: str
    signed_on: int
    valid_until: int

    def text(self) -> str:
        return build_statement(
            self.identity, self.claim_id, self.claim_type, self.commitment,
            self.chain_head, self.signed_on, self.valid_until,
        )


def build_statement(
    identity: str,
    claim_id: str,
    claim_type: str,
    commitment: str,
    chain_head: str,
    signed_on: int,
    valid_until: int,
) -> str:
    for name, value, pattern in (
        ("identity", identity, _HASH), ("claim_id", claim_id, _CLAIM_ID),
        ("claim_type", claim_type, _TYPE), ("commitment", commitment, _HASH),
        ("chain_head", chain_head, _HASH),
    ):
        if not pattern.match(value):
            raise StatementError(f"invalid {name}")
    if valid_until <= signed_on:
        raise StatementError("valid_until must be after signed_on")
    lines = [
        HEADER,
        f"Identity: {identity}",
        f"Claim: {claim_id}",
        f"Type: {claim_type}",
        f"Commitment: {commitment}",
        f"Chain head: {chain_head}",
        f"Signed on: {format_time(signed_on)}",
        f"Valid until: {format_time(valid_until)}",
        FOOTER,
    ]
    return "\n".join(lines)


def parse_statement(text: str) -> Statement:
    if not isinstance(text, str) or len(text) > 2048:
        raise StatementError("statement must be a short string")
    lines = text.split("\n")
    if len(lines) != 2 + len(_ORDER) + 1 or lines[0] != HEADER:
        raise StatementError("not a Nodetide claim statement")
    fields: dict[str, str] = {}
    for key, line in zip(_ORDER, lines[1 : 1 + len(_ORDER)]):
        prefix = f"{key}: "
        if not line.startswith(prefix):
            raise StatementError(f"expected {key!r}")
        fields[key] = line[len(prefix):]
    try:
        statement = Statement(
            identity=fields["Identity"], claim_id=fields["Claim"], claim_type=fields["Type"],
            commitment=fields["Commitment"], chain_head=fields["Chain head"],
            signed_on=parse_time(fields["Signed on"]), valid_until=parse_time(fields["Valid until"]),
        )
        canonical = statement.text()
    except StatementError:
        raise
    except ValueError as e:
        raise StatementError(str(e)) from None
    if canonical != text:  # catches altered footer text, stray whitespace, odd line endings
        raise StatementError("statement is not in canonical form")
    return statement
