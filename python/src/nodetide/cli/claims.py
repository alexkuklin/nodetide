"""CLI: `nodetide claim ...` (make and manage claims) and `nodetide eid ...` (eID signatures)."""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import click
from asn1crypto import pem

from nodetide.core.claims import Attestation, ClaimDocument, ClaimError, verify_attestation
from nodetide.core.identity import ClaimRecord, Identity, Sigchain
from nodetide.core.storage import Storage


def _storage() -> Storage:
    return Storage.open(Path.home() / ".nodetide" / "nodetide.db")


def _claims_dir(storage: Storage) -> Path:
    path = storage.db_path.parent / "claims"
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, data: str) -> None:
    """Write a file only the current user can read (claim documents hold salts and values)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)


def _default(storage: Storage) -> Identity:
    identity = storage.get_default_identity()
    if identity is None:
        raise click.ClickException("No default identity. Create one with: nodetide identity create")
    return identity


def _record(identity: Identity, claim_id: str) -> ClaimRecord:
    record = identity.sigchain.get_claim(claim_id)
    if record is None:
        raise click.ClickException(f"No claim {claim_id} on the default identity")
    return record


def _load_document(storage: Storage, claim_id: str) -> ClaimDocument:
    path = _claims_dir(storage) / f"{claim_id}.json"
    if not path.is_file():
        raise click.ClickException(f"The claim document for {claim_id} is not stored here ({path})")
    try:
        return ClaimDocument.from_dict(json.loads(path.read_text()))
    except (ClaimError, ValueError) as e:
        raise click.ClickException(f"Unreadable claim document: {e}") from None


@click.group()
def claim():
    """Make claims about your identity (email, phone, legal name)."""


@claim.command("add")
@click.option("--type", "claim_type", type=click.Choice(["email", "phone", "legal_name"]), required=True)
@click.option("--email")
@click.option("--phone", help="International format, e.g. +359881234567")
@click.option("--given", help="Given name (legal_name)")
@click.option("--family", help="Family name (legal_name)")
@click.option("--expires-days", type=int, help="Make the claim expire after this many days")
def claim_add(claim_type: str, email: str | None, phone: str | None, given: str | None,
              family: str | None, expires_days: int | None):
    """Record a claim on your sigchain. Only a commitment goes on the chain; the value stays here."""
    value: Any
    if claim_type == "email":
        value = email
    elif claim_type == "phone":
        value = phone
    else:
        value = {"given_name": given, "family_name": family} if given and family else None
    if value is None:
        raise click.UsageError(f"Provide the value for a {claim_type} claim (see --help)")

    storage = _storage()
    identity = _default(storage)
    try:
        document = ClaimDocument.create(identity.identity_hash or "", claim_type, value)
    except ClaimError as e:
        raise click.ClickException(str(e)) from None
    expires = int(time.time()) + expires_days * 86400 if expires_days else None
    identity.add_claim(document.claim_id, claim_type, document.commitment, expires=expires)
    assert identity.sigchain.verify()[0]
    storage.save_sigchain(identity.sigchain)
    path = _claims_dir(storage) / f"{document.claim_id}.json"
    _write_private(path, json.dumps(document.to_dict(), indent=2, ensure_ascii=False))
    storage.close()

    click.echo(f"Claim {document.claim_id} ({claim_type}) recorded on your sigchain.")
    click.echo(f"Value and salt are kept private in {path}")
    click.echo("Share that file only with parties you want to reveal the value to.")


@claim.command("list")
def claim_list():
    """List your claims."""
    storage = _storage()
    identity = _default(storage)
    held = {p.stem for p in _claims_dir(storage).glob("*.json")}
    attestations = storage.list_attestations(subject=identity.identity_hash, limit=500)
    for record in identity.sigchain.get_claims():
        count = sum(1 for a in attestations if a["attestation"]["claim_id"] == record.claim_id)
        click.echo(f"{record.claim_id}  {record.claim_type:<11} {record.status():<8} "
                   f"document: {'held' if record.claim_id in held else 'not here'}  attestations: {count}")
    if not identity.sigchain.get_claims():
        click.echo("No claims.")
    storage.close()


@claim.command("revoke")
@click.argument("claim_id")
@click.option("--reason")
def claim_revoke(claim_id: str, reason: str | None):
    """Withdraw a claim."""
    storage = _storage()
    identity = _default(storage)
    _record(identity, claim_id)
    identity.revoke_claim(claim_id, reason)
    storage.save_sigchain(identity.sigchain)
    storage.close()
    click.echo(f"Claim {claim_id} revoked.")


@claim.command("export")
@click.argument("claim_id")
@click.option("--out", "-o", type=click.Path(dir_okay=False), help="Write to a file instead of stdout")
def claim_export(claim_id: str, out: str | None):
    """Print the claim document (reveals the value and salt)."""
    storage = _storage()
    text = json.dumps(_load_document(storage, claim_id).to_dict(), indent=2, ensure_ascii=False)
    storage.close()
    if out:
        _write_private(Path(out), text)
        click.echo(f"Written to {out}")
    else:
        click.echo(text)


# --- eID ----------------------------------------------------------------------------------------------


@click.group()
def eid():
    """Prove a claim with an eIDAS qualified electronic signature."""


def _read_signature(path: str) -> bytes:
    raw = Path(path).read_bytes()
    if pem.detect(raw):
        return pem.unarmor(raw)[2]
    if raw[:1] == b"\x30":
        return raw
    try:
        return base64.b64decode(raw, validate=False)
    except Exception:
        raise click.ClickException("The signature file is neither DER, PEM nor base64") from None


def _save_attestation(storage: Storage, attestation: Attestation, out: str) -> None:
    _write_private(Path(out), json.dumps(attestation.to_dict(), indent=2))


def _describe(attestation: Attestation) -> None:
    from nodetide.eidas.verify import inspect_proof

    summary = inspect_proof(attestation)
    facts = summary.facts
    click.echo(f"  assurance:   {attestation.assurance}")
    click.echo(f"  certificate: issued by {facts.issuer_name} ({facts.country or '?'}), "
               f"qualified={facts.qualified}, qscd={facts.qscd}, valid until {facts.not_after:%Y-%m-%d}")
    click.echo(f"  attestation valid until {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(attestation.expires_at))}")


@eid.command("statement")
@click.argument("claim_id")
@click.option("--valid-days", type=int, default=30, show_default=True)
@click.option("--out", "-o", type=click.Path(dir_okay=False), default=None, help="File to write (default: ./statement-<id>.txt)")
def eid_statement(claim_id: str, valid_days: int, out: str | None):
    """Write the statement to sign with your eID signing application.

    Sign the file as it is (a detached CAdES signature, .p7s), then run `eid attach`.
    """
    from nodetide.eidas.statement import build_statement

    storage = _storage()
    identity = _default(storage)
    record = _record(identity, claim_id)
    now = int(time.time())
    text = build_statement(
        identity.identity_hash or "", record.claim_id, record.claim_type, record.commitment,
        identity.sigchain.head_hash or "", now, now + valid_days * 86400,
    )
    path = Path(out or f"statement-{claim_id[:8]}.txt")
    path.write_bytes(text.encode("utf-8"))  # exact bytes: UTF-8, LF line endings, no trailing newline
    storage.close()
    click.echo(f"Statement written to {path}\n")
    click.echo(text)
    click.echo(f"\nSign {path} with your eID application as a detached CAdES signature,")
    click.echo("then: nodetide eid attach " + claim_id + f" {path} {path}.p7s")


@eid.command("attach")
@click.argument("claim_id")
@click.argument("statement_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("signature_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "-o", type=click.Path(dir_okay=False), default=None)
def eid_attach(claim_id: str, statement_file: str, signature_file: str, out: str | None):
    """Turn a signature made by your eID application into an attestation file."""
    from nodetide.eidas.cms import CmsError
    from nodetide.eidas.issue import attestation_from_signature
    from nodetide.eidas.statement import StatementError

    storage = _storage()
    identity = _default(storage)
    record = _record(identity, claim_id)
    try:
        text = Path(statement_file).read_bytes().decode("utf-8")
        attestation = attestation_from_signature(identity.sigchain, record, text, _read_signature(signature_file))
    except (CmsError, StatementError, UnicodeDecodeError) as e:
        raise click.ClickException(f"Cannot use this signature: {e}") from None
    path = out or f"attestation-{claim_id[:8]}.json"
    _save_attestation(storage, attestation, path)
    storage.close()
    click.echo(f"Attestation written to {path}")
    _describe(attestation)
    click.echo("It contains your certificate (with personal identifiers): give it only to parties you want to prove this to.")


def _slot_state(info) -> str:
    if info.pin_locked:
        return "PIN LOCKED"
    if info.pin_final_try:
        return "ONE PIN attempt left"
    if info.pin_count_low:
        return "some PIN attempts already failed"
    return "PIN ok"


@eid.command("tokens")
@click.option("--module", help="PKCS#11 module (default: $NODETIDE_PKCS11_MODULE or a known location)")
def eid_tokens(module: str | None):
    """Show the token's slots (each has its own PIN) and its certificates. Needs no PIN."""
    from nodetide.eidas.pkcs11 import Pkcs11Error, Pkcs11Token, find_module

    try:
        path = find_module(module)
        token = Pkcs11Token(path)
        slots, certs = token.slots(), token.certificates()
    except Pkcs11Error as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"Module: {path}\n")
    for info in slots:
        hint = "  <- digital signature PIN" if info.looks_like_signature_slot else ""
        click.echo(f"slot {info.slot}: {info.label} [{info.model}] PIN {info.min_pin}-{info.max_pin} chars, "
                   f"{_slot_state(info)}{hint}")
    click.echo()
    for c in certs:
        f = c.facts
        use = "for signing" if c.usable_for_signing else "not for signing"
        click.echo(f"cert [{c.index}] {c.subject}, issued by {f.issuer_name}, valid until {f.not_after:%Y-%m-%d}")
        click.echo(f"       {use}; qualified={f.qualified}, qscd={f.qscd} -> assurance {f.assurance}; seen on slot {c.slot}")
    click.echo("\nEvery slot has its own PIN, and a wrong PIN uses up one of a few attempts. "
               "A qualified signature normally needs the digital signature PIN.")


@eid.command("sign")
@click.argument("claim_id")
@click.option("--module", help="PKCS#11 module path")
@click.option("--slot", type=int, help="Slot whose PIN you will type (see `eid tokens`)")
@click.option("--cert", "cert_index", type=int, help="Certificate number from `eid tokens`")
@click.option("--valid-days", type=int, default=30, show_default=True)
@click.option("--out", "-o", type=click.Path(dir_okay=False), default=None)
def eid_sign(claim_id: str, module: str | None, slot: int | None, cert_index: int | None,
             valid_days: int, out: str | None):
    """Sign the claim statement with the key on your eID token.

    The PIN is typed at a hidden prompt, used once and never stored. If the key
    needs the PIN for each signature you are asked for it a second time.
    """
    from nodetide.eidas.issue import build_eidas_attestation, statement_for
    from nodetide.eidas.pkcs11 import Pkcs11Error, Pkcs11Token, find_module

    storage = _storage()
    identity = _default(storage)
    record = _record(identity, claim_id)
    signer = None
    try:
        token = Pkcs11Token(find_module(module))
        entry = token.choose_certificate(cert_index)
        slots = token.slots()

        if slot is None:
            if len(slots) == 1:
                slot = slots[0].slot
            else:
                click.echo("This token has several slots, each with its own PIN:")
                for info in slots:
                    hint = "  <- digital signature PIN (usually the one for qualified signatures)" if info.looks_like_signature_slot else ""
                    click.echo(f"  slot {info.slot}: {info.label} - {_slot_state(info)}{hint}")
                guess = next((i.slot for i in slots if i.looks_like_signature_slot), slots[0].slot)
                slot = click.prompt("Slot to log in to", type=int, default=guess)
        info = token.slot_info(slot)
        if info.pin_locked:
            raise click.ClickException(f"The PIN of slot {slot} is locked. Unblock it with your PUK first.")

        text, _, _ = statement_for(identity.sigchain, record, entry.facts.not_after, valid_days)
        click.echo("\nYou are about to sign this statement:\n")
        click.echo(text)
        click.echo(f"\nwith the certificate of: {entry.subject}")
        click.echo(f"and the PIN of slot {slot} ({info.label}).")
        if info.pin_final_try:
            click.echo("\n!! Only ONE PIN attempt is left on this slot. A wrong PIN will LOCK it.")
            if not click.confirm("Continue anyway?", default=False):
                raise click.Abort()
        elif info.pin_count_low:
            click.echo("\nNote: some PIN attempts on this slot have already failed.")
        if not click.confirm("Sign?", default=False):
            raise click.Abort()

        signer = token.signer(entry, slot, lambda reason: click.prompt(reason, hide_input=True))
        signer.login()
        attestation = build_eidas_attestation(identity.sigchain, record, signer, valid_days)
    except Pkcs11Error as e:
        raise click.ClickException(str(e)) from None
    finally:
        if signer is not None:
            signer.close()
    target = out or f"attestation-{claim_id[:8]}.json"
    _save_attestation(storage, attestation, target)
    storage.close()
    click.echo(f"\nAttestation written to {target}")
    _describe(attestation)


@eid.command("chain")
@click.argument("attestation_file", type=click.Path(exists=True, dir_okay=False))
def eid_chain(attestation_file: str):
    """Show the certificates inside an attestation (to decide which CAs to trust)."""
    import hashlib

    from nodetide.eidas.verify import inspect_proof

    attestation = Attestation.from_dict(json.loads(Path(attestation_file).read_text()))
    summary = inspect_proof(attestation)
    for label, cert in [("signer", summary.cades.signer_cert)] + [("chain", c) for c in summary.cades.other_certs]:
        subject = cert.subject.native
        shown = subject.get("common_name") if label == "chain" else "(signer certificate)"
        click.echo(f"{label}: {shown}")
        click.echo(f"  issuer:      {cert.issuer.native.get('common_name')}")
        click.echo(f"  sha256:      {hashlib.sha256(cert.dump()).hexdigest()}")
        for ext in cert["tbs_certificate"]["extensions"] or []:
            if ext["extn_id"].native == "authority_information_access":
                for access in ext["extn_value"].native:
                    click.echo(f"  {access['access_method']}: {access['access_location']}")
    click.echo("\nPut the CA certificates you trust (from your eID provider or the EU trusted list)")
    click.echo("into a directory and pass it to `eid verify --anchors DIR`.")


@eid.command("verify")
@click.argument("attestation_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--anchors", required=True, type=click.Path(exists=True, file_okay=False),
              help="Directory with trusted CA certificates (PEM/DER)")
@click.option("--document", type=click.Path(exists=True, dir_okay=False), help="Claim document to check the name against")
@click.option("--revocation", type=click.Choice(["hard-fail", "soft-fail", "off"]), default="hard-fail", show_default=True)
def eid_verify(attestation_file: str, anchors: str, document: str | None, revocation: str):
    """Verify an eID attestation locally, as a relying party would."""
    from nodetide.eidas.validate import TrustStore
    from nodetide.eidas.verify import EidasPolicy, check_legal_name

    storage = _storage()
    identity = _default(storage)
    attestation = Attestation.from_dict(json.loads(Path(attestation_file).read_text()))
    if attestation.subject != identity.identity_hash:
        raise click.ClickException("This attestation is for a different identity than your default one")
    policy = EidasPolicy(TrustStore.from_directory(anchors), revocation_mode=revocation)
    base = verify_attestation(attestation, identity.sigchain, None)
    if base.code != "unsupported_method":
        raise click.ClickException(f"Not valid: {base.error}")
    check = policy.verify(attestation, identity.sigchain, int(time.time()))
    storage.close()
    if not check.ok:
        raise click.ClickException(f"Not valid ({check.code}): {check.error}")
    click.echo("Signature, statement, certificate chain and revocation status are valid.")
    _describe(attestation)
    if document:
        doc = ClaimDocument.from_dict(json.loads(Path(document).read_text()))
        name = check_legal_name(attestation, doc)
        click.echo(f"  name check:  {'matches (' + str(name.how) + ')' if name.ok else 'DOES NOT MATCH: ' + str(name.reason)}")
