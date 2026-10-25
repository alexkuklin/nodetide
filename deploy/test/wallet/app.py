"""Test wallet: stands in for the Nodetide app that does not exist yet.

It holds one development identity (keys in plain JSON in its volume: never put anything real
here), makes claims, and gets them attested by the independent verification service: email and
phone with a one-time code, legal name / birth date / "over 18" by that service acting as an eID
notary on a statement you sign with your own eID card (the signature, which contains your
certificate, goes to the notary only and is not kept). It approves OIDC sign-ins while choosing
which claims to reveal. Everything is behind HTTP basic auth.

Every action is a JSON endpoint under /api (send `Accept: application/json`); the HTML forms
post to the same endpoints and are redirected back to the dashboard.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse, urlunparse

import aiohttp
from aiohttp import web

from nodetide.core.auth import create_assertion
from nodetide.core.claims import Attestation, ClaimDocument, ClaimError
from nodetide.core.crypto import KeyPair
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.eidas.notary_statement import NOTARIZABLE, build_notary_statement

log = logging.getLogger("wallet")

NODE_URL = os.environ["NODE_URL"].rstrip("/")
WALLET_URL = os.environ.get("WALLET_URL", "").rstrip("/")
VERIFIER_URL = os.environ.get("VERIFIER_URL", "").rstrip("/")  # the independent email verification service
PASSWORD = os.environ["WALLET_PASSWORD"]
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_FILE = DATA_DIR / "wallet.json"
STATEMENT_DAYS = 7
SIGNIN_TTL = 600
CODE_CLAIMS = ("email", "phone")  # verified by the verification service with a one-time code


class WalletError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# --- state ---------------------------------------------------------------------------------------


class Wallet:
    def __init__(self) -> None:
        self.state: dict[str, Any] = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        self.pending: dict[str, dict[str, Any]] = {}  # sign-in previews waiting for approval

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(STATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)

    def ensure_identity(self) -> None:
        if self.state:
            return
        identity = Identity.create(name="Test wallet")
        device, _ = identity.add_device(
            "test wallet", capabilities=[DeviceCapability.AUTHENTICATE, DeviceCapability.MANAGE_CLAIMS])
        assert identity.local_keypair is not None
        self.state = {"master": identity.local_keypair.to_dict(), "device": device.to_dict(),
                      "sigchain": identity.sigchain.to_list(), "claims": {}, "attestations": [], "statements": {}}
        self.save()

    @property
    def identity(self) -> Identity:
        return Identity(sigchain=Sigchain.from_list(self.state["sigchain"]),
                        local_keypair=KeyPair.from_dict(self.state["master"]))

    @property
    def device(self) -> KeyPair:
        return KeyPair.from_dict(self.state["device"])

    def documents(self, claim_type: str | None = None) -> list[ClaimDocument]:
        docs = [ClaimDocument.from_dict(d) for d in self.state["claims"].values()]
        return [d for d in docs if claim_type in (None, d.claim_type)]

    def document(self, claim_id: str) -> ClaimDocument:
        if claim_id not in self.state["claims"]:
            raise WalletError("unknown claim", 404)
        return ClaimDocument.from_dict(self.state["claims"][claim_id])

    def add_claim(self, claim_type: str, value: Any) -> ClaimDocument:
        identity = self.identity
        try:
            document = ClaimDocument.create(identity.identity_hash or "", claim_type, value)
        except ClaimError as e:
            raise WalletError(str(e)) from None
        identity.add_claim(document.claim_id, claim_type, document.commitment)
        self.state["claims"][document.claim_id] = document.to_dict()
        self.state["sigchain"] = identity.sigchain.to_list()
        self.save()
        return document

    def add_attestation(self, attestation: dict[str, Any], verdict: str) -> None:
        attestation = {**attestation, "_node_verdict": verdict}
        self.state["attestations"] = [a for a in self.state["attestations"]
                                      if not (a["claim_id"] == attestation["claim_id"] and a["method"] == attestation["method"])]
        self.state["attestations"].append(attestation)
        self.save()


wallet = Wallet()


# --- talking to the node ---------------------------------------------------------------------------


async def node(method: str, path: str, **kw: Any) -> tuple[int, Any]:
    return await call(NODE_URL, method, path, **kw)


async def verifier(method: str, path: str, **kw: Any) -> tuple[int, Any]:
    if not VERIFIER_URL:
        raise WalletError("no verification service is configured (VERIFIER_URL)", 501)
    return await call(VERIFIER_URL, method, path, **kw)


async def call(base: str, method: str, path: str, **kw: Any) -> tuple[int, Any]:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as http:
        async with http.request(method, base + path, **kw) as resp:
            try:
                return resp.status, await resp.json(content_type=None)
            except Exception:
                return resp.status, {"error": "non_json", "message": (await resp.text())[:200]}


async def publish() -> int:
    """Send the identity's events the node does not have yet."""
    identity = wallet.identity
    events = identity.sigchain.to_list()
    status, body = await node("GET", f"/api/identities/{identity.identity_hash}/sigchain")
    known = body.get("length", 0) if status == 200 else 0
    for index in range(known, len(events)):
        path = "/api/identities" if index == 0 else f"/api/identities/{identity.identity_hash}/events"
        status, body = await node("POST", path, json={"event": events[index]})
        if status not in (200, 201):
            raise WalletError(f"the node refused event {index}: {body}", 502)
    return len(events) - known


async def publish_forever(app: web.Application) -> None:
    while True:
        try:
            await publish()
            return
        except (WalletError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.warning("waiting for the node: %s", e)
            await asyncio.sleep(3)


async def start_email_verification(claim_id: str) -> dict[str, Any]:
    """Ask the verification service to email a code. The person reads the mail and types the code (confirm_email)."""
    document = wallet.document(claim_id)
    if document.claim_type not in CODE_CLAIMS:
        raise WalletError("only email and phone claims are verified with a code")
    identity = wallet.identity
    status, request = await verifier("POST", "/api/auth/challenge", json={})
    if status != 201:
        raise WalletError(f"the verification service refused a challenge: {request}", 502)
    assertion = create_assertion(request, identity.identity_hash or "", wallet.device, identity.sigchain.head_hash or "",
                                 claims={"purpose": "claim_verification", "claim_id": claim_id})
    status, begun = await verifier("POST", f"/api/verify/{document.claim_type}/start", json={
        "document": document.to_dict(), "assertion": assertion, "sigchain": identity.sigchain.to_list()})
    if status != 202:
        raise WalletError(f"verification not started: {begun.get('message', begun)}", 502)
    wallet.state.setdefault("verifications", {})[claim_id] = {
        "verification_id": begun["verification_id"], "expires_at": begun["expires_at"], "kind": document.claim_type}
    wallet.save()
    return {"expires_at": begun["expires_at"], "message": begun.get("message", "")}


async def confirm_email(claim_id: str, code: str) -> dict[str, Any]:
    pending = wallet.state.get("verifications", {}).get(claim_id)
    if pending is None:
        raise WalletError("start the verification first")
    status, confirmed = await verifier("POST", f"/api/verify/{pending.get('kind', 'email')}/confirm",
                                       json={"verification_id": pending["verification_id"], "code": str(code).strip()})
    if status != 201:
        raise WalletError(confirmed.get("message", f"code not accepted: {confirmed}"), 502 if status >= 500 else 400)
    # keep the issuer's chain with the attestation, so it can be shown anywhere without a lookup
    status, info = await verifier("GET", "/api/verify/issuer")
    attestation = confirmed["attestation"]
    if status == 200 and info.get("issuer") == attestation["issuer"]:
        wallet.state.setdefault("issuer_chains", {})[attestation["issuer"]] = info["sigchain"]
        who = info.get("name") or attestation["issuer"][:12]
    else:
        who = attestation["issuer"][:12]
    wallet.state["verifications"].pop(claim_id, None)
    wallet.add_attestation(attestation, f"issued by {who}")
    return attestation


# --- statements and signatures ---------------------------------------------------------------------------


async def notary_info() -> dict[str, Any]:
    """Who the eID notary is (the verification service's identity) and what it can attest."""
    status, info = await verifier("GET", "/api/verify/issuer")
    method = next((m for m in info.get("methods", []) if m.get("method") == "eidas_notary"), None) if status == 200 else None
    if method is None:
        raise WalletError("the verification service does not attest eID signatures", 501)
    return {"issuer": info["issuer"], "name": info.get("name") or info["issuer"][:12], "sigchain": info["sigchain"],
            "claim_types": method["claim_types"]}


async def new_notary_statement(claim_ids: list[str]) -> str:
    """The statement to sign with the card: it names the notary and lists exactly the claims to attest."""
    info = await notary_info()
    identity, now = wallet.identity, int(time.time())
    claims = []
    for claim_id in claim_ids:
        record = identity.sigchain.get_claim(claim_id)
        if record is None or record.claim_type not in info["claim_types"]:
            raise WalletError("only legal name, birth date and over-18 claims can be attested from an eID signature")
        claims.append((record.claim_id, record.claim_type, record.commitment))
    if not claims:
        raise WalletError("tick at least one claim")
    try:
        text = build_notary_statement(identity.identity_hash or "", info["issuer"], identity.sigchain.head_hash or "",
                                      now, now + STATEMENT_DAYS * 86400, claims)
    except ValueError as e:
        raise WalletError(str(e)) from None
    wallet.state["notary_statement"] = {"text": text, "claim_ids": claim_ids}
    wallet.save()
    return text


async def submit_signature(der: bytes) -> list[dict[str, Any]]:
    """Send the card's signature (it embeds the certificate, so the ID number) to the notary and nowhere else.

    The signature is not stored here; what comes back are attestations without it.
    """
    pending = wallet.state.get("notary_statement")
    if not pending:
        raise WalletError("create a statement first")
    info = await notary_info()
    identity, text = wallet.identity, pending["text"]
    status, request = await verifier("POST", "/api/auth/challenge", json={})
    if status != 201:
        raise WalletError(f"the notary refused a challenge: {request}", 502)
    assertion = create_assertion(request, identity.identity_hash or "", wallet.device, identity.sigchain.head_hash or "",
                                 claims={"purpose": "eid_attestation", "statement_sha256": hashlib.sha256(text.encode()).hexdigest()})
    status, body = await verifier("POST", "/api/verify/eid/attest", json={
        "statement": text, "signature": base64.b64encode(der).decode("ascii"),
        "documents": [wallet.document(c).to_dict() for c in pending["claim_ids"]],
        "assertion": assertion, "sigchain": identity.sigchain.to_list()})
    if status != 201:
        raise WalletError(f"the notary said: {body.get('message', body)}", 400 if status < 500 else 502)
    wallet.state.setdefault("issuer_chains", {})[info["issuer"]] = info["sigchain"]
    for attestation in body["attestations"]:
        wallet.add_attestation(attestation, f"attested by {info['name']} (eID notary)")
    wallet.state.pop("notary_statement", None)
    wallet.save()
    return body["attestations"]


# --- sign-in -------------------------------------------------------------------------------------------------


def challenge_url_from(login: str) -> str:
    login = login.strip()
    if login.startswith("nodetide://"):
        values = parse_qs(urlparse(login).query).get("challenge_url")
        if not values:
            raise WalletError("that deep link has no challenge_url")
        return values[0]
    url = urlparse(login)
    if url.scheme not in ("http", "https") or not url.netloc:
        raise WalletError("paste the sign-in address shown by the application")
    path = url.path.rstrip("/")
    if not path.endswith("/challenge"):
        path += "/challenge"
    return urlunparse(url._replace(path=path, query="", fragment=""))


async def signin_preview(login: str) -> dict[str, Any]:
    url = challenge_url_from(login)
    if urlparse(url).netloc != urlparse(NODE_URL).netloc:
        raise WalletError("this wallet only signs in to its own node")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as http:
        async with http.get(url) as resp:
            challenge = await resp.json(content_type=None)
            if resp.status != 200:
                raise WalletError(f"cannot fetch the challenge: {challenge}", 502)
    wanted = {c["claim_type"] for c in challenge["display"].get("claims_requested", [])}
    now = int(time.time())
    docs = {d.claim_id: d for d in wallet.documents()}
    candidates = [
        {"attestation_id": a_id, "claim_type": a["claim_type"], "method": a["method"], "assurance": a["assurance"],
         "expires_at": a["expires_at"], "value": docs[a["claim_id"]].value}
        for a in wallet.state["attestations"] if a["claim_type"] in wanted and a["claim_id"] in docs and a["expires_at"] > now
        for a_id in [Attestation.from_dict({k: v for k, v in a.items() if not k.startswith("_")}).id]
    ]
    token = secrets.token_urlsafe(16)
    wallet.pending = {t: p for t, p in wallet.pending.items() if p["expires"] > now}
    wallet.pending[token] = {"challenge": challenge, "candidates": candidates, "expires": now + SIGNIN_TTL}
    return {"token": token, "client": challenge["display"]["client_name"], "issuer": challenge["display"]["issuer"],
            "claims_requested": challenge["display"].get("claims_requested", []), "candidates": candidates}


async def signin_approve(token: str, share: list[str]) -> dict[str, Any]:
    pending = wallet.pending.pop(token, None)
    if pending is None or pending["expires"] < time.time():
        raise WalletError("that sign-in preview expired; start again", 410)
    identity, challenge = wallet.identity, pending["challenge"]
    docs = {d.claim_id: d for d in wallet.documents()}
    presentations = []
    for att in wallet.state["attestations"]:
        clean = {k: v for k, v in att.items() if not k.startswith("_")}
        if Attestation.from_dict(clean).id in share and att["claim_id"] in docs:
            item = {"document": docs[att["claim_id"]].to_dict(), "attestation": clean}
            chain = wallet.state.get("issuer_chains", {}).get(att["issuer"])
            if chain:
                item["issuer_sigchain"] = chain
            presentations.append(item)
    assertion = create_assertion(challenge["request"], identity.identity_hash or "", wallet.device,
                                 identity.sigchain.head_hash or "")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as http:
        async with http.post(challenge["respond_url"], json={
                "assertion": assertion, "sigchain": identity.sigchain.to_list(), "presentations": presentations}) as resp:
            body = await resp.json(content_type=None)
            return {"http_status": resp.status, **body}


# --- web ---------------------------------------------------------------------------------------------------------


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def wants_json(request: web.Request) -> bool:
    return "application/json" in request.headers.get("Accept", "") or request.path.startswith("/api/state")


async def params(request: web.Request) -> dict[str, Any]:
    if request.content_type == "application/json":
        data = await request.json()
        return data if isinstance(data, dict) else {}
    if request.content_type in ("application/x-www-form-urlencoded", "multipart/form-data"):
        form = await request.post()
        return {k: (v if not isinstance(v, web.FileField) else v) for k, v in form.items()} \
            | {"_multi": {k: form.getall(k) for k in form}}
    return {}


def done(request: web.Request, data: dict[str, Any], message: str) -> web.Response:
    if wants_json(request):
        return web.json_response(data)
    raise web.HTTPSeeOther("/?msg=" + quote(message))


@web.middleware
async def errors(request: web.Request, handler):
    try:
        return await handler(request)
    except WalletError as e:
        if wants_json(request):
            return web.json_response({"error": str(e)}, status=e.status)
        raise web.HTTPSeeOther("/?err=" + quote(str(e)[:300])) from None


@web.middleware
async def basic_auth(request: web.Request, handler):
    if request.path == "/healthz":
        return await handler(request)
    header = request.headers.get("Authorization", "")
    ok = False
    if header.lower().startswith("basic "):
        import base64
        try:
            _, _, supplied = base64.b64decode(header[6:]).decode().partition(":")
            ok = hmac.compare_digest(supplied.encode(), PASSWORD.encode())
        except Exception:
            ok = False
    if not ok:
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Nodetide test wallet"'}, text="login required")
    return await handler(request)


def state_view() -> dict[str, Any]:
    identity, now = wallet.identity, int(time.time())
    docs = {d.claim_id: d for d in wallet.documents()}
    claims = []
    for record in identity.sigchain.get_claims():
        doc = docs.get(record.claim_id)
        atts = [{"attestation_id": Attestation.from_dict({k: v for k, v in a.items() if not k.startswith("_")}).id,
                 "method": a["method"], "assurance": a["assurance"], "expires_at": a["expires_at"],
                 "expired": a["expires_at"] <= now, "node_verdict": a.get("_node_verdict", "")}
                for a in wallet.state["attestations"] if a["claim_id"] == record.claim_id]
        claims.append({"claim_id": record.claim_id, "claim_type": record.claim_type, "status": record.status(now),
                       "value": doc.value if doc else None, "attestations": atts,
                       })
    return {"identity": identity.identity_hash, "claims": claims}


async def api_state(request: web.Request) -> web.Response:
    return web.json_response(state_view())


async def api_claim_email(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("email", str(data.get("address", "")))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "email claim created")


async def api_claim_phone(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("phone", str(data.get("number", "")).replace(" ", ""))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "phone claim created")


async def api_claim_name(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("legal_name", {"given_name": str(data.get("given", "")), "family_name": str(data.get("family", ""))})
    await publish()
    return done(request, {"claim_id": document.claim_id}, "legal name claim created")


async def api_verify_email(request: web.Request) -> web.Response:
    """Step 1: the verification service emails a code."""
    started = await start_email_verification(request.match_info["id"])
    return done(request, started, "A code was sent. Type it below to finish.")


async def api_confirm_email(request: web.Request) -> web.Response:
    """Step 2: the person types the code from the email."""
    data = await params(request)
    attestation = await confirm_email(request.match_info["id"], str(data.get("code", "")))
    return done(request, {"attestation": attestation}, "Verified.")


async def api_eid_statement(request: web.Request) -> web.Response:
    if request.method == "POST":
        data = await params(request)
        claim_ids = data.get("claims") if isinstance(data.get("claims"), list) else data.get("_multi", {}).get("claim", [])
        text = await new_notary_statement([str(c) for c in claim_ids])
        return done(request, {"statement": text}, "Statement created: download it and sign it with your card within 10 minutes.")
    pending = wallet.state.get("notary_statement")
    if not pending:
        raise WalletError("no statement yet", 404)
    return web.Response(body=pending["text"].encode("utf-8"), content_type="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="notary-statement.txt"'})


async def api_eid_signature(request: web.Request) -> web.Response:
    if request.content_type == "multipart/form-data":
        reader = await request.multipart()
        der = b""
        async for part in reader:
            if part.name == "signature":
                der = await part.read(decode=False)
    else:
        der = await request.read()
    if not der:
        raise WalletError("no signature received")
    attestations = await submit_signature(der)
    types = ", ".join(sorted(a["claim_type"] for a in attestations))
    return done(request, {"attestations": attestations}, f"The notary attested: {types}. Your certificate was not kept.")


async def api_claim_birthdate(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("birthdate", str(data.get("date", "")))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "birth date claim created")


async def api_claim_age(request: web.Request) -> web.Response:
    document = wallet.add_claim("age_over_18", True)
    await publish()
    return done(request, {"claim_id": document.claim_id}, "over-18 claim created")


async def api_signin_preview(request: web.Request) -> web.Response:
    data = await params(request)
    preview = await signin_preview(str(data.get("login_url", "")))
    if wants_json(request):
        return web.json_response(preview)
    return web.Response(text=signin_page(preview), content_type="text/html")


async def api_signin_approve(request: web.Request) -> web.Response:
    data = await params(request)
    share = data.get("share", [])
    if isinstance(share, str):
        share = [share]
    if "_multi" in data:
        share = data["_multi"].get("share", [])
    result = await signin_approve(str(data.get("token", "")), [str(s) for s in share])
    if wants_json(request):
        return web.json_response(result)
    released = ", ".join(r["claim_type"] for r in (result.get("claims") or {}).get("released", [])) or "nothing"
    raise web.HTTPSeeOther("/?msg=" + quote(f"{result.get('message', '')} Released: {released}."))


# --- pages ---------------------------------------------------------------------------------------------------------

CSS = """body{font:16px/1.5 system-ui,sans-serif;max-width:52rem;margin:1.5rem auto;padding:0 1rem}
code{word-break:break-all;background:#eee;padding:0 .25rem;border-radius:.2rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
form{margin:.4rem 0}input[type=text],input[type=url],input[type=email]{width:min(28rem,100%)}
.msg{background:#e6f6ec;padding:.5rem 1rem;border-radius:.3rem}.err{background:#fde8e8;padding:.5rem 1rem;border-radius:.3rem}
.muted{color:#666}"""


def layout(body: str, request: web.Request | None = None) -> str:
    note = ""
    if request is not None:
        if request.query.get("msg"):
            note += f'<p class="msg">{esc(request.query["msg"])}</p>'
        if request.query.get("err"):
            note += f'<p class="err">{esc(request.query["err"])}</p>'
    return f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nodetide test wallet</title><style>{CSS}</style><h1>Nodetide test wallet</h1>{note}{body}"""


def signin_page(preview: dict[str, Any]) -> str:
    asked = ", ".join(c["claim_type"] for c in preview["claims_requested"]) or "nothing beyond your identity"
    rows = "".join(
        f'<tr><td><input type="checkbox" name="share" value="{esc(c["attestation_id"])}" checked></td>'
        f'<td>{esc(c["claim_type"])}</td><td>{esc(json.dumps(c["value"], ensure_ascii=False))}</td>'
        f'<td>{esc(c["method"])} / {esc(c["assurance"])}</td></tr>' for c in preview["candidates"])
    table = (f"<table><tr><th></th><th>claim</th><th>value that will be revealed</th><th>attested by</th></tr>{rows}</table>"
             if rows else '<p class="muted">You hold no attestation that fits; you will sign in with your identity only.</p>')
    return layout(f"""<h2>Approve sign-in?</h2>
<p><b>{esc(preview['client'])}</b> (via <code>{esc(preview['issuer'])}</code>) asks for: {esc(asked)}.</p>
<form method="post" action="/api/signin/approve"><input type="hidden" name="token" value="{esc(preview['token'])}">
{table}<p><button>Approve</button> <a href="/">Cancel</a></p></form>""")


async def signin_link(request: web.Request) -> web.Response:
    """GET /signin?link=...  the "open in wallet" link on the node's sign-in page. Only previews: approving is a POST."""
    link = request.query.get("link", "")
    return web.Response(text=signin_page(await signin_preview(link)), content_type="text/html")


def eid_form(view: dict[str, Any]) -> str:
    eligible = [c for c in view["claims"] if c["claim_type"] in NOTARIZABLE]
    if not eligible:
        return ('<h2>Prove claims with your eID card</h2><p class="muted">Add a legal name, birth date or over-18 claim '
                'first; then you can have them attested from your eID signature.</p>')
    boxes = "".join(
        f'<label><input type="checkbox" name="claim" value="{esc(c["claim_id"])}"> {esc(c["claim_type"])}: '
        f'{esc(json.dumps(c["value"], ensure_ascii=False))}</label><br>' for c in eligible)
    pending = wallet.state.get("notary_statement")
    step2 = ""
    if pending:
        step2 = ('<p><b>Statement ready.</b> <a href="/api/eid/statement">download it</a>, sign it with your card '
                 '(<code>nodetide eid sign-file notary-statement.txt</code>, within 10 minutes), then upload the .p7s. '
                 'It goes to the notary only and is not kept here.</p>'
                 '<form method="post" action="/api/eid/signature" enctype="multipart/form-data">'
                 '<input type="file" name="signature" required> <button>Send to the notary</button></form>'
                 f'<pre class="muted">{esc(pending["text"])}</pre>')
    return f"""<h2>Prove claims with your eID card</h2>
<p>Tick what the notary should attest. Only these claims are attested, each as a separate attestation that holds neither
your certificate nor your personal number. The signature you create contains your certificate: it goes to the notary
({esc(VERIFIER_URL)}) and nowhere else.</p>
<form method="post" action="/api/eid/statement">{boxes}<button>Create the statement to sign</button></form>{step2}"""


async def delivery_state(claim_id: str) -> str:
    """Where the code is: for SMS it may still be in the gateway's queue, or have been refused."""
    pending = wallet.state.get("verifications", {}).get(claim_id)
    if not pending or pending.get("kind") != "phone":
        return ""
    try:
        status, body = await verifier("GET", f"/api/verify/phone/{pending['verification_id']}/status")
    except (WalletError, aiohttp.ClientError, asyncio.TimeoutError):
        return "state unknown"
    if status != 200:
        return "state unknown"
    if body.get("delivery") == "failed":
        return f"the SMS could not be sent ({body.get('reason', 'unknown reason')}); send a new code later"
    return {"queued": "waiting for the SMS gateway to pick it up", "sent": "SMS sent"}.get(body.get("delivery", ""), "state unknown")


async def dashboard(request: web.Request) -> web.Response:
    view = state_view()
    identity = view["identity"]
    rows = []
    for c in view["claims"]:
        value = c["value"]
        shown = f"{value['given_name']} {value['family_name']}" if isinstance(value, dict) else value
        atts = "".join(f"<div>{esc(a['method'])} / {esc(a['assurance'])}{' (expired)' if a['expired'] else ''}: "
                       f"<span class='muted'>{esc(a['node_verdict'])}</span></div>" for a in c["attestations"]) or "none"
        cid = esc(c["claim_id"])
        if c["claim_type"] in CODE_CLAIMS:
            waiting = c["claim_id"] in wallet.state.get("verifications", {})
            how = "email" if c["claim_type"] == "email" else "SMS"
            actions = (f'<form method="post" action="/api/claims/{cid}/verify-email"><button>'
                       f'{"Send a new code" if waiting else f"Verify by {how}"}</button></form>')
            if waiting:
                note = await delivery_state(c["claim_id"])
                actions += (f'<form method="post" action="/api/claims/{cid}/confirm-email">Code from the {how}: '
                            f'<input name="code" required maxlength="16" autocomplete="off" size="12"> <button>Confirm</button></form>'
                            + (f'<div class="muted">{esc(note)}</div>' if note else ""))
        else:
            actions = '<span class="muted">see "Prove claims with your eID card" below</span>' if c["claim_type"] in NOTARIZABLE else ""
        rows.append(f"<tr><td>{esc(c['claim_type'])}<br><code>{cid[:8]}</code></td><td>{esc(c['status'])}</td>"
                    f"<td>{esc(shown)}</td><td>{atts}</td><td>{actions}</td></tr>")
    table = ("<table><tr><th>claim</th><th>status</th><th>value (private)</th><th>attestations</th><th></th></tr>"
             + "".join(rows) + "</table>") if rows else '<p class="muted">No claims yet.</p>'
    explorer = f"{NODE_URL}/explorer/#/identity/{identity}"
    eid_section = eid_form(view)
    body = f"""<p>Test identity: <code>{esc(identity)}</code> (<a href="{esc(explorer)}">see it in the explorer</a>)</p>
<h2>Claims</h2>{table}
<h3>Add a claim</h3>
<form method="post" action="/api/claims/email">Email: <input type="email" name="address" required> <button>Add</button></form>
<form method="post" action="/api/claims/birthdate">Birth date: <input type="date" name="date" required> <button>Add</button></form>
<form method="post" action="/api/claims/age"><button>Add an "I am over 18" claim</button> <span class="muted">(prove your age without your birth date)</span></form>
<form method="post" action="/api/claims/phone">Phone (international format): <input type="text" name="number" required placeholder="+359..."> <button>Add</button></form>
<form method="post" action="/api/claims/name">Legal name as on your certificate:
<input type="text" name="given" placeholder="given name" required> <input type="text" name="family" placeholder="family name" required> <button>Add</button></form>
{eid_section}
<h2>Approve a sign-in</h2>
<form method="post" action="/api/signin/preview">Sign-in address from the application:
<input type="url" name="login_url" required placeholder="{esc(NODE_URL)}/oidc/login/..."> <button>Look at it</button></form>
<p class="muted">Email and phone claims are verified by an independent service ({esc(VERIFIER_URL or 'not configured')}): it sends you a code by email or SMS, you type it here.</p>"""
    return web.Response(text=layout(body, request), content_type="text/html")


async def healthz(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def build_app() -> web.Application:
    wallet.ensure_identity()
    app = web.Application(middlewares=[basic_auth, errors], client_max_size=4 * 1024 * 1024)
    app.router.add_get("/", dashboard)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/signin", signin_link)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/claims/email", api_claim_email)
    app.router.add_post("/api/claims/phone", api_claim_phone)
    app.router.add_post("/api/claims/name", api_claim_name)
    app.router.add_post("/api/claims/{id}/verify-email", api_verify_email)
    app.router.add_post("/api/claims/{id}/confirm-email", api_confirm_email)
    app.router.add_route("*", "/api/eid/statement", api_eid_statement)
    app.router.add_post("/api/eid/signature", api_eid_signature)
    app.router.add_post("/api/claims/birthdate", api_claim_birthdate)
    app.router.add_post("/api/claims/age", api_claim_age)
    app.router.add_post("/api/signin/preview", api_signin_preview)
    app.router.add_post("/api/signin/approve", api_signin_approve)

    async def start(app: web.Application) -> None:
        app["publisher"] = asyncio.create_task(publish_forever(app))

    app.on_startup.append(start)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(build_app(), host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "4572")), print=None)
