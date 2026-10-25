"""Test wallet: stands in for the Nodetide app that does not exist yet.

It holds one development identity (keys in plain JSON in its volume: never put anything real
here), makes claims, gets them attested (email through the stack's test mailbox, legal name
through a statement you sign with your own eID card), and approves OIDC sign-ins while choosing
which claims to reveal. Everything is behind HTTP basic auth.

Every action is a JSON endpoint under /api (send `Accept: application/json`); the HTML forms
post to the same endpoints and are redirected back to the dashboard.
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import os
import re
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
from nodetide.eidas.cms import CmsError
from nodetide.eidas.issue import attestation_from_signature
from nodetide.eidas.statement import StatementError, build_statement

log = logging.getLogger("wallet")

NODE_URL = os.environ["NODE_URL"].rstrip("/")
WALLET_URL = os.environ.get("WALLET_URL", "").rstrip("/")
MAILPIT_URL = os.environ.get("MAILPIT_URL", "http://mailpit:8025").rstrip("/")
PASSWORD = os.environ["WALLET_PASSWORD"]
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_FILE = DATA_DIR / "wallet.json"
STATEMENT_DAYS = 7
SIGNIN_TTL = 600


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
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as http:
        async with http.request(method, NODE_URL + path, **kw) as resp:
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


async def mailbox_code(address: str, since: float, wait: float = 20) -> str:
    """Read the verification code the node emailed to the test mailbox."""
    deadline = time.time() + wait
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as http:
        while time.time() < deadline:
            async with http.get(f"{MAILPIT_URL}/api/v1/messages", params={"limit": 25}) as resp:
                listing = await resp.json(content_type=None)
            for message in listing.get("messages", []):
                if any(t.get("Address", "").lower() == address.lower() for t in message.get("To", [])):
                    async with http.get(f"{MAILPIT_URL}/api/v1/message/{message['ID']}") as resp:
                        text = (await resp.json(content_type=None)).get("Text", "")
                    match = re.search(r"Verification code: ([A-Z0-9]{8})", text)
                    if match and time.time() - since < 600:
                        # the newest matching message wins (the list is newest first)
                        return match.group(1)
            await asyncio.sleep(1)
    raise WalletError("no verification email arrived in the test mailbox", 504)


async def verify_email(claim_id: str) -> dict[str, Any]:
    document = wallet.document(claim_id)
    if document.claim_type != "email":
        raise WalletError("not an email claim")
    identity, started = wallet.identity, time.time()
    status, request = await node("POST", "/api/auth/challenge", json={})
    if status != 201:
        raise WalletError(f"challenge refused: {request}", 502)
    assertion = create_assertion(request, identity.identity_hash or "", wallet.device, identity.sigchain.head_hash or "",
                                 claims={"purpose": "claim_verification", "claim_id": claim_id})
    status, begun = await node("POST", "/api/verify/email/start", json={
        "document": document.to_dict(), "assertion": assertion, "sigchain": identity.sigchain.to_list()})
    if status != 202:
        raise WalletError(f"verification not started: {begun}", 502)
    code = await mailbox_code(str(document.value), started)
    status, confirmed = await node("POST", "/api/verify/email/confirm",
                                   json={"verification_id": begun["verification_id"], "code": code})
    if status != 201:
        raise WalletError(f"code not accepted: {confirmed}", 502)
    wallet.add_attestation(confirmed["attestation"], "issued by the node")
    return confirmed["attestation"]


# --- statements and signatures ---------------------------------------------------------------------------


def new_statement(claim_id: str) -> str:
    identity, now = wallet.identity, int(time.time())
    record = identity.sigchain.get_claim(claim_id)
    if record is None or record.claim_type != "legal_name":
        raise WalletError("statements are for legal_name claims")
    text = build_statement(identity.identity_hash or "", record.claim_id, record.claim_type, record.commitment,
                           identity.sigchain.head_hash or "", now, now + STATEMENT_DAYS * 86400)
    wallet.state["statements"][claim_id] = text
    wallet.save()
    return text


async def attach_signature(claim_id: str, der: bytes) -> dict[str, Any]:
    text = wallet.state["statements"].get(claim_id)
    if not text:
        raise WalletError("create a statement first")
    identity, document = wallet.identity, wallet.document(claim_id)
    try:
        attestation = attestation_from_signature(identity.sigchain, identity.sigchain.get_claim(claim_id), text, der)
    except (CmsError, StatementError) as e:
        raise WalletError(f"cannot use this signature: {e}") from None
    # ask the node, as any relying party would, whether it believes it
    status, verdict = await node("POST", "/api/claims/verify", json={
        "attestation": attestation.to_dict(), "document": document.to_dict(),
        "subject_sigchain": identity.sigchain.to_list(), "name_match": "approximate"})
    summary = ("accepted by the node" + (f" (name match: {verdict.get('name_match')})" if verdict.get("name_match") else "")
               if verdict.get("valid") else f"node says: {verdict.get('code')}: {verdict.get('error')}")
    wallet.add_attestation(attestation.to_dict(), summary)
    return {"attestation_id": attestation.id, "node_verdict": summary, "valid": bool(verdict.get("valid"))}


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
            presentations.append({"document": docs[att["claim_id"]].to_dict(), "attestation": clean})
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
                       "has_statement": record.claim_id in wallet.state["statements"]})
    return {"identity": identity.identity_hash, "claims": claims}


async def api_state(request: web.Request) -> web.Response:
    return web.json_response(state_view())


async def api_claim_email(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("email", str(data.get("address", "")))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "email claim created")


async def api_claim_name(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("legal_name", {"given_name": str(data.get("given", "")), "family_name": str(data.get("family", ""))})
    await publish()
    return done(request, {"claim_id": document.claim_id}, "legal name claim created")


async def api_verify_email(request: web.Request) -> web.Response:
    attestation = await verify_email(request.match_info["id"])
    return done(request, {"attestation": attestation}, "email verified by the node")


async def api_statement(request: web.Request) -> web.Response:
    claim_id = request.match_info["id"]
    if request.method == "POST":
        text = new_statement(claim_id)
        return done(request, {"statement": text, "valid_for": f"sign within 10 minutes; valid {STATEMENT_DAYS} days"},
                    "statement created: download it and sign it with your card within 10 minutes")
    text = wallet.state["statements"].get(claim_id)
    if not text:
        raise WalletError("no statement yet", 404)
    return web.Response(body=text.encode("utf-8"), content_type="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="statement-{claim_id[:8]}.txt"'})


async def api_signature(request: web.Request) -> web.Response:
    claim_id = request.match_info["id"]
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
    result = await attach_signature(claim_id, der)
    return done(request, result, result["node_verdict"])


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
        if c["claim_type"] == "email":
            actions = f'<form method="post" action="/api/claims/{cid}/verify-email"><button>Verify (reads the code from the test mailbox)</button></form>'
        else:
            download = f' <a href="/api/claims/{cid}/statement">download statement</a>' if c["has_statement"] else ""
            actions = (f'<form method="post" action="/api/claims/{cid}/statement"><button>Create statement to sign</button>{download}</form>'
                       f'<form method="post" action="/api/claims/{cid}/signature" enctype="multipart/form-data">'
                       f'<input type="file" name="signature" required> <button>Upload signature (.p7s)</button></form>')
        rows.append(f"<tr><td>{esc(c['claim_type'])}<br><code>{cid[:8]}</code></td><td>{esc(c['status'])}</td>"
                    f"<td>{esc(shown)}</td><td>{atts}</td><td>{actions}</td></tr>")
    table = ("<table><tr><th>claim</th><th>status</th><th>value (private)</th><th>attestations</th><th></th></tr>"
             + "".join(rows) + "</table>") if rows else '<p class="muted">No claims yet.</p>'
    explorer = f"{NODE_URL}/explorer/#/identity/{identity}"
    body = f"""<p>Test identity: <code>{esc(identity)}</code> (<a href="{esc(explorer)}">see it in the explorer</a>)</p>
<h2>Claims</h2>{table}
<h3>Add a claim</h3>
<form method="post" action="/api/claims/email">Email: <input type="email" name="address" required> <button>Add</button></form>
<form method="post" action="/api/claims/name">Legal name as on your certificate:
<input type="text" name="given" placeholder="given name" required> <input type="text" name="family" placeholder="family name" required> <button>Add</button></form>
<h2>Approve a sign-in</h2>
<form method="post" action="/api/signin/preview">Sign-in address from the application:
<input type="url" name="login_url" required placeholder="{esc(NODE_URL)}/oidc/login/..."> <button>Look at it</button></form>
<p class="muted">The test mailbox (verification emails) is private to the server: open it through an SSH tunnel to port 4573.</p>"""
    return web.Response(text=layout(body, request), content_type="text/html")


async def healthz(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def build_app() -> web.Application:
    wallet.ensure_identity()
    app = web.Application(middlewares=[basic_auth, errors], client_max_size=4 * 1024 * 1024)
    app.router.add_get("/", dashboard)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/claims/email", api_claim_email)
    app.router.add_post("/api/claims/name", api_claim_name)
    app.router.add_post("/api/claims/{id}/verify-email", api_verify_email)
    app.router.add_route("*", "/api/claims/{id}/statement", api_statement)
    app.router.add_post("/api/claims/{id}/signature", api_signature)
    app.router.add_post("/api/signin/preview", api_signin_preview)
    app.router.add_post("/api/signin/approve", api_signin_approve)

    async def start(app: web.Application) -> None:
        app["publisher"] = asyncio.create_task(publish_forever(app))

    app.on_startup.append(start)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(build_app(), host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "4572")), print=None)
