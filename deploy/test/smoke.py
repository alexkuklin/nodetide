#!/usr/bin/env python3
"""End-to-end check of a running test stack, walking the flow the way a person would.

    smoke.py prepare     make a synthetic "eID" CA so the legal-name path can be tested without a card
    smoke.py run         sign in through the standard OIDC client twice (sharing claims, then not)

Needs the repository's Python environment (nodetide and aiohttp). `run` reads .env for the URLs
and the wallet password. Against a remote server the URLs resolve normally; for *.localtest.me
they are pinned to 127.0.0.1 so no DNS is needed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SMOKE = HERE / ".smoke"
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "python" / "src"))

EMAIL = "smoke@example.com"
GIVEN, FAMILY = "Maria", "Ivanova"


def load_env() -> dict[str, str]:
    env = {}
    for line in (HERE / ".env").read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


class PinLocal(AbstractResolver):
    """Resolve the stack's *.localtest.me names to this machine without DNS."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host.endswith("localtest.me"):
            return [{"hostname": host, "host": "127.0.0.1", "port": port, "family": socket.AF_INET, "proto": 0, "flags": 0}]
        return await aiohttp.ThreadedResolver().resolve(host, port, family)

    async def close(self):
        pass


class Check:
    def __init__(self) -> None:
        self.failed = 0

    def ok(self, label: str, detail: str = "") -> None:
        print(f"  ok    {label}" + (f"  ({detail})" if detail else ""), flush=True)

    def fail(self, label: str, detail: str = "") -> None:
        self.failed += 1
        print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""), flush=True)

    def expect(self, condition: bool, label: str, detail: str = "") -> bool:
        (self.ok if condition else self.fail)(label, detail)
        return condition


# --- prepare ----------------------------------------------------------------------------------------


def prepare() -> None:
    from cryptography.hazmat.primitives import serialization
    from tests import pki

    root = pki.make_ca("Smoke Test Root CA", path_length=1)
    inter = pki.make_ca("Smoke Test Qualified CA", parent=root, path_length=0)
    leaf = pki.make_signer_cert(inter, GIVEN, FAMILY)
    SMOKE.mkdir(exist_ok=True)
    (SMOKE / "anchors").mkdir(exist_ok=True)
    (SMOKE / "anchors" / "root.pem").write_bytes(root.cert.public_bytes(serialization.Encoding.PEM))
    der = lambda c: base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()  # noqa: E731
    (SMOKE / "signer.json").write_text(json.dumps({
        "key": base64.b64encode(leaf.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
        "cert": der(leaf.cert), "chain": [der(inter.cert)],
    }))
    (SMOKE / "signer.json").chmod(0o600)

    env_path = HERE / ".env"
    lines = [l for l in env_path.read_text().splitlines() if not l.startswith(("ANCHORS_DIR=", "EIDAS_REVOCATION="))]
    lines += ["ANCHORS_DIR=./.smoke/anchors", "EIDAS_REVOCATION=off"]
    env_path.write_text("\n".join(lines) + "\n")
    print("Synthetic CA written to .smoke/ and .env now trusts it (revocation off, for the test only).")
    print("Restart the node so it picks that up:  docker compose up -d node")
    print("Before using the stack for real, remove those two lines from .env and the .smoke/ folder.")


def synthetic_signer():
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization

    data = json.loads((SMOKE / "signer.json").read_text())

    class Signer:
        hash_alg = "sha256"
        certificate = asn1_x509.Certificate.load(base64.b64decode(data["cert"]))
        chain = [asn1_x509.Certificate.load(base64.b64decode(c)) for c in data["chain"]]
        _key = serialization.load_der_private_key(base64.b64decode(data["key"]), None)

        def sign(self, payload: bytes) -> bytes:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            return self._key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return Signer()


# --- the run ---------------------------------------------------------------------------------------------


async def follow(http: aiohttp.ClientSession, url: str, stop_at: str | None = None, limit: int = 12) -> tuple[str, aiohttp.ClientResponse | None]:
    """Follow redirects by hand (the sign-in secret lives in a URL fragment a client library would drop)."""
    for _ in range(limit):
        if stop_at and urlparse(url).path.startswith(stop_at):
            return url, None
        resp = await http.get(url.split("#")[0], allow_redirects=False)
        location = resp.headers.get("Location")
        if resp.status in (301, 302, 303, 307, 308) and location:
            url = urljoin(url, location)
            continue
        return url, resp
    raise RuntimeError("too many redirects")


async def wait_ready(http: aiohttp.ClientSession, url: str, seconds: int = 90) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            async with http.get(url, allow_redirects=False) as resp:
                if resp.status < 500:
                    return
        except aiohttp.ClientError:
            pass
        await asyncio.sleep(1.5)
    raise RuntimeError(f"{url} did not come up")


async def sign_in(env: dict[str, str], resolver, wallet, check: Check, share_claims: bool, label: str) -> dict:
    """One complete OIDC sign-in through the relying party, approved by the wallet."""
    node, rp = env["NODE_URL"], env["RP_URL"]
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver), cookie_jar=jar) as browser:
        login_url, _ = await follow(browser, rp + "/", stop_at="/oidc/login/")
        check.expect("/oidc/login/" in login_url and "#" in login_url, f"{label}: the application sends the browser to the Nodetide sign-in page")
        page_url, secret = login_url.split("#", 1)

        preview = await wallet("POST", "/api/signin/preview", {"login_url": page_url})
        asked = [c["claim_type"] for c in preview["claims_requested"]]
        check.expect({"email", "legal_name"} <= set(asked) or {"email"} <= set(asked), f"{label}: the wallet sees what the application asked for", ", ".join(asked))
        share = [c["attestation_id"] for c in preview["candidates"]] if share_claims else []
        approval = await wallet("POST", "/api/signin/approve", {"token": preview["token"], "share": share})
        check.expect(approval.get("http_status") == 200, f"{label}: the wallet's approval is accepted", approval.get("message", ""))

        status = {}
        for _ in range(20):
            async with browser.get(page_url + "/status", headers={"X-Login-Secret": secret}) as resp:
                status = await resp.json()
            if status["status"] == "approved":
                break
            await asyncio.sleep(0.5)
        check.expect(status.get("status") == "approved", f"{label}: the sign-in page reports approval")

        final, resp = await follow(browser, status["redirect_to"])
        check.expect(resp is not None and resp.status == 200, f"{label}: the application accepts the id_token and serves the page")
        async with browser.get(rp + "/claims.json") as resp:
            claims = await resp.json()
    return claims


async def run() -> int:
    env = load_env()
    check = Check()
    node, rp, wallet_url = env["NODE_URL"], env["RP_URL"], env["WALLET_URL"]
    auth_header = "Basic " + base64.b64encode(f"wallet:{env['WALLET_PASSWORD']}".encode()).decode()
    resolver = PinLocal()
    eid = (SMOKE / "signer.json").exists()

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver)) as http:
        print("services")
        await wait_ready(http, node + "/health")
        await wait_ready(http, wallet_url + "/healthz")
        async with http.get(rp + "/ping") as resp:
            check.expect(resp.status == 200, "relying party (oauth2-proxy) is up")
        async with http.get(node + "/.well-known/openid-configuration") as resp:
            discovery = await resp.json()
        check.expect(discovery["issuer"] == node, "OIDC discovery names the public issuer", discovery["issuer"])
        async with http.get(node + "/api/verify/issuer") as resp:
            check.expect(resp.status == 200, "email verification is enabled on the node")

        async def wallet(method: str, path: str, body: dict | None = None, raw: bytes | None = None) -> dict:
            async with http.request(method, wallet_url + path, json=body if raw is None else None, data=raw,
                                    headers={"Accept": "application/json", "Authorization": auth_header}) as resp:
                data = await resp.json(content_type=None)
                if resp.status >= 400:
                    raise RuntimeError(f"wallet {method} {path}: {resp.status} {data}")
                return data

        print("claims")
        state = await wallet("GET", "/api/state")
        identity = state["identity"]
        email_claim = next((c for c in state["claims"] if c["claim_type"] == "email" and c["value"] == EMAIL), None)
        if email_claim is None:
            email_claim = {"claim_id": (await wallet("POST", "/api/claims/email", {"address": EMAIL}))["claim_id"]}
        attested = await wallet("POST", f"/api/claims/{email_claim['claim_id']}/verify-email")
        check.expect(attested["attestation"]["method"] == "email_code", "email claim verified through the test mailbox")

        if eid:
            name_claim = next((c for c in state["claims"] if c["claim_type"] == "legal_name"), None)
            claim_id = name_claim["claim_id"] if name_claim else (await wallet("POST", "/api/claims/name", {"given": GIVEN, "family": FAMILY}))["claim_id"]
            statement = (await wallet("POST", f"/api/claims/{claim_id}/statement"))["statement"]
            from datetime import datetime, timezone
            from nodetide.eidas.cms import create_cades_detached
            from nodetide.eidas.statement import parse_statement
            parsed = parse_statement(statement)
            der = create_cades_detached(statement.encode(), synthetic_signer(), datetime.fromtimestamp(parsed.signed_on, tz=timezone.utc))
            uploaded = await wallet("POST", f"/api/claims/{claim_id}/signature", raw=der)
            check.expect(uploaded["valid"], "legal name proven by a qualified-style signature, accepted by the node", uploaded["node_verdict"])

        print("explorer privacy")
        async with http.get(f"{node}/api/explorer/identities/{identity}") as resp:
            text = await resp.text()
        check.expect(resp.status == 200 and EMAIL not in text, "the explorer shows the wallet's claims but not the email address")

        print("sign-in through a standard OIDC client")
        shared = await sign_in(env, resolver, wallet, check, True, "sharing")
        check.expect(shared.get("sub") == identity, "id_token subject is the wallet's identity hash")
        check.expect(shared.get("email") == EMAIL and shared.get("email_verified") is True, "verified email released")
        if eid:
            check.expect(shared.get("name") == f"{GIVEN} {FAMILY}" and shared.get("name_verified") is True, "verified legal name released")
            frameworks = [v["verification"]["trust_framework"] for v in shared.get("verified_claims", [])]
            check.expect(frameworks == ["eidas"], "verified_claims names the eIDAS trust framework", str(frameworks))

        private = await sign_in(env, resolver, wallet, check, False, "not sharing")
        check.expect("email" not in private and "verified_claims" not in private, "nothing is released when the wallet shares nothing")
        check.expect(private.get("name_verified") is False, "only the self-asserted display name remains, labelled as such")

    print("\nPASSED" if not check.failed else f"\n{check.failed} check(s) FAILED")
    return 1 if check.failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["prepare", "run"])
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    else:
        raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
