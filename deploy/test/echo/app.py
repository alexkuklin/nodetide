"""The "application" behind the OIDC client: shows what the sign-in delivered.

oauth2-proxy has already verified the id_token and passes it on as `Authorization: Bearer`.
This page only decodes the payload for display; it is a test aid, not a security boundary.
"""

import base64
import html
import json
import os

from aiohttp import web


def claims_from(request: web.Request) -> dict | None:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    try:
        payload = header[7:].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None


async def claims_json(request: web.Request) -> web.Response:
    claims = claims_from(request)
    if claims is None:
        return web.json_response({"error": "no id_token"}, status=401)
    return web.json_response(claims)


async def index(request: web.Request) -> web.Response:
    claims = claims_from(request)
    if claims is None:
        return web.Response(text="Not signed in (no id_token reached the application).", status=401)
    rows = "".join(
        f"<tr><th>{html.escape(k)}</th><td><pre>{html.escape(json.dumps(v, indent=2, ensure_ascii=False) if not isinstance(v, str) else v)}</pre></td></tr>"
        for k, v in claims.items()
    )
    verified = claims.get("name_verified")
    banner = (
        "Verified legal name" if verified is True else
        "Self-asserted display name only" if verified is False else
        "No name released"
    )
    body = f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed in with Nodetide</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}
th{{text-align:left;vertical-align:top;padding-right:1rem;white-space:nowrap}}pre{{margin:0;white-space:pre-wrap}}
.ok{{color:#0a7a4f}}</style>
<h1>Signed in with Nodetide</h1>
<p>You are <code>{html.escape(str(claims.get('sub')))}</code>.</p>
<p class="ok">Name: {html.escape(banner)}. Email: {'verified' if claims.get('email_verified') else 'not released'}.</p>
<h2>Claims the application received</h2><table>{rows}</table>
<p><a href="/oauth2/sign_out">Sign out</a> · <a href="/claims.json">claims.json</a></p>"""
    return web.Response(text=body, content_type="text/html")


app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/claims.json", claims_json)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), print=None)
