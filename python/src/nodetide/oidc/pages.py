"""HTML for the bridge's sign-in page (no external assets)."""

from __future__ import annotations

import html
import json
from urllib.parse import quote

_STYLE = """
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.4rem}
code{display:block;word-break:break-all;background:#f3f3f3;padding:.6rem;border-radius:.4rem;font-size:.85rem}
#status{padding:.8rem 1rem;border-left:4px solid #888;background:#f7f7f7;margin:1.2rem 0}
.btn{display:inline-block;padding:.6rem 1rem;background:#1a56db;color:#fff;border-radius:.4rem;text-decoration:none}
a{color:#1a56db}
@media (prefers-color-scheme:dark){
body{background:#111;color:#eee}code,#status{background:#222}a{color:#8ab4ff}
}
"""

_SCRIPT = """
(function () {
  var statusUrl = %(status_url)s;
  var secret = location.hash.slice(1);
  var statusEl = document.getElementById('status');
  var back = document.getElementById('back');
  function done(text, href, label) {
    statusEl.textContent = text;
    if (href) { back.href = href; back.textContent = label; }
  }
  async function poll() {
    if (!secret) { done('This sign-in page is not valid. Please start again from the application.'); return; }
    try {
      var r = await fetch(statusUrl, {headers: {'X-Login-Secret': secret}, cache: 'no-store'});
      if (r.status === 404) { done('This sign-in page is no longer valid. Please start again.'); return; }
      var s = await r.json();
      if (s.status === 'approved' && s.redirect_to) { statusEl.textContent = s.message; location.replace(s.redirect_to); return; }
      if (s.status === 'expired' || s.status === 'failed') { done(s.message, s.redirect_to, 'Return to the application'); return; }
      statusEl.textContent = s.message;
      if (s.cancel_url) { back.href = s.cancel_url; back.textContent = 'Cancel'; }
    } catch (e) { statusEl.textContent = 'Connection problem. Retrying…'; }
    setTimeout(poll, 2000);
  }
  poll();
})();
"""


def csp(script_nonce: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{script_nonce}'; "
        "style-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )


def render_login_page(client_name: str, attempt_id: str, issuer: str, script_nonce: str) -> str:
    challenge_url = f"{issuer}/oidc/login/{attempt_id}/challenge"
    deep_link = "nodetide://login?challenge_url=" + quote(challenge_url, safe="")
    status_url = json.dumps(f"/oidc/login/{attempt_id}/status").replace("</", "<\\/")
    script = _SCRIPT % {"status_url": status_url}
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Sign in with Nodetide</title><style>{_STYLE}</style></head>
<body>
<h1>Sign in to {html.escape(client_name)}</h1>
<p>Approve this sign-in in your Nodetide app. Only approve it if you started it just now.</p>
<p><a class="btn" href="{html.escape(deep_link, quote=True)}">Open Nodetide app</a></p>
<p>Or paste this address into your Nodetide app:</p>
<code>{html.escape(challenge_url)}</code>
<div id="status" role="status" aria-live="polite">Checking…</div>
<p><a id="back" href="#"></a></p>
<noscript><p>JavaScript is required to follow the sign-in progress.</p></noscript>
<script nonce="{html.escape(script_nonce, quote=True)}">{script}</script>
</body></html>"""


def render_error_page(message: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in error</title><style>{_STYLE}</style></head>
<body><h1>Sign-in error</h1><p>{html.escape(message)}</p></body></html>"""
