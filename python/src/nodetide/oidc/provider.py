"""OIDC bridge state machine: sign-in attempts, authorization codes, tokens.

A relying party sends the user's browser to /oidc/authorize. The bridge opens a
*sign-in attempt* holding a Nodetide AuthRequest (audience = issuer). The user's
Nodetide app answers it with a signed AuthAssertion; the bridge verifies it
against the identity's sigchain and, if good, hands the browser back to the
relying party with an authorization code.

Unknown or stale identities are not an error to retry by hand: the attempt moves
to "fetching", the identity is queued with the IdentityFetcher, and the page
tells the user sign-in has failed *for now*.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from nodetide.core.auth import (
    CLOCK_SKEW,
    AuthRequest,
    AuthResult,
    choose_sigchain,
    verify_assertion,
)
from nodetide.core.identity import Sigchain
from nodetide.core.storage import Storage
from nodetide.oidc.config import OIDCClient, OIDCConfig
from nodetide.oidc.fetcher import IDENTITY_RE, FetchFn, IdentityFetcher
from nodetide.oidc.keys import OIDCSigningKey

MAX_ATTEMPTS = 5000
MAX_FAILURES = 5
REQUEST_LIFETIME = 300  # one AuthRequest; rotated while the attempt lives

# User-facing messages
MSG_WAITING = "Waiting for you to approve this sign-in in your Nodetide app."
MSG_FETCHING = (
    "Nodetide doesn't know this identity yet. We've asked the network for it — "
    "this can take a few minutes. Keep this page open, or try again later."
)
MSG_STALE = (
    "We have an out-of-date copy of this identity. We're fetching the latest — "
    "this can take a few minutes. Keep this page open, or try again later."
)
MSG_FETCH_RETRY = (
    "Sign-in failed for now: we couldn't reach this identity yet. "
    "We'll keep trying in the background, so try again in a few minutes."
)
MSG_REAPPROVE = "We now know this identity. Please approve the sign-in in your app again."
MSG_APPROVED = "Approved. Returning you to the application…"
MSG_EXPIRED = "This sign-in timed out. Please start again."
MSG_EXPIRED_FETCHING = (
    "Sign-in failed for now: this identity isn't available yet. "
    "We're still fetching it in the background — try again in a few minutes."
)
MSG_TOO_MANY_FAILURES = "Too many rejected approvals. Please start again."


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def add_query(uri: str, params: dict[str, str | None]) -> str:
    """Append query parameters to a redirect URI, keeping any it already has."""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit(parts._replace(query=urlencode(query)))


@dataclass
class LoginAttempt:
    id: str  # public: appears in QR codes / deep links
    secret: str  # private: lets the originating browser poll status
    client: OIDCClient
    redirect_uri: str
    state: str | None
    oidc_nonce: str | None
    scope: str
    code_challenge: str | None
    login_hint: str | None
    hint_urls: list[str]
    auth_request: AuthRequest
    created_at: int
    expires_at: int
    status: str = "waiting"  # waiting | fetching | approved | failed | expired
    message: str = MSG_WAITING
    assertion: dict[str, Any] | None = None  # held while the identity is fetched
    identity: str | None = None
    failures: int = 0
    redirect_to: str | None = None


@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str | None
    oidc_nonce: str | None
    scope: str
    identity: str
    device: str
    name: str | None
    auth_time: int
    expires_at: int


@dataclass
class AccessToken:
    token: str
    identity: str
    scope: str
    name: str | None
    expires_at: int


@dataclass
class Submission:
    """Result of an app submitting an assertion."""

    outcome: str  # approved | fetching | reapprove | <verification error code> | ...
    http_status: int
    message: str


class TokenError(Exception):
    """OAuth token endpoint error (RFC 6749 section 5.2)."""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def safe_equal(a: str, b: str) -> bool:
    """Constant-time string comparison that tolerates non-ASCII input."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class OIDCProvider:
    def __init__(
        self,
        config: OIDCConfig,
        storage: Storage,
        key: OIDCSigningKey | None = None,
        fetch: FetchFn | None = None,
        clock=time.time,
    ):
        self.config = config
        self.storage = storage
        self.key = key or OIDCSigningKey.load_or_create(config.key_file)
        self._clock = clock
        self.attempts: dict[str, LoginAttempt] = {}
        self.codes: dict[str, AuthCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.fetcher = IdentityFetcher(
            storage,
            seed_nodes=config.seed_nodes,
            fetch=fetch,
            on_update=self.on_identity_update,
            allow_private=config.allow_private_fetch,
            clock=clock,
        )

    def _now(self) -> int:
        return int(self._clock())

    # --- discovery ---------------------------------------------------------

    def discovery_document(self) -> dict[str, Any]:
        iss = self.config.issuer
        return {
            "issuer": iss,
            "authorization_endpoint": f"{iss}/oidc/authorize",
            "token_endpoint": f"{iss}/oidc/token",
            "userinfo_endpoint": f"{iss}/oidc/userinfo",
            "jwks_uri": f"{iss}/oidc/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post", "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name"],
        }

    # --- attempts ----------------------------------------------------------

    def parse_login_hint(self, login_hint: str | None) -> tuple[str | None, list[str]]:
        """login_hint is "<identity hash>" optionally followed by "@<node url>"."""
        if not login_hint:
            return None, []
        identity, _, url = login_hint.partition("@")
        identity = identity.strip().lower()
        if not IDENTITY_RE.match(identity):
            return None, []
        return identity, [url] if url else []

    def create_attempt(
        self,
        client: OIDCClient,
        redirect_uri: str,
        state: str | None,
        oidc_nonce: str | None,
        scope: str,
        code_challenge: str | None,
        login_hint: str | None,
    ) -> LoginAttempt | None:
        self.cleanup()
        if len(self.attempts) >= MAX_ATTEMPTS:
            return None
        now = self._now()
        hinted_identity, hint_urls = self.parse_login_hint(login_hint)
        attempt = LoginAttempt(
            id=secrets.token_urlsafe(16),
            secret=secrets.token_urlsafe(24),
            client=client,
            redirect_uri=redirect_uri,
            state=state,
            oidc_nonce=oidc_nonce,
            scope=scope,
            code_challenge=code_challenge,
            login_hint=hinted_identity,
            hint_urls=hint_urls,
            auth_request=AuthRequest.new(aud=self.config.issuer, lifetime=REQUEST_LIFETIME),
            created_at=now,
            expires_at=now + self.config.attempt_lifetime,
        )
        self.attempts[attempt.id] = attempt

        # Warm the cache: if the user told us who they are and we don't know
        # them, start fetching before they even approve.
        if hinted_identity and self.storage.get_sigchain(hinted_identity) is None:
            self.fetcher.schedule(hinted_identity, hint_urls)
        return attempt

    def get_attempt(self, attempt_id: str) -> LoginAttempt | None:
        attempt = self.attempts.get(attempt_id)
        if attempt is not None:
            self._refresh(attempt)
        return attempt

    def check_secret(self, attempt: LoginAttempt, secret: str | None) -> bool:
        return bool(secret) and safe_equal(attempt.secret, secret or "")

    def _refresh(self, attempt: LoginAttempt) -> None:
        if attempt.status in ("approved", "failed", "expired"):
            return
        if self._now() > attempt.expires_at:
            attempt.message = MSG_EXPIRED_FETCHING if attempt.status == "fetching" else MSG_EXPIRED
            attempt.status = "expired"
            attempt.assertion = None

    def current_request(self, attempt: LoginAttempt) -> AuthRequest:
        """The attempt's live AuthRequest, rotating it when it has expired."""
        if attempt.auth_request.is_expired and attempt.status in ("waiting", "fetching"):
            attempt.auth_request = AuthRequest.new(
                aud=self.config.issuer, lifetime=REQUEST_LIFETIME
            )
        return attempt.auth_request

    def error_redirect(self, attempt: LoginAttempt, error: str, description: str) -> str:
        return add_query(
            attempt.redirect_uri,
            {"error": error, "error_description": description, "state": attempt.state},
        )

    def status(self, attempt: LoginAttempt) -> dict[str, Any]:
        """JSON for the polling page."""
        self._refresh(attempt)
        body: dict[str, Any] = {"status": attempt.status, "message": attempt.message}

        if attempt.status == "fetching" and attempt.assertion is not None:
            info = self.fetcher.status(str(attempt.assertion.get("identity")))
            if info is not None:
                body["fetch"] = {
                    "state": info["state"],
                    "attempts": info["attempts"],
                    "next_attempt_at": info["next_attempt_at"],
                }
                if info["attempts"] > 0 and info["last_error"]:
                    body["message"] = MSG_FETCH_RETRY
        if attempt.status == "approved":
            body["redirect_to"] = attempt.redirect_to
        elif attempt.status in ("expired", "failed"):
            code = "temporarily_unavailable" if "for now" in body["message"] else "access_denied"
            body["redirect_to"] = self.error_redirect(attempt, code, body["message"])
        else:
            body["cancel_url"] = self.error_redirect(
                attempt, "access_denied", "The user cancelled the sign-in."
            )
        return body

    # --- assertions --------------------------------------------------------

    async def submit_assertion(
        self,
        attempt: LoginAttempt,
        assertion: Any,
        supplied_chain: Any = None,
        hints: Iterable[str] = (),
    ) -> Submission:
        self._refresh(attempt)
        if attempt.status == "approved":
            return Submission("conflict", 409, "This sign-in was already completed.")
        if attempt.status in ("expired", "failed"):
            return Submission("gone", 410, attempt.message)

        if not isinstance(assertion, dict):
            return Submission("invalid_request", 400, "Missing assertion")
        nonce, identity = assertion.get("nonce"), assertion.get("identity")
        if not isinstance(nonce, str) or not isinstance(identity, str):
            return Submission("invalid_request", 400, "Assertion needs string nonce and identity")
        if not IDENTITY_RE.match(identity):
            return Submission("invalid_request", 400, "Invalid identity")
        if not safe_equal(nonce, self.current_request(attempt).nonce):
            return Submission("unknown_challenge", 401, "Challenge expired; fetch a fresh one.")

        provided: Sigchain | None = None
        if supplied_chain is not None:
            if not isinstance(supplied_chain, list):
                return Submission("invalid_request", 400, "sigchain must be a list of events")
            try:
                provided = Sigchain.from_list(supplied_chain)
            except Exception:
                return Submission("invalid_request", 400, "Malformed sigchain")

        chain, conflict = choose_sigchain(self.storage.get_sigchain(identity), provided)
        if conflict:
            return Submission("conflict", 409, "Supplied sigchain conflicts with the stored one.")

        hint_list = list(attempt.hint_urls) + [h for h in hints if isinstance(h, str)]
        if chain is None:
            return self._start_fetch(attempt, assertion, hint_list, MSG_FETCHING)
        return self._evaluate(attempt, assertion, chain, hint_list)

    def _start_fetch(
        self,
        attempt: LoginAttempt,
        assertion: dict[str, Any],
        hints: list[str],
        message: str,
    ) -> Submission:
        identity = assertion["identity"]
        want_head = assertion.get("chain_head")
        if not self.fetcher.schedule(identity, hints, want_head if isinstance(want_head, str) else None):
            return Submission(
                "fetch_unavailable", 503,
                "Sign-in failed for now: the node can't look up new identities right now. "
                "Try again in a few minutes.",
            )
        attempt.assertion = assertion
        attempt.status = "fetching"
        attempt.message = message
        return Submission("fetching", 202, message)

    def _evaluate(
        self,
        attempt: LoginAttempt,
        assertion: dict[str, Any],
        chain: Sigchain,
        hints: list[str],
        after_fetch: bool = False,
    ) -> Submission:
        request = attempt.auth_request
        result = verify_assertion(assertion, chain, expected_aud=self.config.issuer, now=self._now())
        if result.ok and assertion["exp"] > request.expires_at + CLOCK_SKEW:
            result = AuthResult.fail("invalid_assertion", "Assertion outlives its challenge")

        if result.ok:
            return self._approve(attempt, result, chain)

        if result.code == "unknown_chain_head":
            return self._start_fetch(attempt, assertion, hints, MSG_STALE)

        attempt.assertion = None
        if after_fetch and result.code == "expired":
            # The identity is known now, but the old approval timed out while we
            # were fetching. Ask the user to approve again (instant this time).
            attempt.status = "waiting"
            attempt.auth_request = AuthRequest.new(aud=self.config.issuer, lifetime=REQUEST_LIFETIME)
            attempt.message = MSG_REAPPROVE
            return Submission("reapprove", 202, MSG_REAPPROVE)

        attempt.failures += 1
        attempt.message = f"Approval rejected: {result.error}"
        if attempt.failures >= MAX_FAILURES:
            attempt.status = "failed"
            attempt.message = MSG_TOO_MANY_FAILURES
        else:
            attempt.status = "waiting"
        return Submission(result.code or "invalid_assertion", 401, attempt.message)

    def _approve(self, attempt: LoginAttempt, result: AuthResult, chain: Sigchain) -> Submission:
        now = self._now()
        genesis = chain.genesis
        name = genesis.name if genesis is not None else None
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthCode(
            code=code,
            client_id=attempt.client.client_id,
            redirect_uri=attempt.redirect_uri,
            code_challenge=attempt.code_challenge,
            oidc_nonce=attempt.oidc_nonce,
            scope=attempt.scope,
            identity=result.identity or "",
            device=result.device or "",
            name=name,
            auth_time=now,
            expires_at=now + self.config.code_lifetime,
        )
        attempt.status = "approved"
        attempt.identity = result.identity
        attempt.assertion = None
        attempt.message = MSG_APPROVED
        attempt.redirect_to = add_query(attempt.redirect_uri, {"code": code, "state": attempt.state})
        return Submission("approved", 200, MSG_APPROVED)

    async def on_identity_update(self, identity_hash: str) -> None:
        """Called by the fetcher when a chain was stored: finish waiting attempts."""
        chain = self.storage.get_sigchain(identity_hash)
        if chain is None:
            return
        for attempt in list(self.attempts.values()):
            self._refresh(attempt)
            if (
                attempt.status == "fetching"
                and attempt.assertion is not None
                and attempt.assertion.get("identity") == identity_hash
            ):
                self._evaluate(attempt, attempt.assertion, chain, [], after_fetch=True)

    # --- token endpoint ----------------------------------------------------

    def exchange_code(
        self,
        client: OIDCClient,
        code: str | None,
        redirect_uri: str | None,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        # Codes are single use: remove first so failed guesses cannot be retried.
        auth_code = self.codes.pop(code, None) if code else None
        if auth_code is None or self._now() > auth_code.expires_at:
            raise TokenError("invalid_grant", "Unknown, used or expired code")
        if auth_code.client_id != client.client_id:
            raise TokenError("invalid_grant", "Code was issued to another client")
        if auth_code.redirect_uri != redirect_uri:
            raise TokenError("invalid_grant", "redirect_uri mismatch")

        if auth_code.code_challenge:
            if not code_verifier or not (43 <= len(code_verifier) <= 128):
                raise TokenError("invalid_grant", "code_verifier required")
            expected = b64url(hashlib.sha256(code_verifier.encode("ascii", "ignore")).digest())
            if not safe_equal(expected, auth_code.code_challenge):
                raise TokenError("invalid_grant", "PKCE verification failed")
        elif client.is_public:
            raise TokenError("invalid_grant", "PKCE required for public clients")

        now = self._now()
        claims: dict[str, Any] = {
            "iss": self.config.issuer,
            "sub": auth_code.identity,
            "aud": client.client_id,
            "iat": now,
            "exp": now + self.config.id_token_lifetime,
            "auth_time": auth_code.auth_time,
            "nodetide_device": auth_code.device,
        }
        if auth_code.oidc_nonce:
            claims["nonce"] = auth_code.oidc_nonce
        scopes = auth_code.scope.split()
        if "profile" in scopes and auth_code.name:
            claims["name"] = auth_code.name  # self-asserted in the identity's genesis

        access_token = "at_" + secrets.token_urlsafe(32)
        self.access_tokens[access_token] = AccessToken(
            token=access_token,
            identity=auth_code.identity,
            scope=auth_code.scope,
            name=auth_code.name if "profile" in scopes else None,
            expires_at=now + self.config.access_token_lifetime,
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_lifetime,
            "id_token": self.key.sign_jwt(claims),
        }

    def userinfo(self, token: str | None) -> dict[str, Any] | None:
        access = self.access_tokens.get(token) if token else None
        if access is None or self._now() > access.expires_at:
            return None
        info: dict[str, Any] = {"sub": access.identity}
        if access.name:
            info["name"] = access.name
        return info

    # --- housekeeping ------------------------------------------------------

    def cleanup(self) -> None:
        now = self._now()
        for attempt_id, attempt in list(self.attempts.items()):
            # keep finished attempts around briefly so the page can read the result
            if now > attempt.expires_at + 300:
                del self.attempts[attempt_id]
        for code, auth_code in list(self.codes.items()):
            if now > auth_code.expires_at:
                del self.codes[code]
        for token, access in list(self.access_tokens.items()):
            if now > access.expires_at:
                del self.access_tokens[token]

    async def start(self) -> None:
        await self.fetcher.start()

    async def stop(self) -> None:
        await self.fetcher.stop()
