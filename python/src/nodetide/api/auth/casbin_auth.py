"""Casbin-based authorization for nodetide API."""

from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path
from typing import Callable, Awaitable

import casbin
import jwt
from aiohttp import web

from nodetide.api.auth.sessions import extract_bearer_token
from nodetide.core.crypto import VerifyKey

logger = logging.getLogger(__name__)

# Maximum age of signed request for token exchange (5 minutes)
MAX_TIMESTAMP_AGE = 300

# Default JWT expiry (24 hours)
DEFAULT_JWT_EXPIRY = 86400

# Get the directory containing this file for loading policy files
AUTH_DIR = Path(__file__).parent


class CasbinAuth:
    """Casbin authorization manager with JWT support."""

    def __init__(
        self,
        model_path: Path | str | None = None,
        policy_path: Path | str | None = None,
        admin_token: str | None = None,
        jwt_secret: str | None = None,
        jwt_expiry: int = DEFAULT_JWT_EXPIRY,
    ):
        """Initialize casbin enforcer.

        Args:
            model_path: Path to model.conf file (defaults to auth/model.conf)
            policy_path: Path to policy.csv file (defaults to auth/policy.csv)
            admin_token: Admin token for API access (or from NODETIDE_ADMIN_TOKEN env)
            jwt_secret: Secret for signing JWTs (or from NODETIDE_JWT_SECRET env)
            jwt_expiry: JWT expiry time in seconds (default 24 hours)
        """
        self.model_path = Path(model_path) if model_path else AUTH_DIR / "model.conf"
        self.policy_path = Path(policy_path) if policy_path else AUTH_DIR / "policy.csv"
        self.admin_token = admin_token or os.environ.get("NODETIDE_ADMIN_TOKEN")
        self.jwt_secret = jwt_secret or os.environ.get("NODETIDE_JWT_SECRET") or secrets.token_hex(32)
        self.jwt_expiry = jwt_expiry

        # Load enforcer
        self.enforcer = casbin.Enforcer(str(self.model_path), str(self.policy_path))
        logger.info(f"Casbin enforcer loaded from {self.model_path}, {self.policy_path}")

    def create_token(self, identity: str) -> str:
        """Create a JWT token for an identity.

        Args:
            identity: The identity hash

        Returns:
            JWT token string
        """
        now = int(time.time())
        payload = {
            "sub": identity,
            "iat": now,
            "exp": now + self.jwt_expiry,
            "type": "identity",
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def verify_token(self, token: str) -> dict | None:
        """Verify a JWT token.

        Args:
            token: JWT token string

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            logger.debug("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid JWT token: {e}")
            return None

    def get_subject(self, request: web.Request) -> str:
        """Determine the subject (role) for a request.

        Returns:
            - "localhost" if request is from localhost
            - "token_holder" if valid admin token is provided
            - "authenticated" if valid JWT is provided
            - "anonymous" otherwise
        """
        # Check for localhost
        peername = request.transport.get_extra_info("peername") if request.transport else None
        if peername:
            client_ip = peername[0]
            if client_ip in ("127.0.0.1", "::1", "localhost"):
                return "localhost"

        # Check X-Forwarded-For header (for reverse proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip in ("127.0.0.1", "::1"):
                return "localhost"

        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        token = extract_bearer_token(auth_header)

        if token:
            # Check for admin token first
            if self.admin_token and token == self.admin_token:
                return "token_holder"

            # Try JWT verification
            payload = self.verify_token(token)
            if payload and payload.get("type") == "identity":
                request["auth_identity"] = payload.get("sub")
                return "authenticated"

        return "anonymous"

    def enforce(self, subject: str, obj: str, action: str) -> bool:
        """Check if the request is allowed."""
        return self.enforcer.enforce(subject, obj, action)

    def check_request(self, request: web.Request) -> tuple[bool, str]:
        """Check if a request is authorized."""
        subject = self.get_subject(request)
        path = request.path
        method = request.method
        allowed = self.enforce(subject, path, method)
        return allowed, subject


def verify_identity_signature(
    storage,
    identity_hash: str,
    timestamp: int,
    signature: str,
) -> bool:
    """Verify a signature for identity authentication.

    The client signs: "auth:identity_hash:timestamp"

    Args:
        storage: Storage instance
        identity_hash: The identity hash
        timestamp: Unix timestamp
        signature: Hex-encoded signature

    Returns:
        True if signature is valid
    """
    from nodetide.core.identity import Sigchain

    # Check timestamp freshness
    now = int(time.time())
    if abs(now - timestamp) > MAX_TIMESTAMP_AGE:
        logger.debug(f"Timestamp too old or in future: {timestamp}")
        return False

    # Load sigchain for identity
    events = storage.get_sigchain(identity_hash)
    if not events:
        logger.debug(f"Identity not found: {identity_hash}")
        return False

    sigchain = Sigchain.from_events(events)

    # Build the signed message
    message = f"auth:{identity_hash}:{timestamp}"
    message_bytes = message.encode("utf-8")

    # Get all valid signing keys (master + active devices)
    valid_keys = []
    master_key = sigchain.get_current_master_key()
    if master_key:
        valid_keys.append(master_key)

    for device in sigchain.get_active_devices():
        valid_keys.append(device.pubkey)

    # Try to verify with each valid key
    for key_hex in valid_keys:
        try:
            verify_key = VerifyKey.from_hex(key_hex)
            if verify_key.verify_hex(message_bytes, signature):
                return True
        except Exception:
            continue

    return False


async def token_handler(request: web.Request) -> web.Response:
    """POST /api/auth/token - Exchange signed request for JWT.

    Request body:
    {
        "identity": "identity_hash",
        "timestamp": 1234567890,
        "signature": "hex_signature"
    }

    The signature signs: "auth:identity_hash:timestamp"

    Response:
    {
        "token": "jwt_token",
        "expires_at": 1234567890
    }
    """
    casbin_auth: CasbinAuth | None = request.app.get("casbin_auth")
    if not casbin_auth:
        return web.json_response(
            {"error": "auth_not_configured", "message": "Authentication not configured"},
            status=500,
        )

    try:
        data = await request.json()
    except Exception:
        return web.json_response(
            {"error": "invalid_json", "message": "Invalid JSON body"},
            status=400,
        )

    identity = data.get("identity")
    timestamp = data.get("timestamp")
    signature = data.get("signature")

    if not identity or not timestamp or not signature:
        return web.json_response(
            {"error": "missing_fields", "message": "Missing identity, timestamp, or signature"},
            status=400,
        )

    try:
        timestamp = int(timestamp)
    except ValueError:
        return web.json_response(
            {"error": "invalid_timestamp", "message": "Timestamp must be an integer"},
            status=400,
        )

    storage = request.app.get("storage")
    if not storage:
        return web.json_response(
            {"error": "storage_unavailable", "message": "Storage not available"},
            status=500,
        )

    if not verify_identity_signature(storage, identity, timestamp, signature):
        return web.json_response(
            {"error": "invalid_signature", "message": "Signature verification failed"},
            status=401,
        )

    token = casbin_auth.create_token(identity)
    expires_at = int(time.time()) + casbin_auth.jwt_expiry

    return web.json_response({
        "token": token,
        "expires_at": expires_at,
        "identity": identity,
    })


def setup_casbin_auth(
    app: web.Application,
    admin_token: str | None = None,
) -> CasbinAuth:
    """Setup casbin authorization for the application."""
    casbin_auth = CasbinAuth(admin_token=admin_token)
    app["casbin_auth"] = casbin_auth

    # Add token endpoint
    app.router.add_post("/api/auth/token", token_handler)

    return casbin_auth


@web.middleware
async def casbin_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.Response]],
) -> web.Response:
    """aiohttp middleware for casbin authorization."""
    casbin_auth: CasbinAuth | None = request.app.get("casbin_auth")

    if not casbin_auth:
        return await handler(request)

    allowed, subject = casbin_auth.check_request(request)

    if not allowed:
        logger.warning(
            f"Access denied: {subject} -> {request.method} {request.path}"
        )
        return web.json_response(
            {"error": "forbidden", "message": "Access denied"},
            status=403,
        )

    request["auth_subject"] = subject
    return await handler(request)
