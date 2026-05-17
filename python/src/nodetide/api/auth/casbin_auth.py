"""Casbin-based authorization for nodetide API."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Callable, Awaitable

import casbin
from aiohttp import web

from nodetide.api.auth.sessions import extract_bearer_token
from nodetide.core.crypto import VerifyKey

logger = logging.getLogger(__name__)

# Maximum age of signed request (5 minutes)
MAX_TIMESTAMP_AGE = 300

# Get the directory containing this file for loading policy files
AUTH_DIR = Path(__file__).parent


class CasbinAuth:
    """Casbin authorization manager."""

    def __init__(
        self,
        model_path: Path | str | None = None,
        policy_path: Path | str | None = None,
        admin_token: str | None = None,
    ):
        """Initialize casbin enforcer.

        Args:
            model_path: Path to model.conf file (defaults to auth/model.conf)
            policy_path: Path to policy.csv file (defaults to auth/policy.csv)
            admin_token: Admin token for API access (or from NODETIDE_ADMIN_TOKEN env)
        """
        self.model_path = Path(model_path) if model_path else AUTH_DIR / "model.conf"
        self.policy_path = Path(policy_path) if policy_path else AUTH_DIR / "policy.csv"
        self.admin_token = admin_token or os.environ.get("NODETIDE_ADMIN_TOKEN")

        # Load enforcer
        self.enforcer = casbin.Enforcer(str(self.model_path), str(self.policy_path))
        logger.info(f"Casbin enforcer loaded from {self.model_path}, {self.policy_path}")

    def get_subject(self, request: web.Request) -> str:
        """Determine the subject (role) for a request.

        Returns:
            - "localhost" if request is from localhost
            - "token_holder" if valid admin token is provided
            - "authenticated" if valid identity signature is provided
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
            # If behind a reverse proxy, check the original client IP
            # For relay security, we trust the immediate forwarded IP
            first_ip = forwarded_for.split(",")[0].strip()
            if first_ip in ("127.0.0.1", "::1"):
                return "localhost"

        # Check for admin token
        if self.admin_token:
            auth_header = request.headers.get("Authorization")
            token = extract_bearer_token(auth_header)
            if token == self.admin_token:
                return "token_holder"

        # Check for identity-based authentication
        identity_hash = request.headers.get("X-Identity")
        timestamp_str = request.headers.get("X-Timestamp")
        signature = request.headers.get("X-Signature")

        if identity_hash and timestamp_str and signature:
            verified, identity = self._verify_identity_auth(
                request, identity_hash, timestamp_str, signature
            )
            if verified:
                # Store authenticated identity in request for later use
                request["auth_identity"] = identity
                return "authenticated"

        return "anonymous"

    def _verify_identity_auth(
        self,
        request: web.Request,
        identity_hash: str,
        timestamp_str: str,
        signature: str,
    ) -> tuple[bool, str | None]:
        """Verify identity-based authentication.

        The client signs: "method:path:timestamp"
        with a valid key for the identity (master or device key).

        Args:
            request: The aiohttp request
            identity_hash: The identity hash
            timestamp_str: Unix timestamp as string
            signature: Hex-encoded signature

        Returns:
            Tuple of (is_verified, identity_hash or None)
        """
        from nodetide.core.storage import Storage
        from nodetide.core.identity import Sigchain

        try:
            timestamp = int(timestamp_str)
        except ValueError:
            logger.debug(f"Invalid timestamp format: {timestamp_str}")
            return False, None

        # Check timestamp freshness
        now = int(time.time())
        if abs(now - timestamp) > MAX_TIMESTAMP_AGE:
            logger.debug(f"Timestamp too old or in future: {timestamp}")
            return False, None

        # Get storage from app
        storage: Storage | None = request.app.get("storage")
        if not storage:
            logger.warning("No storage available for identity verification")
            return False, None

        # Load sigchain for identity
        events = storage.get_sigchain(identity_hash)
        if not events:
            logger.debug(f"Identity not found: {identity_hash}")
            return False, None

        sigchain = Sigchain.from_events(events)

        # Build the signed message
        message = f"{request.method}:{request.path}:{timestamp}"
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
                    logger.debug(f"Identity auth verified: {identity_hash}")
                    return True, identity_hash
            except Exception:
                continue

        logger.debug(f"Identity auth failed: no valid signature for {identity_hash}")
        return False, None

    def enforce(self, subject: str, obj: str, action: str) -> bool:
        """Check if the request is allowed.

        Args:
            subject: The subject (user role)
            obj: The object (request path)
            action: The action (HTTP method)

        Returns:
            True if allowed, False otherwise
        """
        return self.enforcer.enforce(subject, obj, action)

    def check_request(self, request: web.Request) -> tuple[bool, str]:
        """Check if a request is authorized.

        Args:
            request: The aiohttp request

        Returns:
            Tuple of (is_allowed, subject)
        """
        subject = self.get_subject(request)
        path = request.path
        method = request.method

        allowed = self.enforce(subject, path, method)
        return allowed, subject


def setup_casbin_auth(
    app: web.Application,
    admin_token: str | None = None,
) -> CasbinAuth:
    """Setup casbin authorization for the application.

    Args:
        app: The aiohttp application
        admin_token: Optional admin token (or from NODETIDE_ADMIN_TOKEN env)

    Returns:
        The CasbinAuth instance
    """
    casbin_auth = CasbinAuth(admin_token=admin_token)
    app["casbin_auth"] = casbin_auth
    return casbin_auth


@web.middleware
async def casbin_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.Response]],
) -> web.Response:
    """aiohttp middleware for casbin authorization.

    This middleware checks if the request is authorized based on:
    - The client IP (localhost gets admin access)
    - Bearer token (matching admin token gets admin access)
    - Default anonymous access for public endpoints
    """
    casbin_auth: CasbinAuth | None = request.app.get("casbin_auth")

    if not casbin_auth:
        # If casbin is not configured, allow all requests
        return await handler(request)

    allowed, subject = casbin_auth.check_request(request)

    if not allowed:
        logger.warning(
            f"Access denied: {subject} -> {request.method} {request.path}"
        )
        return web.json_response(
            {
                "error": "forbidden",
                "message": "Access denied",
            },
            status=403,
        )

    # Store subject in request for use in handlers
    request["auth_subject"] = subject

    return await handler(request)
