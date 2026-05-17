"""Casbin-based authorization for nodetide API."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Awaitable

import casbin
from aiohttp import web

from nodetide.api.auth.sessions import extract_bearer_token

logger = logging.getLogger(__name__)

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

        return "anonymous"

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
