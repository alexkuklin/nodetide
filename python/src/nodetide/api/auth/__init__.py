"""Authentication and authorization for nodetide API."""

from nodetide.api.auth.sessions import (
    Session,
    SessionStore,
    AuthContext,
    PendingRecovery,
    RecoveryStore,
    verify_event_signature,
    get_required_capability,
    verify_session_request,
    extract_bearer_token,
)
from nodetide.api.auth.casbin_auth import (
    CasbinAuth,
    setup_casbin_auth,
    casbin_middleware,
)
from nodetide.api.auth.challenges import ChallengeStore, ChallengeStoreFull
from nodetide.api.auth.native import setup_native_auth_routes

__all__ = [
    # Sessions
    "Session",
    "SessionStore",
    "AuthContext",
    "PendingRecovery",
    "RecoveryStore",
    "verify_event_signature",
    "get_required_capability",
    "verify_session_request",
    "extract_bearer_token",
    # Casbin
    "CasbinAuth",
    "setup_casbin_auth",
    "casbin_middleware",
    # Native SSO
    "ChallengeStore",
    "ChallengeStoreFull",
    "setup_native_auth_routes",
]
