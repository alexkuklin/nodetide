"""Authentication and authorization for nodetide API."""

from nodetide.api.auth.sessions import (
    Session,
    SessionStore,
    AuthContext,
    PendingRecovery,
    RecoveryStore,
    verify_event_signature,
    get_required_capability,
    verify_assertion_signature,
    verify_session_request,
    extract_bearer_token,
)
from nodetide.api.auth.casbin_auth import (
    CasbinAuth,
    setup_casbin_auth,
    casbin_middleware,
)

__all__ = [
    # Sessions
    "Session",
    "SessionStore",
    "AuthContext",
    "PendingRecovery",
    "RecoveryStore",
    "verify_event_signature",
    "get_required_capability",
    "verify_assertion_signature",
    "verify_session_request",
    "extract_bearer_token",
    # Casbin
    "CasbinAuth",
    "setup_casbin_auth",
    "casbin_middleware",
]
