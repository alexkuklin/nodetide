"""OIDC bridge: lets any Nodetide identity sign in to standard OIDC applications."""

from nodetide.oidc.config import ConfigError, OIDCClient, OIDCConfig
from nodetide.oidc.handlers import setup_oidc
from nodetide.oidc.provider import OIDCProvider

__all__ = ["ConfigError", "OIDCClient", "OIDCConfig", "OIDCProvider", "setup_oidc"]
