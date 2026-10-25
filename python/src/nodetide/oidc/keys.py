"""RSA signing key for id_tokens, with JWKS export."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


class OIDCSigningKey:
    """The bridge's own RS256 key (not a Nodetide identity key)."""

    def __init__(self, private_key: rsa.RSAPrivateKey):
        self._key = private_key
        numbers = private_key.public_key().public_numbers()
        self._n = _b64url(_int_bytes(numbers.n))
        self._e = _b64url(_int_bytes(numbers.e))
        # RFC 7638 JWK thumbprint
        thumb = json.dumps(
            {"e": self._e, "kty": "RSA", "n": self._n}, sort_keys=True, separators=(",", ":")
        )
        self.kid = _b64url(hashlib.sha256(thumb.encode("ascii")).digest())

    @classmethod
    def generate(cls) -> OIDCSigningKey:
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    @classmethod
    def load_or_create(cls, path: Path | None) -> OIDCSigningKey:
        """Load the PEM at `path`, creating it (mode 0600) if missing.

        With no path the key is ephemeral: tokens stop verifying after restart.
        """
        if path is None:
            logger.warning("OIDC signing key is ephemeral (no key file configured)")
            return cls.generate()

        path = Path(path)
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError(f"{path} is not an RSA private key")
            return cls(key)

        key = cls.generate()
        pem = key._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        logger.info("Created OIDC signing key at %s", path)
        return key

    def jwk(self) -> dict[str, Any]:
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": self._n,
            "e": self._e,
        }

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk()]}

    def sign_jwt(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.kid})
