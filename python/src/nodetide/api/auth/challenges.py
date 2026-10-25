"""In-memory store of outstanding AuthRequests (nonce -> request)."""

from __future__ import annotations

from nodetide.core.auth import AuthRequest

# Bound memory: challenge issuance is unauthenticated.
MAX_PENDING_CHALLENGES = 10_000


class ChallengeStoreFull(Exception):
    """Too many outstanding challenges."""


class ChallengeStore:
    """Tracks issued challenges until they are used or expire."""

    def __init__(self, max_pending: int = MAX_PENDING_CHALLENGES):
        self._requests: dict[str, AuthRequest] = {}
        self._max_pending = max_pending

    def add(self, request: AuthRequest) -> None:
        if len(self._requests) >= self._max_pending:
            self.cleanup_expired()
            if len(self._requests) >= self._max_pending:
                raise ChallengeStoreFull()
        self._requests[request.nonce] = request

    def peek(self, nonce: str) -> AuthRequest | None:
        """Get an outstanding, unexpired request without consuming it."""
        request = self._requests.get(nonce)
        if request is not None and request.is_expired:
            del self._requests[nonce]
            return None
        return request

    def consume(self, nonce: str) -> bool:
        """Mark a nonce as used. Returns False if it was not outstanding."""
        return self._requests.pop(nonce, None) is not None

    def cleanup_expired(self) -> int:
        expired = [n for n, r in self._requests.items() if r.is_expired]
        for nonce in expired:
            del self._requests[nonce]
        return len(expired)

    def __len__(self) -> int:
        return len(self._requests)
