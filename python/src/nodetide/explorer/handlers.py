"""Read-only explorer API (GET /api/explorer/*) and static UI (/explorer)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from aiohttp import web

from nodetide.explorer.service import MAX_LIMIT, Explorer, is_hash

_HEADERS = {"Cache-Control": "no-cache"}
_UI_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    # The UI is plain same-origin script plus fetches to the node(s) it browses.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self' http: https:; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
}


def _explorer(request: web.Request) -> Explorer:
    return request.app["explorer"]


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, headers=_HEADERS)


def _error(code: str, message: str, status: int) -> web.Response:
    return _json({"error": code, "message": message, "code": status}, status)


class BadParam(Exception):
    pass


def _int(request: web.Request, name: str, default: int, lo: int, hi: int) -> int:
    raw = request.query.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadParam(f"{name} must be an integer") from None
    if not lo <= value <= hi:
        raise BadParam(f"{name} must be between {lo} and {hi}")
    return value


def _hash_param(request: web.Request, name: str) -> str | None:
    value = request.query.get(name)
    if not value:
        return None
    value = value.lower()
    if not is_hash(value):
        raise BadParam(f"{name} must be a 64-character hex hash")
    return value


def _paged(request: web.Request) -> tuple[int, int]:
    return _int(request, "limit", 25, 1, MAX_LIMIT), _int(request, "offset", 0, 0, 10_000_000)


def _route(fn: Callable[[web.Request], Any]):
    """Turn BadParam into a 400 response."""

    async def wrapper(request: web.Request) -> web.Response:
        try:
            return await fn(request)
        except BadParam as e:
            return _error("invalid_request", str(e), 400)

    return wrapper


@_route
async def stats(request: web.Request) -> web.Response:
    return _json(_explorer(request).stats())


@_route
async def identities(request: web.Request) -> web.Response:
    limit, offset = _paged(request)
    q = request.query.get("q", "")
    if len(q) > 100:
        raise BadParam("q is too long")
    return _json(_explorer(request).list_identities(
        limit, offset, q or None, request.query.get("sort", "recent")
    ))


@_route
async def identity(request: web.Request) -> web.Response:
    identity_hash = request.match_info["hash"].lower()
    result = _explorer(request).get_identity(identity_hash) if is_hash(identity_hash) else None
    if result is None:
        return _error("not_found", "Identity not found on this node", 404)
    return _json(result)


@_route
async def events(request: web.Request) -> web.Response:
    limit, offset = _paged(request)
    event_type = request.query.get("type") or None
    if event_type is not None and not event_type.replace("_", "").isalpha():
        raise BadParam("type is invalid")
    return _json(_explorer(request).list_events(
        limit, offset, event_type, _hash_param(request, "identity")
    ))


@_route
async def event(request: web.Request) -> web.Response:
    event_hash = request.match_info["hash"].lower()
    result = _explorer(request).get_event(event_hash) if is_hash(event_hash) else None
    if result is None:
        return _error("not_found", "Event not found on this node", 404)
    return _json(result)


@_route
async def messages(request: web.Request) -> web.Response:
    limit, offset = _paged(request)
    return _json(_explorer(request).list_messages(limit, offset, _hash_param(request, "sender")))


@_route
async def message(request: web.Request) -> web.Response:
    message_hash = request.match_info["hash"].lower()
    result = _explorer(request).get_message(message_hash) if is_hash(message_hash) else None
    if result is None:
        return _error("not_found", "Public message not found on this node", 404)
    return _json(result)


@_route
async def delegations(request: web.Request) -> web.Response:
    limit, offset = _paged(request)
    return _json(_explorer(request).list_delegations(
        limit, offset, _hash_param(request, "from"), _hash_param(request, "to")
    ))


@_route
async def attestations(request: web.Request) -> web.Response:
    limit, offset = _paged(request)
    claim_type = request.query.get("claim_type") or None
    if claim_type is not None and len(claim_type) > 80:
        raise BadParam("claim_type is too long")
    return _json(_explorer(request).list_attestations(
        limit, offset, _hash_param(request, "subject"), _hash_param(request, "issuer"), claim_type
    ))


@_route
async def search(request: web.Request) -> web.Response:
    q = request.query.get("q", "")
    if len(q) > 100:
        raise BadParam("q is too long")
    return _json({"query": q, "results": _explorer(request).search(q)})


@_route
async def network(request: web.Request) -> web.Response:
    poller = request.app.get("relay_poller")
    status = poller.get_status() if poller is not None else None
    return _json(_explorer(request).network(status))


def setup_explorer_api(app: web.Application) -> Explorer:
    """Register the read-only JSON API."""
    explorer = Explorer(app["storage"])
    app["explorer"] = explorer

    get = app.router.add_get
    get("/api/explorer/stats", stats)
    get("/api/explorer/identities", identities)
    get("/api/explorer/identities/{hash}", identity)
    get("/api/explorer/events", events)
    get("/api/explorer/events/{hash}", event)
    get("/api/explorer/messages", messages)
    get("/api/explorer/messages/{hash}", message)
    get("/api/explorer/trust/delegations", delegations)
    get("/api/explorer/attestations", attestations)
    get("/api/explorer/search", search)
    get("/api/explorer/network", network)
    return explorer


def setup_explorer_ui(app: web.Application, web_root: Path | str) -> bool:
    """Serve the static explorer from <web_root>/explorer at /explorer.

    Returns False if the directory does not exist.
    """
    root = Path(web_root) / "explorer"
    index = root / "index.html"
    if not index.is_file():
        return False
    root = root.resolve()

    async def serve_index(request: web.Request) -> web.StreamResponse:
        return web.FileResponse(index, headers=_UI_HEADERS)

    async def serve_asset(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        path = (root / name).resolve()
        # No traversal out of the explorer directory, no dotfiles, no subdirectories.
        if path.parent != root or name.startswith(".") or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(path, headers=_UI_HEADERS)

    async def redirect(request: web.Request) -> web.StreamResponse:
        raise web.HTTPFound("/explorer/")

    app.router.add_get("/explorer", redirect)
    app.router.add_get("/explorer/", serve_index)
    app.router.add_get("/explorer/{name}", serve_asset)
    return True


def explorer_enabled() -> bool:
    """NODETIDE_EXPLORER=0 turns the explorer (API and UI) off."""
    return os.environ.get("NODETIDE_EXPLORER", "1") != "0"
