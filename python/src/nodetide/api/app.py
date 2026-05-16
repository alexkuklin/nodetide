"""API application factory."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from aiohttp import web

from nodetide.core.storage import Storage
from nodetide.api.routes import setup_routes
from nodetide.api.auth import SessionStore, RecoveryStore


logger = logging.getLogger(__name__)


async def health_handler(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({
        "status": "healthy",
        "service": "nodetide",
        "commit": os.environ.get("GIT_COMMIT", "dev"),
    })


async def cleanup_task(app: web.Application) -> None:
    """Background task to cleanup expired sessions and recoveries."""
    session_store: SessionStore = app["session_store"]
    recovery_store: RecoveryStore = app["recovery_store"]

    while True:
        await asyncio.sleep(60)  # Run every minute

        sessions_cleaned = session_store.cleanup_expired()
        recoveries_cleaned = recovery_store.cleanup_expired()

        if sessions_cleaned or recoveries_cleaned:
            logger.debug(f"Cleanup: {sessions_cleaned} sessions, {recoveries_cleaned} recoveries")


async def on_startup(app: web.Application) -> None:
    """Called on application startup."""
    app["cleanup_task"] = asyncio.create_task(cleanup_task(app))
    logger.info("API server started")


async def on_cleanup(app: web.Application) -> None:
    """Called on application cleanup."""
    if "cleanup_task" in app:
        app["cleanup_task"].cancel()
        try:
            await app["cleanup_task"]
        except asyncio.CancelledError:
            pass

    if "storage" in app:
        app["storage"].close()

    logger.info("API server stopped")


def create_app(
    storage: Storage | None = None,
    db_path: Path | str | None = None,
    web_root: Path | str | None = None,
) -> web.Application:
    """Create the API application.

    Args:
        storage: Existing storage instance to use
        db_path: Path to database file (if storage not provided)
        web_root: Path to web client files (optional)

    Returns:
        Configured aiohttp Application
    """
    app = web.Application()

    # Setup storage
    if storage:
        app["storage"] = storage
    elif db_path:
        app["storage"] = Storage.open(Path(db_path))
    else:
        # Check environment variable or use default
        env_db_path = os.environ.get("NODETIDE_DB_PATH")
        if env_db_path:
            app["storage"] = Storage.open(Path(env_db_path))
        else:
            data_dir = Path.home() / ".nodetide"
            app["storage"] = Storage.open(data_dir / "nodetide.db")

    # Setup stores
    app["session_store"] = SessionStore()
    app["recovery_store"] = RecoveryStore()

    # Health check endpoint
    app.router.add_get("/health", health_handler)

    # Setup API routes
    setup_routes(app)

    # Setup lifecycle hooks
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Add CORS middleware for browser clients
    @web.middleware
    async def cors_middleware(request: web.Request, handler) -> web.Response:
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)

        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    app.middlewares.append(cors_middleware)

    # Setup static file serving for web client
    resolved_web_root = web_root or os.environ.get("NODETIDE_WEB_ROOT")
    if resolved_web_root:
        web_path = Path(resolved_web_root)
        if web_path.exists():
            logger.info(f"Serving web client from {web_path}")

            # Serve index.html for root
            async def index_handler(request: web.Request) -> web.FileResponse:
                return web.FileResponse(web_path / "index.html")

            app.router.add_get("/", index_handler)

            # Serve specific static directories
            if (web_path / "js").exists():
                app.router.add_static("/js/", web_path / "js", name="js")

            # Serve manifest.json
            async def manifest_handler(request: web.Request) -> web.FileResponse:
                return web.FileResponse(web_path / "manifest.json")

            # Serve service worker
            async def sw_handler(request: web.Request) -> web.FileResponse:
                return web.FileResponse(web_path / "sw.js")

            # Serve icon
            async def icon_handler(request: web.Request) -> web.FileResponse:
                return web.FileResponse(web_path / "icon.svg")

            if (web_path / "manifest.json").exists():
                app.router.add_get("/manifest.json", manifest_handler)
            if (web_path / "sw.js").exists():
                app.router.add_get("/sw.js", sw_handler)
            if (web_path / "icon.svg").exists():
                app.router.add_get("/icon.svg", icon_handler)

    return app


async def run_api_server(
    host: str = "127.0.0.1",
    port: int = 4557,
    storage: Storage | None = None,
    db_path: Path | str | None = None,
    web_root: Path | str | None = None,
) -> None:
    """Run the API server.

    Args:
        host: Host to bind to
        port: Port to listen on
        storage: Existing storage instance
        db_path: Path to database file
        web_root: Path to web client files
    """
    app = create_app(storage=storage, db_path=db_path, web_root=web_root)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()

    logger.info(f"API server running on http://{host}:{port}")

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
