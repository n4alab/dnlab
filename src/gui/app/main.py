"""FastAPI application factory."""

import asyncio
import html
import logging
import logging.handlers
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.security import allowed_origins
from app.services.events_bus import bus
from app.openapi_docs import install_openapi_docs
from app.auth.assistant import block_assistant_gui
from app.views.api.auth_routes import router as auth_router
from app.views.api.admin_routes import router as admin_router
from app.views.api.topology_routes import router as topology_router
from app.views.api.lab_routes import router as lab_router
from app.views.api.docker_routes import router as docker_router
from app.views.api.console_routes import router as console_router
from app.views.api.capture_routes import router as capture_router
from app.views.api.follow_rabbit_routes import router as follow_rabbit_router
from app.views.api.log_routes import router as log_router
from app.views.api.lab_log_routes import router as lab_log_router
from app.views.api.multinode_routes import router as multinode_router
from app.views.api.user_routes import router as user_router
from app.views.api.webui_routes import (
    WebUIHostProxyMiddleware,
    router as webui_router,
)


def _setup_logging() -> None:
    """Configure application-wide logging.

    Logs go to:
      - Console (stderr): INFO and above
      - File (<log_root>/gui/dnlab-gui.log): DEBUG and above, rotating 5x10MB
    """
    log_dir = settings.LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "dnlab-gui.log"

    # Root logger for the app package
    root = logging.getLogger("app")
    root.setLevel(logging.DEBUG)
    if root.handlers:
        return

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler — INFO
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # File handler — DEBUG, rotating
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Also capture uvicorn access logs to file
    for uv_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv_log = logging.getLogger(uv_name)
        uv_log.addHandler(fh)

    root.info("Logging initialized → %s", log_file)


def create_app() -> FastAPI:
    _setup_logging()

    application = FastAPI(
        title="ContainerLab GUI",
        description="Web-based GUI for ContainerLab network topology management",
        version="1.0.0",
    )

    # Strict CORS — explicit allowlist, never "*". WebSocket handshakes
    # are validated separately in app.security.
    origins = allowed_origins()
    logging.getLogger("app").info("CORS allowlist: %s", origins)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    application.add_middleware(WebUIHostProxyMiddleware)
    application.middleware("http")(block_assistant_gui)

    # API routers
    application.include_router(auth_router)
    application.include_router(admin_router)
    application.include_router(topology_router)
    application.include_router(lab_router)
    application.include_router(docker_router)
    application.include_router(console_router)
    application.include_router(capture_router)
    application.include_router(follow_rabbit_router)
    application.include_router(log_router)
    application.include_router(lab_log_router)
    application.include_router(multinode_router)
    application.include_router(user_router)
    application.include_router(webui_router)
    install_openapi_docs(application)

    @application.get("/config/devices.json", include_in_schema=False)
    async def active_device_catalog() -> Response:
        """Serve the merged catalog instead of the immutable static asset."""
        from app.services import device_catalog
        return Response(
            content=device_catalog.catalog_json(),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/config/version.json", include_in_schema=False)
    async def product_version() -> JSONResponse:
        """Expose the deployment version injected from the Compose .env file."""
        return JSONResponse(
            {"version": settings.DNLAB_VERSION},
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/config/version.svg", include_in_schema=False)
    async def product_version_badge() -> Response:
        """Render the deployment version as the small footer badge image."""
        version = html.escape(settings.DNLAB_VERSION, quote=True)
        width = max(28, 8 + len(settings.DNLAB_VERSION) * 7)
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="22" '
            f'viewBox="0 0 {width} 22"><text x="4" y="15" fill="#64748B" '
            'font-family="system-ui, sans-serif" font-size="12">'
            f'{version}</text></svg>'
        )
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-store"},
        )

    @application.on_event("startup")
    async def _on_startup() -> None:
        # EventsBus.publish() is thread-safe only after it knows the
        # owning loop. Orchestrator callbacks run on worker threads.
        loop = asyncio.get_running_loop()
        from app.services import device_catalog
        device_catalog.initialize()
        bus.bind_loop(loop)
        from app.services.shutdown_registry import shutdown_registry
        shutdown_registry.bind_loop(loop)
        # Warn on non-UUID topology YAMLs / orphan labs rows — see
        # app/services/startup_guard.py for the full invariant.
        from app.services.startup_guard import check_lab_identity_invariant
        await check_lab_identity_invariant()
        # RealNet RR is global infrastructure: keep it available with the GUI,
        # independent from any lab deploy/destroy lifecycle.
        from app.services.realnet_bgp import ensure_route_reflector_on_startup
        await ensure_route_reflector_on_startup()
        # Mette in piedi il cleanup loop dei tunnel WebUI idle (10 min).
        from app.services.webui_service import webui_service
        webui_service.start_cleanup_task(asyncio.get_running_loop())

    @application.on_event("shutdown")
    async def _on_shutdown() -> None:
        # Chiude tutti i tunnel ssh aperti: evita di lasciare processi
        # orfani quando systemd ferma il servizio.
        from app.services.shutdown_registry import shutdown_registry
        from app.services.webui_service import webui_service
        await shutdown_registry.drain(timeout=5.0)
        webui_service.shutdown()

    # Serve frontend static files (SPA)
    application.mount(
        "/",
        StaticFiles(directory=str(settings.STATIC_DIR), html=True),
        name="static",
    )

    return application


app = create_app()
