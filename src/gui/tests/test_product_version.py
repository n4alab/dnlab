from __future__ import annotations

import asyncio

from app import main
from app.config import settings


def test_version_config_uses_the_compose_injected_version(monkeypatch) -> None:
    monkeypatch.setattr(main, "_setup_logging", lambda: None)
    monkeypatch.setattr(settings, "DNLAB_VERSION", "9.8.7-test")

    app = main.create_app()
    route = next(route for route in app.routes if route.path == "/config/version.json")
    response = asyncio.run(route.endpoint())

    assert response.status_code == 200
    assert response.body == b'{"version":"9.8.7-test"}'
    assert response.headers["cache-control"] == "no-store"


def test_version_badge_is_an_svg_image(monkeypatch) -> None:
    monkeypatch.setattr(main, "_setup_logging", lambda: None)
    monkeypatch.setattr(settings, "DNLAB_VERSION", "9.8.7-test")

    app = main.create_app()
    route = next(route for route in app.routes if route.path == "/config/version.svg")
    response = asyncio.run(route.endpoint())

    assert response.status_code == 200
    assert response.media_type == "image/svg+xml"
    assert b">9.8.7-test</text>" in response.body
    assert response.headers["cache-control"] == "no-store"
