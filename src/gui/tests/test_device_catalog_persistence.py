import asyncio
import json

from app.config import settings
from app.services import device_catalog


def _catalog(label="Linux", *, extra_kind=None):
    kinds = {
        "linux": {
            "label": label,
            "vendor": "linux",
            "type": "router",
        },
    }
    if extra_kind:
        kinds.update(extra_kind)
    return {
        "defaults": {"type": "router"},
        "vendors": {"linux": {"title": "Linux", "color": "#4A4A4A"}},
        "icons": {"router": "img/devices/router.svg"},
        "kinds": kinds,
    }


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _configure(monkeypatch, tmp_path, builtin):
    static = tmp_path / "static"
    _write(static / "config" / "devices.json", builtin)
    monkeypatch.setattr(settings, "STATIC_DIR", static)
    monkeypatch.setattr(settings, "DEVICE_CATALOG_DIR", tmp_path / "state")
    device_catalog.reload()


def test_uses_builtin_catalog_without_persistent_file(monkeypatch, tmp_path):
    builtin = _catalog()
    _configure(monkeypatch, tmp_path, builtin)

    device_catalog.initialize()

    assert device_catalog.catalog() == builtin
    assert not device_catalog.custom_path().exists()
    assert device_catalog.active_path() == device_catalog.builtin_path()


def test_upgrade_merges_release_additions_and_keeps_admin_conflicts(monkeypatch, tmp_path):
    previous = _catalog("Linux")
    current = _catalog("Linux release", extra_kind={
        "new_release": {"label": "New", "vendor": "linux", "type": "router"},
    })
    saved = _catalog("Linux admin", extra_kind={
        "custom": {"label": "Custom", "vendor": "linux", "type": "router"},
    })
    _configure(monkeypatch, tmp_path, current)
    _write(device_catalog.custom_path(), saved)
    _write(device_catalog.baseline_path(), previous)

    device_catalog.initialize()

    active = device_catalog.catalog()
    assert active["kinds"]["linux"]["label"] == "Linux admin"
    assert "custom" in active["kinds"]
    assert "new_release" in active["kinds"]
    assert json.loads(device_catalog.baseline_path().read_text()) == current


def test_upgrade_preserves_admin_deletion(monkeypatch, tmp_path):
    previous = _catalog(extra_kind={
        "old": {"label": "Old", "vendor": "linux", "type": "router"},
    })
    current = _catalog("Linux release", extra_kind={
        "old": {"label": "Old release", "vendor": "linux", "type": "router"},
    })
    saved = _catalog()
    _configure(monkeypatch, tmp_path, current)
    _write(device_catalog.custom_path(), saved)
    _write(device_catalog.baseline_path(), previous)

    device_catalog.initialize()

    assert "old" not in device_catalog.catalog()["kinds"]


def test_merge_combines_independent_nested_changes_and_treats_arrays_as_atomic():
    base = {"nested": {"admin": "old", "release": "old"}, "items": ["old"]}
    custom = {"nested": {"admin": "custom", "release": "old"}, "items": ["custom"]}
    builtin = {"nested": {"admin": "old", "release": "release"}, "items": ["release"]}

    merged = device_catalog._merge(base, custom, builtin)

    assert merged == {
        "nested": {"admin": "custom", "release": "release"},
        "items": ["custom"],
    }


def test_missing_baseline_preserves_saved_catalog(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, _catalog("Linux release"))
    saved = _catalog("Linux admin")
    _write(device_catalog.custom_path(), saved)

    device_catalog.initialize()

    assert device_catalog.catalog()["kinds"]["linux"]["label"] == "Linux admin"
    assert device_catalog.baseline_path().exists()


def test_admin_write_persists_only_host_catalog_and_keeps_backup(monkeypatch, tmp_path):
    builtin = _catalog()
    _configure(monkeypatch, tmp_path, builtin)
    first = _catalog("Linux admin")
    second = _catalog("Linux admin v2")

    assert device_catalog.write_custom(json.dumps(first)) is None
    backup = device_catalog.write_custom(json.dumps(second))

    assert json.loads(device_catalog.custom_path().read_text()) == second
    assert backup is not None and backup.exists()
    assert json.loads(device_catalog.builtin_path().read_text()) == builtin
    assert json.loads(device_catalog.baseline_path().read_text()) == builtin


def test_invalid_persistent_catalog_falls_back_to_builtin(monkeypatch, tmp_path):
    builtin = _catalog()
    _configure(monkeypatch, tmp_path, builtin)
    device_catalog.custom_path().parent.mkdir(parents=True)
    device_catalog.custom_path().write_text("not json", encoding="utf-8")

    device_catalog.initialize()
    device_catalog.reload()

    assert device_catalog.catalog() == builtin


def test_browser_catalog_route_returns_active_catalog_without_cache(monkeypatch, tmp_path):
    from app import main

    builtin = _catalog()
    _configure(monkeypatch, tmp_path, builtin)
    monkeypatch.setattr(main, "_setup_logging", lambda: None)
    app = main.create_app()
    endpoint = next(route.endpoint for route in app.routes if route.path == "/config/devices.json")

    response = asyncio.run(endpoint())

    assert json.loads(response.body) == builtin
    assert response.headers["cache-control"] == "no-store"
