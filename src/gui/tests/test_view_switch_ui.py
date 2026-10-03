from pathlib import Path


STATIC = Path(__file__).parents[1] / "app/views/static"


def test_avatar_labs_returns_to_the_lab_route_instead_of_opening_picker() -> None:
    toolbar = (STATIC / "js/toolbar.js").read_text(encoding="utf-8")
    binding = toolbar[toolbar.index("_bind('btn-labs'"):toolbar.index("_bind('btn-mode-select'")]
    assert "location.hash = 'labs'" in binding
    assert "_showOpenDialog" not in binding


def test_route_switcher_renders_lab_view_for_labs_hash() -> None:
    app = (STATIC / "js/app.js").read_text(encoding="utf-8")
    assert "const wantsAdmin = route === 'admin';" in app
    assert "labView.hidden = admin;" in app
    assert "adminView.hidden = !admin;" in app
