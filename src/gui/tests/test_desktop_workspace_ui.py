from pathlib import Path
from uuid import uuid4

from app.services.lab_log_service import LabLogService
from app.services.lab_resolver import ResolvedLab


STATIC = Path(__file__).parents[1] / "app/views/static"


def _read(relative: str) -> str:
    return (STATIC / relative).read_text(encoding="utf-8")


def test_canvas_controls_are_floating_and_keep_wheel_zoom() -> None:
    html = _read("index.html")
    canvas = _read("js/canvas.js")
    assert 'id="canvas-tools"' in html
    assert 'id="canvas-view-controls"' in html
    assert 'id="btn-zoom-in"' in html
    assert 'wheelSensitivity: 0.3' in canvas
    assert "function zoomBy(delta)" in canvas


def test_selection_and_properties_use_distinct_mouse_gestures() -> None:
    app = _read("js/app.js")
    canvas = _read("js/canvas.js")
    assert "Canvas.on('node-rightclick'" in app
    assert "await _openPropertiesModal(data);" in app
    assert "_emit('node-select', node.data());" in canvas
    assert 'id="workspace-drawer"' in _read("index.html")


def test_inspector_and_correlated_log_websocket_are_present() -> None:
    html = _read("index.html")
    logs = _read("js/lab_logs.js")
    assert 'id="lab-inspector"' in html
    assert 'data-inspector-tab="trace"' in html
    assert "/ws/lab-logs/${encodeURIComponent(labId)}" in logs


def test_lab_log_filter_does_not_match_unrelated_records(tmp_path) -> None:
    lab = ResolvedLab(uuid4(), "training", "dnlab-a1b2c3d4", "br-test", tmp_path / "lab.yml", None)
    assert LabLogService._belongs_to_lab("deploy dnlab-a1b2c3d4 complete", lab)
    assert not LabLogService._belongs_to_lab("deploy dnlab-other complete", lab)
    assert not LabLogService._belongs_to_lab("deploy training complete", lab)
