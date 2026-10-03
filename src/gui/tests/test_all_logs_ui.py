from pathlib import Path


STATIC = Path(__file__).parents[1] / "app/views/static"


def _read(relative: str) -> str:
    return (STATIC / relative).read_text(encoding="utf-8")


def test_toolbar_places_all_logs_next_to_consoles_and_initially_disables_it():
    html = _read("index.html")
    consoles = html.index('id="btn-all-consoles"')
    logs = html.index('id="btn-all-logs"')
    delete = html.index('id="btn-delete-topo"')

    assert consoles < logs < delete
    button = html[logs : html.index("</button>", logs)]
    assert "disabled" in button
    assert 'use href="#i-file-text"' in button
    assert "VD Logs" in button


def test_toolbar_exposes_read_only_safe_all_logs_action():
    toolbar = _read("js/toolbar.js")

    assert "_bind('btn-all-logs',     () => _emit('all-logs'))" in toolbar
    assert "function setAllLogsEnabled(enabled)" in toolbar
    write_only = toolbar[toolbar.index("const writeBtns") : toolbar.index("writeBtns.forEach")]
    assert "btn-all-logs" not in write_only


def test_all_logs_opens_fresh_sized_window_and_handles_blocking():
    logs_entry = _read("js/logs.js")
    app = _read("js/app.js")

    assert "`/all-logs.html?lab=${encodeURIComponent(labId)}`" in logs_entry
    assert "WindowManager.open(url, '_blank', { width: 1280, height: 820 })" in logs_entry
    assert "if (!popup) showToast('Popup blocked: allow popups to open all logs', 'warn');" in app
    assert "Toolbar.on('all-logs', () =>" in app
    assert "Toolbar.on('all-logs', async" not in app


def test_all_logs_uses_the_same_live_runtime_availability_as_consoles():
    app = _read("js/app.js")

    assert "Toolbar.setAllLogsEnabled(false)" in app
    assert "Toolbar.setAllLogsEnabled(enabled)" in app
    assert "_labHasLiveConsoles(lastLab)" in app


def test_aggregated_page_takes_sorted_live_snapshot_and_connects_eagerly():
    page = _read("all-logs.html")
    logs = _read("js/all_logs.js")

    assert '<script src="/js/api.js"></script>' in page
    assert '<script src="/js/log_session.js"></script>' in page
    assert "API.Labs.status(labId)" in logs
    assert ".filter(container => container.state === 'running' && container.node_name)" in logs
    assert "localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })" in logs
    assert "names.forEach(name => _addLog(name))" in logs
    assert "session.connect();" in logs


def test_aggregated_tabs_close_and_reconnect_isolated_log_sessions():
    logs = _read("js/all_logs.js")

    assert "entry.session.dispose()" in logs
    assert "entries.delete(nodeName)" in logs
    assert "session.connect({ resetLog: true })" in logs
    assert "window.addEventListener('pagehide', _disposeAll" in logs


def test_single_and_aggregated_logs_share_the_same_session_component():
    standalone_page = _read("logs.html")
    standalone = _read("js/logs_tab.js")
    shared = _read("js/log_session.js")

    assert '<script src="/js/log_session.js"></script>' in standalone_page
    assert "new LogSession" in standalone
    assert "class LogSession" in shared
    assert "/ws/logs/${encodeURIComponent(this.labId)}/${encodeURIComponent(this.nodeName)}" in shared
    assert "if (resetLog) this.container.replaceChildren();" in shared
