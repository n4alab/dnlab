from pathlib import Path


STATIC = Path(__file__).parents[1] / "app/views/static"


def _read(relative: str) -> str:
    return (STATIC / relative).read_text(encoding="utf-8")


def test_toolbar_places_all_consoles_next_to_start_stop_and_initially_disables_it():
    html = _read("index.html")
    start = html.index('id="btn-deploy"')
    stop = html.index('id="btn-destroy"')
    consoles = html.index('id="btn-all-consoles"')
    delete = html.index('id="btn-delete-topo"')

    assert start < stop < consoles < delete
    button = html[consoles : html.index("</button>", consoles)]
    assert "disabled" in button
    assert 'use href="#i-terminal"' in button
    assert "Consoles" in button


def test_toolbar_exposes_read_only_safe_all_consoles_action():
    toolbar = _read("js/toolbar.js")

    assert "_bind('btn-all-consoles', () => _emit('all-consoles'))" in toolbar
    assert "function setAllConsolesEnabled(enabled)" in toolbar
    write_only = toolbar[toolbar.index("const writeBtns") : toolbar.index("writeBtns.forEach")]
    assert "btn-all-consoles" not in write_only


def test_all_consoles_opens_fresh_sized_window_and_handles_blocking():
    console_entry = _read("js/console.js")
    app = _read("js/app.js")

    assert "`/consoles.html?lab=${encodeURIComponent(labId)}`" in console_entry
    assert "WindowManager.open(url, '_blank', { width: 1280, height: 820 })" in console_entry
    assert "if (!popup) showToast('Popup blocked:" in app
    assert "Toolbar.on('all-consoles', () =>" in app
    assert "Toolbar.on('all-consoles', async" not in app


def test_all_consoles_availability_requires_finished_runtime_and_live_vd():
    app = _read("js/app.js")

    assert "lab?.status === 'running' || lab?.status === 'partial'" in app
    assert "container.state === 'running' && !!container.node_name" in app
    assert "Toolbar.setAllConsolesEnabled(false)" in app
    assert "Runtime status is stale or contains no live VD consoles" in app


def test_aggregated_page_takes_sorted_live_snapshot_and_connects_eagerly():
    page = _read("consoles.html")
    consoles = _read("js/consoles.js")

    assert '<script src="/js/api.js"></script>' in page
    assert '<script src="/js/console_session.js"></script>' in page
    assert "API.Labs.status(labId)" in consoles
    assert ".filter(container => container.state === 'running' && container.node_name)" in consoles
    assert "localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })" in consoles
    assert "names.forEach(name => _addConsole(name))" in consoles
    assert "_activate(names[0])" in consoles
    assert "session.connect();" in consoles


def test_aggregated_tabs_close_isolated_sessions_and_reconnect_with_clean_terminal():
    consoles = _read("js/consoles.js")

    assert "entry.session.dispose()" in consoles
    assert "entries.delete(nodeName)" in consoles
    assert "session.connect({ resetTerminal: true })" in consoles
    assert "requestAnimationFrame(() => entry.session.fit())" in consoles
    assert "window.addEventListener('resize'" in consoles
    assert "window.addEventListener('pagehide', _disposeAll" in consoles


def test_single_and_aggregated_consoles_share_the_same_session_component():
    standalone_page = _read("console.html")
    standalone = _read("js/console_tab.js")
    shared = _read("js/console_session.js")

    assert '<script src="/js/console_session.js"></script>' in standalone_page
    assert "new ConsoleSession" in standalone
    assert "class ConsoleSession" in shared
    assert "/ws/console/${encodeURIComponent(this.labId)}/${encodeURIComponent(this.nodeName)}" in shared
    assert "if (resetTerminal || !this.terminal) this._createTerminal()" in shared
