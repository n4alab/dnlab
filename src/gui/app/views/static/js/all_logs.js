/** Aggregated, snapshot-based live log window. */
(() => {
  const params = new URLSearchParams(location.search);
  const labId = params.get('lab') || '';
  const labLabel = document.getElementById('logs-lab');
  const summary = document.getElementById('logs-summary');
  const tabBar = document.getElementById('log-tabs');
  const panes = document.getElementById('log-panes');
  const message = document.getElementById('logs-message');
  const entries = new Map();
  let activeNode = null;

  if (!labId) {
    _showMessage('Missing lab parameter.');
    summary.textContent = 'error';
    return;
  }

  window.addEventListener('pagehide', _disposeAll, { once: true });
  window.addEventListener('beforeunload', _disposeAll, { once: true });
  _loadSnapshot();

  async function _loadSnapshot() {
    try {
      const lab = await API.Labs.status(labId);
      const names = [...new Set((lab.containers || [])
        .filter(container => container.state === 'running' && container.node_name)
        .map(container => container.node_name))]
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
      labLabel.textContent = lab.name || `lab ${labId.slice(0, 8)}…`;
      document.title = `Logs · ${lab.name || 'dNLab'}`;
      if (!names.length) {
        summary.textContent = '0 live VDs';
        _showMessage('The runtime snapshot contains no live VD logs.');
        _notifyOpener('Runtime status is stale or contains no live VD logs', 'warn');
        return;
      }
      message.hidden = true;
      names.forEach(name => _addLog(name));
      _activate(names[0]);
      _updateSummary();
    } catch (error) {
      summary.textContent = 'error';
      _showMessage(`Unable to load live VDs: ${error.message}`);
      _notifyOpener('Runtime status is stale or unavailable', 'warn');
    }
  }

  function _addLog(nodeName) {
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.className = 'log-tab';
    tab.dataset.status = 'connecting';
    tab.innerHTML = '<span class="log-tab-name"></span><span class="log-tab-status">connecting</span><span class="log-tab-close" role="button" aria-label="Close logs" title="Close logs">×</span>';
    tab.querySelector('.log-tab-name').textContent = nodeName;
    const pane = document.createElement('section');
    pane.className = 'log-pane';
    const viewer = document.createElement('div');
    viewer.className = 'log-viewer';
    const reconnect = document.createElement('button');
    reconnect.type = 'button';
    reconnect.className = 'log-reconnect';
    reconnect.textContent = 'Reconnect';
    reconnect.hidden = true;
    pane.append(viewer, reconnect);
    tabBar.appendChild(tab);
    panes.appendChild(pane);
    const session = new LogSession({
      labId, nodeName, container: viewer,
      onStatus: status => {
        tab.dataset.status = status;
        tab.querySelector('.log-tab-status').textContent = status;
        reconnect.hidden = status !== 'closed' && status !== 'error' && status !== 'unauthorized';
        _updateSummary();
      },
    });
    entries.set(nodeName, { nodeName, tab, pane, reconnect, session });
    tab.addEventListener('click', event => {
      if (event.target.closest('.log-tab-close')) {
        event.stopPropagation();
        _removeLog(nodeName);
      } else _activate(nodeName);
    });
    reconnect.addEventListener('click', () => {
      reconnect.hidden = true;
      session.connect({ resetLog: true });
    });
    session.connect();
  }

  function _activate(nodeName) {
    const entry = entries.get(nodeName);
    if (!entry) return;
    activeNode = nodeName;
    entries.forEach(item => {
      const active = item === entry;
      item.tab.classList.toggle('active', active);
      item.tab.setAttribute('aria-selected', active ? 'true' : 'false');
      item.pane.classList.toggle('active', active);
    });
  }

  function _removeLog(nodeName) {
    const entry = entries.get(nodeName);
    if (!entry) return;
    const ordered = [...entries.keys()];
    const index = ordered.indexOf(nodeName);
    entry.session.dispose();
    entry.tab.remove();
    entry.pane.remove();
    entries.delete(nodeName);
    if (activeNode === nodeName) {
      activeNode = null;
      const next = ordered[index + 1] || ordered[index - 1];
      if (next && entries.has(next)) _activate(next);
    }
    if (!entries.size) _showMessage('All log tabs have been closed.');
    _updateSummary();
  }

  function _updateSummary() {
    const connected = [...entries.values()].filter(entry => entry.tab.dataset.status === 'connected').length;
    summary.textContent = `${connected}/${entries.size} connected`;
  }
  function _showMessage(text) { message.hidden = false; message.textContent = text; }
  function _disposeAll() { entries.forEach(entry => entry.session.dispose()); entries.clear(); }
  function _notifyOpener(text, level) {
    try { if (window.opener && typeof window.opener.showToast === 'function') window.opener.showToast(text, level); } catch (_) {}
  }
})();
