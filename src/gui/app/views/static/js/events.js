/**
 * EventsPanel – docked footer that streams orchestrator progress events.
 *
 * Subscribes to /ws/events/{lab} for the currently-open topology.
 * Displays a running log of BusEvent dicts ({phase, status, host, detail,
 * elapsed_ms, data}) and exposes the latest status so the toolbar badge
 * can reflect the orchestrator's view.
 *
 * Only one subscription is active at a time — switching topology tears
 * down the previous socket before opening the next.
 */
const EventsPanel = (() => {
  let _ws = null;
  let _lab = null;
  let _rootEl = null;
  let _bodyEl = null;
  let _statusEl = null;
  let _autoScroll = true;
  let _latestPhase = null;
  let _statusListener = null;
  let _intentionalClose = false;
  let _reconnectAttempt = 0;
  let _reconnectTimer = null;
  const _lastSigByKey = new Map();

  function init(rootId = 'inspector-events') {
    _rootEl = document.getElementById(rootId);
    if (!_rootEl) return;
    _bodyEl = _rootEl;
    _statusEl = document.getElementById('inspector-summary');

    _bodyEl.addEventListener('scroll', () => {
      const atBottom = _bodyEl.scrollHeight - _bodyEl.scrollTop - _bodyEl.clientHeight < 8;
      _autoScroll = atBottom;
    });

  }

  function setLab(labId) {
    if (labId === _lab) return;
    _close();
    _lab = labId;
    _lastSigByKey.clear();
    if (!labId) {
      LabInspector?.setCollapsed(true);
      return;
    }
    LabInspector?.setCollapsed(true);
    _appendLine(`— connection to the lab —`, 'events-sys');
    _intentionalClose = false;
    _openWs(labId);
  }

  function _openWs(labId) {
    const shortId = String(labId).slice(0, 8);
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/events/${labId}`);
    _ws = ws;

    ws.onopen = () => {
      if (_reconnectAttempt > 0) {
        _appendLine(`[WebSocket connected (lab=${shortId})]`, 'events-sys events-ok');
      }
      _reconnectAttempt = 0;
    };

    ws.onmessage = (ev) => {
      let data;
      try { data = JSON.parse(ev.data); } catch (_) { return; }
      // Per-slot deduplication: the poller republishes the same events on every
      // cycle. Key = phase|host. We render only if the new
      // signature (status|detail) differs from the last one for that slot.
      const key = `${data.phase}|${data.host || ''}`;
      const sig = `${data.status}|${data.detail || ''}`;
      if (_lastSigByKey.get(key) !== sig) {
        _renderEvent(data);
        _lastSigByKey.set(key, sig);
      }
      _latestPhase = data;
      _updateLatest(data);
      if (_statusListener) _statusListener(data);
    };

    ws.onclose = () => {
      if (_intentionalClose) return;
      const delay = Math.min(1000 * 2 ** _reconnectAttempt, 30000);
      const cls = _reconnectAttempt >= 3 ? 'events-sys events-warn' : 'events-sys';
      _appendLine(`[WebSocket closed (lab=${shortId}), retrying in ${Math.round(delay / 1000)}s]`, cls);
      _reconnectTimer = setTimeout(() => {
        _reconnectTimer = null;
        _openWs(labId);
      }, delay);
      _reconnectAttempt++;
    };

    ws.onerror = () => _appendLine(`[Error WebSocket (lab=${shortId})]`, 'events-sys events-err');
  }

  function onStatus(cb) { _statusListener = cb; }

  function latest() { return _latestPhase; }

  // ── internals ──────────────────────────────────────────────────────
  function _close() {
    _intentionalClose = true;
    if (_reconnectTimer !== null) {
      clearTimeout(_reconnectTimer);
      _reconnectTimer = null;
    }
    _reconnectAttempt = 0;
    if (_ws) {
    // Detach handlers before closing: the intentional shutdown
    // is silent (no "[WebSocket closed]" while we're already
    // showing "— connecting to the lab —" for the new lab).
      _ws.onopen = _ws.onmessage = _ws.onclose = _ws.onerror = null;
      try { _ws.close(); } catch (_) {}
      _ws = null;
    }
  }

  function _renderEvent(evt) {
    const cls = _statusClass(evt.status);
    const elapsed = evt.elapsed_ms ? `${(evt.elapsed_ms / 1000).toFixed(1)}s` : '';
    const host = evt.host ? ` @${evt.host}` : '';
    const detail = evt.detail ? ` — ${evt.detail}` : '';
    const line = `[${evt.phase}/${evt.status}]${host}${detail}${elapsed ? `  (${elapsed})` : ''}`;
    _appendLine(line, cls);
    if (['error', 'failed', 'warning'].includes(evt.status)) LabInspector?.open('events');
  }

  function _appendLine(text, extraClass = '') {
    if (!_bodyEl) return;
    const el = document.createElement('div');
    el.className = `inspector-line ${extraClass}`;
    el.textContent = text;
    _bodyEl.appendChild(el);
    // Cap buffer to 500 lines to match server-side ring buffer.
    while (_bodyEl.childNodes.length > 500) _bodyEl.removeChild(_bodyEl.firstChild);
    if (_autoScroll) _bodyEl.scrollTop = _bodyEl.scrollHeight;
  }

  function _updateLatest(evt) {
    const host = evt.host ? `@${evt.host}` : '';
    const text = `${evt.phase}/${evt.status} ${host} ${evt.detail || ''}`.trim();
    if (_statusEl) _statusEl.textContent = text;
    LabInspector?.setSummary(text);
  }

  function _statusClass(status) {
    switch (status) {
      case 'ok':
      case 'done':
      case 'success':   return 'events-ok';
      case 'error':
      case 'failed':    return 'events-err';
      case 'warn':
      case 'warning':   return 'events-warn';
      case 'started':
      case 'running':
      case 'progress':  return 'events-running';
      default:          return '';
    }
  }

  return { init, setLab, onStatus, latest };
})();
