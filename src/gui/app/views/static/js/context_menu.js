/**
 * ContextMenu – floating context menu for nodes and links.
 *
 * Uso:
 *   ContextMenu.init()
 *   ContextMenu.show(nodeData, screenX, screenY, isLabRunning, isNodeRunning)
 *   ContextMenu.showEdge(edgeData, screenX, screenY)
 *   ContextMenu.hide()
 *   ContextMenu.on('console',    cb)  // cb(nodeData)
 *   ContextMenu.on('logs',       cb)
 *   ContextMenu.on('properties', cb)
 *   ContextMenu.on('start-vd',   cb)
 *   ContextMenu.on('stop-vd',    cb)
 *   ContextMenu.on('restart-vd', cb)
 *   ContextMenu.on('wipe-disk',  cb)
 *   ContextMenu.on('remove',     cb)
 *   ContextMenu.on('capture-mgmt', cb)
 *   ContextMenu.on('capture-link', cb) // cb({edge, side})
 *   ContextMenu.on('delete-link', cb) // cb(edgeData)
 *   ContextMenu.on('color-link', cb) // cb(edgeData)
 *   ContextMenu.on('edit-annotation', cb)
 *   ContextMenu.on('annotation-front', cb)
 *   ContextMenu.on('annotation-forward', cb)
 *   ContextMenu.on('annotation-backward', cb)
 *   ContextMenu.on('annotation-back', cb)
 *   ContextMenu.on('delete-annotation', cb)
 */
const ContextMenu = (() => {
  let _el = null;
  let _currentNode = null;
  let _currentEdge = null;
  const listeners = {};

  function init() {
    _el = document.getElementById('context-menu');

    // Close al click fuori dal menu
    document.addEventListener('click', (e) => {
      if (_el && !_el.contains(e.target)) hide();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') hide();
    });
  }

  /**
   * Show context menu for a node.
   */
  function show(nodeData, screenX, screenY, isLabRunning = false, isNodeRunning = false) {
    _currentNode = nodeData;
    _currentEdge = null;

    const runCls = isNodeRunning ? '' : 'cm-disabled';
    const runtimeState = nodeData.runtime_state || (isNodeRunning ? 'running' : '');
    const isPerVdRuntime = _isPerVdRuntime(nodeData);
    const isBusy = runtimeState === 'starting' || runtimeState === 'stopping' || runtimeState === 'restarting';
    const canStop = isLabRunning && !!nodeData.can_stop;
    const canStart = isLabRunning && !!nodeData.can_start && !isBusy;
    const canRestart = isLabRunning && isPerVdRuntime && runtimeState === 'running' && !isBusy;
    const stopCls = canStop ? '' : 'cm-disabled';
    const startCls = canStart ? '' : 'cm-disabled';
    const restartCls = canRestart ? '' : 'cm-disabled';
    const labTitle = isLabRunning ? '' : 'Lab not deployed';
    const runtimeTitle = isPerVdRuntime ? '' : 'Available only on per-VD runtime deployments';
    const stopTitle = canStop ? 'Force stop VD in any runtime phase' : (labTitle || runtimeTitle || 'VD cannot be stopped');
    const startTitle = canStart ? '' : (labTitle || runtimeTitle || 'VD cannot be started live');
    const restartTitle = canRestart ? '' : (labTitle || runtimeTitle || 'VD is not running');

    const webuiItems = _webuiItems(nodeData, isNodeRunning);
    const mgmtCapture = _mgmtCaptureItem(nodeData, isNodeRunning);

    _el.innerHTML = `
      <div class="cm-header">
        <span class="cm-node-icon" style="background:${_kindColor(nodeData.kind)}">
          ${_kindInitial(nodeData.kind)}
        </span>
        <span class="cm-node-label">${nodeData.label}</span>
        <span class="cm-node-kind">${nodeData.kind || ''}</span>
      </div>
      <div class="cm-sep"></div>
      <div class="cm-item ${runCls}" data-action="console" title="${isNodeRunning ? '' : 'Node not running'}">
        🖥️ Open Console
      </div>
      <div class="cm-item ${runCls}" data-action="logs" title="${isNodeRunning ? '' : 'Node not running'}">
        📋 Show Log
      </div>
      ${webuiItems}
      ${mgmtCapture}
      <div class="cm-sep"></div>
      <div class="cm-item ${stopCls}" data-action="stop-vd" title="${stopTitle}">
        ⏹️ Stop VD
      </div>
      <div class="cm-item ${startCls}" data-action="start-vd" title="${startTitle}">
        ▶️ Start VD
      </div>
      <div class="cm-item ${restartCls}" data-action="restart-vd" title="${restartTitle}">
        🔁 Restart VD
      </div>
      <div class="cm-sep"></div>
      <div class="cm-item" data-action="rename">
        ✏️ Rename
      </div>
      <div class="cm-item" data-action="properties">
        ⚙️ Properties
      </div>
      <div class="cm-item cm-danger" data-action="wipe-disk" title="Delete this node persistent disk">
        🧹 Wipe Disk
      </div>
      <div class="cm-item cm-danger" data-action="remove">
        🗑️ Remove Node
      </div>
    `;

    _bindItems(_currentNode);
    _position(screenX, screenY);
  }

  function _mgmtCaptureItem(nodeData, isNodeRunning) {
    if (!nodeData || nodeData.kind === '_real_net' || nodeData.kind === '_mgmt') return '';
    const mgmt = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindMgmtIface(nodeData.kind || '')
      : null;
    if (!mgmt) return '';
    const cls = isNodeRunning ? '' : 'cm-disabled';
    const title = isNodeRunning ? '' : 'Node not running';
    return `
      <div class="cm-sep"></div>
      <div class="cm-item ${cls}" data-action="capture-mgmt" title="${title}">
        🔎 Capture ${_esc(_captureSideLabel(nodeData.id || nodeData.name || nodeData.label, mgmt, nodeData.kind || ''))}
      </div>`;
  }

  // ── WebUI menu items ──────────────────────────────────────────────
  // Render a "Web UI" group with one item for each known port
  // + quelle custom aggiunte dall'user in nodeData.extra.webui_ports.
  // All entries are disabled if the node is not running.
  function _webuiItems(nodeData, isNodeRunning) {
    const ports = _collectWebUIPorts(nodeData);
    if (ports.length === 0) return '';
    const runCls = isNodeRunning ? '' : 'cm-disabled';
    const title = isNodeRunning ? '' : 'Node not running';
    const lines = ports.map((p, idx) => {
      const sub = `${p.scheme}:${p.port} · ${p.label}`;
      return `
        <div class="cm-item ${runCls}" data-action="webui" data-webui-idx="${idx}" title="${title}">
          🌐 Web UI — <span class="cm-subtle">${_esc(sub)}</span>
        </div>`;
    }).join('');
    return `<div class="cm-sep"></div>${lines}`;
  }

  function _collectWebUIPorts(nodeData) {
    // Source-of-truth: ``nodeData.webui_state`` (sidecar GUI). Per i
    // nodes loaded before the plumbing fix, fallback al catalog
    // del kind so il bottone non sparisce.
    const sidecar = Array.isArray(nodeData.webui_state) ? nodeData.webui_state : [];
    let entries = sidecar.map(p => ({
      scheme: (p.scheme || 'https').toLowerCase(),
      port:   Number(p.container_port || p.port || 0),
      path:   p.path || '/',
      label:  p.label || '',
    })).filter(p => p.port > 0);
    if (entries.length === 0 && typeof DeviceCatalog !== 'undefined') {
      entries = DeviceCatalog.kindWebUI(nodeData.kind || '').map(p => ({
        scheme: (p.scheme || 'https').toLowerCase(),
        port:   Number(p.port),
        path:   p.path || '/',
        label:  p.label || '',
      }));
    }
    // Deduplica for (scheme, port) e normalizza il label.
    const seen = new Set();
    const out = [];
    entries.forEach(p => {
      const key = `${p.scheme}:${p.port}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({
        ...p,
        label: p.label || `${p.scheme.toUpperCase()} ${p.port}`,
      });
    });
    return out;
  }

  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function _captureSideLabel(node, iface, kind = '') {
    return `from VD ${node || ''} - interface ${_ifaceLabel(kind, iface) || '-'}`;
  }

  function _ifaceLabel(kind, iface) {
    if (typeof Canvas !== 'undefined' && typeof Canvas.formatInterfaceLabel === 'function') {
      return Canvas.formatInterfaceLabel(kind || '', iface || '');
    }
    return iface || '';
  }

  function _isPerVdRuntime(nodeData) {
    const container = String(nodeData.runtime_container || '');
    const topoFile = String(nodeData.runtime_topology_file || '');
    return container.startsWith('clab-dnlab-') || /\/dnlab-[^/]+\.clab\.ya?ml$/.test(topoFile);
  }

  /**
   * Show context menu for an edge/link.
   */
  function showEdge(edgeData, screenX, screenY) {
    _currentEdge = edgeData;
    _currentNode = null;

    const srcLabel = _ifaceLabel(edgeData.source_kind || '', edgeData.source_iface) || edgeData.source;
    const tgtLabel = _ifaceLabel(edgeData.target_kind || '', edgeData.target_iface) || edgeData.target;
    const isRealNet = edgeData.source_kind === '_real_net' || edgeData.target_kind === '_real_net';
    const sourceCapture = _captureSideLabel(edgeData.source, edgeData.source_iface, edgeData.source_kind || '');
    const targetCapture = _captureSideLabel(edgeData.target, edgeData.target_iface, edgeData.target_kind || '');
    const activeSessions = Array.isArray(edgeData.capture_sessions) ? edgeData.capture_sessions : [];
    const stopCaptureItem = activeSessions.length
      ? `<div class="cm-item cm-danger" data-action="stop-capture">⏹ Stop Capture</div>
         <div class="cm-sep"></div>`
      : '';
    const captureItems = isRealNet
      ? `<div class="cm-item" data-action="capture-link" data-side="vd">🔎 Capture ${_esc(_realNetCaptureLabel(edgeData))}</div>`
      : `
        <div class="cm-item" data-action="capture-link" data-side="source" title="Capture on ${_esc(sourceCapture)}">
          🔎 Capture ${_esc(sourceCapture)}
        </div>
        <div class="cm-item" data-action="capture-link" data-side="target" title="Capture on ${_esc(targetCapture)}">
          🔎 Capture ${_esc(targetCapture)}
        </div>`;

    _el.innerHTML = `
      <div class="cm-header">
        <span class="cm-node-icon" style="background:#888">⟷</span>
        <span class="cm-node-label">${edgeData.source} — ${edgeData.target}</span>
      </div>
      <div class="cm-sep"></div>
      <div class="cm-item" style="font-size:11px;color:var(--text-muted);cursor:default;pointer-events:none">
        ${srcLabel} ↔ ${tgtLabel}
      </div>
      <div class="cm-sep"></div>
      ${stopCaptureItem}
      ${captureItems}
      <div class="cm-sep"></div>
      <div class="cm-item" data-action="color-link">
        🎨 Color Link
      </div>
      <div class="cm-item cm-danger" data-action="delete-link">
        🗑️ Delete Link
      </div>
    `;

    _bindItems(_currentEdge);
    _position(screenX, screenY);
  }

  function showAnnotation(annotation, screenX, screenY) {
    _currentEdge = null;
    _currentNode = null;
    const typeLabel = annotation.type === 'note'
      ? 'Note'
      : (annotation.type === 'ellipse' ? 'Circle' : 'Rectangle');
    const zIndex = Number(annotation.z_index);
    const layerLabel = `${Number.isFinite(zIndex) ? zIndex : (annotation.layer === 'below_vd' ? -1 : 1)} · ${annotation.layer === 'below_vd' ? 'below VD icons' : 'above VD icons'}`;
    _el.innerHTML = `
      <div class="cm-header">
        <span class="cm-node-icon" style="background:#64748b">A</span>
        <span class="cm-node-label">${_esc(typeLabel)}</span>
        <span class="cm-node-kind">${_esc(layerLabel)}</span>
      </div>
      <div class="cm-sep"></div>
      <div class="cm-item" data-action="edit-annotation">✏️ Style / Text</div>
      <div class="cm-item" data-action="annotation-front">⇡ Bring to Front</div>
      <div class="cm-item" data-action="annotation-forward">↑ Bring Forward</div>
      <div class="cm-item" data-action="annotation-backward">↓ Send Backward</div>
      <div class="cm-item" data-action="annotation-back">⇣ Send to Back</div>
      <div class="cm-sep"></div>
      <div class="cm-item cm-danger" data-action="delete-annotation">🗑️ Delete</div>
    `;
    _bindItems(annotation);
    _position(screenX, screenY);
  }

  function _realNetCaptureLabel(edgeData) {
    if (edgeData.source_kind === '_real_net') {
      return _captureSideLabel(edgeData.target, edgeData.target_iface, edgeData.target_kind || '');
    }
    return _captureSideLabel(edgeData.source, edgeData.source_iface, edgeData.source_kind || '');
  }

  function hide() {
    if (_el) _el.style.display = 'none';
    _currentNode = null;
    _currentEdge = null;
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  function _bindItems(data) {
    _el.querySelectorAll('.cm-item:not(.cm-disabled)').forEach(item => {
      if (item.style.pointerEvents === 'none') return;
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = item.dataset.action;
        if (action === 'webui' && data && data.kind !== undefined) {
          const ports = _collectWebUIPorts(data);
          const idx = parseInt(item.dataset.webuiIdx || '0', 10);
          _emit('webui', { node: data, port: ports[idx] });
        } else if (action === 'capture-link') {
          _emit(action, { edge: data, side: item.dataset.side || '' });
        } else {
          _emit(action, data);
        }
        hide();
      });
    });
  }

  function _position(screenX, screenY) {
    _el.style.display = 'block';
    _el.style.left = `${screenX + 4}px`;
    _el.style.top  = `${screenY + 4}px`;

    requestAnimationFrame(() => {
      const rect = _el.getBoundingClientRect();
      if (rect.right  > window.innerWidth)  _el.style.left = `${screenX - rect.width  - 4}px`;
      if (rect.bottom > window.innerHeight) _el.style.top  = `${screenY - rect.height - 4}px`;
    });
  }

  // Delega a DeviceCatalog (config/devices.json).
  function _kindColor(kind = '') { return DeviceCatalog.kindColor(kind); }

  // Iniziale del badge: prima lettera del vendor come risolto dal catalog.
  function _kindInitial(kind = '') {
    const vendor = DeviceCatalog.kindVendor(kind);
    return (vendor || '?')[0].toUpperCase();
  }

  function on(event, cb) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(cb);
  }

  function _emit(event, data) {
    (listeners[event] || []).forEach(cb => cb(data));
  }

  return { init, show, showEdge, showAnnotation, hide, on };
})();
