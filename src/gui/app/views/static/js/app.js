/**
 * app.js – Main application controller (MVC glue layer).
 *
 * Post-PR4c: every lab-scoped API call is keyed by UUID. We track two
 * pieces of state together:
 *   - `currentLabId`: UUID used in URLs / WS topics. Authoritative.
 *   - `currentLabName`: display name, rendered in the toolbar badge.
 *
 * The login gate lives in AuthGate (auth.js) — bootstrap blocks on
 * whoami; a 401 anywhere raises the `auth:unauthorized` DOM event which
 * reopens the login overlay.
 */
(async () => {
// The device catalog (vendor, color, icon type, label) is used by
// the canvas / sidebar / context menu already on the first render. Load it
// before the auth gate so that, in case of failure, we can continue
// with the built-in DeviceCatalog fallback.
  await DeviceCatalog.load();

  // ── Auth gate ─────────────────────────────────────────────────────────
  // Blocks until the user is logged in; also wires the 401 handler so
  // any subsequent fetch that loses the session re-shows the overlay.
  const me = await AuthGate.ensureAuthenticated();
  AuthGate.renderUserBadge(me);

  // ── State ─────────────────────────────────────────────────────────────
  let currentLabId = null;
  let currentLabName = null;
  let currentLabCanWrite = false;
  let labStatus = 'stopped';
  let interfaceMap = {};  // kind → { linux_fmt, vendor_fmt, count }
  const INTERFACE_KIND_ALIASES = {
    mikrotik: 'mikrotik_ros',
    routeros: 'mikrotik_ros',
  };
  // Cache of the last /api/labs/{id}/status response, refreshed by
  // _refreshLabStatus() every 15s. Right-click must be instant — the
  // multinode status probe takes seconds, so we read from this cache
  // instead of awaiting a fresh call each time.
  let lastLab = null;
  let lastLiveStatus = null;
  let capturePollTimer = null;
  let annotationSaveTimer = null;
  const activeNodeStarts = new Map();
  let statusPollTimer = null;
  const _containerForNode = (name) =>
    (lastLab?.containers || []).find(c => c.node_name === name)
    || (lastLiveStatus?.nodes && lastLiveStatus.nodes[name])
    || null;
  // State of the mgmt network for the current lab. Optional position.
  // ``userTouchedV6`` is set true when the user explicitly edits the v6
  // fields, so subsequent v4 changes stop overwriting their custom v6.
  let currentMgmt = {
    subnet: '', gw: '',
    subnet_v6: '', gw_v6: '',
    dhcp: false,
    pos: null,
    userTouchedV6: false,
  };

  // ── Init ──────────────────────────────────────────────────────────────
  Canvas.init('cy');
  Sidebar.init('sidebar');
  Toolbar.init();
  Properties.init('props-panel');
  ConsolePanel.init('console-tabs', 'console-term-area');
  LogsPanel.init();
  LabInspector.init();
  EventsPanel.init('inspector-events');
  _initWorkspaceDrawer();
  AdminPage.init('admin-view');
  ContextMenu.init();
  MgmtPanel.init('mgmt-panel');
  JumphostBox.init('jumphost-box');
  _initViewSwitch(me);
  _initSidebarToggle();

  // Badge driven by progress events (unchanged from PR4b).
  EventsPanel.onStatus((evt) => {
    if (!evt) return;
    const phase = evt.phase || '';
    const status = evt.status || '';
    if (phase === 'status') return;

    const isTerminal = ['ok', 'done', 'success'].includes(status);
    const isError = ['error', 'failed'].includes(status);
    const isDeploy = phase.startsWith('deploy');
    const isDestroy = phase.startsWith('destroy');

    if (phase === 'follow-rabbit') {
      _refreshFollowRabbitSessions();
      return;
    }

    if (isError && (isDeploy || isDestroy)) {
      Toolbar.setLabStatus('error', `${phase}: ${evt.detail || ''}`);
      _refreshLabStatus();
      return;
    }
    if (isTerminal && (phase === 'deploy' || phase === 'destroy')) {
      _refreshLabStatus();
      return;
    }
    if (isDeploy && !isTerminal) {
      Toolbar.setLabStatus('deploying', `${phase} (${status})${evt.detail ? ' — ' + evt.detail : ''}`);
      Toolbar.setAllConsolesEnabled(false);
      Toolbar.setAllLogsEnabled(false);
    } else if (isDestroy && !isTerminal) {
      Toolbar.setLabStatus('destroying', `${phase} (${status})${evt.detail ? ' — ' + evt.detail : ''}`);
      Toolbar.setAllConsolesEnabled(false);
      Toolbar.setAllLogsEnabled(false);
    }
  });

  Sidebar.load();
  await _refreshLabStatus();

  try { interfaceMap = await API.Docker.interfaces(); } catch (_) {}
  Canvas.setInterfaceResolver(_resolveVendorIface);

  async function _reloadImages() {
    try {
      const imgs = await API.Docker.networkImages();
      Properties.setImages(imgs);
    } catch (_) { Properties.setImages([]); }
  }
  await _reloadImages();

  // ── Canvas: dblclick → place node ─────────────────────────────────────
  Canvas.on('canvas-dblclick', async (pos) => {
    const device = Sidebar.getPendingDevice();
    if (!device || !currentLabId) {
      if (!currentLabId) showToast('Create or open a topology first', 'warn');
      return;
    }
    if (!currentLabCanWrite) {
      showToast('Insufficient permissions to modify this lab', 'warn');
      return;
    }
    // Mgmt cloud: is not a device and is handled separately.
    if (device.kind === '_mgmt') {
      await _placeOrEditMgmt({ x: Math.round(pos.x), y: Math.round(pos.y) });
      Sidebar.clearPending();
      document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
      return;
    }
    if (device.kind === '_real_net') {
      if (_hasRealNetNode()) {
        showToast('Only one realnet-router is allowed per lab', 'warn');
        return;
      }
      const name = _uniqueNodeName('real_net');
      const node = {
        name,
        kind: '_real_net',
        image: '',
        position: { x: Math.round(pos.x), y: Math.round(pos.y) },
        extra: { network: '', ipv4: '', nat: true, bgp: false, description: '' },
      };
      try {
        const updatedTopo = await API.Labs.addNode(currentLabId, node);
        const createdNode = (updatedTopo.nodes || []).find(n => n.name === name) || node;
        Canvas.addNode(createdNode);
        Sidebar.clearPending();
        document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
        await _openPropertiesModal(createdNode);
      } catch (e) {
        showToast('Adding real network failed: ' + e.message, 'error');
      }
      return;
    }
    const name = _uniqueNodeName(device.kind);
    const node = {
      name,
      kind:     device.kind,
      image:    device.image,
      position: { x: Math.round(pos.x), y: Math.round(pos.y) },
      extra:    {},
    };
    try {
      await API.Labs.addNode(currentLabId, node);
      Canvas.addNode(node);
      if (_labIsRuntimeReconcileable()) await _refreshLabStatus();
      Sidebar.clearPending();
      document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
    } catch (e) {
      showToast('Adding node failed: ' + e.message, 'error');
    }
  });

  // ── Canvas: click sul cloud mgmt → modal edit ─────────────────────────
  Canvas.on('mgmt-click', () => {
    _openMgmtModal(false);
  });

  Canvas.on('node-select', () => {
    if (!lastLab) _refreshLabStatus();
  });

  // ── Canvas: right-click on node → context menu ────────────────────────
  Canvas.on('node-rightclick', async ({ data, screenX, screenY }) => {
    // Right-click is the deliberate edit gesture. Left click remains a pure
    // selection action, so inspecting a dense topology never shifts layout.
    await _openPropertiesModal(data);
  });

  Canvas.on('edge-select', () => {});

  Canvas.on('edge-rightclick', ({ data, screenX, screenY }) => {
    ContextMenu.showEdge(data, screenX, screenY);
  });

  Canvas.on('link-draw', async ({ source, target }) => {
    if (!currentLabId) return;
    _showInterfacePickerModal(source, target);
  });

  Canvas.on('node-move', async ({ id, position }) => {
    if (!currentLabId || !currentLabCanWrite) return;
    // Mgmt cloud: the position is stored in topo.extra.mgmt.canvas_pos, not
    // as a real node position.
    if (Canvas.isMgmtId(id)) {
      try {
        await API.Labs.setMgmtConfig(currentLabId, {
          ipv4_subnet: currentMgmt.subnet || '',
          ipv4_gw:     currentMgmt.gw     || '',
          ipv6_subnet: currentMgmt.subnet_v6 || '',
          ipv6_gw:     currentMgmt.gw_v6     || '',
          dhcp:        Boolean(currentMgmt.dhcp),
          canvas_pos:  { x: Math.round(position.x), y: Math.round(position.y) },
        });
        currentMgmt.pos = { x: Math.round(position.x), y: Math.round(position.y) };
      } catch (_) {}
      return;
    }
    try { await API.Labs.updateNode(currentLabId, id, { position }); } catch (_) {}
  });

  // ── Context menu ──────────────────────────────────────────────────────
  ContextMenu.on('console', (nodeData) => {
    if (!currentLabId) { showToast('Lab not running', 'warn'); return; }
    ConsolePanel.open(currentLabId, nodeData.id);
  });

  ContextMenu.on('logs', (nodeData) => {
    if (!currentLabId) { showToast('Lab not running', 'warn'); return; }
    LogsPanel.open(currentLabId, nodeData.id);
  });

  ContextMenu.on('webui', async ({ node, port }) => {
    if (!currentLabId) { showToast('Lab not running', 'warn'); return; }
    if (!port || !port.port) return;
    try {
      const res = await API.Labs.openWebUI(currentLabId, node.id, {
        scheme: port.scheme, port: port.port,
        path:   port.path || '/',
        label:  port.label || '',
      });
      const winName = `dnlab-webui-${currentLabId}-${node.id}-${port.port}`;
      WindowManager.open(res.url, winName, { width: 1280, height: 820 });
    } catch (e) {
      if (String(e.message || '').includes('Device Web UI proxying requires')) {
        const winName = `dnlab-webui-${currentLabId}-${node.id}-${port.port}`;
        WindowManager.open('/webui/unavailable', winName, { width: 1280, height: 820 });
        return;
      }
      showToast('Opening Web UI failed: ' + e.message, 'error');
    }
  });

  ContextMenu.on('capture-mgmt', (nodeData) => {
    if (!currentLabId) { showToast('Open a lab first', 'warn'); return; }
    CaptureModal.openMgmt(currentLabId, nodeData);
  });

  ContextMenu.on('capture-link', ({ edge, side }) => {
    if (!currentLabId) { showToast('Open a lab first', 'warn'); return; }
    CaptureModal.openEdge(currentLabId, edge, side);
  });

  window.addEventListener('dnlab:capture-launched', () => {
    _refreshActiveCaptures();
    _startCapturePolling();
  });

  ContextMenu.on('properties', (nodeData) => {
    _openPropertiesModal(nodeData);
  });

  ContextMenu.on('stop-vd', (nodeData) => {
    _stopRuntimeNode(nodeData.id);
  });

  ContextMenu.on('start-vd', (nodeData) => {
    _startRuntimeNode(nodeData.id);
  });

  ContextMenu.on('restart-vd', (nodeData) => {
    _restartRuntimeNode(nodeData.id);
  });

  ContextMenu.on('rename', (nodeData) => {
    showModal('Rename Node', `
      <label>New name for <strong>${nodeData.id}</strong><br>
        <input id="rename-input" class="props-input" type="text" value="${nodeData.id}" style="width:100%;margin-top:6px">
      </label>`, [
      {
        label: 'Rename', class: 'btn-primary', action: async () => {
          const newName = document.getElementById('rename-input').value.trim();
          if (!newName || newName === nodeData.id) return;
          if (!currentLabId) return;
          try {
            await API.Labs.updateNode(currentLabId, nodeData.id, { new_name: newName });
            Canvas.renameNode(nodeData.id, newName);
            showToast(`Renameto: ${nodeData.id} → ${newName}`, 'success');
          } catch (e) {
            showToast('Rename failed: ' + e.message, 'error');
          }
        },
      },
      { label: 'Cancel' },
    ]);
    setTimeout(() => {
      const input = document.getElementById('rename-input');
      if (input) { input.focus(); input.select(); }
    }, 50);
  });

  ContextMenu.on('remove', async (nodeData) => {
    if (!currentLabId) return;
    try {
      await API.Labs.removeNode(currentLabId, nodeData.id);
      Canvas.removeNode(nodeData.id);
    } catch (e) {
      showToast('Removal failed: ' + e.message, 'error');
    }
  });

  ContextMenu.on('wipe-disk', (nodeData) => {
    if (!currentLabId) return;
    const c = _containerForNode(nodeData.id);
    if (c && c.state === 'running') {
      showToast(`Node ${nodeData.id} is running. Stop the lab before wiping disk.`, 'warn');
      return;
    }
    const image = nodeData.image || 'unknown image';
    showModal('Wipe Disk', `
      <p>Delete persistent disk data for <strong>${_escHtml(nodeData.id)}</strong>?</p>
      <p style="color:var(--text-muted);font-size:12px">This removes the VD persistent directory on every host. The topology is kept unchanged.</p>
      <p style="color:var(--text-muted);font-size:12px">Image: <code>${_escHtml(image)}</code></p>
    `, [
      {
        label: 'Wipe Disk', class: 'btn-danger', action: async () => {
          try {
            const res = await API.Labs.wipeNodeDisk(currentLabId, nodeData.id);
            if (res.success) {
              showToast(`Disk wiped for ${nodeData.id}`, 'success');
            } else if (res.code === 'node_running') {
              showToast(res.output || `Node ${nodeData.id} is running`, 'warn');
              return;
            } else {
              showToast('Wipe disk failed: ' + (res.output || ''), 'error');
              return;
            }
            (res.warnings || []).forEach(msg => showToast(msg, 'warn'));
          } catch (e) {
            showToast('Wipe disk error: ' + e.message, 'error');
          }
        },
      },
      { label: 'Cancel' },
    ]);
  });

  ContextMenu.on('delete-link', async (edgeData) => {
    if (!currentLabId) return;
    try {
      await API.Labs.removeLink(
        currentLabId, edgeData.source, edgeData.target,
        edgeData.source_iface, edgeData.target_iface
      );
      Canvas.removeEdge(edgeData.source, edgeData.target, edgeData.source_iface, edgeData.target_iface);
      showToast('Link deleted', 'success');
    } catch (e) {
      showToast('Deletion link failed: ' + e.message, 'error');
    }
  });

  ContextMenu.on('color-link', (edgeData) => {
    if (!currentLabId) return;
    const current = edgeData.color || '#3b82f6';
    showModal('Color Link', `
      <div class="props-form">
        <label>Color
          <input id="link-color-picker" class="props-input" type="color" value="${_escHtml(_validHex(current) ? current : '#3b82f6')}">
        </label>
        <label>Hex
          <input id="link-color-hex" class="props-input" type="text" value="${_escHtml(_validHex(current) ? current : '#3b82f6')}" placeholder="#3b82f6">
        </label>
      </div>
    `, [
      {
        label: 'Apply', class: 'btn-primary', action: async () => {
          const value = document.getElementById('link-color-hex').value.trim();
          if (!_validHex(value)) {
            showToast('Use a hex color like #3b82f6', 'warn');
            return;
          }
          await _saveLinkStyle(edgeData, { color: value.toLowerCase() });
        },
      },
      {
        label: 'Reset', class: 'btn-secondary', action: async () => {
          await _saveLinkStyle(edgeData, {});
        },
      },
      { label: 'Cancel' },
    ]);
    const picker = document.getElementById('link-color-picker');
    const hex = document.getElementById('link-color-hex');
    picker?.addEventListener('input', () => { hex.value = picker.value; });
    hex?.addEventListener('input', () => {
      if (_validHex(hex.value.trim())) picker.value = hex.value.trim();
    });
  });

  ContextMenu.on('edit-annotation', (annotation) => _showAnnotationStyleModal(annotation));

  ContextMenu.on('annotation-front', (annotation) => {
    Canvas.moveAnnotationLayer(annotation.id, 'front');
  });

  ContextMenu.on('annotation-forward', (annotation) => {
    Canvas.moveAnnotationLayer(annotation.id, 'forward');
  });

  ContextMenu.on('annotation-backward', (annotation) => {
    Canvas.moveAnnotationLayer(annotation.id, 'backward');
  });

  ContextMenu.on('annotation-back', (annotation) => {
    Canvas.moveAnnotationLayer(annotation.id, 'back');
  });

  ContextMenu.on('delete-annotation', (annotation) => {
    Canvas.deleteAnnotation(annotation.id);
  });

  ContextMenu.on('stop-capture', async (edgeData) => {
    if (!currentLabId) return;
    const sessions = Array.isArray(edgeData.capture_sessions) ? edgeData.capture_sessions : [];
    if (!sessions.length) {
      showToast('No active capture on this link', 'info');
      return;
    }
    try {
      await Promise.all(sessions.map(sessionId => API.Labs.stopCapture(currentLabId, sessionId)));
      await _refreshActiveCaptures();
      showToast('Capture stopped', 'success');
    } catch (e) {
      showToast('Stop capture failed: ' + e.message, 'error');
    }
  });

  // ── Toolbar ───────────────────────────────────────────────────────────
  Toolbar.on('new', () => {
    showModal('New Topology', `
      <label>Topology name<br>
        <input id="new-topo-name" class="props-input" type="text" placeholder="my-lab">
      </label>`, [
      {
        label: 'Create', class: 'btn-primary', action: async () => {
          const name = document.getElementById('new-topo-name').value.trim();
          if (!name) return;
          try {
            const created = await API.Labs.create(name);
            // C2: the mgmt is created with the topology. Default seeding so that
            // the user can edit it from the cloud on the canvas.
            await _seedDefaultMgmt(created.id);
            _loadLab(created.id, created.name);
          } catch (e) {
            showToast('Creation failed: ' + e.message, 'error');
          }
        },
      },
      { label: 'Cancel' },
    ]);
  });

  Toolbar.on('open', ({ id, name }) => _loadLab(id, name));

  Toolbar.on('add-annotation', (type) => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    Canvas.addAnnotation(type);
  });

  Canvas.on('annotations-change', () => _scheduleAnnotationSave());
  Canvas.on('annotation-rightclick', ({ annotation, screenX, screenY }) => {
    ContextMenu.showAnnotation(annotation, screenX, screenY);
  });

  Toolbar.on('export-drawio', async () => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    try {
      const xml = await API.Labs.exportDrawio(currentLabId);
      _download(xml, `${currentLabName}.drawio`, 'application/xml');
    } catch (e) {
      showToast('Export failed: ' + e.message, 'error');
    }
  });

  Toolbar.on('import-drawio', async ({ xml, filename }) => {
    if (!currentLabId) {
      // No lab open: create one first, derived from the uploaded filename.
      const base = filename.replace(/\.(drawio|xml)$/, '').trim() || 'imported';
      try {
        const created = await API.Labs.create(base);
        currentLabId = created.id;
        currentLabName = created.name;
        currentLabCanWrite = true;
        Toolbar.setCurrentTopo(created.name);
        EventsPanel.setLab(created.id);
        LabLogsPanel.setLab(created.id);
      } catch (e) {
        showToast('Creation lab failed: ' + e.message, 'error');
        return;
      }
    }
    try {
      const topo = await API.Labs.importDrawio(currentLabId, xml, filename);
      Canvas.loadTopology(topo);
      showToast('Importato da draw.io', 'success');
    } catch (e) {
      showToast('Import failed: ' + e.message, 'error');
    }
  });

  Toolbar.on('deploy', async () => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    if (labStatus === 'running' || labStatus === 'partial') {
      showToast('Lab already running — destroy it before redeploying', 'warn');
      return;
    }
    PlanModal.show(currentLabId, currentLabName, {
      onConfirm: () => _executeDeploy(),
      onCancel:  () => {},
    });
  });

  // ── Aggregated VD consoles ───────────────────────────────────────────
  Toolbar.on('all-consoles', () => {
    const labId = currentLabId;
    if (!labId) { showToast('No topology open', 'warn'); return; }
    if (!_labHasLiveConsoles(lastLab)) {
      Toolbar.setAllConsolesEnabled(false);
      showToast('Runtime status is stale or contains no live VD consoles', 'warn');
      return;
    }
    // Keep window.open in the direct click call stack so browser popup
    // protection recognises the explicit user gesture.
    const popup = ConsolePanel.openAll(labId);
    if (!popup) showToast('Popup blocked: allow popups to open all consoles', 'warn');
  });

  Toolbar.on('all-logs', () => {
    const labId = currentLabId;
    if (!labId) { showToast('No topology open', 'warn'); return; }
    if (!_labHasLiveConsoles(lastLab)) {
      Toolbar.setAllLogsEnabled(false);
      showToast('Runtime status is stale or contains no live VD logs', 'warn');
      return;
    }
    // Keep window.open in the direct click call stack so browser popup
    // protection recognises the explicit user gesture.
    const popup = LogsPanel.openAll(labId);
    if (!popup) showToast('Popup blocked: allow popups to open all logs', 'warn');
  });

  async function _executeDeploy() {
    Toolbar.setLabStatus('deploying', 'starting deploy...');
    Toolbar.setAllConsolesEnabled(false);
    Toolbar.setAllLogsEnabled(false);
    showToast('Deployment in progress…', 'info');
    try {
      const res = await API.Labs.deploy(currentLabId);
      if (res.success) {
        showToast('Lab started!', 'success');
      } else {
        Toolbar.setLabStatus('error', res.output || 'deploy failed');
        showToast('Deploy failed: ' + (res.output || ''), 'error');
      }
      await _refreshLabStatus();
    } catch (e) {
      Toolbar.setLabStatus('error', e.message || 'exception');
      showToast('Deploy error: ' + e.message, 'error');
    }
  }

  // ── Stop lab ─────────────────────────────────────────────────────────
  Toolbar.on('destroy', async () => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    const canDestroy = labStatus === 'running' || labStatus === 'partial';
    if (!canDestroy) {
      showToast('No lab running', 'warn'); return;
    }
    showModal('⚠️ Stop Lab', `
      <p>Do you want to stop lab <strong>${currentLabName}</strong>?</p>
      <p style="color:var(--text-muted);font-size:12px">The VD persistent state is kept on disk and reused on the next deploy.</p>
    `, [
      { label: 'Stop Lab', class: 'btn-danger', action: () => _executeDestroy() },
      { label: 'Cancel' },
    ]);
  });

  // ── Delete topology ───────────────────────────────────────────────────
  Toolbar.on('delete-topo', async () => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    const name = currentLabName;
    const isRunning = labStatus === 'running' || labStatus === 'partial';
    const extra = isRunning
      ? '<p style="color:var(--error);font-size:12px">The lab is running — it will be stopped automatically.</p>'
      : '';
    showModal('⚠️ Delete Topology', `
      <p>Are you sure you want to delete topology <strong>${name}</strong>?</p>
      <p style="color:var(--text-muted);font-size:12px">This will delete: topology file, container persistent volumes on all hosts${isRunning ? ', and the running lab' : ''}.</p>
      ${extra}
    `, [
      {
        label: 'Si', class: 'btn-danger', action: async () => {
          showToast('Deletion in progress…', 'info');
          if (isRunning) Toolbar.setLabStatus('destroying', 'destroy + delete…');
          try {
            const res = await API.Labs.remove(currentLabId);
            if (res.success) {
              showToast(`Topology ${name} deleted`, 'success');
              _clearCurrentLab();
            } else {
              showToast('Deletion failed: ' + (res.output || ''), 'error');
              if (isRunning) await _refreshLabStatus();
            }
          } catch (e) {
            showToast('Deletion error: ' + e.message, 'error');
            if (isRunning) await _refreshLabStatus();
          }
        },
      },
      { label: 'No' },
    ]);
  });

  Toolbar.on('fit', () => Canvas.fit());
  Toolbar.on('zoom-in', () => Canvas.zoomBy(0.2));
  Toolbar.on('zoom-out', () => Canvas.zoomBy(-0.2));
  Toolbar.on('mgmt-visible', (v) => Canvas.setMgmtVisible(v));
  Canvas.setMgmtVisible(Toolbar.isMgmtVisible());
  Toolbar.on('follow-rabbit', () => {
    if (!currentLabId) { showToast('No topology open', 'warn'); return; }
    _openWorkspaceDrawer('rabbit');
    FollowRabbitModal.open(currentLabId, Canvas.getTopologyData().nodes || [], document.getElementById('rabbit-panel'));
  });
  Toolbar.on('delete-selected', async () => {
    if (!currentLabId) return;
    const { nodes, edges } = Canvas.getSelected();
    if (!nodes.length && !edges.length) return;

    const nodeSet = new Set(nodes);
    const standaloneEdges = edges.filter(e =>
      !nodeSet.has(e.source) && !nodeSet.has(e.target));

    let removed = 0;
    for (const e of standaloneEdges) {
      try {
        await API.Labs.removeLink(currentLabId, e.source, e.target, e.source_iface, e.target_iface);
        Canvas.removeEdge(e.source, e.target, e.source_iface, e.target_iface);
        removed++;
      } catch (err) {
        showToast(`Link delete failed (${e.source}↔${e.target}): ${err.message}`, 'error');
      }
    }
    for (const id of nodes) {
      try {
        await API.Labs.removeNode(currentLabId, id);
        Canvas.removeNode(id);
        removed++;
      } catch (err) {
        showToast(`Node delete failed (${id}): ${err.message}`, 'error');
      }
    }
    if (removed) showToast(`${removed} item${removed > 1 ? 's' : ''} deleted`, 'success');
  });
  Toolbar.on('mode-change', (m) => Canvas.setMode(m));
  Toolbar.on('logout', async () => { await AuthGate.logout(); });

  // ── Properties panel ─────────────────────────────────────────────────
  Properties.on('node-update', async ({ name, kind, image, mgmt_ipv4, mgmt_ipv6, extra, advanced_extra_yaml, webui_ports, node_overrides, node_features }) => {
    if (!currentLabId) return;
    try {
      // ``webui_ports`` is now a dedicated field of the PATCH (see
      // backend topology_routes.py::WebUIPortSpec). The backend writes it to
      // ``Topology.gui_webui_state[node]`` (GUI sidecar), no longer in
      // ``node.extra``.
      const patch = { kind, image };
      if (extra !== undefined) patch.extra = extra;
      if (advanced_extra_yaml !== undefined) patch.advanced_extra_yaml = advanced_extra_yaml;
      if (Array.isArray(webui_ports)) patch.webui_ports = webui_ports;
      if (node_overrides !== undefined) patch.node_overrides = node_overrides;
      if (node_features !== undefined) patch.node_features = node_features;
      let updatedTopo = await API.Labs.updateNode(currentLabId, name, patch);
      updatedTopo = await API.Labs.setNodeMgmtIpv4(currentLabId, name, mgmt_ipv4 || '');
      updatedTopo = await API.Labs.setNodeMgmtIpv6(currentLabId, name, mgmt_ipv6 || '');
      const updatedNode = (updatedTopo.nodes || []).find(n => n.name === name) || null;
      const updatedOverride = (updatedTopo.gui_node_overrides_state || {})[name] || null;
      const updatedFeatures = (updatedTopo.gui_node_features_state || {})[name] || null;
      const canvasUpdates = {
        kind,
        image,
        webui_state: webui_ports || [],
        node_overrides_state: updatedOverride,
        node_features_state: updatedFeatures,
      };
      if (updatedNode && updatedNode.extra) {
        canvasUpdates.extra = updatedNode.extra;
      } else if (extra !== undefined) {
        canvasUpdates.extra = extra;
      }
      Canvas.updateNode(name, canvasUpdates);
      showToast('Node updated', 'success');
    } catch (e) {
      showToast('Update failed: ' + e.message, 'error');
    }
  });

  Properties.on('realnet-update', async ({ name, extra }) => {
    if (!currentLabId) return;
    try {
      const updatedTopo = await API.Labs.updateNode(currentLabId, name, { extra });
      const updatedNode = (updatedTopo.nodes || []).find(n => n.name === name) || null;
      Canvas.updateNode(name, { extra: (updatedNode && updatedNode.extra) || extra });
      if (updatedNode) {
        try {
          Properties.setRealNetImportOptions(await API.Labs.importableRealNetRouters(currentLabId));
        } catch (_) {
          Properties.setRealNetImportOptions([]);
        }
        Properties.showRealNet(_buildPropertiesNodeData(updatedNode));
      }
      if (_labIsRuntimeReconcileable()) {
        const applyLive = confirm('Lab running: apply the RealNet router change live without restarting the lab?');
        if (applyLive) {
          const result = await API.Labs.reconcileRealNet(currentLabId, name);
          if (!result || result.success === false) {
            throw new Error(result?.output || 'RealNet live reconcile failed');
          }
          await _refreshLabStatus();
          showToast('Real network updated and reconciled live', 'success');
        } else {
          showToast('Real network saved; live router not changed', 'info');
        }
      } else {
        showToast('Real network updated', 'success');
      }
    } catch (e) {
      showToast('Real network update failed: ' + e.message, 'error');
    }
  });

  MgmtPanel.on('mgmt-update', async (mgmt) => {
    if (!currentLabId) return;
    try {
      const updated = await API.Labs.setMgmtConfig(currentLabId, mgmt);
      const cfg = (updated && updated.extra && updated.extra.mgmt) || {};
      currentMgmt.subnet = cfg['ipv4-subnet'] || '';
      currentMgmt.gw = _gatewayForSubnet(_parseCidr(currentMgmt.subnet)) || cfg['ipv4-gw'] || '';
      currentMgmt.subnet_v6 = cfg['ipv6-subnet'] || '';
      currentMgmt.gw_v6 = _ipv6GatewayForSubnet(currentMgmt.subnet_v6) || cfg['ipv6-gw'] || '';
      currentMgmt.dhcp = Boolean(cfg.dhcp);
      currentMgmt.userTouchedV6 = !!(currentMgmt.subnet_v6 && currentMgmt.subnet_v6 !== _deriveIpv6FromIpv4(currentMgmt.subnet).subnet_v6);
      Canvas.setMgmt({ ...currentMgmt });
      MgmtPanel.setTopology(currentLabName, cfg);
      showToast('Mgmt network updated', 'success');
    } catch (e) {
      showToast('Mgmt update failed: ' + e.message, 'error');
    }
  });

  Properties.on('node-remove', async (name) => {
    if (!currentLabId) return;
    try {
      await API.Labs.removeNode(currentLabId, name);
      Canvas.removeNode(name);
      hideModal();
    } catch (e) {
      showToast('Removal failed: ' + e.message, 'error');
    }
  });

  Properties.on('edge-update', async ({ source, target, source_iface, target_iface, old_source_iface, old_target_iface }) => {
    if (!currentLabId) return;
    try {
      await API.Labs.removeLink(currentLabId, source, target, old_source_iface, old_target_iface);
      const link = { source, source_iface, target, target_iface };
      await API.Labs.addLink(currentLabId, link);
      Canvas.removeEdge(source, target, old_source_iface, old_target_iface);
      Canvas.addEdge(source, target, source_iface, target_iface);
      await _applyLiveLink(link);
      if (!_labIsRuntimeReconcileable()) showToast('Link updated', 'success');
    } catch (e) {
      showToast('Update failed: ' + e.message, 'error');
    }
  });

  Properties.on('edge-remove', async ({ source, target, source_iface, target_iface }) => {
    if (!currentLabId) return;
    try {
      await API.Labs.removeLink(currentLabId, source, target, source_iface, target_iface);
      Canvas.removeEdge(source, target, source_iface, target_iface);
    } catch (e) {
      showToast('Removal failed: ' + e.message, 'error');
    }
  });

  Properties.on('open-console', (nodeName) => {
    if (!currentLabId) { showToast('Lab not running', 'warn'); return; }
    ConsolePanel.open(currentLabId, nodeName);
  });

  async function _stopRuntimeNode(nodeName, refreshProperties = false) {
    if (!currentLabId) { showToast('Lab not deployed', 'warn'); return; }
    const activeStart = activeNodeStarts.get(nodeName);
    if (activeStart) activeStart.cancelRequested = true;
    Canvas.setNodeOperation(
      nodeName, activeStart ? 'cancelling' : 'stopping', !!activeStart,
    );
    try {
      showToast(`Stopping ${nodeName}…`, 'info');
      const result = await API.Labs.stopNode(currentLabId, nodeName);
      if (!result || result.success === false) throw new Error(result?.output || 'Node stop failed');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
      if (result.cancelled) {
        showToast(`Forced stop requested for ${nodeName}`, 'info');
      } else {
        showToast(`${nodeName} stopped`, 'success');
      }
    } catch (e) {
      showToast(`Stop failed: ${e.message}`, 'error');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
    }
  }

  async function _startRuntimeNode(nodeName, refreshProperties = false) {
    if (!currentLabId) { showToast('Lab not deployed', 'warn'); return; }
    if (activeNodeStarts.has(nodeName)) return;
    const operation = { cancelRequested: false };
    activeNodeStarts.set(nodeName, operation);
    Canvas.setNodeOperation(nodeName, 'starting', true);
    try {
      showToast(`Starting ${nodeName}…`, 'info');
      const result = await API.Labs.startNode(currentLabId, nodeName);
      if (!result || result.success === false) throw new Error(result?.output || 'Node start failed');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
      if (result.cancelled || operation.cancelRequested) {
        showToast(`${nodeName} start cancelled`, 'info');
      } else {
        showToast(`${nodeName} running`, 'success');
      }
    } catch (e) {
      if (!operation.cancelRequested) showToast(`Start failed: ${e.message}`, 'error');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
    } finally {
      if (activeNodeStarts.get(nodeName) === operation) activeNodeStarts.delete(nodeName);
    }
  }

  async function _restartRuntimeNode(nodeName, refreshProperties = false) {
    if (!currentLabId) { showToast('Lab not deployed', 'warn'); return; }
    try {
      showToast(`Restarting ${nodeName}…`, 'info');
      const result = await API.Labs.restartNode(currentLabId, nodeName);
      if (!result || result.success === false) throw new Error(result?.output || 'Node restart failed');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
      showToast(`${nodeName} restarted`, 'success');
    } catch (e) {
      showToast(`Restart failed: ${e.message}`, 'error');
      await _refreshLabStatus();
      if (refreshProperties) _refreshOpenNodeProperties(nodeName);
    }
  }

  // ── Drop zone ─────────────────────────────────────────────────────────
  const cyEl = document.getElementById('cy');

  cyEl.addEventListener('dragover', e => { e.preventDefault(); cyEl.classList.add('drag-over'); });
  cyEl.addEventListener('dragleave', () => cyEl.classList.remove('drag-over'));

  cyEl.addEventListener('drop', async e => {
    e.preventDefault();
    cyEl.classList.remove('drag-over');

    const raw = e.dataTransfer.getData('text/plain');
    if (raw) {
      let device;
      try { device = JSON.parse(raw); } catch (_) { device = null; }
      if (device && device.kind) {
        if (!currentLabId) { showToast('Create or open a topology first', 'warn'); return; }
        const pos  = Canvas.projectPosition(e.clientX, e.clientY);
        // Mgmt cloud: it is not a real device.
        if (device.kind === '_mgmt') {
          await _placeOrEditMgmt({ x: Math.round(pos.x), y: Math.round(pos.y) });
          Sidebar.clearPending();
          document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
          return;
        }
        if (device.kind === '_real_net') {
          if (_hasRealNetNode()) {
            showToast('Only one realnet-router is allowed per lab', 'warn');
            return;
          }
          const name = _uniqueNodeName('real_net');
          const node = {
            name,
            kind: '_real_net',
            image: '',
            position: { x: Math.round(pos.x), y: Math.round(pos.y) },
            extra: {
              network: '',
              ipv4: '',
              nat: true,
              bgp: false,
              description: '',
            },
          };
          try {
            const updatedTopo = await API.Labs.addNode(currentLabId, node);
            const createdNode = (updatedTopo.nodes || []).find(n => n.name === name) || node;
            Canvas.addNode(createdNode);
            Sidebar.clearPending();
            document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
            await _openPropertiesModal(createdNode);
          } catch (err) {
            showToast('Adding real network failed: ' + err.message, 'error');
          }
          return;
        }
        const name = _uniqueNodeName(device.kind);
        const node = { name, kind: device.kind, image: device.image,
                       position: { x: Math.round(pos.x), y: Math.round(pos.y) }, extra: {} };
        try {
          await API.Labs.addNode(currentLabId, node);
          Canvas.addNode(node);
          if (_labIsRuntimeReconcileable()) await _refreshLabStatus();
          Sidebar.clearPending();
          document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
          showToast(`Aggiunto: ${name}`, 'success');
        } catch (err) {
          showToast('Adding node failed: ' + err.message, 'error');
        }
        return;
      }
    }

    const file = e.dataTransfer.files[0];
    if (!file) return;
    const xml  = await file.text();
    if (!currentLabId) {
      const base = file.name.replace(/\.(drawio|xml)$/, '').trim() || 'imported';
      try {
        const created = await API.Labs.create(base);
        currentLabId = created.id;
        currentLabName = created.name;
        currentLabCanWrite = true;
        Toolbar.setCurrentTopo(created.name);
        EventsPanel.setLab(created.id);
        LabLogsPanel.setLab(created.id);
      } catch (e) {
        showToast('Creation lab failed: ' + e.message, 'error');
        return;
      }
    }
    try {
      const topo = await API.Labs.importDrawio(currentLabId, xml, file.name);
      Canvas.loadTopology(topo);
      showToast('Importato da draw.io', 'success');
    } catch (err) {
      showToast('Import failed: ' + err.message, 'error');
    }
  });

  // ── Interface picker modal ─────────────────────────────────────────────
  function _showInterfacePickerModal(sourceName, targetName) {
    const topoData = Canvas.getTopologyData();
    const sourceNode = topoData.nodes.find(n => n.name === sourceName);
    const targetNode = topoData.nodes.find(n => n.name === targetName);
    if (!sourceNode || !targetNode) return;
    if (sourceNode.kind === '_real_net' || targetNode.kind === '_real_net') {
      const realNode = sourceNode.kind === '_real_net' ? sourceNode : targetNode;
      const vdNode = sourceNode.kind === '_real_net' ? targetNode : sourceNode;
      const vdName = vdNode.name;
      const realName = realNode.name;
      const ifaces = _getAvailableInterfaces(vdNode, topoData.links);
      const options = ifaces.map(({ linux, vendor }) =>
        `<option value="${linux}" title="${linux}">${vendor}</option>`
      ).join('');
      showModal('Collega real network', `
        <div class="iface-picker">
          <div class="iface-picker-col">
            <label class="iface-picker-label">${vdName}</label>
            <select id="iface-realnet-vd" class="props-input">${options}</select>
          </div>
          <div class="iface-picker-arrow">⟷</div>
          <div class="iface-picker-col">
            <label class="iface-picker-label">${realName}</label>
            <input class="props-input" value="real_net" readonly>
          </div>
        </div>
      `, [
        { label: 'Collega', class: 'btn-primary', action: async () => {
            const iface = document.getElementById('iface-realnet-vd').value;
            const link = sourceNode.kind === '_real_net'
              ? { source: realName, source_iface: 'real', target: vdName, target_iface: iface }
              : { source: vdName, source_iface: iface, target: realName, target_iface: 'real' };
            try {
              await API.Labs.addLink(currentLabId, link);
              Canvas.addEdge(link.source, link.target, link.source_iface, link.target_iface);
              await _applyLiveLink(link);
            } catch (e) { showToast('Add link failed: ' + e.message, 'error'); }
          } },
        { label: 'Cancel' },
      ]);
      return;
    }

    const sourceIfaces = _getAvailableInterfaces(sourceNode, topoData.links);
    const targetIfaces = _getAvailableInterfaces(targetNode, topoData.links);

    const buildOptions = (ifaces) => ifaces.map(({ linux, vendor }) =>
      `<option value="${linux}" title="${linux}">${vendor}</option>`
    ).join('');

    const body = `
      <div class="iface-picker">
        <div class="iface-picker-col">
          <label class="iface-picker-label">${sourceName}</label>
          <select id="iface-src" class="props-input">${buildOptions(sourceIfaces)}</select>
        </div>
        <div class="iface-picker-arrow">⟷</div>
        <div class="iface-picker-col">
          <label class="iface-picker-label">${targetName}</label>
          <select id="iface-tgt" class="props-input">${buildOptions(targetIfaces)}</select>
        </div>
      </div>
    `;

    showModal('Select Interfaces', body, [
      {
        label: 'Collega', class: 'btn-primary', action: async () => {
          const srcIface = document.getElementById('iface-src').value;
          const tgtIface = document.getElementById('iface-tgt').value;
          if (!srcIface || !tgtIface) { showToast('Select both interfaces', 'warn'); return; }
          const link = { source: sourceName, source_iface: srcIface, target: targetName, target_iface: tgtIface };
          try {
            await API.Labs.addLink(currentLabId, link);
            Canvas.addEdge(sourceName, targetName, srcIface, tgtIface);
            await _applyLiveLink(link);
          } catch (e) {
            showToast('Add link failed: ' + e.message, 'error');
          }
        },
      },
      { label: 'Cancel' },
    ]);
  }

  // Reverse-map a linux iface name (what the YAML stores) to the vendor
  // name for display. Per-node override state is required for dynamic
  // interfaces such as Cumulus breakout lanes.
  function _resolveVendorIface(kind, linuxName, nodeData = null) {
    if (!linuxName) return '';
    const info = _interfaceInfoForKind(kind);
    if (!info) return linuxName;
    const count = info.count || 8;
    const baseInterfaces = [];
    for (let n = 1; n <= count; n++) {
      const i = n - 1;
      baseInterfaces.push({
        linux: _fmtIface(info.linux_fmt, n, i),
        vendor: _vendorIfaceName(info, n, i),
      });
    }
    let candidates = baseInterfaces;
    const override = (typeof DeviceCatalog !== 'undefined') ? DeviceCatalog.kindOverrides(kind || '') : null;
    if (override && typeof NodeOverridePlugins !== 'undefined') {
      candidates = NodeOverridePlugins.interfaces({
        nodeData: nodeData || {},
        override,
        baseInterfaces,
      });
    }
    const match = candidates.find(({ linux }) => linux === linuxName);
    return match ? match.vendor : linuxName;
  }

  function _getAvailableInterfaces(node, links) {
    const nodeName = node.name;
    const kind = node.kind;
    if (kind === '_real_net') return [{ linux: 'real', vendor: 'real_net' }];
    const ifaceInfo = _interfaceInfoForKind(kind) || { linux_fmt: 'eth{n}', vendor_fmt: 'eth{n}', count: 8 };
    const count = ifaceInfo.count || 8;
    const used = new Set();
    const mgmtLinux = _mgmtLinuxIfaceForKind(kind, ifaceInfo);
    if (mgmtLinux) used.add(mgmtLinux);
    links.forEach(lk => {
      if (lk.source === nodeName && lk.source_iface) used.add(lk.source_iface);
      if (lk.target === nodeName && lk.target_iface) used.add(lk.target_iface);
    });
    let candidates = [];
    for (let n = 1; n <= count; n++) {
      const i = n - 1;
      const linux  = _fmtIface(ifaceInfo.linux_fmt, n, i);
      const vendor = _vendorIfaceName(ifaceInfo, n, i);
      candidates.push({ linux, vendor });
    }
    const override = (typeof DeviceCatalog !== 'undefined') ? DeviceCatalog.kindOverrides(kind || '') : null;
    if (override && typeof NodeOverridePlugins !== 'undefined') {
      candidates = NodeOverridePlugins.interfaces({ nodeData: node, override, baseInterfaces: candidates });
    }
    return candidates.filter(({ linux }) => !used.has(linux));
  }

  function _mgmtLinuxIfaceForKind(kind, ifaceInfo) {
    const mgmt = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindMgmtIface(kind)
      : null;
    if (!mgmt || !ifaceInfo) return '';
    const mgmtNorm = _normIface(mgmt);
    const count = ifaceInfo.count || 8;
    for (let n = 1; n <= count; n++) {
      const i = n - 1;
      const linux = _fmtIface(ifaceInfo.linux_fmt, n, i);
      const vendor = _vendorIfaceName(ifaceInfo, n, i);
      if (_normIface(linux) === mgmtNorm || _normIface(vendor) === mgmtNorm) {
        return linux;
      }
    }
    return '';
  }

  function _normIface(name) {
    return String(name || '').toLowerCase().replace(/\s+/g, '');
  }

  function _fmtIface(fmt, n, i) {
    const module = Math.floor(n / 4);
    const port = n % 4;
    return String(fmt || '')
      .replace(/\{module([+-]\d+)?\}/g, (_, off) => String(module + Number(off || 0)))
      .replace(/\{port([+-]\d+)?\}/g, (_, off) => String(port + Number(off || 0)))
      .replace(/\{n([+-]\d+)?\}/g, (_, off) => String(n + Number(off || 0)))
      .replace(/\{i([+-]\d+)?\}/g, (_, off) => String(i + Number(off || 0)));
  }

  function _vendorIfaceName(info, n, i) {
    const names = info && typeof info.vendor_names === 'object' ? info.vendor_names : null;
    return String((names && names[String(n)]) || _fmtIface(info.vendor_fmt, n, i));
  }

  function _interfaceInfoForKind(kind) {
    const raw = (kind || '').trim();
    const normalized = raw.toLowerCase();
    const alias = INTERFACE_KIND_ALIASES[raw] || INTERFACE_KIND_ALIASES[normalized];
    return interfaceMap[raw] || interfaceMap[normalized] || (alias && interfaceMap[alias]) || interfaceMap['linux'];
  }

  async function _executeDestroy() {
    Toolbar.setLabStatus('destroying', 'starting destroy...');
    showToast('Destruction in progress…', 'info');
    try {
      const res = await API.Labs.destroy(currentLabId);
      if (res.success) {
        showToast('Lab destroyed', 'success');
        JumphostBox.clear();
      } else {
        Toolbar.setLabStatus('error', res.output || 'destroy failed');
        showToast('Destroy failed: ' + (res.output || ''), 'error');
      }
      await _refreshLabStatus();
    } catch (e) {
      Toolbar.setLabStatus('error', e.message || 'exception');
      showToast('Destroy error: ' + e.message, 'error');
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  async function _loadLab(id, nameHint = null) {
    try {
      const topo = await API.Labs.getTopology(id);
      currentLabId = id;
      currentLabName = topo.name || nameHint || '(senza nome)';
      // Re-read the labs index to pick up can_write for this row.
      try {
        const all = await API.Labs.list();
        const row = all.find(l => l.id === id);
        currentLabCanWrite = row ? !!row.can_write : false;
      } catch (_) { currentLabCanWrite = false; }
      Toolbar.setCurrentTopo(currentLabName, currentLabCanWrite);
      await _refreshRealNetConfig();
      // Load webui_state for the node before rendering: the backend
      // exposes ``topo.gui_webui_state`` (from the `# dnlab-gui-webui` sidecar).
      _enrichNodesWithWebUIState(topo);
      _enrichNodesWithOverrideState(topo);
      _enrichNodesWithFeatureState(topo);
      Canvas.loadTopology(topo);
      await _refreshActiveCaptures();
      _startCapturePolling();
      // Mgmt cloud: loaded from topo.extra.mgmt; if missing (topology created
      // before visible mgmt existed), default seeding occurs on first save.
      const mgmtCfg = (topo.extra && topo.extra.mgmt) || {};
      const v6Subnet = mgmtCfg['ipv6-subnet'] || '';
      const v6Gw     = mgmtCfg['ipv6-gw']     || '';
      const v4Subnet = mgmtCfg['ipv4-subnet'] || '';
      const v4Gw     = mgmtCfg['ipv4-gw']     || '';
      const effectiveV4Gw = _gatewayForSubnet(_parseCidr(v4Subnet)) || v4Gw;
      // If the saved v6 matches the one derived from v4, we consider that
      // the user has not modified it; auto-sync remains enabled.
      // Otherwise, we set a flag to avoid overwriting the custom value.
      const derived = _deriveIpv6FromIpv4(v4Subnet);
      const v6Touched = (
        (v6Subnet && v6Subnet !== derived.subnet_v6)
      );
      const effectiveV6Subnet = v6Subnet || derived.subnet_v6 || '';
      const effectiveV6Gw     = _ipv6GatewayForSubnet(effectiveV6Subnet) || v6Gw || derived.gw_v6 || '';
      currentMgmt = {
        subnet:    v4Subnet,
        gw:        effectiveV4Gw,
        subnet_v6: effectiveV6Subnet,
        gw_v6:     effectiveV6Gw,
        dhcp:      Boolean(mgmtCfg.dhcp),
        pos:       mgmtCfg.canvas_pos || null,
        userTouchedV6: !!v6Touched,
      };
      if (currentMgmt.subnet || currentMgmt.gw || currentMgmt.pos) {
        Canvas.setMgmt({
          subnet:    currentMgmt.subnet,
          gw:        currentMgmt.gw,
          subnet_v6: currentMgmt.subnet_v6,
          gw_v6:     currentMgmt.gw_v6,
          pos:       currentMgmt.pos,
        });
      } else {
        Canvas.clearMgmt();
      }
      MgmtPanel.setTopology(currentLabName, mgmtCfg);
      EventsPanel.setLab(currentLabId);
      LabLogsPanel.setLab(currentLabId);
      await _refreshLabStatus();
      showToast(`Aperto: ${currentLabName}`, 'success');
    } catch (e) {
      showToast('Opening failed: ' + e.message, 'error');
    }
  }

  function _clearCurrentLab() {
    currentLabId = null;
    currentLabName = null;
    currentLabCanWrite = false;
    labStatus = 'stopped';
    lastLab = null;
    currentMgmt = {
      subnet: '', gw: '',
      subnet_v6: '', gw_v6: '',
      dhcp: false,
      pos: null,
      userTouchedV6: false,
    };
    Toolbar.setCurrentTopo(null);
    Toolbar.setLabStatus('stopped');
    Toolbar.setAllConsolesEnabled(false);
    Toolbar.setAllLogsEnabled(false);
    Canvas.loadTopology({ name: '', nodes: [], links: [], extra: {} });
    Canvas.clearMgmt();
    MgmtPanel.clear();
    JumphostBox.clear();
    EventsPanel.setLab(null);
    LabLogsPanel.setLab(null);
    Canvas.setRealNetRemoteAs('');
    Canvas.setActiveCaptures([]);
    Canvas.setFollowRabbitSessions([]);
    _stopCapturePolling();
    Properties.setRealNetRemoteAs('');
  }

  function _startCapturePolling() {
    if (capturePollTimer || !currentLabId) return;
    capturePollTimer = setInterval(_refreshActiveCaptures, 3000);
  }

  function _stopCapturePolling() {
    if (!capturePollTimer) return;
    clearInterval(capturePollTimer);
    capturePollTimer = null;
  }

  async function _refreshActiveCaptures() {
    if (!currentLabId) {
      Canvas.setActiveCaptures([]);
      return;
    }
    try {
      const res = await API.Labs.activeCaptures(currentLabId);
      Canvas.setActiveCaptures(res.captures || []);
    } catch (_) {
      Canvas.setActiveCaptures([]);
    }
  }

  async function _refreshFollowRabbitSessions() {
    if (!currentLabId) {
      Canvas.setFollowRabbitSessions([]);
      return;
    }
    try {
      const res = await API.Labs.followRabbitSessions(currentLabId);
      Canvas.setFollowRabbitSessions(res.sessions || []);
    } catch (_) {}
  }

  async function _refreshLabStatus() {
    if (!currentLabId) return;
    try {
      const lab = await API.Labs.status(currentLabId);
      lastLab = lab || null;
      labStatus = lab.status || (lab.containers?.length ? 'running' : 'stopped');
      Toolbar.setLabStatus(labStatus);
      _updateAllConsolesAvailability();
      Canvas.setMgmtRuntime(_runtimeMgmtFromContainers(lab?.containers || []));
    } catch (_) {
      lastLab = null;
      Toolbar.setLabStatus('unknown');
      Toolbar.setAllConsolesEnabled(false);
      Toolbar.setAllLogsEnabled(false);
      Canvas.setMgmtRuntime({});
    }
    try {
      const live = await API.Labs.statusLive(currentLabId);
      lastLiveStatus = live || null;
      const jh = live && live.infra && live.infra.jumphost;
      JumphostBox.update(jh && jh.container ? { ...jh, lab_id: currentLabId } : null);
      // Host-side Web UI allocations: from multinode.status report
      // ``nodes[name].webui_ports = [{container_port, host_port,
      // bind_ip, proto}, ...]``. We pass it to the canvas, which binds it
      // to each node, so Properties can render the annotated pill.
      if (live && live.nodes) {
        const byNode = {};
        const mgmtByNode = {};
        const placementByNode = {};
        const runtimeByNode = {};
        for (const [name, info] of Object.entries(live.nodes)) {
          const mgmtIpv4 = info?.mgmt_ipv4 || info?.ipv4 || '';
          byNode[name] = Array.isArray(info?.webui_ports) ? info.webui_ports : [];
          mgmtByNode[name] = {
            mgmt_ipv4: mgmtIpv4,
            mgmt_ipv6: _runtimeNodeMgmtIpv6(info, mgmtIpv4),
          };
          placementByNode[name] = {
            host: info?.host || '',
            scheduled_host: info?.scheduled_host || '',
            placement_mismatch: !!info?.placement_mismatch,
            duplicate_hosts: Array.isArray(info?.duplicate_hosts) ? info.duplicate_hosts : [],
          };
          runtimeByNode[name] = {
            state: info?.state || '',
            container: info?.container || '',
            topology_file: info?.topology_file || '',
            last_error: info?.last_error || '',
            can_start: !!info?.can_start,
            can_stop: !!info?.can_stop,
            operation_active: !!info?.operation_active,
          };
        }
        Canvas.setWebUIRuntime(byNode);
        Canvas.setMgmtRuntime(mgmtByNode);
        Canvas.setPlacementRuntime(placementByNode);
        Canvas.setNodeRuntime(runtimeByNode);
        Canvas.setRuntimeLinks(live.runtime_links || []);
      }
    } catch (_) {
      lastLiveStatus = null;
      JumphostBox.clear();
    }
  }

  function _labHasLiveConsoles(lab) {
    return (lab?.status === 'running' || lab?.status === 'partial')
      && (lab?.containers || []).some(container =>
        container.state === 'running' && !!container.node_name);
  }

  function _updateAllConsolesAvailability() {
    const enabled = _labHasLiveConsoles(lastLab);
    Toolbar.setAllConsolesEnabled(enabled);
    Toolbar.setAllLogsEnabled(enabled);
  }

  function _runtimeMgmtFromContainers(containers) {
    const byNode = {};
    for (const c of containers || []) {
      if (!c || !c.node_name) continue;
      byNode[c.node_name] = {
        mgmt_ipv4: c.ipv4_address || '',
        mgmt_ipv6: _runtimeNodeMgmtIpv6(c, c.ipv4_address || ''),
      };
    }
    return byNode;
  }

  function _runtimeNodeMgmtIpv6(info, mgmtIpv4) {
    const explicit = info?.mgmt_ipv6 || info?.ipv6_address || info?.ipv6 || '';
    if (explicit) return explicit;
    return '';
  }

  function _enrichNodesWithWebUIState(topo) {
    if (!topo || !Array.isArray(topo.nodes)) return;
    const sidecar = topo.gui_webui_state || {};
    for (const n of topo.nodes) {
      n.webui_state = Array.isArray(sidecar[n.name]) ? sidecar[n.name] : [];
    }
  }

  function _enrichNodesWithOverrideState(topo) {
    if (!topo || !Array.isArray(topo.nodes)) return;
    const sidecar = topo.gui_node_overrides_state || {};
    for (const n of topo.nodes) {
      n.node_overrides_state = sidecar[n.name] && typeof sidecar[n.name] === 'object'
        ? sidecar[n.name]
        : null;
    }
  }

  function _enrichNodesWithFeatureState(topo) {
    if (!topo || !Array.isArray(topo.nodes)) return;
    const sidecar = topo.gui_node_features_state || {};
    for (const n of topo.nodes) {
      n.node_features_state = sidecar[n.name] && typeof sidecar[n.name] === 'object'
        ? sidecar[n.name]
        : null;
    }
  }

  function _getNodePosition(nodeId) {
    const data = Canvas.getTopologyData();
    const node = data.nodes.find(n => n.name === nodeId);
    return node?.position || { x: 0, y: 0 };
  }

  function _hasRealNetNode() {
    const topo = Canvas.getTopologyData();
    return (topo.nodes || []).some(n => (n.kind || '') === '_real_net');
  }

  async function _openPropertiesModal(nodeData) {
    if (!nodeData) return;
    _openWorkspaceDrawer('properties');
    const host = document.getElementById('props-panel');
    if (!host) return;
    host.replaceChildren();
    Properties.setPanelElement(host);

    if (!lastLiveStatus && currentLabId) {
      await _refreshLabStatus();
    }
    const data = _buildPropertiesNodeData(nodeData);
    if (data.kind === '_real_net') {
      await _refreshRealNetConfig();
      try {
        Properties.setRealNetImportOptions(await API.Labs.importableRealNetRouters(currentLabId));
      } catch (_) {
        Properties.setRealNetImportOptions([]);
      }
      Properties.showRealNet(data);
      return;
    }
    Properties.showNode(data);
    const c = _containerForNode(data.id);
    if (c) Properties.showRunningInfo(c);
    if (!lastLab) {
      await _refreshLabStatus();
      _refreshOpenNodeProperties(data.id);
    }
  }

  function _openWorkspaceDrawer(tab) {
    const drawer = document.getElementById('workspace-drawer');
    if (!drawer) return;
    drawer.hidden = false;
    drawer.querySelectorAll('[data-drawer-tab]').forEach(button => {
      const active = button.dataset.drawerTab === tab;
      button.classList.toggle('active', active);
      const panel = document.getElementById(active ? `${tab === 'properties' ? 'props' : 'rabbit'}-panel` : `${button.dataset.drawerTab === 'properties' ? 'props' : 'rabbit'}-panel`);
      if (panel) panel.hidden = !active;
    });
  }

  function _initWorkspaceDrawer() {
    document.querySelectorAll('[data-drawer-tab]').forEach(button => {
      button.addEventListener('click', () => _openWorkspaceDrawer(button.dataset.drawerTab));
    });
    document.getElementById('btn-close-drawer')?.addEventListener('click', () => {
      FollowRabbitModal.close();
      document.getElementById('workspace-drawer').hidden = true;
    });
  }

  async function _refreshRealNetConfig() {
    if (!currentLabId) {
      Canvas.setRealNetRemoteAs('');
      Properties.setRealNetRemoteAs('');
      return;
    }
    try {
      const cfg = await API.Labs.realNetConfig(currentLabId);
      const remoteAs = cfg.remote_as || '';
      Canvas.setRealNetRemoteAs(remoteAs);
      Properties.setRealNetRemoteAs(remoteAs);
    } catch (_) {
      Canvas.setRealNetRemoteAs('');
      Properties.setRealNetRemoteAs('');
    }
  }

  function _buildPropertiesNodeData(nodeData) {
    const nodeId = nodeData.id || nodeData.name;
    const pos = _getNodePosition(nodeId);
    const liveNode = (lastLiveStatus && lastLiveStatus.nodes && lastLiveStatus.nodes[nodeId]) || {};
    return {
      ...nodeData,
      id: nodeId,
      runtime_state: liveNode.state || nodeData.runtime_state || '',
      runtime_host: liveNode.host || nodeData.runtime_host || '',
      scheduled_host: liveNode.scheduled_host || nodeData.scheduled_host || '',
      runtime_container: liveNode.container || nodeData.runtime_container || '',
      runtime_topology_file: liveNode.topology_file || nodeData.runtime_topology_file || '',
      runtime_last_error: liveNode.last_error || nodeData.runtime_last_error || '',
      can_start: liveNode.can_start ?? nodeData.can_start ?? false,
      placement_mismatch: liveNode.placement_mismatch ?? nodeData.placement_mismatch,
      duplicate_hosts: Array.isArray(liveNode.duplicate_hosts)
        ? liveNode.duplicate_hosts
        : nodeData.duplicate_hosts,
      pos_x: Math.round(pos.x),
      pos_y: Math.round(pos.y),
    };
  }

  function _refreshOpenNodeProperties(nodeName) {
    const topo = Canvas.getTopologyData();
    const node = (topo.nodes || []).find(n => n.name === nodeName || n.id === nodeName);
    if (!node || (node.kind || '') === '_real_net') return;
    const data = _buildPropertiesNodeData({
      ...node,
      id: node.name || node.id,
    });
    Properties.showNode(data);
    const c = _containerForNode(data.id);
    if (c) Properties.showRunningInfo(c);
  }

  function _initSidebarToggle() {
    const shell = document.getElementById('sidebar-shell');
    const header = document.getElementById('sidebar-header');
    const btn = document.getElementById('sidebar-toggle');
    if (!shell || !header || !btn) return;
    const setCollapsed = (collapsed) => {
      shell.classList.toggle('collapsed', collapsed);
      btn.textContent = collapsed ? '›' : '‹';
      btn.title = collapsed ? 'Show devices' : 'Hide devices';
      localStorage.setItem('dnlab-sidebar-collapsed', collapsed ? '1' : '0');
      setTimeout(() => Canvas.fit(), 240);
    };
    setCollapsed(localStorage.getItem('dnlab-sidebar-collapsed') === '1');
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      setCollapsed(!shell.classList.contains('collapsed'));
    });
    header.addEventListener('click', () => {
      if (shell.classList.contains('collapsed')) setCollapsed(false);
    });
  }

  function _uniqueNodeName(kind) {
    const base = (kind.split('_').pop() || 'node').slice(0, 6);
    const data = Canvas.getTopologyData();
    const existing = new Set(data.nodes.map(n => n.name));
    let i = 1;
    while (existing.has(`${base}${i}`)) i++;
    return `${base}${i}`;
  }

  function _download(content, filename, mimeType) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type: mimeType }));
    a.download = filename;
    a.click();
  }

  function _initViewSwitch(user) {
    const isAdmin = user && user.role === 'admin';
    const adminBtn = document.getElementById('view-admin');
    const labView = document.getElementById('lab-view');
    const adminView = document.getElementById('admin-view');
    if (!adminBtn || !labView || !adminView) return;

    adminBtn.hidden = !isAdmin;
    adminBtn.addEventListener('click', () => { location.hash = 'admin'; });
    window.addEventListener('hashchange', applyRoute);
    applyRoute();

    function applyRoute() {
      const route = (location.hash || '#labs').replace(/^#/, '');
      const wantsAdmin = route === 'admin';
      if (wantsAdmin && !isAdmin) {
        location.hash = 'labs';
        return;
      }
      const admin = wantsAdmin && isAdmin;
      labView.hidden = admin;
      adminView.hidden = !admin;
      labView.classList.toggle('active', !admin);
      adminView.classList.toggle('active', admin);
      document.body.classList.toggle('admin-active', admin);
      if (admin) {
        EventsPanel.setLab(null);
        LabLogsPanel.setLab(null);
        AdminPage.show();
      } else if (currentLabId) {
        EventsPanel.setLab(currentLabId);
        LabLogsPanel.setLab(currentLabId);
      }
    }
  }

  async function _pollLabStatus() {
    await _refreshLabStatus();
    const delay = Canvas.hasActiveNodeOperations() ? 5000 : 15000;
    statusPollTimer = setTimeout(_pollLabStatus, delay);
  }
  statusPollTimer = setTimeout(_pollLabStatus, 15000);

  // ── Mgmt network helpers ───────────────────────────────────────────
  const DEFAULT_MGMT_SUBNET = '172.20.20.0/24';
  const DEFAULT_MGMT_GW     = '172.20.20.254';
  // The default IPv6 is derived from the current IPv4 without using
  // IPv4-mapped IPv6; Docker/containerlab treats ::ffff:* as overlapping IPv4.
  const DEFAULT_MGMT_SUBNET_V6 = _deriveIpv6FromIpv4(DEFAULT_MGMT_SUBNET).subnet_v6;
  const DEFAULT_MGMT_GW_V6     = _ipv6GatewayForSubnet(DEFAULT_MGMT_SUBNET_V6) || '3fff:172:20:20:ffff:ffff:ffff:ffff';

  function _deriveIpv6FromIpv4(v4_subnet) {
    const cidr = _parseCidr(v4_subnet);
    if (!cidr) return { subnet_v6: '', gw_v6: '' };
    const octets = _intToIp(cidr.network).split('.');
    const subnet_v6 = `3fff:${octets[0]}:${octets[1]}:${octets[2]}::/64`;
    const gw_v6 = _ipv6GatewayForSubnet(subnet_v6);
    return { subnet_v6, gw_v6 };
  }

  function _ipToInt(ip) {
    const parts = String(ip || '').split('.').map(x => Number(x));
    if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
  }

  function _intToIp(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }

  function _parseCidr(cidr) {
    const [ip, prefixRaw] = String(cidr || '').split('/');
    const prefix = Number(prefixRaw);
    const addr = _ipToInt(ip);
    if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (addr & mask) >>> 0;
    const size = 2 ** (32 - prefix);
    return { cidr: `${_intToIp(network)}/${prefix}`, network, prefix, size };
  }

  function _lastHostForSubnet(subnet) {
    if (!subnet || subnet.size < 8) return '';
    return _intToIp((subnet.network + subnet.size - 2) >>> 0);
  }

  function _gatewayForSubnet(subnet, defaultSubnet = DEFAULT_MGMT_SUBNET, defaultGw = DEFAULT_MGMT_GW) {
    return _lastHostForSubnet(subnet) || defaultGw;
  }

  function _parseIpv6Cidr(cidr) {
    const [addrRaw, prefixRaw] = String(cidr || '').split('/');
    const prefix = Number(prefixRaw);
    const addr = _ipv6ToBigInt(addrRaw);
    if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
    const hostBits = 128n - BigInt(prefix);
    const size = 1n << hostBits;
    const mask = ((1n << 128n) - 1n) ^ (size - 1n);
    const network = addr & mask;
    return { network, prefix, size, cidr: `${_bigIntToIpv6(network)}/${prefix}` };
  }

  function _ipv6GatewayForSubnet(cidr) {
    const parsed = _parseIpv6Cidr(cidr);
    if (!parsed || parsed.size < 2n) return '';
    return _bigIntToIpv6(parsed.network + parsed.size - 1n);
  }

  function _ipv6ToBigInt(addr) {
    let raw = String(addr || '').trim().toLowerCase();
    if (!raw) return null;
    if (raw.includes('.')) {
      const lastColon = raw.lastIndexOf(':');
      const v4 = _ipToInt(raw.slice(lastColon + 1));
      if (v4 === null) return null;
      raw = `${raw.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
    }
    if ((raw.match(/::/g) || []).length > 1) return null;
    const parts = raw.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    if (parts.length === 1 && left.length !== 8) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 0) return null;
    const groups = [...left, ...Array(missing).fill('0'), ...right];
    if (groups.length !== 8) return null;
    let out = 0n;
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      out = (out << 16n) + BigInt(parseInt(group, 16));
    }
    return out;
  }

  function _bigIntToIpv6(value) {
    const groups = [];
    for (let i = 7; i >= 0; i--) {
      groups.push(Number((value >> BigInt(i * 16)) & 0xffffn).toString(16));
    }
    return groups.join(':');
  }

  async function _suggestMgmtDefaults() {
    const subnet = _parseCidr(DEFAULT_MGMT_SUBNET);
    if (!subnet) return { subnet: DEFAULT_MGMT_SUBNET, gw: DEFAULT_MGMT_GW };
    return { subnet: subnet.cidr, gw: _gatewayForSubnet(subnet) };
  }

  async function _seedDefaultMgmt(labId) {
    // Calls setMgmtConfig with default subnet/gateway if the lab
    // does not already have one. Used when creating a new topology (C2).
    try {
      const suggested = await _suggestMgmtDefaults(labId);
      const derived = _deriveIpv6FromIpv4(suggested.subnet);
      await API.Labs.setMgmtConfig(labId, {
        ipv4_subnet: suggested.subnet,
        ipv4_gw:     suggested.gw,
        ipv6_subnet: derived.subnet_v6,
        ipv6_gw:     derived.gw_v6,
        canvas_pos:  { x: 120, y: 120 },
      });
    } catch (_) { /* lab appena created: error non bloccante */ }
  }

  async function _placeOrEditMgmt(pos) {
    // Triggered by drop/double-click on the "Mgmt Network" card.
    // If the cloud already exists: move it to the drop point (if the lab is stopped). If missing:
    // create it with current or default values + open the modal for
    // subnet/gw.
    if (!_assertMgmtEditable()) return;
    const isNew = !currentMgmt.subnet && !currentMgmt.gw;
    const suggested = isNew ? await _suggestMgmtDefaults(currentLabId) : null;
    currentMgmt.pos = pos;
    const v4Subnet = currentMgmt.subnet || suggested?.subnet || DEFAULT_MGMT_SUBNET;
    const v4Gw     = _gatewayForSubnet(_parseCidr(v4Subnet)) || currentMgmt.gw || suggested?.gw || DEFAULT_MGMT_GW;
    const v6Auto   = !currentMgmt.userTouchedV6;
    const v6FromV4 = _deriveIpv6FromIpv4(v4Subnet);
    const v6Subnet = v6Auto ? v6FromV4.subnet_v6 : (currentMgmt.subnet_v6 || v6FromV4.subnet_v6);
    const v6Gw     = _ipv6GatewayForSubnet(v6Subnet) || v6FromV4.gw_v6;
    Canvas.setMgmt({
      subnet:    v4Subnet,
      gw:        v4Gw,
      subnet_v6: v6Subnet,
      gw_v6:     v6Gw,
      pos,
    });
    if (isNew) {
      currentMgmt.subnet    = v4Subnet;
      currentMgmt.gw        = v4Gw;
      currentMgmt.subnet_v6 = v6Subnet;
      currentMgmt.gw_v6     = v6Gw;
      await _persistMgmt();
      _openMgmtModal(true);
    } else {
      if (v6Auto) {
        currentMgmt.subnet_v6 = v6Subnet;
        currentMgmt.gw_v6     = v6Gw;
      }
      await _persistMgmt();
    }
  }

  function _openMgmtModal(isFirstTime) {
    if (!currentLabId) return;
    const readOnly = _labIsLive();
    const title = isFirstTime ? 'Mgmt Network — configura' : 'Mgmt Network';
    const v4Subnet = currentMgmt.subnet || DEFAULT_MGMT_SUBNET;
    const v4Gw     = _gatewayForSubnet(_parseCidr(v4Subnet)) || currentMgmt.gw || DEFAULT_MGMT_GW;
    const derived = _deriveIpv6FromIpv4(v4Subnet);
    const v6Subnet = currentMgmt.subnet_v6 || derived.subnet_v6 || DEFAULT_MGMT_SUBNET_V6;
    const v6Gw     = _ipv6GatewayForSubnet(v6Subnet) || currentMgmt.gw_v6 || derived.gw_v6 || DEFAULT_MGMT_GW_V6;
    const dhcp = Boolean(currentMgmt.dhcp);
    const body = `
      <div class="mgmt-modal-body">
        <label>IPv4 subnet<br>
          <input id="mgmt-modal-subnet" class="props-input" type="text"
                 value="${_escAttr(v4Subnet)}"
                 placeholder="${DEFAULT_MGMT_SUBNET}" ${readOnly ? 'disabled' : ''}>
        </label>
        <label>IPv4 gateway<br>
          <input id="mgmt-modal-gw" class="props-input" type="text"
                 value="${_escAttr(v4Gw)}"
                 placeholder="${DEFAULT_MGMT_GW}" disabled>
        </label>
        <label>IPv6 subnet<br>
          <input id="mgmt-modal-subnet-v6" class="props-input" type="text"
                 value="${_escAttr(v6Subnet)}"
                 placeholder="${DEFAULT_MGMT_SUBNET_V6}" ${readOnly ? 'disabled' : ''}>
        </label>
        <label>IPv6 gateway<br>
          <input id="mgmt-modal-gw-v6" class="props-input" type="text"
                 value="${_escAttr(v6Gw)}"
                 placeholder="${DEFAULT_MGMT_GW_V6}" disabled>
        </label>
        <label class="props-check">
          <input id="mgmt-modal-dhcp" type="checkbox" ${dhcp ? 'checked' : ''} ${readOnly ? 'disabled' : ''}>
          <span>Abilita DHCPv4 + RA/DHCPv6 per tutta la rete mgmt</span>
        </label>
        <p class="mgmt-hint">I gateway sono derivati dagli ultimi indirizzi delle subnet.
        IPv6 è derivata da IPv4 se lasciata vuota.</p>
        ${readOnly
          ? '<p class="mgmt-modal-readonly">Lab running — mgmt can only be edited while the lab is stopped.</p>'
          : ''}
      </div>
    `;
    const actions = readOnly
      ? [{ label: 'Close' }]
      : [
          {
            label: 'Save', class: 'btn-primary', action: async () => {
              const subnet     = document.getElementById('mgmt-modal-subnet').value.trim();
              const gw         = document.getElementById('mgmt-modal-gw').value.trim();
              const subnet_v6  = document.getElementById('mgmt-modal-subnet-v6').value.trim();
              const gw_v6      = document.getElementById('mgmt-modal-gw-v6').value.trim();
              const dhcp       = document.getElementById('mgmt-modal-dhcp').checked;
              const autoDerived = _deriveIpv6FromIpv4(subnet);
              currentMgmt.userTouchedV6 = (
                (subnet_v6 && subnet_v6 !== autoDerived.subnet_v6)
              );
              currentMgmt.subnet    = subnet;
              currentMgmt.gw        = gw;
              currentMgmt.subnet_v6 = subnet_v6;
              currentMgmt.gw_v6     = gw_v6;
              currentMgmt.dhcp      = dhcp;
              Canvas.setMgmt({ subnet, gw, subnet_v6, gw_v6, pos: currentMgmt.pos });
              await _persistMgmt();
              MgmtPanel.setTopology(currentLabName, {
                'ipv4-subnet': subnet,    'ipv4-gw': gw,
                'ipv6-subnet': subnet_v6, 'ipv6-gw': gw_v6,
                dhcp,
              });
            },
          },
          { label: 'Cancel' },
        ];
    showModal(title, body, actions);
    // Auto-sync v6 fields while editing v4, until the user
    // explicitly edits the v6 block.
    if (!readOnly) _wireMgmtModalAutoSync();
  }

  function _wireMgmtModalAutoSync() {
    const v4Subnet = document.getElementById('mgmt-modal-subnet');
    const v4Gw     = document.getElementById('mgmt-modal-gw');
    const v6Subnet = document.getElementById('mgmt-modal-subnet-v6');
    const v6Gw     = document.getElementById('mgmt-modal-gw-v6');
    if (!v4Subnet || !v4Gw || !v6Subnet || !v6Gw) return;
    let userTouched = !!currentMgmt.userTouchedV6;
    const refresh = () => {
      const subnet = _parseCidr(v4Subnet.value.trim());
      const gw4 = subnet ? _gatewayForSubnet(subnet) : '';
      if (gw4) v4Gw.value = gw4;
      if (userTouched) return;
      const d = _deriveIpv6FromIpv4(v4Subnet.value.trim());
      if (d.subnet_v6) v6Subnet.value = d.subnet_v6;
      const gw6 = _ipv6GatewayForSubnet(v6Subnet.value.trim()) || d.gw_v6;
      if (gw6) v6Gw.value = gw6;
    };
    v4Subnet.addEventListener('input', refresh);
    v4Gw.addEventListener('input', refresh);
    const markTouched = () => { userTouched = true; };
    v6Subnet.addEventListener('input', () => {
      markTouched();
      const gw6 = _ipv6GatewayForSubnet(v6Subnet.value.trim());
      if (gw6) v6Gw.value = gw6;
    });
  }

  async function _persistMgmt() {
    if (!currentLabId) return;
    try {
      await API.Labs.setMgmtConfig(currentLabId, {
        ipv4_subnet: currentMgmt.subnet    || '',
        ipv4_gw:     currentMgmt.gw        || '',
        ipv6_subnet: currentMgmt.subnet_v6 || '',
        ipv6_gw:     currentMgmt.gw_v6     || '',
        dhcp:        Boolean(currentMgmt.dhcp),
        canvas_pos:  currentMgmt.pos || undefined,
      });
    } catch (e) {
      showToast('Mgmt save failed: ' + e.message, 'error');
    }
  }

  function _assertMgmtEditable() {
    if (!currentLabId) {
      showToast('Create or open a topology first', 'warn');
      return false;
    }
    if (!currentLabCanWrite) {
      showToast('Insufficient permissions to modify this lab', 'warn');
      return false;
    }
    if (_labIsLive()) {
      showToast('Lab running — stop the lab to modify mgmt', 'warn');
      return false;
    }
    return true;
  }

  function _labIsLive() {
    return labStatus === 'running' || labStatus === 'partial' || labStatus === 'deploying' || labStatus === 'destroying';
  }

  function _labIsRuntimeReconcileable() {
    return labStatus === 'running' || labStatus === 'partial';
  }

  async function _applyLiveLink(link) {
    if (!_labIsRuntimeReconcileable()) return null;
    const result = await API.Labs.reconcileLink(currentLabId, link);
    if (!result || result.success === false) {
      await _refreshLabStatus();
      showToast(`Link saved; live reconcile failed: ${result?.output || 'unknown error'}`, 'error');
      return { state: 'error', last_error: result?.output || 'Live reconcile failed' };
    }
    await _refreshLabStatus();
    const runtime = result.link || {};
    if (runtime.state === 'error') {
      showToast(`Link saved but runtime activation failed: ${runtime.last_error || 'unknown error'}`, 'error');
    } else if (runtime.state === 'partial') {
      showToast(`Link saved and pending: ${runtime.last_error || 'endpoint not running'}`, 'info');
    } else if (runtime.state === 'up') {
      showToast('Link applied live', 'success');
    }
    return runtime;
  }

  async function _saveLinkStyle(edgeData, style) {
    try {
      const link = {
        source: edgeData.source,
        source_iface: edgeData.source_iface || '',
        target: edgeData.target,
        target_iface: edgeData.target_iface || '',
      };
      const topo = await API.Labs.setLinkStyle(currentLabId, link, style || {});
      const key = _edgeStyleKey(link.source, link.source_iface, link.target, link.target_iface);
      const nextStyle = (topo.gui_link_styles_state || {})[key] || {};
      Canvas.setLinkStyle(link, nextStyle);
      showToast(Object.keys(nextStyle).length ? 'Link color updated' : 'Link color reset', 'success');
    } catch (e) {
      showToast('Link color failed: ' + e.message, 'error');
    }
  }

  function _showAnnotationStyleModal(annotation) {
    if (!annotation) return;
    const style = annotation.style || {};
    const isNote = annotation.type === 'note';
    const zIndex = Number.isFinite(Number(annotation.z_index))
      ? Math.round(Number(annotation.z_index))
      : (annotation.layer === 'below_vd' ? -1 : 1);
    showModal('Annotation', `
      <div class="props-form">
        <label>Text
          <textarea id="ann-text" class="props-input" rows="4">${_escHtml(annotation.text || '')}</textarea>
        </label>
        <label>Layer
          <input id="ann-z-index" class="props-input" type="number" min="-999" max="999" step="1" value="${zIndex}">
        </label>
        <label>Text color
          <input id="ann-text-color" class="props-input" type="color" value="${_escAttr(_validHex(style.text_color) ? style.text_color : '#111827')}">
        </label>
        <label>Font
          <select id="ann-font-family" class="props-input">
            ${['Arial', 'Inter', 'Verdana', 'Georgia', 'Courier New', 'monospace'].map(font =>
              `<option value="${_escAttr(font)}" ${font === (style.font_family || 'Arial') ? 'selected' : ''}>${_escHtml(font)}</option>`
            ).join('')}
          </select>
        </label>
        <label>Font size
          <input id="ann-font-size" class="props-input" type="number" min="6" max="72" value="${Number(style.font_size || 14)}">
        </label>
        <label>
          <span><input id="ann-bold" type="checkbox" ${Number(style.font_weight || 400) >= 600 ? 'checked' : ''}> Bold</span>
        </label>
        <label>
          <span><input id="ann-italic" type="checkbox" ${style.font_style === 'italic' ? 'checked' : ''}> Italic</span>
        </label>
        ${isNote ? '' : `
          <label>Fill color
            <input id="ann-fill-color" class="props-input" type="color" value="${_escAttr(_validHex(style.fill_color) ? style.fill_color : '#fef3c7')}">
          </label>
          <label>Border color
            <input id="ann-stroke-color" class="props-input" type="color" value="${_escAttr(_validHex(style.stroke_color) ? style.stroke_color : '#64748b')}">
          </label>
          <label>Border width
            <input id="ann-border-width" class="props-input" type="number" min="0" max="20" value="${Number(style.border_width ?? 2)}">
          </label>
        `}
        <label>Opacity
          <input id="ann-opacity" class="props-input" type="number" min="0.1" max="1" step="0.05" value="${Number(style.opacity ?? 0.9)}">
        </label>
      </div>
    `, [
      {
        label: 'Apply', class: 'btn-primary', action: () => {
          const nextStyle = {
            ...style,
            text_color: document.getElementById('ann-text-color').value,
            font_family: document.getElementById('ann-font-family').value,
            font_size: Number(document.getElementById('ann-font-size').value || 14),
            font_weight: document.getElementById('ann-bold').checked ? '700' : '400',
            font_style: document.getElementById('ann-italic').checked ? 'italic' : 'normal',
            opacity: Number(document.getElementById('ann-opacity').value || 0.9),
          };
          if (isNote) {
            nextStyle.fill_color = 'transparent';
            nextStyle.stroke_color = 'transparent';
            nextStyle.border_width = 0;
          } else {
            nextStyle.fill_color = document.getElementById('ann-fill-color').value;
            nextStyle.stroke_color = document.getElementById('ann-stroke-color').value;
            nextStyle.border_width = Number(document.getElementById('ann-border-width').value || 0);
          }
          Canvas.updateAnnotation(annotation.id, {
            text: document.getElementById('ann-text').value,
            z_index: Number(document.getElementById('ann-z-index').value),
            style: nextStyle,
          });
        },
      },
      { label: 'Cancel' },
    ]);
  }

  function _scheduleAnnotationSave() {
    if (!currentLabId) return;
    clearTimeout(annotationSaveTimer);
    annotationSaveTimer = setTimeout(async () => {
      try {
        await API.Labs.setCanvasAnnotations(currentLabId, Canvas.getAnnotations());
      } catch (e) {
        showToast('Annotation save failed: ' + e.message, 'error');
      }
    }, 400);
  }

  function _edgeStyleKey(source, sourceIface, target, targetIface) {
    return [`${source}:${sourceIface || ''}`, `${target}:${targetIface || ''}`].sort().join('|');
  }

  function _validHex(value) {
    return /^#[0-9a-fA-F]{6}$/.test(String(value || ''));
  }

  function _escAttr(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  }

  function _escHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
})();
