/**
 * Toolbar module – top action bar.
 *
 * Post-PR4c: labs are keyed by UUID. The "Open" dialog calls the
 * labs index and emits `{id, name}` to the app shell; read-only rows
 * (can_write=false) are still openable but the app shell disables
 * edit/deploy/destroy for them.
 */
const Toolbar = (() => {
  let _currentTopo = null;
  const listeners = {};

  function init() {
    _bind('btn-new',          () => _emit('new'));
    _bind('btn-open',         () => _showOpenDialog());
    _bind('btn-import-drawio',() => _triggerImport());
    _bind('btn-export-drawio',() => _emit('export-drawio'));
    _bind('btn-deploy',       () => _emit('deploy'));
    _bind('btn-destroy',      () => _emit('destroy'));
    _bind('btn-all-consoles', () => _emit('all-consoles'));
    _bind('btn-delete-topo',  () => _emit('delete-topo'));
    _bind('btn-fit',          () => _emit('fit'));
    _bind('btn-follow-rabbit',() => _emit('follow-rabbit'));
    _bind('btn-delete',       () => _emit('delete-selected'));
    _bind('btn-logout',       () => _emit('logout'));

    _bind('btn-mode-select', () => _setMode('select'));
    _bind('btn-mode-link',   () => _setMode('link'));
    _bind('btn-add-note',    () => _emit('add-annotation', 'note'));
    _bind('btn-add-rect',    () => _emit('add-annotation', 'rectangle'));
    _bind('btn-add-ellipse', () => _emit('add-annotation', 'ellipse'));

    // Mgmt visibility toggle: nasconde il cloud, i link tratteggiati
    // e gli IP mgmt mostrati sotto i nodi. Stato persistito in
    // localStorage so l'user non deve rimetterlo ad ogni refresh.
    const btnMgmt = document.getElementById('btn-toggle-mgmt');
    if (btnMgmt) {
      const stored = localStorage.getItem('dnlab-mgmt-visible');
      const initial = stored === null ? true : stored === '1';
      _setMgmtVisible(initial);
      btnMgmt.addEventListener('click', () => toggleMgmtVisible());
    }
  }

  function toggleMgmtVisible() {
    const btn = document.getElementById('btn-toggle-mgmt');
    if (!btn) return;
    _setMgmtVisible(!(btn.dataset.on === '1'));
  }

  function isMgmtVisible() {
    const btn = document.getElementById('btn-toggle-mgmt');
    if (!btn) return true;
    return btn.dataset.on === '1';
  }

  function _setMgmtVisible(on) {
    const btn = document.getElementById('btn-toggle-mgmt');
    if (!btn) return;
    _applyMgmtToggleUI(btn, on);
    localStorage.setItem('dnlab-mgmt-visible', on ? '1' : '0');
    _emit('mgmt-visible', on);
  }

  function _applyMgmtToggleUI(btn, on) {
    btn.dataset.on = on ? '1' : '0';
    btn.classList.toggle('active', on);
    btn.title = on
      ? 'Hide mgmt cloud, links and node mgmt IPs (M)'
      : 'Show mgmt cloud, links and node mgmt IPs (M)';
  }

  function setCurrentTopo(name, canWrite = true) {
    _currentTopo = name;
    const label = name ? (canWrite ? name : `${name} (read-only)`) : '(noa topology)';
    document.getElementById('topo-name-display').textContent = label;
    // Disable write-only buttons when the lab is read-only.
    const writeBtns = ['btn-deploy', 'btn-destroy', 'btn-delete-topo'];
    writeBtns.forEach(id => {
      const b = document.getElementById(id);
      if (b) b.disabled = name ? !canWrite : false;
    });
  }

  function setLabStatus(status, tooltip = '') {
    const badge = document.getElementById('lab-status-badge');
    if (!badge) return;
    const isTransient = status === 'deploying' || status === 'destroying';
    const spinner = isTransient ? '<span class="badge-spinner"></span>' : '';
    badge.innerHTML = `${spinner}<span class="badge-text">${status}</span>`;
    badge.className = `status-badge status-${status}${isTransient ? ' status-transient' : ''}`;
    badge.title = tooltip || '';
  }

  function setAllConsolesEnabled(enabled) {
    const button = document.getElementById('btn-all-consoles');
    if (button) button.disabled = !enabled;
  }

  // ── Internals ────────────────────────────────────────────────────────
  function _bind(id, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', handler);
  }

  function _setMode(m) {
    document.getElementById('btn-mode-select')?.classList.toggle('active', m === 'select');
    document.getElementById('btn-mode-link')?.classList.toggle('active', m === 'link');
    _emit('mode-change', m);
  }

  async function _showOpenDialog() {
    try {
      const labs = await API.Labs.list();
      if (!labs.length) { showToast('No saved labs', 'info'); return; }

      const listEl = document.createElement('ul');
      listEl.className = 'topo-list';
      labs.forEach(l => {
        const li = document.createElement('li');
        const owner = l.owner_username ? `owner: ${l.owner_username}` : 'owner: —';
        const rw = l.can_write ? '' : ' <small class="ro-tag">read-only</small>';
        li.innerHTML = `<span>${_esc(l.name)}${rw}</span> <small>${_esc(owner)}</small>`;
        li.addEventListener('click', () => {
          hideModal();
          _emit('open', { id: l.id, name: l.name });
        });
        listEl.appendChild(li);
      });

      showModal('Open Lab', listEl, [{ label: 'Cancel', class: 'btn-secondary' }]);
    } catch (e) {
      showToast('Lab list unavailable: ' + e.message, 'error');
    }
  }

  function _triggerImport() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.drawio,.xml';
    input.addEventListener('change', async () => {
      const file = input.files[0];
      if (!file) return;
      const xml = await file.text();
      _emit('import-drawio', { xml, filename: file.name });
    });
    input.click();
  }

  function on(event, cb) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(cb);
  }

  function _emit(event, data) {
    (listeners[event] || []).forEach(cb => cb(data));
  }

  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  return {
    init,
    setCurrentTopo,
    setLabStatus,
    setAllConsolesEnabled,
    toggleMgmtVisible,
    isMgmtVisible,
    on,
  };
})();
