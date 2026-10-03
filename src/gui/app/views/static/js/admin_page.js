/**
 * AdminPage - site-wide infrastructure management area.
 */
const AdminPage = (() => {
  const TABS = [
    ['users', 'Users'],
    ['paths', 'Paths'],
    ['hosts', 'Hosts'],
    ['realnet-bgp', 'RealNet BGP'],
    ['devices', 'Devices'],
    ['images', 'Images'],
  ];
  const ROLES = ['admin', 'graduate', 'assistant', 'student', 'rookie'];
  let _root = null;
  let _content = null;
  let _active = 'users';
  let _initialized = false;
  let _jobsTimer = null;
  let _buildKindsByName = {};

  function init(rootId) {
    _root = document.getElementById(rootId);
  }

  function show() {
    if (!_root) return;
    if (!_initialized) {
      _root.innerHTML = `
        <div class="admin-shell">
          <aside class="admin-nav">
            ${TABS.map(([id, label]) => `
              <button class="admin-tab" type="button" data-tab="${id}">${label}</button>
            `).join('')}
          </aside>
          <section class="admin-content" id="admin-content"></section>
        </div>
      `;
      _content = _root.querySelector('#admin-content');
      _root.querySelectorAll('.admin-tab').forEach(btn => {
        btn.addEventListener('click', () => _activate(btn.dataset.tab));
      });
      _initialized = true;
    }
    _activate(_active);
  }

  async function _activate(tab) {
    _active = tab || 'users';
    if (!_root || !_content) return;
    _root.querySelectorAll('.admin-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === _active);
    });
    clearInterval(_jobsTimer);
    _jobsTimer = null;
    _content.innerHTML = '<div class="admin-loading">Loading...</div>';
    if (_active === 'users') return _renderUsers();
    if (_active === 'paths') return _renderPathsConfig();
    if (_active === 'hosts') return _renderHostsConfig();
    if (_active === 'realnet-bgp') return _renderRealNetBgpConfig();
    if (_active === 'devices') return _renderDevicesConfig();
    if (_active === 'images') return _renderImages();
  }

  // Users
  async function _renderUsers() {
    let users;
    try {
      users = await API.Users.list();
    } catch (e) {
      _content.innerHTML = _error('Cannot load users', e);
      return;
    }
    const me = AuthGate.currentUser();
    _content.innerHTML = `
      <div class="admin-panel-head">
        <div>
          <h2>Users</h2>
          <p>Local accounts and operational roles.</p>
        </div>
        <button id="admin-user-add" class="btn btn-primary btn-sm">+ Add user</button>
      </div>
      <div id="admin-user-form" class="admin-inline-form" hidden></div>
      <table class="admin-table">
        <thead><tr>
          <th>id</th><th>username</th><th>role</th><th>backend</th><th>active</th><th>last login</th><th></th>
        </tr></thead>
        <tbody>${users.map(u => _userRow(u, me?.username)).join('')}</tbody>
      </table>
    `;
    _content.querySelector('#admin-user-add').addEventListener('click', _toggleUserForm);
    _wireUserActions(users);
  }

  function _userRow(u, myUsername) {
    const isSelf = u.username === myUsername;
    return `
      <tr data-user-id="${u.id}" data-username="${_esc(u.username)}" data-role="${_esc(u.role)}"
          data-backend="${_esc(u.backend)}" data-active="${u.is_active ? '1' : '0'}">
        <td class="admin-num">${u.id}</td>
        <td><strong>${_esc(u.username)}</strong>${isSelf ? ' <span class="admin-muted">(you)</span>' : ''}</td>
        <td><span class="role-pill role-${_esc(u.role)}">${_esc(u.role)}</span></td>
        <td><code>${_esc(u.backend)}</code></td>
        <td>${u.is_active ? '<span class="admin-ok">yes</span>' : '<span class="admin-warn">no</span>'}</td>
        <td class="admin-muted">${u.last_login_at ? _fmtDate(u.last_login_at) : '-'}</td>
        <td class="admin-actions">
          <button class="btn btn-xs admin-user-edit" title="Edit user">Edit</button>
          <button class="btn btn-xs btn-danger admin-user-del" ${isSelf ? 'disabled' : ''}>Delete</button>
        </td>
      </tr>
    `;
  }

  function _toggleUserForm() {
    const form = _content.querySelector('#admin-user-form');
    if (!form.hidden) {
      form.hidden = true;
      form.innerHTML = '';
      return;
    }
    form.innerHTML = `
      <input id="admin-new-username" class="props-input" placeholder="username" autocomplete="off">
      <input id="admin-new-password" class="props-input" placeholder="password" type="password">
      <select id="admin-new-role" class="props-input">
        ${ROLES.map(r => `<option value="${r}" ${r === 'student' ? 'selected' : ''}>${r}</option>`).join('')}
      </select>
      <input id="admin-new-email" class="props-input" placeholder="email">
      <button id="admin-new-save" class="btn btn-primary btn-sm">Create</button>
    `;
    form.hidden = false;
    form.querySelector('#admin-new-save').addEventListener('click', _createUser);
  }

  async function _createUser() {
    const username = _content.querySelector('#admin-new-username').value.trim();
    const password = _content.querySelector('#admin-new-password').value;
    const role = _content.querySelector('#admin-new-role').value;
    const email = _content.querySelector('#admin-new-email').value.trim();
    if (!username || !password || password.length < 8) {
      showToast('Username and password >= 8 characters required', 'warn');
      return;
    }
    try {
      await API.Users.create({ username, password, role, email: email || null });
      showToast('User created', 'success');
      await _renderUsers();
    } catch (e) {
      showToast(_apiErr('Creation failed', e), 'error');
    }
  }

  function _wireUserActions(users) {
    _content.querySelectorAll('tr[data-user-id]').forEach(tr => {
      const id = Number(tr.dataset.userId);
      const username = tr.dataset.username;
      const user = users.find(u => u.id === id);
      tr.querySelector('.admin-user-edit').addEventListener('click', () => _editUser(user));
      tr.querySelector('.admin-user-del').addEventListener('click', () => _deleteUser(id, username));
    });
  }

  async function _editUser(user) {
    const local = user.backend === 'local_db';
    const body = document.createElement('div');
    body.innerHTML = `
      <p>User: <strong>${_esc(user.username)}</strong></p>
      <label>Email
        <input id="admin-edit-email" class="props-input" type="email" value="${_esc(user.email || '')}" ${local ? '' : 'disabled'}>
      </label>
      ${local ? '' : '<p class="admin-muted">Email is managed by the external authentication backend.</p>'}
      <label>Role
        <select id="admin-edit-role" class="props-input">
          ${ROLES.map(r => `<option value="${r}" ${r === user.role ? 'selected' : ''}>${r}</option>`).join('')}
        </select>
      </label>
      <label><input id="admin-edit-active" type="checkbox" ${user.is_active ? 'checked' : ''}> Active</label>
      ${local ? `<label>New password <span class="admin-muted">(optional)</span>
        <input id="admin-edit-password" class="props-input" type="password" minlength="8">
      </label>` : ''}
    `;
    showModal('Edit user', body, [
      { label: 'Cancel' },
      { label: 'Save', class: 'btn-primary', action: async () => {
          const patch = {};
          const email = body.querySelector('#admin-edit-email').value.trim() || null;
          const role = body.querySelector('#admin-edit-role').value;
          const active = body.querySelector('#admin-edit-active').checked;
          const password = local ? body.querySelector('#admin-edit-password').value : '';
          if (local && email !== (user.email || null)) patch.email = email;
          if (role !== user.role) patch.role = role;
          if (active !== user.is_active) patch.is_active = active;
          if (password && password.length < 8) {
            showToast('Password too short', 'warn');
            return;
          }
          try {
            if (Object.keys(patch).length) await API.Users.patch(user.id, patch);
            if (password) await API.Users.resetPassword(user.id, password);
            showToast('User updated', 'success');
            await _renderUsers();
          } catch (e) { showToast(_apiErr('Update failed', e), 'error'); }
        } },
    ]);
  }

  async function _deleteUser(id, username) {
    if (!confirm(`Deletere permanently l'user "${username}"?`)) return;
    try {
      await API.Users.remove(id);
      await _renderUsers();
    } catch (e) {
      showToast(_apiErr('Deletion failed', e), 'error');
    }
  }

  // Structured config wrappers
  async function _renderPathsConfig() {
    let cfg;
    try { cfg = await API.Admin.readConfigModel('paths'); }
    catch (e) { _content.innerHTML = _error('Cannot load paths.yml', e); return; }
    const rows = (cfg.data.entries || []).map(_pathRow).join('');
    _content.innerHTML = `
      ${_configHead('Paths', cfg.path, cfg.exists, 'admin-path-add', 'Add path', 'admin-path-save')}
      <table class="admin-table admin-config-table">
        <thead><tr><th>key</th><th>value</th><th>state</th><th></th></tr></thead>
        <tbody id="admin-paths-body">${rows}</tbody>
      </table>
      <div class="admin-form-actions">
        <button id="admin-path-save-bottom" class="btn btn-primary btn-sm">Save paths</button>
      </div>
      <div id="admin-config-result" class="admin-result" hidden></div>
    `;
    _content.querySelector('#admin-path-add').addEventListener('click', () => {
      _content.querySelector('#admin-paths-body').insertAdjacentHTML('beforeend', _pathRow({ key: '', value: '', known: false }));
      _wireRemoveButtons();
    });
    const confirmAndSavePaths = () => {
      if (!confirm('Save paths.yml to disk? A service restart will be required to apply the new paths.')) return;
      _savePathsConfig(cfg);
    };
    _content.querySelector('#admin-path-save').addEventListener('click', confirmAndSavePaths);
    _content.querySelector('#admin-path-save-bottom').addEventListener('click', confirmAndSavePaths);
    _wireRemoveButtons();
  }

  function _pathRow(entry) {
    const label = entry.status_label || (entry.warning ? entry.warning : (entry.exists === false ? 'missing' : 'ok'));
    const cls = entry.warning || (!entry.status_label && entry.exists === false) ? 'admin-warn' : 'admin-ok';
    const state = `<span class="${cls}">${_esc(label)}</span>`;
    return `
      <tr class="admin-path-row" data-known="${entry.known ? '1' : '0'}">
        <td><input class="props-input admin-path-key" value="${_esc(entry.key)}" ${entry.known ? 'readonly' : ''}></td>
        <td><input class="props-input admin-path-value" value="${_esc(entry.value)}"></td>
        <td>${state}</td>
        <td class="admin-actions"><button class="btn btn-xs admin-row-remove" ${entry.known ? 'disabled' : ''}>Delete</button></td>
      </tr>
    `;
  }

  async function _savePathsConfig(cfg) {
    cfg.data.entries = [..._content.querySelectorAll('.admin-path-row')].map(row => ({
      key: row.querySelector('.admin-path-key').value.trim(),
      value: row.querySelector('.admin-path-value').value.trim(),
      known: row.dataset.known === '1',
    }));
    try {
      await API.Admin.writeConfigModel('paths', cfg.data);
      showToast('Paths saved', 'success');
      showModal('Restart required', `
        <p>The changes to <code>paths.yml</code> have been saved.</p>
        <p>Restart dNLab GUI and the related services for all new paths to take effect.</p>
      `, [{ label: 'OK', class: 'btn-primary' }]);
      await _renderPathsConfig();
    } catch (e) { showToast(_apiErr('Save failed', e), 'error'); }
  }

  async function _renderHostsConfig() {
    let cfg;
    try { cfg = await API.Admin.readConfigModel('hosts'); }
    catch (e) { _content.innerHTML = _error('Cannot load hosts.yml', e); return; }
    _content.innerHTML = `
      ${_configHead('Hosts', cfg.path, cfg.exists, 'admin-worker-add', 'Add worker', 'admin-hosts-save')}
      <table class="admin-table admin-config-table">
        <thead><tr><th>name</th><th>host</th><th>ssh user</th><th>ssh key</th><th></th></tr></thead>
        <tbody id="admin-hosts-body">
          ${_hostRow(cfg.data.master, true)}
          ${(cfg.data.workers || []).map(h => _hostRow(h, false)).join('')}
        </tbody>
      </table>
      ${_hostsInfrastructureBlocks(cfg)}
      ${_persistenceBlock((cfg.data.extra_infrastructure || {}).persistence || {})}
      ${_followRabbitBlock((cfg.data.extra_top_level || {}).follow_the_rabbit || ((cfg.data.extra_top_level || {}).plus || {}).follow_the_rabbit || {})}
      <div class="admin-form-actions">
        <button id="admin-hosts-save-bottom" class="btn btn-primary btn-sm">Save hosts</button>
      </div>
    `;
    _content.querySelector('#admin-worker-add').addEventListener('click', () => {
      _content.querySelector('#admin-hosts-body').insertAdjacentHTML('beforeend', _hostRow({ name: `worker${Date.now().toString().slice(-4)}`, host: '', ssh_user: 'root', ssh_key: '' }, false));
      _wireRemoveButtons();
    });
    const confirmAndSaveHosts = () => {
      if (!confirm('Save hosts.yml to disk? A restart of dnlab-image-sync is recommended if workers were added or removed.')) return;
      _saveHostsConfig(cfg);
    };
    _content.querySelector('#admin-hosts-save').addEventListener('click', confirmAndSaveHosts);
    _content.querySelector('#admin-hosts-save-bottom').addEventListener('click', confirmAndSaveHosts);
    _wireRemoveButtons();
  }

  function _hostRow(host, master) {
    return `
      <tr class="admin-host-row" data-master="${master ? '1' : '0'}">
        <td><input class="props-input admin-host-name" value="${_esc(host.name)}" ${master ? 'readonly' : ''}></td>
        <td><input class="props-input admin-host-host" value="${_esc(host.host)}" placeholder="10.0.0.10"></td>
        <td><input class="props-input admin-host-user" value="${_esc(host.ssh_user || 'root')}"></td>
        <td><input class="props-input admin-host-key" value="${_esc(host.ssh_key || '')}" placeholder="/root/.ssh/id_ed25519"></td>
        <td class="admin-actions"><button class="btn btn-xs admin-row-remove" ${master ? 'disabled' : ''}>Delete</button></td>
      </tr>
    `;
  }

  function _persistenceBlock(p) {
    const ceph = p.cephfs || {};
    const backend = p.backend || 'local-sticky';
    return `
      <section class="admin-section">
        <h3>Persistence</h3>
        <div class="admin-grid">
          <label>backend
            <select class="props-input" id="admin-persist-backend">
              <option value="local-sticky" ${backend === 'local-sticky' ? 'selected' : ''}>local-sticky</option>
              <option value="cephfs" ${backend === 'cephfs' ? 'selected' : ''}>cephfs</option>
            </select>
          </label>
          <label>root
            <input class="props-input" id="admin-persist-root" value="${_esc(p.root || '/var/lib/docker/dnlab-backups')}">
          </label>
          <label>migration fallback
            <select class="props-input" id="admin-persist-fallback">
              <option value="1" ${p.allow_migration_fallback !== false ? 'selected' : ''}>enabled</option>
              <option value="0" ${p.allow_migration_fallback === false ? 'selected' : ''}>disabled</option>
            </select>
          </label>
          <label>CephFS mountpoint
            <input class="props-input" id="admin-ceph-mount" value="${_esc(ceph.mountpoint || p.root || '/var/lib/docker/dnlab-backups')}">
          </label>
          <label>CephFS fstype
            <input class="props-input" id="admin-ceph-fstype" value="${_esc(ceph.expected_fstype || 'ceph')}">
          </label>
          <label>shared marker
            <input class="props-input" id="admin-ceph-marker" value="${_esc(ceph.marker || '.dnlab-cephfs')}">
          </label>
          <label><input id="admin-ceph-require-marker" type="checkbox" ${ceph.require_shared_marker !== false ? 'checked' : ''}> require shared marker</label>
        </div>
      </section>
    `;
  }

  function _followRabbitBlock(r) {
    return `
      <section class="admin-section">
        <h3>Follow the Rabbit</h3>
        <div class="admin-grid">
          <label>max sessions
            <input class="props-input" id="admin-rabbit-max-sessions" type="number" min="0" max="32" value="${_esc(r.max_sessions ?? 1)}">
          </label>
        </div>
      </section>
    `;
  }

  function _hostsInfrastructureBlocks(cfg) {
    const infra = cfg.data.extra_infrastructure || {};
    const top = cfg.data.extra_top_level || {};
    const jh = infra.jumphost_net || {};
    const web = infra.webui_ports || {};
    const rn = infra.realnet || {};
    const mgmt = (top.defaults || {}).mgmt || {};
    const sync = top.image_sync || {};
    const cleanup = top.lab_cleanup || {};
    const lines = value => Array.isArray(value) ? value.join('\n') : '';
    return `
      <section class="admin-section"><h3>Distributed underlay</h3><div class="admin-grid">
        <label>underlay interface<input class="props-input" id="admin-underlay-iface" value="${_esc(infra.underlay_iface || 'eth0')}"></label>
      </div></section>
      <section class="admin-section"><h3>Jumphost network</h3><div class="admin-grid">
        <label>network<input class="props-input" id="admin-jh-network" value="${_esc(jh.network || 'dnlab-jumphost')}"></label>
        <label>bridge<input class="props-input" id="admin-jh-bridge" value="${_esc(jh.bridge || 'br-dnlab-jh')}"></label>
        <label>IPv4 subnet<input class="props-input" id="admin-jh-subnet" value="${_esc(jh.ipv4_subnet || '192.168.100.0/24')}"></label>
        <label>IPv4 gateway<input class="props-input" id="admin-jh-gateway" value="${_esc(jh.ipv4_gw || '192.168.100.1')}"></label>
        <label>SSH port range<input class="props-input" id="admin-jh-ports" value="${_esc(jh.ssh_port_range || '2200-2299')}"></label>
        <label>SSH bind IP<input class="props-input" id="admin-jh-bind" value="${_esc(jh.ssh_bind_ip || '0.0.0.0')}"></label>
      </div></section>
      <section class="admin-section"><h3>VD Web UI ports</h3><div class="admin-grid">
        <label>port range<input class="props-input" id="admin-webui-ports" value="${_esc(web.port_range || '8443-8999')}"></label>
        <label>bind IP<input class="props-input" id="admin-webui-bind" value="${_esc(web.bind_ip || '127.0.0.1')}"></label>
      </div></section>
      <section class="admin-section"><h3>RealNet infrastructure</h3><p>Route-reflector BGP settings remain on the dedicated RealNet BGP page.</p><div class="admin-grid">
        <label>network<input class="props-input" id="admin-rn-network" value="${_esc(rn.network || 'dnlab-realnet')}"></label>
        <label>bridge<input class="props-input" id="admin-rn-bridge" value="${_esc(rn.bridge || 'br-dnlab-rn')}"></label>
        <label>IPv4 subnet<input class="props-input" id="admin-rn-subnet" value="${_esc(rn.ipv4_subnet || '192.168.101.0/24')}"></label>
        <label>IPv4 gateway<input class="props-input" id="admin-rn-gateway" value="${_esc(rn.ipv4_gw || '192.168.101.1')}"></label>
        <label>router image<input class="props-input" id="admin-rn-image" value="${_esc(rn.image || '')}"></label>
        <label>WAN interface<input class="props-input" id="admin-rn-wan-iface" value="${_esc(rn.wan_iface || '')}"></label>
      </div></section>
      <section class="admin-section"><h3>Management defaults</h3><div class="admin-grid">
        <label>IPv4 subnet<input class="props-input" id="admin-mgmt-subnet" value="${_esc(mgmt.ipv4_subnet || '172.20.0.0/24')}"></label>
        <label>IPv4 gateway<input class="props-input" id="admin-mgmt-gateway" value="${_esc(mgmt.ipv4_gw || '172.20.0.1')}"></label>
      </div></section>
      <section class="admin-section"><h3>Image sync</h3><div class="admin-grid">
        <label><input id="admin-sync-enabled" type="checkbox" ${sync.enabled !== false ? 'checked' : ''}> enabled</label>
        <label>interval seconds<input class="props-input" id="admin-sync-interval" type="number" min="30" value="${_esc(sync.interval_seconds ?? 300)}"></label>
        <label>include (one pattern per line)<textarea class="props-input" id="admin-sync-include">${_esc(lines(sync.include || ['*']))}</textarea></label>
        <label>exclude (one pattern per line)<textarea class="props-input" id="admin-sync-exclude">${_esc(lines(sync.exclude || ['dnlab-jumphost', 'dnlab-dns', 'dnlab-realnet-router', 'dnlab-realnet-rr', 'postgres', '<none>:<none>']))}</textarea></label>
      </div></section>
      <section class="admin-section"><h3>Lab cleanup</h3><div class="admin-grid">
        <label><input id="admin-cleanup-enabled" type="checkbox" ${cleanup.enabled !== false ? 'checked' : ''}> enabled</label>
        <label><input id="admin-cleanup-dry-run" type="checkbox" ${cleanup.dry_run ? 'checked' : ''}> dry run</label>
        <label>interval seconds<input class="props-input" id="admin-cleanup-interval" type="number" min="30" value="${_esc(cleanup.interval_seconds ?? 300)}"></label>
        <label>grace seconds<input class="props-input" id="admin-cleanup-grace" type="number" min="0" value="${_esc(cleanup.grace_seconds ?? 600)}"></label>
      </div></section>
    `;
  }

  async function _saveHostsConfig(cfg) {
    const rows = [..._content.querySelectorAll('.admin-host-row')];
    const hosts = rows.map(row => ({
      name: row.querySelector('.admin-host-name').value.trim(),
      host: row.querySelector('.admin-host-host').value.trim(),
      ssh_user: row.querySelector('.admin-host-user').value.trim() || 'root',
      ssh_key: row.querySelector('.admin-host-key').value.trim() || null,
      extra: row.dataset.master === '1' ? (cfg.data.master.extra || {}) : ((cfg.data.workers || []).find(w => w.name === row.querySelector('.admin-host-name').value.trim())?.extra || {}),
    }));
    cfg.data.master = hosts.find((_, i) => rows[i].dataset.master === '1') || hosts[0];
    cfg.data.workers = hosts.filter((_, i) => rows[i].dataset.master !== '1');
    cfg.data.extra_infrastructure = cfg.data.extra_infrastructure || {};
    const value = id => _content.querySelector(id)?.value.trim() || '';
    const lines = id => value(id).split(/\n/).map(v => v.trim()).filter(Boolean);
    cfg.data.extra_infrastructure.underlay_iface = value('#admin-underlay-iface') || 'eth0';
    cfg.data.extra_infrastructure.jumphost_net = {
      network: value('#admin-jh-network'), bridge: value('#admin-jh-bridge'),
      ipv4_subnet: value('#admin-jh-subnet'), ipv4_gw: value('#admin-jh-gateway'),
      ssh_port_range: value('#admin-jh-ports'), ssh_bind_ip: value('#admin-jh-bind'),
    };
    cfg.data.extra_infrastructure.webui_ports = {
      port_range: value('#admin-webui-ports'), bind_ip: value('#admin-webui-bind'),
    };
    cfg.data.extra_infrastructure.realnet = {
      ...(cfg.data.extra_infrastructure.realnet || {}),
      network: value('#admin-rn-network'), bridge: value('#admin-rn-bridge'),
      ipv4_subnet: value('#admin-rn-subnet'), ipv4_gw: value('#admin-rn-gateway'),
      ...(value('#admin-rn-image') ? { image: value('#admin-rn-image') } : {}),
      wan_iface: value('#admin-rn-wan-iface'),
    };
    cfg.data.extra_top_level = cfg.data.extra_top_level || {};
    cfg.data.extra_top_level.defaults = { mgmt: {
      ipv4_subnet: value('#admin-mgmt-subnet'), ipv4_gw: value('#admin-mgmt-gateway'),
    }};
    cfg.data.extra_top_level.image_sync = {
      enabled: !!_content.querySelector('#admin-sync-enabled')?.checked,
      include: lines('#admin-sync-include'), exclude: lines('#admin-sync-exclude'),
      interval_seconds: Number(_content.querySelector('#admin-sync-interval')?.value || 300),
    };
    cfg.data.extra_top_level.lab_cleanup = {
      enabled: !!_content.querySelector('#admin-cleanup-enabled')?.checked,
      dry_run: !!_content.querySelector('#admin-cleanup-dry-run')?.checked,
      interval_seconds: Number(_content.querySelector('#admin-cleanup-interval')?.value || 300),
      grace_seconds: Number(_content.querySelector('#admin-cleanup-grace')?.value || 600),
    };
    cfg.data.extra_infrastructure.persistence = {
      backend: _content.querySelector('#admin-persist-backend')?.value || 'local-sticky',
      root: _content.querySelector('#admin-persist-root')?.value.trim() || '/var/lib/docker/dnlab-backups',
      allow_migration_fallback: (_content.querySelector('#admin-persist-fallback')?.value || '1') === '1',
      cephfs: {
        mountpoint: _content.querySelector('#admin-ceph-mount')?.value.trim() || '/var/lib/docker/dnlab-backups',
        expected_fstype: _content.querySelector('#admin-ceph-fstype')?.value.trim() || 'ceph',
        marker: _content.querySelector('#admin-ceph-marker')?.value.trim() || '.dnlab-cephfs',
        require_shared_marker: !!_content.querySelector('#admin-ceph-require-marker')?.checked,
      },
    };
    cfg.data.extra_top_level.follow_the_rabbit = {
      max_sessions: Number(_content.querySelector('#admin-rabbit-max-sessions')?.value || 1),
    };
    delete cfg.data.extra_top_level.plus;
    try {
      await API.Admin.writeConfigModel('hosts', cfg.data);
      showToast('Hosts saved', 'success');
      showModal('Restart may be required', `
        <p>The changes to <code>hosts.yml</code> have been saved.</p>
        <p>The dnlab-gui backend re-reads the file on every deploy, so lab operations pick up the changes automatically.</p>
        <p>Restart <code>dnlab-image-sync</code> (and any other long-lived sidecar) if you added or removed workers, so the new inventory is in effect.</p>
      `, [{ label: 'OK', class: 'btn-primary' }]);
      await _renderHostsConfig();
    } catch (e) { showToast(_apiErr('Save failed', e), 'error'); }
  }

  async function _renderRealNetBgpConfig() {
    let cfg;
    try { cfg = await API.Admin.readRealNetBgp(); }
    catch (e) { _content.innerHTML = _error('Cannot load RealNet BGP config', e); return; }
    const d = cfg.data || {};
    _content.innerHTML = `
      ${_configHead('RealNet BGP', cfg.path, cfg.exists, 'admin-realnet-bgp-reconcile', 'Reconcile RR', 'admin-realnet-bgp-save')}
      <section class="admin-section">
        <div class="admin-grid">
          <label>RR AS
            <input id="realnet-rr-as" class="props-input" type="number" min="1" max="4294967294" value="${_esc(d.rr_as || '')}">
          </label>
          <label>RR IP
            <input id="realnet-rr-ip" class="props-input" placeholder="10.0.0.10" value="${_esc(d.rr_ip || '')}">
          </label>
          <label>Host network
            <input id="realnet-host-net" class="props-input" placeholder="10.0.0.0/24" value="${_esc(d.host_net || '')}">
          </label>
          <label>Router AS pool
            <input id="realnet-router-as-pool" class="props-input" placeholder="64513-65534" value="${_esc(d.router_as_pool || '')}">
          </label>
          <label>Router IP pool
            <input id="realnet-router-ip-pool" class="props-input" placeholder="10.0.0.100-10.0.0.200" value="${_esc(d.router_ip_pool || '')}">
          </label>
          <label>RealNet node network pool
            <input id="realnet-network-pool" class="props-input" placeholder="100.64.0.0/10" value="${_esc(d.realnet_network_pool || '100.64.0.0/10')}">
          </label>
          <label>RR BGP password
            <div class="admin-inline-field">
              <input id="realnet-rr-password" class="props-input" type="text" readonly value="${_esc(d.rr_password || '')}">
              <button id="admin-realnet-bgp-generate-password" type="button" class="btn btn-sm">Generate</button>
            </div>
          </label>
        </div>
      </section>
      <div class="admin-form-actions">
        <button id="admin-realnet-bgp-save-bottom" class="btn btn-primary btn-sm">Save RealNet BGP</button>
      </div>
    `;
    const save = () => {
      if (!confirm('Save RealNet BGP settings to hosts.yml?')) return;
      _saveRealNetBgpConfig();
    };
    _content.querySelector('#admin-realnet-bgp-reconcile').addEventListener('click', _reconcileRealNetBgp);
    _content.querySelector('#admin-realnet-bgp-save').addEventListener('click', save);
    _content.querySelector('#admin-realnet-bgp-save-bottom').addEventListener('click', save);
    _content.querySelector('#admin-realnet-bgp-generate-password').addEventListener('click', _regenerateRealNetBgpPassword);
  }

  async function _saveRealNetBgpConfig() {
    const payload = {
      rr_as: Number(_content.querySelector('#realnet-rr-as')?.value || 0),
      rr_ip: _content.querySelector('#realnet-rr-ip')?.value.trim() || '',
      host_net: _content.querySelector('#realnet-host-net')?.value.trim() || '',
      router_as_pool: _content.querySelector('#realnet-router-as-pool')?.value.trim() || '',
      router_ip_pool: _content.querySelector('#realnet-router-ip-pool')?.value.trim() || '',
      realnet_network_pool: _content.querySelector('#realnet-network-pool')?.value.trim() || '100.64.0.0/10',
      rr_password: _content.querySelector('#realnet-rr-password')?.value.trim() || '',
    };
    try {
      await API.Admin.writeRealNetBgp(payload);
      showToast('RealNet BGP saved', 'success');
      await _renderRealNetBgpConfig();
    } catch (e) {
      showToast(_apiErr('Save failed', e), 'error');
    }
  }

  async function _regenerateRealNetBgpPassword() {
    if (!confirm('Regenerate the RR BGP password and reconcile the route reflector? Existing BGP sessions will be updated on next router deploy/reconcile.')) return;
    try {
      await API.Admin.regenerateRealNetBgpPassword();
      showToast('RR BGP password regenerated', 'success');
      await _renderRealNetBgpConfig();
    } catch (e) {
      showToast(_apiErr('Password generation failed', e), 'error');
    }
  }

  async function _reconcileRealNetBgp() {
    try {
      const result = await API.Admin.reconcileRealNetBgp();
      if (result.ok) {
        showToast('RealNet RR running', 'success');
      } else {
        showToast(result.reason || 'RealNet RR reconcile skipped', 'warn');
      }
    } catch (e) {
      showToast(_apiErr('RR reconcile failed', e), 'error');
    }
  }

  async function _renderDevicesConfig() {
    let cfg;
    try { cfg = await API.Admin.readConfigModel('devices'); }
    catch (e) { _content.innerHTML = _error('Cannot load devices.json', e); return; }
    _content.innerHTML = `
      ${_configHead('Devices', cfg.path, cfg.exists)}
      <div class="admin-device-tools">
        <button id="admin-vendor-add" class="btn btn-sm">Add vendor</button>
        <button id="admin-icon-add" class="btn btn-sm">Add type</button>
        <button id="admin-kind-add" class="btn btn-sm">Add kind</button>
        <button id="admin-devices-save" class="btn btn-primary btn-sm">Save</button>
      </div>
      <h3 class="admin-section-title">Vendors</h3>
      <table class="admin-table admin-config-table"><thead><tr><th>id</th><th>title</th><th>color</th><th></th></tr></thead><tbody id="admin-vendors-body">${(cfg.data.vendors || []).map(_vendorRow).join('')}</tbody></table>
      <h3 class="admin-section-title">Types</h3>
      <table class="admin-table admin-config-table"><thead><tr><th>type</th><th>icon path</th><th></th></tr></thead><tbody id="admin-icons-body">${(cfg.data.icons || []).map(_iconRow).join('')}</tbody></table>
      <h3 class="admin-section-title">Kinds</h3>
      <div id="admin-kinds-list" class="admin-kind-list">${_renderKindList(cfg)}</div>
      <div class="admin-form-actions">
        <button id="admin-devices-save-bottom" class="btn btn-primary btn-sm">Save devices</button>
      </div>
    `;
    _content.querySelector('#admin-vendor-add').addEventListener('click', () => { _content.querySelector('#admin-vendors-body').insertAdjacentHTML('beforeend', _vendorRow({ id: '', title: '', color: '#888888' })); _wireRemoveButtons(); });
    _content.querySelector('#admin-icon-add').addEventListener('click', () => { _content.querySelector('#admin-icons-body').insertAdjacentHTML('beforeend', _iconRow({ type: '', path: 'img/devices/router.svg' })); _wireRemoveButtons(); });
    _content.querySelector('#admin-kind-add').addEventListener('click', () => _openKindEditor(null, cfg));
    const confirmAndSaveDevices = () => {
      if (!confirm('Save device catalog to disk?')) return;
      _saveDevicesConfig(cfg);
    };
    _content.querySelector('#admin-devices-save').addEventListener('click', confirmAndSaveDevices);
    _content.querySelector('#admin-devices-save-bottom').addEventListener('click', confirmAndSaveDevices);
    _wireKindList(cfg);
    _wireRemoveButtons();
  }

  function _vendorRow(v) {
    return `<tr class="admin-vendor-row"><td><input class="props-input admin-vendor-id" value="${_esc(v.id)}"></td><td><input class="props-input admin-vendor-title" value="${_esc(v.title)}"></td><td><input type="color" class="admin-color admin-vendor-color" value="${_esc(v.color || '#888888')}"></td><td class="admin-actions"><button class="btn btn-xs admin-row-remove">Delete</button></td></tr>`;
  }

  function _iconRow(i) {
    return `<tr class="admin-icon-row"><td><input class="props-input admin-icon-type" value="${_esc(i.type)}"></td><td><input class="props-input admin-icon-path" value="${_esc(i.path)}"></td><td class="admin-actions"><button class="btn btn-xs admin-row-remove">Delete</button></td></tr>`;
  }

  function _renderKindList(cfg) {
    const kinds = [...(cfg.data.kinds || [])].sort((a, b) => String(a.kind || '').localeCompare(String(b.kind || '')));
    if (!kinds.length) {
      return '<p class="admin-muted">No kind configurato.</p>';
    }
    return kinds.map(k => _kindCard(k, cfg)).join('');
  }

  function _kindCard(k, cfg) {
    const vendor = _vendorById(cfg, k.vendor);
    const icon = _iconByType(cfg, k.type);
    const env = _kindEnv(k);
    const deploy = k.deploy_kind || k.kind;
    const imageMatch = (k.image_patterns || []).join(', ');
    return `
      <button type="button" class="admin-kind-card" data-kind="${_esc(k.kind)}">
        <span class="admin-kind-card-main">
          <span class="admin-kind-icon" style="background:${_esc(vendor.color || '#888888')}">
            ${icon ? `<img src="${_esc(icon.path)}" alt="">` : ''}
          </span>
          <span class="admin-kind-copy">
            <span class="admin-kind-name">${_esc(k.kind)}</span>
            <span class="admin-kind-label">${_esc(k.label || k.kind)}</span>
          </span>
        </span>
        <span class="admin-kind-badges">
          <span>${_esc(vendor.title || k.vendor || 'vendor')}</span>
          <span>${_esc(k.type || 'type')}</span>
          ${deploy !== k.kind ? `<span>deploy ${_esc(deploy)}</span>` : ''}
          ${imageMatch ? `<span>match ${_esc(imageMatch)}</span>` : ''}
          <span>${_esc(env.VCPU)} vCPU</span>
          <span>${_esc(env.RAM)} MiB</span>
          ${env.CLAB_MGMT_PASSTHROUGH ? '<span>mgmt passthrough</span>' : ''}
          ${(k.webui || []).length ? `<span>${(k.webui || []).length} Web UI</span>` : ''}
        </span>
      </button>
    `;
  }

  function _wireKindList(cfg) {
    _content.querySelectorAll('.admin-kind-card').forEach(card => {
      card.addEventListener('click', () => {
        const kind = (cfg.data.kinds || []).find(k => k.kind === card.dataset.kind);
        if (kind) _openKindEditor(kind, cfg);
      });
    });
  }

  function _refreshKindList(cfg) {
    const list = _content.querySelector('#admin-kinds-list');
    if (!list) return;
    list.innerHTML = _renderKindList(cfg);
    _wireKindList(cfg);
  }

  function _openKindEditor(kind, cfg) {
    _syncDeviceListsFromDom(cfg);
    const isNew = !kind;
    const draft = _cloneKind(kind || _newKindDraft(cfg));
    const body = document.createElement('div');
    body.className = 'admin-kind-editor';
    body.dataset.modalSize = 'wide';
    body.innerHTML = _kindEditorHtml(draft, cfg, isNew);
    showModal(isNew ? 'New kind' : `Kind ${draft.kind}`, body, [{ label: 'Close' }]);
    _wireKindEditor(body, cfg, draft, isNew);
  }

  function _syncDeviceListsFromDom(cfg) {
    if (!_content) return;
    const vendorRows = [..._content.querySelectorAll('.admin-vendor-row')];
    if (vendorRows.length) {
      const vendorExtra = Object.fromEntries((cfg.data.vendors || []).map(v => [v.id, v.extra || {}]));
      cfg.data.vendors = vendorRows.map(row => {
        const id = row.querySelector('.admin-vendor-id').value.trim();
        return {
          id,
          title: row.querySelector('.admin-vendor-title').value.trim(),
          color: row.querySelector('.admin-vendor-color').value,
          extra: vendorExtra[id] || {},
        };
      });
    }
    const iconRows = [..._content.querySelectorAll('.admin-icon-row')];
    if (iconRows.length) {
      cfg.data.icons = iconRows.map(row => ({
        type: row.querySelector('.admin-icon-type').value.trim(),
        path: row.querySelector('.admin-icon-path').value.trim(),
      }));
    }
  }

  function _kindEditorHtml(k, cfg, isNew) {
    const env = _kindEnv(k);
    const intf = _kindInterfaces(k);
    const extraJson = _extraForEditor(k);
    const patterns = (k.image_patterns || []).join(', ');
    const webui = (k.webui || []).map(w => `${w.scheme || 'https'}:${w.port || 443}${w.path || '/'} ${w.label || ''}`).join('; ');
    return `
      <div class="admin-kind-editor-grid">
        <fieldset class="props-fieldset">
          <legend>Identity</legend>
          <label>GUI kind<input id="kind-edit-id" class="props-input" value="${_esc(k.kind || '')}" placeholder="juniper_apstra"></label>
          <label>Label<input id="kind-edit-label" class="props-input" value="${_esc(k.label || '')}" placeholder="Apstra"></label>
          <label>Vendor<input id="kind-edit-vendor" class="props-input" value="${_esc(k.vendor || 'generic')}" list="kind-vendor-options"></label>
          <label>Type<input id="kind-edit-type" class="props-input" value="${_esc(k.type || 'router')}" list="kind-type-options"></label>
        </fieldset>
        <fieldset class="props-fieldset">
          <legend>Containerlab</legend>
          <label>Deploy kind<input id="kind-edit-deploy" class="props-input" value="${_esc(k.deploy_kind || '')}" placeholder="same as GUI kind"></label>
          <label>Image match<input id="kind-edit-patterns" class="props-input" value="${_esc(patterns)}" placeholder="juniper_apstra, apstra"></label>
          <label>Mgmt iface<input id="kind-edit-mgmt" class="props-input" value="${_esc(k.mgmt_iface || '')}" placeholder="eth0"></label>
        </fieldset>
        <fieldset class="props-fieldset">
          <legend>Interfaces</legend>
          <label>Linux fmt<input id="kind-if-linux" class="props-input" value="${_esc(intf.linux_fmt)}" placeholder="eth{n}"></label>
          <label>Vendor fmt<input id="kind-if-vendor" class="props-input" value="${_esc(intf.vendor_fmt)}" placeholder="Ethernet{n}"></label>
          <label>Count<input id="kind-if-count" class="props-input" type="number" min="0" max="256" step="1" value="${_esc(intf.count)}"></label>
        </fieldset>
        <fieldset class="props-fieldset admin-kind-resources">
          <legend>Resources</legend>
          ${_stepperHtml('kind-vcpu', 'vCPU', env.VCPU, 'vCPU')}
          ${_stepperHtml('kind-ram', 'RAM', env.RAM, 'MiB')}
          <label class="props-check admin-kind-mgmt-passthrough">
            <input id="kind-mgmt-passthrough" type="checkbox" ${env.CLAB_MGMT_PASSTHROUGH ? 'checked' : ''}>
            <span>MGMT passthrough</span>
          </label>
          <div class="admin-kind-step-control">
            <span>RAM step</span>
            <div class="props-segmented" role="radiogroup" aria-label="RAM step">
              ${[256, 512, 1024].map(step => `
                <label><input type="radio" name="kind-ram-step" value="${step}" ${step === 512 ? 'checked' : ''}><span>${step}</span></label>
              `).join('')}
            </div>
          </div>
        </fieldset>
        <fieldset class="props-fieldset">
          <legend>Web UI</legend>
          <label>Entries<input id="kind-edit-webui" class="props-input" value="${_esc(webui)}" placeholder="https:443/ WebUI"></label>
        </fieldset>
        <fieldset class="props-fieldset admin-kind-advanced">
          <legend>Advanced</legend>
          <label>Additional JSON<textarea id="kind-edit-extra" class="props-input admin-kind-extra" spellcheck="false">${_esc(extraJson)}</textarea></label>
        </fieldset>
      </div>
      <datalist id="kind-vendor-options">${(cfg.data.vendors || []).map(v => `<option value="${_esc(v.id)}"></option>`).join('')}</datalist>
      <datalist id="kind-type-options">${(cfg.data.icons || []).map(i => `<option value="${_esc(i.type)}"></option>`).join('')}</datalist>
      <div class="admin-kind-editor-actions">
        ${isNew ? '' : '<button type="button" id="kind-edit-delete" class="btn btn-danger btn-sm">Delete</button>'}
        <span class="admin-kind-editor-spacer"></span>
        <button type="button" id="kind-edit-cancel" class="btn btn-sm">Cancel</button>
        <button type="button" id="kind-edit-save" class="btn btn-primary btn-sm">${isNew ? 'Add kind' : 'Save kind'}</button>
      </div>
    `;
  }

  function _stepperHtml(id, label, value, unit) {
    return `
      <div class="admin-kind-stepper" data-stepper="${id}">
        <span>${label}</span>
        <div>
          <button type="button" class="btn btn-xs" data-step="${id}" data-dir="-1">-</button>
          <output id="${id}" data-value="${_esc(value)}">${_esc(value)} ${unit}</output>
          <button type="button" class="btn btn-xs" data-step="${id}" data-dir="1">+</button>
        </div>
      </div>
    `;
  }

  function _wireKindEditor(body, cfg, draft, isNew) {
    body.querySelectorAll('[data-step]').forEach(btn => {
      btn.addEventListener('click', () => _adjustResource(body, btn.dataset.step, Number(btn.dataset.dir || 1)));
    });
    body.querySelector('#kind-edit-cancel')?.addEventListener('click', hideModal);
    body.querySelector('#kind-edit-delete')?.addEventListener('click', async () => {
      if (!confirm(`Permanently delete kind "${draft.kind}"? A backup .bak is kept on disk.`)) return;
      const previous = cfg.data.kinds || [];
      cfg.data.kinds = previous.filter(k => k.kind !== draft.kind);
      const ok = await _saveDevicesConfig(cfg);
      if (!ok) { cfg.data.kinds = previous; return; }
      _refreshKindList(cfg);
      hideModal();
    });
    body.querySelector('#kind-edit-save').addEventListener('click', async () => {
      const next = _collectKindEditor(body, draft);
      if (!next) return;
      const oldKind = isNew ? null : draft.kind;
      const duplicate = (cfg.data.kinds || []).some(k => k.kind === next.kind && k.kind !== oldKind);
      if (duplicate) {
        showToast(`Kind already exists: ${next.kind}`, 'warn');
        return;
      }
      const prompt = isNew
        ? `Add new kind "${next.kind}" to the device catalog?`
        : `Save changes to kind "${next.kind}" and write the catalog to disk?`;
      if (!confirm(prompt)) return;
      const previous = cfg.data.kinds || [];
      if (isNew) cfg.data.kinds = [...previous, next];
      else cfg.data.kinds = previous.map(k => k.kind === oldKind ? next : k);
      const ok = await _saveDevicesConfig(cfg);
      if (!ok) { cfg.data.kinds = previous; return; }
      _refreshKindList(cfg);
      hideModal();
    });
  }

  function _collectKindEditor(body, original) {
    const kind = body.querySelector('#kind-edit-id').value.trim();
    const label = body.querySelector('#kind-edit-label').value.trim();
    const vendor = body.querySelector('#kind-edit-vendor').value.trim();
    const type = body.querySelector('#kind-edit-type').value.trim();
    if (!kind || !label || !vendor || !type) {
      showToast('GUI kind, label, vendor and type are required', 'warn');
      return null;
    }
    let extra;
    try {
      extra = JSON.parse(body.querySelector('#kind-edit-extra').value || '{}');
      if (!extra || Array.isArray(extra) || typeof extra !== 'object') throw new Error('not an object');
    } catch (_) {
      showToast('Advanced JSON non valido', 'error');
      return null;
    }
    const baseEnv = (extra.env && !Array.isArray(extra.env) && typeof extra.env === 'object') ? extra.env : {};
    extra.env = {
      ...baseEnv,
      VCPU: String(_readOutput(body, 'kind-vcpu', 1)),
      RAM: String(_readOutput(body, 'kind-ram', 2048)),
    };
    if (body.querySelector('#kind-mgmt-passthrough')?.checked) {
      extra.env.CLAB_MGMT_PASSTHROUGH = 'true';
    } else {
      delete extra.env.CLAB_MGMT_PASSTHROUGH;
    }
    extra.interfaces = {
      linux_fmt: body.querySelector('#kind-if-linux').value.trim() || 'eth{n}',
      vendor_fmt: body.querySelector('#kind-if-vendor').value.trim() || 'eth{n}',
      count: Math.max(0, Math.min(256, Number(body.querySelector('#kind-if-count').value || 8) || 8)),
    };
    return {
      kind,
      label,
      vendor,
      type,
      deploy_kind: body.querySelector('#kind-edit-deploy').value.trim() || null,
      image_patterns: _parsePatternList(body.querySelector('#kind-edit-patterns').value),
      mgmt_iface: body.querySelector('#kind-edit-mgmt').value.trim() || null,
      webui: _parseWebuiList(body.querySelector('#kind-edit-webui').value),
      extra,
    };
  }

  function _adjustResource(body, id, dir) {
    const out = body.querySelector(`#${id}`);
    if (!out) return;
    if (id === 'kind-vcpu') {
      const next = Math.max(1, Math.min(64, _readOutput(body, id, 1) + dir));
      _writeOutput(out, next, 'vCPU');
      return;
    }
    const step = Number(body.querySelector('[name="kind-ram-step"]:checked')?.value || 512);
    const current = _roundForQemuRam(_readOutput(body, id, 2048), step);
    const next = Math.max(256, current + (dir * step));
    _writeOutput(out, next, 'MiB');
  }

  function _roundForQemuRam(value, step) {
    const safeStep = [256, 512, 1024].includes(step) ? step : 512;
    const safeValue = Math.max(256, Number(value) || 2048);
    return Math.max(256, Math.round(safeValue / safeStep) * safeStep);
  }

  function _readOutput(body, id, fallback) {
    return Number(body.querySelector(`#${id}`)?.dataset.value || fallback);
  }

  function _writeOutput(out, value, unit) {
    out.dataset.value = String(value);
    out.textContent = `${value} ${unit}`;
  }

  function _newKindDraft(cfg) {
    return {
      kind: '',
      label: '',
      vendor: (cfg.data.vendors || []).find(v => v.id === 'generic') ? 'generic' : ((cfg.data.vendors || [])[0]?.id || 'generic'),
      type: (cfg.data.icons || []).find(i => i.type === 'router') ? 'router' : ((cfg.data.icons || [])[0]?.type || 'router'),
      deploy_kind: null,
      image_patterns: [],
      mgmt_iface: 'eth0',
      webui: [],
      extra: {
        env: { VCPU: '1', RAM: '2048', CLAB_MGMT_PASSTHROUGH: 'true' },
        interfaces: { linux_fmt: 'eth{n}', vendor_fmt: 'eth{n}', count: 8 },
      },
    };
  }

  function _cloneKind(kind) {
    return JSON.parse(JSON.stringify(kind || {}));
  }

  function _kindEnv(kind) {
    const env = (kind.extra && kind.extra.env && typeof kind.extra.env === 'object') ? kind.extra.env : {};
    return {
      VCPU: String(Math.max(1, Number(env.VCPU || env.vcpu || 1) || 1)),
      RAM: String(_roundForQemuRam(Number(env.RAM || env.ram || 2048), 512)),
      CLAB_MGMT_PASSTHROUGH: String(env.CLAB_MGMT_PASSTHROUGH ?? 'true').toLowerCase() === 'true',
    };
  }

  function _kindInterfaces(kind) {
    const interfaces = (kind.extra && kind.extra.interfaces && typeof kind.extra.interfaces === 'object')
      ? kind.extra.interfaces
      : {};
    return {
      linux_fmt: String(interfaces.linux_fmt || 'eth{n}'),
      vendor_fmt: String(interfaces.vendor_fmt || interfaces.pattern || 'eth{n}'),
      count: String(Math.max(0, Math.min(256, Number(interfaces.count || 8) || 8))),
    };
  }

  function _extraForEditor(kind) {
    const extra = _cloneKind(kind.extra || {});
    if (extra.env && typeof extra.env === 'object') {
      extra.env = { ...extra.env };
      delete extra.env.VCPU;
      delete extra.env.vcpu;
      delete extra.env.RAM;
      delete extra.env.ram;
      delete extra.env.CLAB_MGMT_PASSTHROUGH;
      if (Object.keys(extra.env).length === 0) delete extra.env;
    }
    delete extra.interfaces;
    return JSON.stringify(extra, null, 2);
  }

  function _vendorById(cfg, id) {
    return (cfg.data.vendors || []).find(v => v.id === id) || { id, title: id || 'Other', color: '#888888' };
  }

  function _iconByType(cfg, type) {
    return (cfg.data.icons || []).find(i => i.type === type) || null;
  }

  async function _saveDevicesConfig(cfg) {
    _syncDeviceListsFromDom(cfg);
    try {
      await API.Admin.writeConfigModel('devices', cfg.data);
      showToast('Device catalog saved', 'success');
      showModal('Catalog updated', `
        <p>The device catalog has been saved and applied live by the backend.</p>
        <p>Reload any other open dnlab-gui tab to see the new kinds, vendors and icons.</p>
      `, [{ label: 'OK', class: 'btn-primary' }]);
      await _renderDevicesConfig();
      return true;
    } catch (e) {
      showToast(_apiErr('Save failed', e), 'error');
      return false;
    }
  }

  function _parsePatternList(value) {
    return String(value || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  function _parseWebuiList(value) {
    return String(value || '').split(';').map(s => s.trim()).filter(Boolean).map(item => {
      const m = item.match(/^(https?):(\d+)(\/\S*)?(?:\s+(.+))?$/);
      if (!m) return { scheme: 'https', port: Number(item) || 443, path: '/', label: 'Web UI' };
      return { scheme: m[1], port: Number(m[2]), path: m[3] || '/', label: m[4] || 'Web UI' };
    });
  }

  function _configHead(title, path, exists, addId, addLabel, saveId) {
    return `
      <div class="admin-panel-head">
        <div><h2>${_esc(title)}</h2><p><code>${_esc(path)}</code>${exists ? '' : ' · nuovo file'}</p></div>
        ${addId || saveId ? `<div class="admin-head-actions">
          ${addId ? `<button id="${addId}" class="btn btn-sm">${addLabel}</button>` : ''}
          ${saveId ? `<button id="${saveId}" class="btn btn-primary btn-sm">Save</button>` : ''}
        </div>` : ''}
      </div>
    `;
  }

  function _wireRemoveButtons() {
    _content.querySelectorAll('.admin-row-remove').forEach(btn => {
      if (btn.dataset.wired) return;
      btn.dataset.wired = '1';
      btn.addEventListener('click', () => btn.closest('tr')?.remove());
    });
  }

  // Images
  async function _renderImages() {
    let meta;
    let sync;
    try {
      [meta, sync] = await Promise.all([
        API.Admin.imageBuildKinds(),
        API.Multinode.imageSyncStatus().catch(() => ({ available: false })),
      ]);
    } catch (e) {
      _content.innerHTML = _error('Cannot load image-build', e);
      return;
    }
    const buildKinds = _imageBuildKindRows(meta);
    _content.innerHTML = `
      <div class="admin-panel-head">
        <div>
          <h2>Devices & Images</h2>
        </div>
        <div class="admin-panel-head-actions">
          <button id="admin-jobs-refresh" class="btn btn-sm">Refresh jobs</button>
          <button id="admin-jobs-clear" class="btn btn-sm">Clear jobs</button>
        </div>
      </div>
      <div class="admin-image-grid">
        <section>
          <h3>New build</h3>
          <label>Kind
            <select id="admin-build-kind" class="props-input">
              ${buildKinds.map(k => `<option value="${_esc(k.kind)}">${_esc(k.kind)} · ${_esc(_kindBuildLabel(k))}</option>`).join('')}
            </select>
          </label>
          <label id="admin-build-upload-label">Upload image
            <input id="admin-build-upload" class="props-input" type="file">
          </label>
          <p id="admin-build-format-hint" class="admin-muted"></p>
          <div id="admin-build-progress" class="admin-build-progress" hidden>
            <div class="admin-build-progress-bar"><span id="admin-build-progress-fill"></span></div>
            <span id="admin-build-progress-label" class="admin-muted"></span>
          </div>
          <button id="admin-build-start" class="btn btn-primary btn-sm" ${meta.available ? '' : 'disabled'}>Start build</button>
        </section>
        <section>
          <h3>Buildable kinds</h3>
          <div class="admin-chip-list">${buildKinds.map(k => `<span>${_esc(k.kind)} · ${_esc(_kindBuildLabel(k))}</span>`).join('') || '<em>none</em>'}</div>
        </section>
        <section>
          <h3>Image sync</h3>
          <p id="admin-sync-summary" class="admin-muted">${_imageSyncSummary(sync)}</p>
          <button id="admin-sync-reconcile" class="btn btn-sm">Reconcile now</button>
        </section>
      </div>
      <div id="admin-jobs"></div>
    `;
    _buildKindsByName = Object.fromEntries(buildKinds.map(k => [k.kind, k]));
    _content.querySelector('#admin-build-start').addEventListener('click', _startBuild);
    _content.querySelector('#admin-build-kind').addEventListener('change', _updateFormatHint);
    _content.querySelector('#admin-jobs-refresh').addEventListener('click', _renderJobs);
    _content.querySelector('#admin-jobs-clear').addEventListener('click', _clearJobs);
    _content.querySelector('#admin-sync-reconcile').addEventListener('click', _triggerReconcile);
    _updateFormatHint();
    await _renderJobs();
    _jobsTimer = setInterval(_renderJobs, 3000);
  }

  function _imageBuildKindRows(meta) {
    if (Array.isArray(meta?.kinds) && meta.kinds.length) {
      return meta.kinds.map(k => ({
        kind: k.kind,
        patchable: Boolean(k.patchable),
        persistent: Boolean(k.persistent || k.patchable),
        builder: k.builder || (k.patchable ? 'dnlab-image-build' : 'vrnetlab-make'),
        vrnetlab_dir: k.vrnetlab_dir || null,
        image_globs: Array.isArray(k.image_globs) ? k.image_globs : [],
        image_examples: Array.isArray(k.image_examples) ? k.image_examples : [],
        source_required: k.source_required !== false,
      })).sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
    }
    return (meta?.patchable || []).map(kind => ({
      kind,
      patchable: true,
      persistent: true,
      builder: 'dnlab-image-build',
      vrnetlab_dir: null,
      image_globs: [],
      image_examples: [],
      source_required: true,
    }));
  }

  function _kindBuildLabel(kind) {
    return kind.persistent ? 'persistent' : 'plain vrnetlab';
  }

  function _imageSyncSummary(sync) {
    if (!sync || !sync.available) return 'image-sync daemon unavailable';
    const state = sync.state || {};
    const status = state.status || state.phase || 'available';
    const updated = state.updated_at || state.last_run_at || state.timestamp || '';
    return updated ? `${status} · ${updated}` : status;
  }

  async function _triggerReconcile() {
    const btn = _content?.querySelector('#admin-sync-reconcile');
    if (btn) btn.disabled = true;
    try {
      await API.Multinode.imageSyncReconcile();
      showToast('Image-sync reconcile requested', 'success');
      await _refreshSyncSummary();
    } catch (e) {
      showToast(_apiErr('Reconcile failed', e), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function _refreshSyncSummary() {
    const el = _content?.querySelector('#admin-sync-summary');
    if (!el) return;
    const sync = await API.Multinode.imageSyncStatus().catch(() => ({ available: false }));
    el.textContent = _imageSyncSummary(sync);
  }

  async function _clearJobs() {
    const btn = _content?.querySelector('#admin-jobs-clear');
    if (btn) btn.disabled = true;
    try {
      const res = await API.Admin.clearImageBuildJobs();
      showToast(`Cleared ${res?.removed ?? 0} build job(s)`, 'success');
      await _renderJobs();
    } catch (e) {
      showToast(_apiErr('Clear jobs failed', e), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function _selectedBuildKind() {
    const sel = _content?.querySelector('#admin-build-kind');
    return sel ? _buildKindsByName[sel.value] : null;
  }

  function _updateFormatHint() {
    const hint = _content?.querySelector('#admin-build-format-hint');
    if (!hint) return;
    const selected = _selectedBuildKind() || {};
    const upload = _content?.querySelector('#admin-build-upload');
    const uploadLabel = _content?.querySelector('#admin-build-upload-label');
    const sourceRequired = selected.source_required !== false;
    if (upload) {
      upload.disabled = !sourceRequired;
      if (!sourceRequired) upload.value = '';
    }
    if (uploadLabel) uploadLabel.firstChild.textContent = sourceRequired ? 'Upload image\n            ' : 'Source-free build\n            ';
    const globs = selected.image_globs || [];
    if (upload) upload.accept = sourceRequired && globs.length ? globs.join(",") : "";
    const examples = selected.image_examples || [];
    const parts = [];
    if (!sourceRequired) parts.push('No upload required; built from the managed vrnetlab source');
    if (sourceRequired && globs.length) parts.push(`Expected format: ${globs.join(' ')}`);
    if (examples.length) parts.push(`Example: ${examples.join(', ')}`);
    hint.textContent = parts.join(' · ');
  }

  function _matchesGlob(name, globs) {
    if (!globs || !globs.length) return true;
    return globs.some(g => {
      const re = new RegExp('^' + g.split('*').map(p =>
        p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i');
      return re.test(name);
    });
  }

  function _setUploadProgress(state, text) {
    const box = _content?.querySelector('#admin-build-progress');
    const fill = _content?.querySelector('#admin-build-progress-fill');
    const label = _content?.querySelector('#admin-build-progress-label');
    if (!box) return;
    if (state === null) { box.hidden = true; return; }
    box.hidden = false;
    if (fill) {
      fill.style.width = (state === null || state < 0) ? '100%' : `${state}%`;
      fill.classList.toggle('indeterminate', state < 0);
    }
    if (label) label.textContent = text || '';
  }

  async function _startBuild() {
    const start = _content.querySelector('#admin-build-start');
    const upload = _content.querySelector('#admin-build-upload');
    const file = upload?.files?.[0] || null;
    const selected = _selectedBuildKind() || {};
    const sourceRequired = selected.source_required !== false;
    if (sourceRequired && !file) {
      showToast('Upload an image to build', 'warn');
      return;
    }
    const kind = _content.querySelector('#admin-build-kind').value;
    const globs = selected.image_globs || [];
    if (file && !_matchesGlob(file.name, globs)) {
      _showBuildError(`'${file.name}' non corrisponde al formato atteso (${globs.join(' ')})`);
      return;
    }
    start.disabled = true;
    try {
      if (!sourceRequired) {
        _setUploadProgress(-1, 'Building…');
        await API.Admin.startImageBuild({ kind, source_path: null });
        showToast('Build started', 'success');
        await _renderJobs();
        return;
      }
      await API.Admin.validateImageBuildFilename({ kind, filename: file.name });
      const form = new FormData();
      form.append('file', file);
      _setUploadProgress(0, 'Uploading… 0%');
      const saved = await API.Admin.uploadImageBuildSource(form, (p) => {
        if (p.percent === null) _setUploadProgress(-1, 'Uploading…');
        else _setUploadProgress(p.percent, `Uploading… ${p.percent}%`);
      });
      _setUploadProgress(-1, 'Building…');
      await API.Admin.startImageBuild({ kind, source_path: saved.source_path });
      showToast('Build started', 'success');
      if (upload) upload.value = '';
      await _renderJobs();
    } catch (e) {
      _showBuildError(_apiErr('Build not started', e));
    } finally {
      _setUploadProgress(null);
      start.disabled = false;
    }
  }

  async function _renderJobs() {
    const box = _content?.querySelector('#admin-jobs');
    if (!box) return;
    let jobs;
    try { jobs = await API.Admin.imageBuildJobs(); }
    catch (e) { box.innerHTML = _error('Job non disponibili', e); return; }
    box.innerHTML = `
      <h3>Build jobs</h3>
      ${jobs.map(j => `
        <article class="admin-job">
          <div><strong>${_esc(j.kind)}</strong> <span class="admin-status admin-status-${_esc(j.status)}">${_esc(j.status)}</span></div>
          <div class="admin-muted">${_esc(j.source_path)}${j.returncode === null ? '' : ` · rc=${j.returncode}`}</div>
          <pre>${_esc((j.log || []).slice(-80).join('\n'))}</pre>
        </article>
      `).join('') || '<p class="admin-muted">No jobs yet.</p>'}
    `;
  }

  function _error(title, e) {
    return `<div class="admin-error"><strong>${_esc(title)}</strong><pre>${_esc(e?.message || e)}</pre></div>`;
  }

  function _showBuildError(message) {
    showModal('Build not started', `<div class="admin-build-error-text">${_esc(message)}</div>`, [{ label: 'Close' }]);
  }

  function _apiErr(prefix, e) {
    const raw = String(e?.message || e || '');
    const m = raw.match(/^\d+:\s*(.*)$/s);
    let detail = m ? m[1] : raw;
    try {
      const parsed = JSON.parse(detail);
      if (parsed && parsed.detail !== undefined) {
        detail = typeof parsed.detail === 'string' ? parsed.detail : JSON.stringify(parsed.detail);
      }
    } catch (_) {}
    return `${prefix}: ${detail}`;
  }

  function _fmtDate(value) {
    try { return new Date(value).toLocaleString(); } catch (_) { return value || '-'; }
  }

  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  return { init, show };
})();
