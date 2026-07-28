/**
 * REST API client for the dNLab GUI backend.
 *
 * Post-PR4b: every lab-scoped endpoint takes a UUID. Callers that know
 * the lab by display name should first resolve it via Labs.list() or
 * cache the id once it's opened — no resolver endpoint on purpose, the
 * listing is cheap and DB-driven.
 *
 * Auth: the backend issues a `dnlab_session` cookie on POST /api/auth/login.
 * `fetch` credentials default to same-origin, so browser automatically
 * re-sends it. On 401 this module dispatches a DOM `auth:unauthorized`
 * event so the shell (app.js) can force the login overlay.
 */
const API = (() => {
  const BASE = '';

  function _raise401() {
    // Dispatched to the window so any shell that cares can react. App
    // shell listens and shows the login overlay.
    window.dispatchEvent(new CustomEvent('auth:unauthorized'));
  }

  async function request(method, path, body = null, opts = {}) {
    const init = {
      method,
      credentials: 'same-origin',
      headers: opts.headers || { 'Content-Type': 'application/json' },
    };
    if (body !== null && body !== undefined) {
      init.body = init.headers['Content-Type'] === 'application/json'
        ? JSON.stringify(body) : body;
    }
    const res = await fetch(BASE + path, init);
    if (res.status === 401) {
      _raise401();
      throw new Error('401: not authenticated');
    }
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`${res.status}: ${err}`);
    }
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  // Multipart upload with progress reporting. `fetch` cannot observe upload
  // progress, so large image uploads use XHR to surface a status bar.
  // `onProgress` receives { loaded, total, percent } (percent null if the
  // length is not computable).
  function upload(path, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', BASE + path, true);
      xhr.withCredentials = true;
      if (typeof onProgress === 'function') {
        xhr.upload.onprogress = (e) => {
          onProgress({
            loaded: e.loaded,
            total: e.total,
            percent: e.lengthComputable ? Math.round((e.loaded / e.total) * 100) : null,
          });
        };
      }
      xhr.onload = () => {
        if (xhr.status === 401) {
          _raise401();
          reject(new Error('401: not authenticated'));
          return;
        }
        if (xhr.status < 200 || xhr.status >= 300) {
          reject(new Error(`${xhr.status}: ${xhr.responseText}`));
          return;
        }
        const ct = xhr.getResponseHeader('content-type') || '';
        try {
          resolve(ct.includes('application/json') ? JSON.parse(xhr.responseText) : xhr.responseText);
        } catch (err) {
          reject(err);
        }
      };
      xhr.onerror = () => reject(new Error('network error during upload'));
      xhr.send(formData);
    });
  }

  // ── Auth ─────────────────────────────────────────────────────────────
  const Auth = {
    whoami: ()                => request('GET',  '/api/auth/whoami'),
    login:  (username, password) =>
      request('POST', '/api/auth/login', { username, password }),
    logout: ()                => request('POST', '/api/auth/logout'),
  };

  // ── Labs (lifecycle + topology, keyed by UUID) ───────────────────────
  const Labs = {
    // Index + create
    list:    ()              => request('GET',  '/api/labs/'),
    running: ()              => request('GET',  '/api/labs/running'),
    create:  (name)          => request('POST', '/api/labs/', { name }),

    // Lifecycle
    status:     (id)         => request('GET',  `/api/labs/${id}/status`),
    statusLive: (id)         => request('GET',  `/api/labs/${id}/status-live`),
    plan:       (id)         => request('GET',  `/api/labs/${id}/plan`),
    deploy:     (id)         => request('POST', `/api/labs/${id}/deploy`),
    destroy:    (id)         => request('POST', `/api/labs/${id}/destroy`),
    remove:     (id)         => request('DELETE',`/api/labs/${id}`),
    syncImages: (id)         => request('POST', `/api/labs/${id}/sync-images`),
    jumphostPassword: (id)   => request('GET',  `/api/labs/${id}/jumphost/password`),

    // WebUI reverse proxy: open (or reuse) an SSH tunnel to the VD Web
    // UI. Returns {token, url, local_port, expires_in_s, label}.
    openWebUI:  (id, node, body) =>
      request('POST', `/api/labs/${id}/nodes/${encodeURIComponent(node)}/webui/open`, body),
    closeWebUI: (id, node, port) =>
      request('POST', `/api/labs/${id}/nodes/${encodeURIComponent(node)}/webui/close?port=${port}`),

    // Topology
    getTopology:  (id)       => request('GET',  `/api/labs/${id}/topology`),
    saveTopology: (id, topo) => request('PUT',  `/api/labs/${id}/topology`, topo),

    // Nodes
    addNode:    (id, node)          => request('POST',  `/api/labs/${id}/topology/nodes`, node),
    updateNode: (id, node, updates) => request('PATCH', `/api/labs/${id}/topology/nodes/${encodeURIComponent(node)}`, updates),
    removeNode: (id, node)          => request('DELETE',`/api/labs/${id}/topology/nodes/${encodeURIComponent(node)}`),
    wipeNodeDisk: (id, node)        => request('POST',  `/api/labs/${id}/nodes/${encodeURIComponent(node)}/wipe-disk`),
    listNodes: (id)                 => request('GET',   `/api/labs/${id}/nodes`),
    startNode: (id, node)           => request('POST',  `/api/labs/${id}/nodes/${encodeURIComponent(node)}/start`),
    stopNode:  (id, node)           => request('POST',  `/api/labs/${id}/nodes/${encodeURIComponent(node)}/stop`),
    restartNode: (id, node)         => request('POST',  `/api/labs/${id}/nodes/${encodeURIComponent(node)}/restart`),
    reconcileNode: (id, node)       => request('POST',  `/api/labs/${id}/nodes/${encodeURIComponent(node)}/reconcile`),
    reconcileLink: (id, link)       => request('POST',  `/api/labs/${id}/links/reconcile`, link),
    reconcileRealNet: (id, node)    => request('POST',  `/api/labs/${id}/realnet/${encodeURIComponent(node)}/reconcile`),
    setMgmtConfig: (id, mgmt) =>
      request('PUT', `/api/labs/${id}/topology/mgmt`, mgmt),
    setNodeMgmtIpv4: (id, node, mgmt_ipv4) =>
      request('PUT', `/api/labs/${id}/topology/nodes/${encodeURIComponent(node)}/mgmt-ipv4`, { mgmt_ipv4 }),
    setNodeMgmtIpv6: (id, node, mgmt_ipv6) =>
      request('PUT', `/api/labs/${id}/topology/nodes/${encodeURIComponent(node)}/mgmt-ipv6`, { mgmt_ipv6 }),
    importableRealNetRouters: (id) =>
      request('GET', `/api/labs/${id}/realnet/importable-routers`),
    realNetConfig: (id) =>
      request('GET', `/api/labs/${id}/realnet/config`),

    // Packet captures / Wireshark handler
    captureTargets: (id) =>
      request('GET', `/api/labs/${id}/captures/targets`),
    launchCapture: (id, payload) =>
      request('POST', `/api/labs/${id}/captures/launch`, payload),
    activeCaptures: (id) =>
      request('GET', `/api/labs/${id}/captures/active`),
    stopCapture: (id, sessionId) =>
      request('POST', `/api/labs/${id}/captures/${encodeURIComponent(sessionId)}/stop`),
    captureHandlerDownloadUrl: (platform = 'python') =>
      `/api/captures/handler/download?platform=${encodeURIComponent(platform)}`,

    followRabbitStart: (id, payload) =>
      request('POST', `/api/labs/${id}/follow-rabbit/sessions`, payload),
    followRabbitSessions: (id) =>
      request('GET', `/api/labs/${id}/follow-rabbit/sessions`),
    followRabbitStop: (id, sessionId) =>
      request('DELETE', `/api/labs/${id}/follow-rabbit/sessions/${encodeURIComponent(sessionId)}`),

    // Links
    addLink:    (id, link)   => request('POST', `/api/labs/${id}/topology/links`, link),
    removeLink: (id, src, tgt, srcIface, tgtIface) => {
      let url = `/api/labs/${id}/topology/links?source=${encodeURIComponent(src)}&target=${encodeURIComponent(tgt)}`;
      if (srcIface) url += `&source_iface=${encodeURIComponent(srcIface)}`;
      if (tgtIface) url += `&target_iface=${encodeURIComponent(tgtIface)}`;
      return request('DELETE', url);
    },
    setLinkStyle: (id, link, style) =>
      request('PATCH', `/api/labs/${id}/topology/links/style`, { ...link, style }),
    setCanvasAnnotations: (id, annotations) =>
      request('PUT', `/api/labs/${id}/topology/canvas-annotations`, { annotations }),

    // draw.io
    exportDrawio: (id) =>
      fetch(`/api/labs/${id}/topology/export-drawio`, { credentials: 'same-origin' })
        .then(r => { if (r.status === 401) { _raise401(); throw new Error('401'); } return r.text(); }),
    importDrawio: async (id, xmlString, filename = 'import.drawio') => {
      const blob = new Blob([xmlString], { type: 'application/xml' });
      const fd   = new FormData();
      fd.append('file', blob, filename);
      const res  = await fetch(`/api/labs/${id}/topology/import-drawio`, {
        method: 'POST',
        credentials: 'same-origin',
        body: fd,
      });
      if (res.status === 401) { _raise401(); throw new Error('401'); }
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
  };

  // ── Docker ───────────────────────────────────────────────────────────
  const Docker = {
    images:        () => request('GET', '/api/docker/images'),
    networkImages: () => request('GET', '/api/docker/images/network'),
    interfaces:    () => request('GET', '/api/docker/interfaces'),
  };

  // ── Multinode (site-wide) ────────────────────────────────────────────
  const Multinode = {
    hosts:              () => request('GET',  '/api/hosts/'),
    imageSyncStatus:    () => request('GET',  '/api/image-sync/status'),
    imageSyncReconcile: () => request('POST', '/api/image-sync/reconcile'),
    // Per-lab helpers (kept here for compatibility with plan_modal.js).
    plan:       (id) => Labs.plan(id),
    statusLive: (id) => Labs.statusLive(id),
  };

  // ── Users (admin-gated) ──────────────────────────────────────────────
  const Users = {
    list:         ()              => request('GET',   '/api/users/'),
    create:       (payload)       => request('POST',  '/api/users/', payload),
    patch:        (id, patch)     => request('PATCH', `/api/users/${id}`, patch),
    resetPassword:(id, password)  => request('POST',  `/api/users/${id}/password`, { password }),
    remove:       (id)            => request('DELETE',`/api/users/${id}`),
  };

  // ── Admin infrastructure ───────────────────────────────────────────
  const Admin = {
    readConfigModel: (key)         => request('GET',  `/api/admin/config/${key}/model`),
    writeConfigModel: (key, data)  => request('PUT',  `/api/admin/config/${key}/model`, { data }),
    imageBuildKinds: ()            => request('GET',  '/api/admin/image-build/kinds'),
    validateImageBuildFilename: (payload) => request('POST', '/api/admin/image-build/validate-filename', payload),
    uploadImageBuildSource: (body, onProgress) => upload('/api/admin/image-build/uploads', body, onProgress),
    imageBuildJobs:  ()            => request('GET',  '/api/admin/image-build/jobs'),
    clearImageBuildJobs: ()        => request('POST', '/api/admin/image-build/jobs/clear'),
    startImageBuild: (payload)     => request('POST', '/api/admin/image-build/jobs', payload),
    imageBuildJob:   (id)          => request('GET',  `/api/admin/image-build/jobs/${id}`),
    readRealNetBgp:  ()            => request('GET',  '/api/admin/realnet-bgp'),
    writeRealNetBgp: (payload)     => request('PUT',  '/api/admin/realnet-bgp', payload),
    regenerateRealNetBgpPassword: () => request('POST', '/api/admin/realnet-bgp/rr-password'),
    reconcileRealNetBgp: ()        => request('POST', '/api/admin/realnet-bgp/reconcile'),
  };

  return { Auth, Labs, Docker, Multinode, Users, Admin };
})();
