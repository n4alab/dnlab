const FollowRabbitModal = (() => {
  let _labId = null;
  let _nodes = [];
  let _timer = null;
  let _host = null;

  function open(labId, nodes, host = null) {
    close();
    _labId = labId;
    _nodes = (nodes || []).filter(n => n.kind !== '_real_net');
    _host = host || document.getElementById('rabbit-panel');
    _render();
    _poll();
    _timer = setInterval(_poll, 2500);
  }

  function close() {
    if (_timer) clearInterval(_timer);
    _timer = null;
  }

  async function _render() {
    const body = document.createElement('div');
    body.className = 'rabbit-modal';
    body.dataset.modalSize = 'wide';
    body.innerHTML = `
      <div class="rabbit-grid">
        <label>Source VD
          <select id="rabbit-source" class="props-input">
            ${_nodes.map(n => `<option value="${_esc(n.name)}">${_esc(n.name)}</option>`).join('')}
          </select>
        </label>
        <label>Source IP<input id="rabbit-src-ip" class="props-input" placeholder="192.0.2.10"></label>
        <label>Destination IP<input id="rabbit-dst-ip" class="props-input" placeholder="198.51.100.20"></label>
        <label>Protocol
          <select id="rabbit-proto" class="props-input">
            <option value="">any</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
            <option value="icmp">icmp</option>
            <option value="icmp6">icmp6</option>
          </select>
        </label>
        <label>Source port<input id="rabbit-src-port" class="props-input" type="number" min="1" max="65535"></label>
        <label>Destination port<input id="rabbit-dst-port" class="props-input" type="number" min="1" max="65535"></label>
        <label>Timeout<input id="rabbit-timeout" class="props-input" type="number" min="5" max="600" value="60"></label>
      </div>
      <div class="rabbit-actions">
        <button id="rabbit-start" class="btn btn-primary btn-sm">Start</button>
        <button id="rabbit-refresh" class="btn btn-sm">Refresh</button>
      </div>
      <div id="rabbit-sessions" class="rabbit-sessions"></div>
    `;
    if (!_host) return;
    _host.replaceChildren(body);
    body.querySelector('#rabbit-start').addEventListener('click', _start);
    body.querySelector('#rabbit-refresh').addEventListener('click', _poll);
  }

  async function _start() {
    const payload = {
      source_node: _val('rabbit-source'),
      src_ip: _val('rabbit-src-ip'),
      dst_ip: _val('rabbit-dst-ip'),
      protocol: _val('rabbit-proto') || null,
      src_port: _num('rabbit-src-port'),
      dst_port: _num('rabbit-dst-port'),
      timeout_seconds: _num('rabbit-timeout') || 60,
    };
    try {
      await API.Labs.followRabbitStart(_labId, payload);
      showToast('Follow the Rabbit session started', 'success');
      await _poll();
    } catch (e) {
      showToast('Follow the Rabbit failed: ' + e.message, 'error');
    }
  }

  async function _poll() {
    if (!_labId) return;
    if (!_host || !document.body.contains(_host) || document.getElementById('workspace-drawer')?.hidden) {
      close();
      return;
    }
    try {
      const res = await API.Labs.followRabbitSessions(_labId);
      const sessions = res.sessions || [];
      Canvas.setFollowRabbitSessions(sessions);
      _renderSessions(sessions);
      LabInspector?.setTraceSessions(sessions);
    } catch (_) {}
  }

  function _renderSessions(sessions) {
    const box = document.getElementById('rabbit-sessions');
    if (!box) return;
    box.innerHTML = (sessions || []).map(s => {
      const hits = s.hits || [];
      const recon = s.reconstruction || {};
      const fwd = _legSummary(recon.forward, hits.filter(h => h.direction !== 'return').length, 'forward');
      const ret = _legSummary(recon.backward, hits.filter(h => h.direction === 'return').length, 'return');
      const asym = recon.asymmetric
        ? '<span class="admin-status admin-status-error" title="forward and return take different paths">asymmetric</span>'
        : '';
      const progress = _progressSummary(s);
      return `
      <article class="rabbit-session">
        <div>
          <strong>${_esc(s.source_node)}</strong>
          <span class="admin-status admin-status-${_esc(s.status)}">${_esc(s.status)}</span>
          ${asym}
          <span class="admin-muted">${_esc(s.flow?.src_ip || '')} -> ${_esc(s.flow?.dst_ip || '')}</span>
        </div>
        <div class="admin-muted">
          <span class="rabbit-leg rabbit-leg--forward">${_esc(fwd)}</span>
          <span class="rabbit-leg rabbit-leg--return">${_esc(ret)}</span>
          <div class="rabbit-progress" title="${_esc(progress.title)}">
            <div class="rabbit-progress-track">
              <div class="rabbit-progress-fill" style="width:${progress.percent}%"></div>
            </div>
            <div class="rabbit-progress-meta">${_esc(progress.label)}</div>
          </div>
        </div>
        ${s.status === 'running' ? `<button class="btn btn-xs rabbit-stop" data-session="${_esc(s.session_id)}">Stop</button>` : ''}
      </article>
    `;
    }).join('') || '<p class="admin-muted">No active sessions.</p>';
    box.querySelectorAll('.rabbit-stop').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await API.Labs.followRabbitStop(_labId, btn.dataset.session);
          await _poll();
        } catch (e) {
          showToast('Stop failed: ' + e.message, 'error');
        }
      });
    });
  }

  // Summarize one reconstructed leg: hop count + classification. Falls back to
  // the raw link-hit count when no reconstruction is available yet.
  function _legSummary(leg, fallbackCount, label) {
    if (leg && Array.isArray(leg.layers)) {
      const hops = leg.layers.reduce((acc, l) => acc + (l.edges ? l.edges.length : 0), 0);
      const cls = { certain: 'certain', multipath: 'multipath', partial: 'partial' };
      const tag = cls[leg.classification] || leg.classification || '';
      if (!hops) return `0 ${label}`;
      return `${hops} ${label}${tag ? ` · ${tag}` : ''}`;
    }
    return `${fallbackCount} ${label}`;
  }

  function _progressSummary(s) {
    const percent = Math.max(0, Math.min(100, Number(s.progress_percent ?? 0)));
    const completed = Number(s.completed_probe_count || 0);
    const total = Number(s.probe_count || 0);
    const packets = Number(s.packet_observation_count || 0);
    const remaining = Number(s.remaining_seconds || 0);
    const probeText = total ? `${completed}/${total} probes` : `${completed} probes`;
    const packetText = `${packets} packets`;
    const timeText = s.status === 'running' ? ` · ${Math.ceil(remaining)}s left` : '';
    const label = `${Math.round(percent)}% · ${probeText} · ${packetText}${timeText}`;
    return {
      percent,
      label,
      title: `Follow the Rabbit progress: ${label}`,
    };
  }

  function _val(id) { return document.getElementById(id)?.value.trim() || ''; }
  function _num(id) {
    const raw = _val(id);
    return raw ? Number(raw) : null;
  }
  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  return { open, close };
})();
