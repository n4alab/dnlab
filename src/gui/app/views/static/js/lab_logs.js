/* Live view for the authenticated, lab-scoped operational-log WebSocket. */
const LabLogsPanel = (() => {
  let socket = null, labId = null, intentional = false, reconnect = null;

  function setLab(nextLabId) {
    if (nextLabId === labId) return;
    _close(); labId = nextLabId;
    const host = document.getElementById('inspector-logs');
    if (host) host.replaceChildren();
    if (labId) _connect();
  }

  function _connect() {
    if (!labId) return;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${proto}://${location.host}/ws/lab-logs/${encodeURIComponent(labId)}`);
    socket.onmessage = event => {
      try { _append(JSON.parse(event.data)); } catch (_) {}
    };
    socket.onclose = () => {
      if (!intentional && labId) reconnect = setTimeout(_connect, 3000);
    };
  }

  function _append(record) {
    const host = document.getElementById('inspector-logs');
    if (!host) return;
    const line = document.createElement('div');
    const level = String(record.level || 'info').toLowerCase();
    line.className = `inspector-line log-${level === 'warning' ? 'warn' : level === 'error' || level === 'critical' ? 'error' : 'info'}`;
    line.textContent = `[${record.timestamp || ''}] ${record.service || 'gui'} ${level}: ${record.message || ''}`;
    host.appendChild(line);
    while (host.childNodes.length > 500) host.removeChild(host.firstChild);
    host.scrollTop = host.scrollHeight;
  }

  function _close() { intentional = true; if (reconnect) clearTimeout(reconnect); reconnect = null; if (socket) { socket.onclose = null; socket.close(); } socket = null; intentional = false; }
  return { setLab };
})();
