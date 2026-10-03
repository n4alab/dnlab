/** Shared WebSocket log viewer for standalone and aggregated log windows. */
class LogSession {
  constructor({ labId, nodeName, container, onStatus }) {
    this.labId = labId;
    this.nodeName = nodeName;
    this.container = container;
    this.onStatus = onStatus || (() => {});
    this.ws = null;
    this.autoScroll = true;
    this.disposed = false;
    this.container.addEventListener('scroll', () => {
      this.autoScroll = this.container.scrollHeight - this.container.scrollTop
        - this.container.clientHeight < 8;
    });
  }

  connect({ resetLog = false } = {}) {
    this._closeSocket();
    this.disposed = false;
    if (resetLog) this.container.replaceChildren();
    this.autoScroll = true;
    this.onStatus('connecting');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/ws/logs/${encodeURIComponent(this.labId)}/${encodeURIComponent(this.nodeName)}`;
    const ws = new WebSocket(url);
    this.ws = ws;
    ws.onopen = () => {
      if (this.ws === ws && !this.disposed) this.onStatus('connected');
    };
    ws.onmessage = (event) => {
      if (this.ws !== ws || this.disposed) return;
      this._appendLine(event.data);
    };
    ws.onclose = (event) => {
      if (this.ws !== ws || this.disposed) return;
      this.ws = null;
      const status = event.code === 4401 ? 'unauthorized' : 'closed';
      this.onStatus(status);
      this._appendLine(event.code === 4401
        ? '[Session expired — reload the page after logging in]'
        : '[WebSocket closed]', 'log-line-warn');
    };
    ws.onerror = () => {
      if (this.ws !== ws || this.disposed) return;
      this.onStatus('error');
      this._appendLine('[Error WebSocket]', 'log-line-err');
    };
  }

  dispose() {
    this.disposed = true;
    this._closeSocket();
  }

  _closeSocket() {
    const ws = this.ws;
    this.ws = null;
    if (ws) ws.close();
  }

  _appendLine(text, extraClass = '') {
    const line = document.createElement('div');
    line.className = `log-line ${extraClass}`.trim();
    line.textContent = String(text).replace(/\r?\n$/, '');
    this.container.appendChild(line);
    if (this.autoScroll) this.container.scrollTop = this.container.scrollHeight;
  }
}
