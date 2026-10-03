/**
 * Standalone logs window: aperta da LogsPanel.open().
 * Come console_tab.js ma con un viewer testuale scrollabile invece di
 * xterm — auto-scroll until the user interrupts it by scrolling up.
 */
(() => {
  const params = new URLSearchParams(location.search);
  const labId = params.get('lab') || '';
  const nodeName = params.get('node') || '';

  const hdrNode = document.getElementById('hdr-node');
  const hdrLab  = document.getElementById('hdr-lab');
  const hdrStat = document.getElementById('hdr-status');
  const logEl   = document.getElementById('log');

  hdrNode.textContent = `📋 ${nodeName || '(no node)'}`;
  hdrLab.textContent  = labId ? `lab ${labId.slice(0, 8)}…` : '';
  document.title = `Logs · ${nodeName || 'dNLab'}`;

  if (!labId || !nodeName) {
    _setStatus('err', 'parametri mancanti');
    return;
  }

  const session = new LogSession({
    labId,
    nodeName,
    container: logEl,
    onStatus: (status) => {
      _setStatus(status === 'connected' ? 'ok' : status === 'connecting' ? '' : 'err', status);
    },
  });
  session.connect();
  window.addEventListener('pagehide', () => session.dispose(), { once: true });
  window.addEventListener('beforeunload', () => session.dispose(), { once: true });

  function _setStatus(cls, text) {
    hdrStat.className = `status ${cls || ''}`;
    hdrStat.textContent = text;
  }
})();
