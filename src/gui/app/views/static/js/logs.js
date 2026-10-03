/**
 * LogsPanel – opens a node log in a dedicated browser window,
 * no longer as a draggable popup.
 *
 * The window (`logs.html`) is self-contained: WebSocket + viewer scrollabile
 * + cookie di sessione ereditato. Questo modulo resta solo come ingresso.
 *
 * API:
 *   LogsPanel.init()
 *   LogsPanel.open(labId, nodeName)   — WindowManager.open('/logs.html?…')
 *   LogsPanel.openAll(labId)          — aggregated snapshot window
 *   LogsPanel.close(nodeName)         — noop
 */
const LogsPanel = (() => {
  function init() {}

  function open(labId, nodeName) {
    if (!labId || !nodeName) return;
    const url = `/logs.html?lab=${encodeURIComponent(labId)}&node=${encodeURIComponent(nodeName)}`;
    const winName = `dnlab-logs-${labId}-${nodeName}`;
    WindowManager.open(url, winName, { width: 1100, height: 720 });
  }

  function openAll(labId) {
    if (!labId) return null;
    const url = `/all-logs.html?lab=${encodeURIComponent(labId)}`;
    return WindowManager.open(url, '_blank', { width: 1280, height: 820 });
  }

  function close(_nodeName) {}

  return { init, open, openAll, close };
})();
