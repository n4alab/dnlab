/* Bottom diagnostics workspace: Events, correlated service Logs and Trace. */
const LabInspector = (() => {
  let root, summary, active = 'events', collapsed = true;

  function init() {
    root = document.getElementById('lab-inspector');
    summary = document.getElementById('inspector-summary');
    if (!root) return;
    root.querySelectorAll('[data-inspector-tab]').forEach(btn => btn.addEventListener('click', () => open(btn.dataset.inspectorTab)));
    document.getElementById('btn-inspector-collapse')?.addEventListener('click', () => setCollapsed(!collapsed));
    setCollapsed(true);
  }

  function open(tab, { expand = true } = {}) {
    if (!root) return;
    active = tab;
    root.querySelectorAll('[data-inspector-tab]').forEach(btn => btn.classList.toggle('active', btn.dataset.inspectorTab === tab));
    ['events', 'logs', 'trace'].forEach(name => {
      const body = document.getElementById(`inspector-${name}`);
      if (body) body.hidden = name !== tab;
    });
    if (expand) setCollapsed(false);
  }

  function setCollapsed(value) {
    collapsed = !!value;
    if (!root) return;
    root.classList.toggle('collapsed', collapsed);
    const btn = document.getElementById('btn-inspector-collapse');
    if (btn) { btn.textContent = collapsed ? '⌃' : '⌄'; btn.title = collapsed ? 'Expand panel' : 'Collapse panel'; }
  }

  function setSummary(text) { if (summary) summary.textContent = text || '—'; }

  function setTraceSessions(sessions) {
    const host = document.getElementById('inspector-trace');
    if (!host) return;
    const items = Array.isArray(sessions) ? sessions : [];
    host.innerHTML = items.map(session => {
      const reconstruction = session.reconstruction || {};
      const forward = reconstruction.forward?.layers || [];
      const backward = reconstruction.backward?.layers || [];
      const hops = leg => leg.reduce((count, layer) => count + (layer.edges?.length || 0), 0);
      const status = session.status || 'unknown';
      return `<article class="trace-session"><strong>${_esc(session.source_node || 'source')}</strong> · ${_esc(status)} · ${_esc(session.flow?.src_ip || '?')} → ${_esc(session.flow?.dst_ip || '?')}<br>forward: ${hops(forward)} hops; return: ${hops(backward)} hops${reconstruction.asymmetric ? ' · asymmetric' : ''}</article>`;
    }).join('') || '<p class="trace-empty">No Follow the Rabbit sessions for this lab.</p>';
  }

  function _esc(value) { const s = String(value ?? ''); return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  return { init, open, setCollapsed, setSummary, setTraceSessions };
})();
