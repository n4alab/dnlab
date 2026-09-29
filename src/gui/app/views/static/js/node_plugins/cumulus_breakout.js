/** NVIDIA Cumulus VX breakout-port node override plugin. */
NodeOverridePlugins.register({
  key: 'cumulus_breakout',

  render({ nodeData, override }) {
    const state = cumulusBreakoutState(nodeData, override);
    const locked = cumulusBreakoutLocked(nodeData);
    const rows = state.breakouts.map(item => cumulusBreakoutRow(item, locked)).join('');
    return `
      <fieldset class="props-fieldset node-override node-override-cumulus">
        <legend>${cumulusEsc(override.label || 'Cumulus breakout')}</legend>
        <p class="mgmt-hint">${cumulusEsc(override.description || '')}</p>
        <p class="mgmt-hint">32 flat ports remain available; breakout lanes use additive warm slots.</p>
        ${locked ? '<p class="mgmt-hint webui-pending">Stop the VD before changing breakout ports.</p>' : ''}
        <div id="cumulus-breakout-rows">${rows}</div>
        <button type="button" id="btn-add-cumulus-breakout" class="btn btn-sm"${locked ? ' disabled' : ''}>+ Add breakout</button>
      </fieldset>
    `;
  },

  read({ panel }) {
    const byParent = new Map();
    panel.querySelectorAll('.cumulus-breakout-row').forEach(row => {
      const parent = Number.parseInt(row.querySelector('[name="cumulus_breakout_parent"]')?.value || '', 10);
      const lanes = Number.parseInt(row.querySelector('[name="cumulus_breakout_lanes"]')?.value || '', 10);
      if (parent >= 1 && parent <= 32 && [2, 4, 8].includes(lanes)) byParent.set(parent, lanes);
    });
    const breakouts = [...byParent.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([parent, lanes]) => ({ parent, lanes }));
    return { type: 'cumulus_breakout', flat_ports: 32, breakouts };
  },

  wire({ panel, nodeData }) {
    if (cumulusBreakoutLocked(nodeData)) return;
    const holder = panel.querySelector('#cumulus-breakout-rows');
    panel.querySelector('#btn-add-cumulus-breakout')?.addEventListener('click', () => {
      if (!holder) return;
      holder.insertAdjacentHTML('beforeend', cumulusBreakoutRow({ parent: 1, lanes: 4 }, false));
    });
    panel.addEventListener('click', event => {
      if (event.target.matches('.btn-remove-cumulus-breakout')) {
        event.target.closest('.cumulus-breakout-row')?.remove();
      }
    });
  },

  interfaces({ nodeData, override, baseInterfaces }) {
    const state = cumulusBreakoutState(nodeData, override);
    let slot = 33;
    const lanes = [];
    state.breakouts.forEach(item => {
      for (let lane = 0; lane < item.lanes; lane += 1) {
        lanes.push({ linux: `eth${slot}`, vendor: `swp${item.parent}s${lane}` });
        slot += 1;
      }
    });
    return [...baseInterfaces, ...lanes];
  },
});

function cumulusBreakoutState(nodeData, override) {
  const raw = nodeData.node_overrides_state || nodeData.node_overrides || {};
  const byParent = new Map();
  (Array.isArray(raw.breakouts) ? raw.breakouts : []).forEach(item => {
    const parent = Number.parseInt(item && item.parent, 10);
    const lanes = Number.parseInt(item && item.lanes, 10);
    if (parent >= 1 && parent <= 32 && [2, 4, 8].includes(lanes)) byParent.set(parent, lanes);
  });
  let used = 32;
  const breakouts = [];
  [...byParent.entries()].sort((a, b) => a[0] - b[0]).forEach(([parent, lanes]) => {
    if (used + lanes <= Number(override.max_total_ports || 64)) {
      breakouts.push({ parent, lanes });
      used += lanes;
    }
  });
  return { type: 'cumulus_breakout', flat_ports: 32, breakouts };
}

function cumulusBreakoutLocked(nodeData) {
  const state = String((nodeData && nodeData.runtime_state) || '').toLowerCase();
  return state !== '' && !['stopped', 'error', 'missing'].includes(state);
}

function cumulusBreakoutRow(item, locked = false) {
  const disabled = locked ? ' disabled' : '';
  const laneOptions = [2, 4, 8].map(value =>
    `<option value="${value}" ${Number(item.lanes) === value ? 'selected' : ''}>${value}x</option>`
  ).join('');
  return `
    <div class="props-inline cumulus-breakout-row">
      <label>swp
        <input type="number" name="cumulus_breakout_parent" min="1" max="32"${disabled}
               value="${cumulusEsc(String(item.parent))}" class="props-input">
      </label>
      <label>Lanes
        <select name="cumulus_breakout_lanes" class="props-input"${disabled}>${laneOptions}</select>
      </label>
      <button type="button" class="btn btn-sm btn-remove-cumulus-breakout"${disabled}>Remove</button>
    </div>
  `;
}

function cumulusEsc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
