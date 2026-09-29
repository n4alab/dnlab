/**
 * Properties panel – shows and edits node / edge properties.
 */
const Properties = (() => {
  let _panel = null;
  let _images = [];          // cache di API.Docker.networkImages()
  let _realnetImportOptions = [];
  let _realnetRemoteAs = '';
  const listeners = {};

  function init(panelId) {
    _panel = document.getElementById(panelId);
    _showEmpty();
  }

  function setPanelElement(el) {
    _panel = el;
  }

  /** Populate the image cache: called by app.js at boot. */
  function setImages(images) {
    _images = Array.isArray(images) ? images : [];
  }

  function setRealNetImportOptions(options) {
    _realnetImportOptions = Array.isArray(options) ? options : [];
  }

  function setRealNetRemoteAs(asn) {
    _realnetRemoteAs = asn ? String(asn) : '';
  }

  function _imageFullName(img) {
    return img.full_name || `${img.repository}:${img.tag}`;
  }

  function _imageOptions(currentKind, currentImage) {
    // If the current image is not in the list (e.g. dangling image
    // or removed), we add it to the top so the user doesn't lose it.
    const options = [];
    const seen = new Set();
    const currentFull = currentImage || '';
    const inList = _images.some(i => _imageFullName(i) === currentFull && i.kind === currentKind);
    if (!inList && (currentFull || currentKind)) {
      options.push(`<option value="${_esc(currentKind)}|${_esc(currentFull)}" selected>
        ${_esc(currentKind || '?')} — ${_esc(currentFull || '(no image)')} [not present]
      </option>`);
      seen.add(`${currentKind}|${currentFull}`);
    }
    _images.forEach(img => {
      const full = _imageFullName(img);
      const key = `${img.kind}|${full}`;
      if (seen.has(key)) return;
      seen.add(key);
      const selected = (img.kind === currentKind && full === currentFull) ? ' selected' : '';
      options.push(`<option value="${_esc(key)}"${selected}>
        ${_esc(img.kind)} — ${_esc(full)}
      </option>`);
    });
    return options.join('');
  }

  function showNode(nodeData) {
    if ((nodeData.kind || '') === '_real_net') {
      showRealNet(nodeData);
      return;
    }

    const currentKind  = nodeData.kind || '';
    const currentImage = nodeData.image || '';
    const currentMgmt  = nodeData.mgmt_ipv4 || (nodeData.extra && nodeData.extra['mgmt-ipv4']) || '';
    const currentMgmt6 = nodeData.mgmt_ipv6 || (nodeData.extra && nodeData.extra['mgmt-ipv6']) || '';
    const currentEnv   = (nodeData.extra && nodeData.extra.env && typeof nodeData.extra.env === 'object') ? nodeData.extra.env : {};
    const mgmtPassthrough = String(currentEnv.CLAB_MGMT_PASSTHROUGH || '').toLowerCase() === 'true';
    const catalogEnv = (typeof DeviceCatalog !== 'undefined') ? DeviceCatalog.kindDefaultEnv(currentKind) : {};
    const effectiveEnv = { ...catalogEnv, ...currentEnv };

    _panel.innerHTML = `
      <h3 class="props-title">Node Properties</h3>
      <form id="node-props-form" class="props-form">
        <label>Name
          <input type="text" name="name" value="${_esc(nodeData.id)}" readonly class="props-input readonly">
        </label>
        <label>Kind / Image
          <select name="kind_image" class="props-input">
            ${_imageOptions(currentKind, currentImage)}
          </select>
        </label>
        <label>Mgmt IPv4
          <input type="text" name="mgmt_ipv4" value="${_esc(currentMgmt)}"
                 placeholder="auto (dal pool)" class="props-input">
        </label>
        <label>Mgmt IPv6
          <input type="text" name="mgmt_ipv6" value="${_esc(currentMgmt6)}"
                 placeholder="auto (dal pool)" class="props-input">
        </label>
        ${_resourcesSection(effectiveEnv)}
        <div id="node-override-section">
          ${_nodeOverrideSection(currentKind, nodeData)}
        </div>
        <div id="node-features-section">
          ${_nodeFeaturesSection(currentKind, nodeData)}
        </div>
        ${_runtimePlacementSection(nodeData)}
        ${_webuiPortsSection(nodeData)}
        ${_advancedExtraSection(nodeData)}
        <div class="props-actions">
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
          <button type="button" id="btn-open-console" class="btn btn-console btn-sm">Open Console</button>
          <button type="button" id="btn-remove-node" class="btn btn-danger btn-sm">Remove</button>
        </div>
      </form>
    `;

    _wireWebUIPortsSection();
    _wireNodeOverrideSection(currentKind, nodeData);

    _panel.querySelector('#node-props-form').addEventListener('submit', e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const combo = (fd.get('kind_image') || '').toString();
      const sep = combo.indexOf('|');
      const kind  = sep >= 0 ? combo.slice(0, sep) : combo;
      const image = sep >= 0 ? combo.slice(sep + 1) : '';
      // Recalculate the catalog defaults of the FINAL kind (it may have
      // changed in the same submit) and merge them with the user's custom
      // values collected from the form. The backend receives the combined
      // list and fully replaces `Topology.gui_webui_state[node]`.
      const catalogDefaults = (typeof DeviceCatalog !== 'undefined'
        ? DeviceCatalog.kindWebUI(kind || '') : []
      ).map(p => ({
        container_port: Number(p.port),
        scheme: p.scheme,
        path:   p.path || '/',
        label:  p.label || '',
        source: 'catalog',
      }));
      const userCustom = _readCustomWebUIPorts();
      const nodeOverrides = _readNodeOverrides(kind, nodeData);
      const nodeFeatures = _readNodeFeatures(kind);
      const extra = _nodeExtraWithMgmtPassthrough(
        nodeData,
        kind,
        false,
        fd.get('node_vcpu'),
        fd.get('node_ram'),
      );
      _emit('node-update', {
        name:  nodeData.id,
        kind,
        image,
        mgmt_ipv4: (fd.get('mgmt_ipv4') || '').trim(),
        mgmt_ipv6: (fd.get('mgmt_ipv6') || '').trim(),
        extra,
        advanced_extra_yaml: (fd.get('advanced_extra_yaml') || '').toString(),
        webui_ports: [...catalogDefaults, ...userCustom],
        node_overrides: nodeOverrides,
        node_features: nodeFeatures,
      });
    });

    const kindImageSelect = _panel.querySelector('select[name="kind_image"]');
    kindImageSelect.addEventListener('change', () => {
      const combo = kindImageSelect.value || '';
      const sep = combo.indexOf('|');
      const kind = sep >= 0 ? combo.slice(0, sep) : combo;
      const holder = _panel.querySelector('#node-override-section');
      if (holder) holder.innerHTML = _nodeOverrideSection(kind, nodeData);
      const featuresHolder = _panel.querySelector('#node-features-section');
      if (featuresHolder) featuresHolder.innerHTML = _nodeFeaturesSection(kind, nodeData);
      const resources = _panel.querySelector('#node-resources-section');
      if (resources) {
        const env = (typeof DeviceCatalog !== 'undefined') ? DeviceCatalog.kindDefaultEnv(kind || '') : {};
        resources.outerHTML = _resourcesSection(env);
      }
      _wireNodeOverrideSection(kind, nodeData);
    });

    _panel.querySelector('#btn-open-console').addEventListener('click', () => {
      _emit('open-console', nodeData.id);
    });

    _panel.querySelector('#btn-remove-node').addEventListener('click', () => {
      _emit('node-remove', nodeData.id);
    });
  }

  function showRealNet(nodeData) {
    const extra = nodeData.extra || {};
    const bgp = !!extra.bgp || !!extra.ospf;
    const mode = bgp ? 'bgp' : 'nat';
    const selectedImports = new Set((extra.import_routers || []).map(r => String(r.lab_id || r.id || '')));
    const importRows = _realnetImportOptions.map(opt => {
      const labId = String(opt.lab_id || '');
      const checked = selectedImports.has(labId) ? 'checked' : '';
      const owner = opt.owner_username || 'unassigned';
      const role = opt.owner_role || '-';
      const label = `${opt.lab_name || labId} (${owner}, ${role})`;
      return `
        <label class="props-check">
          <input type="checkbox" name="import_router" value="${_esc(labId)}"
                 data-lab-name="${_esc(opt.lab_name || '')}"
                 data-owner-username="${_esc(opt.owner_username || '')}"
                 data-owner-role="${_esc(opt.owner_role || '')}"
                 data-realnet-node="${_esc(opt.realnet_node || '')}"
                 data-bgp-as="${_esc(opt.bgp_as || '')}"
                 data-bgp-router-ip="${_esc(opt.bgp_router_ip || '')}" ${checked}>
          <span>${_esc(label)}</span>
        </label>
      `;
    }).join('');

    _panel.innerHTML = `
      <h3 class="props-title">Real Network</h3>
      <form id="realnet-props-form" class="props-form">
        <label>Name
          <input type="text" name="name" value="${_esc(nodeData.id)}" readonly class="props-input readonly">
        </label>
        <label>LAN network
          <input type="text" name="network" value="${_esc(extra.network || '')}"
                 placeholder="auto" class="props-input">
        </label>
        <label>LAN gateway IP
          <input type="text" name="ipv4" value="${_esc(extra.ipv4 || '')}"
                 placeholder="auto" class="props-input">
        </label>
        <label>Description
          <input type="text" name="description" value="${_esc(extra.description || '')}"
                 class="props-input">
        </label>
        <fieldset class="props-fieldset">
          <legend>Mode</legend>
          <div class="props-segmented" role="radiogroup" aria-label="Real network mode">
            <label>
              <input type="radio" name="mode" value="nat" ${mode === 'nat' ? 'checked' : ''}>
              <span>NAT</span>
            </label>
            <label>
              <input type="radio" name="mode" value="bgp" ${mode === 'bgp' ? 'checked' : ''}>
              <span>BGP</span>
            </label>
          </div>
        </fieldset>
        <fieldset id="realnet-bgp-import-row" class="props-fieldset ${mode === 'bgp' ? '' : 'hidden'}">
          <legend>Import routes from</legend>
          <p class="mgmt-hint">Local BGP AS: ${_esc(extra.bgp_as || 'allocated on save')}</p>
          <p class="mgmt-hint">Remote BGP AS: ${_esc(_realnetRemoteAs || '-')}</p>
          ${extra.bgp_password ? `<p class="mgmt-hint">BGP password: <code>${_esc(extra.bgp_password)}</code></p>` : ''}
          ${importRows || '<p class="mgmt-hint">No BGP realnet-router available in other labs.</p>'}
        </fieldset>
        <p class="mgmt-hint">
          Object outside the lab: it does not use mgmt-ipv4 and is not attached to the management network.
        </p>
        <div class="props-actions">
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
          <button type="button" id="btn-remove-realnet" class="btn btn-danger btn-sm">Remove</button>
        </div>
      </form>
    `;

    const form = _panel.querySelector('#realnet-props-form');
    const importRow = form.querySelector('#realnet-bgp-import-row');
    const refreshMode = () => {
      const selected = form.querySelector('input[name="mode"]:checked')?.value || 'nat';
      importRow.classList.toggle('hidden', selected !== 'bgp');
    };
    form.querySelectorAll('input[name="mode"]').forEach(input => {
      input.addEventListener('change', refreshMode);
    });

    form.addEventListener('submit', e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const bgpEnabled = fd.get('mode') === 'bgp';
      const imports = [...form.querySelectorAll('input[name="import_router"]:checked')].map(input => ({
        lab_id: input.value,
        lab_name: input.dataset.labName || '',
        owner_username: input.dataset.ownerUsername || '',
        owner_role: input.dataset.ownerRole || '',
        realnet_node: input.dataset.realnetNode || '',
        bgp_as: Number(input.dataset.bgpAs || 0),
        bgp_router_ip: input.dataset.bgpRouterIp || '',
      }));
      _emit('realnet-update', {
        name: nodeData.id,
        extra: {
          network: (fd.get('network') || '').trim(),
          ipv4: (fd.get('ipv4') || '').trim(),
          description: (fd.get('description') || '').trim(),
          bgp: bgpEnabled,
          nat: !bgpEnabled,
          bgp_as: extra.bgp_as || null,
          bgp_router_ip: extra.bgp_router_ip || null,
          bgp_password: extra.bgp_password || null,
          import_routers: bgpEnabled ? imports : [],
        },
      });
    });

    _panel.querySelector('#btn-remove-realnet').addEventListener('click', () => {
      _emit('node-remove', nodeData.id);
    });
  }

  // ── Per-kind node overrides ────────────────────────────────────────
  function _nodeOverrideSection(kind, nodeData) {
    const override = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindOverrides(kind || '')
      : null;
    if (!override || typeof NodeOverridePlugins === 'undefined') return '';
    return NodeOverridePlugins.render({ nodeData, override });
  }

  function _readNodeOverrides(kind, nodeData) {
    const override = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindOverrides(kind || '')
      : null;
    if (!override || typeof NodeOverridePlugins === 'undefined') return { type: 'none' };
    return NodeOverridePlugins.read({ panel: _panel, nodeData, override });
  }

  // ── Data-driven node features ───────────────────────────────────────
  function _nodeFeaturesSection(kind, nodeData) {
    const features = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindNodeFeatures(kind || '')
      : [];
    if (!features.length) return '';

    return features.map(feature => {
      const ui = feature.ui || {};
      if (ui.type !== 'checkbox-list' || !Array.isArray(ui.items)) return '';
      const state = _nodeFeatureState(nodeData, feature);
      const rows = ui.items.map(item => {
        const key = String(item.key || '');
        if (!key) return '';
        const checked = state[key] ? 'checked' : '';
        const locked = item.locked ? 'disabled' : '';
        return `
          <label class="props-check">
            <input type="checkbox" name="node_feature_${_esc(feature.key)}_${_esc(key)}"
                   data-node-feature="${_esc(feature.key)}" data-node-feature-item="${_esc(key)}"
                   ${checked} ${locked}>
            <span>${_esc(item.label || key)}</span>
          </label>
        `;
      }).join('');
      return `
        <fieldset class="props-fieldset node-feature" data-node-feature-section="${_esc(feature.key)}">
          <legend>${_esc(feature.label || feature.key)}</legend>
          ${rows}
        </fieldset>
      `;
    }).join('');
  }

  function _nodeFeatureState(nodeData, feature) {
    const storedRoot = nodeData.node_features_state || nodeData.node_features || {};
    const stored = storedRoot && typeof storedRoot === 'object' ? (storedRoot[feature.key] || {}) : {};
    const out = {};
    const items = (feature.ui && Array.isArray(feature.ui.items)) ? feature.ui.items : [];
    items.forEach(item => {
      const key = String(item.key || '');
      if (!key) return;
      out[key] = Object.prototype.hasOwnProperty.call(stored, key)
        ? !!stored[key]
        : !!item.default;
      if (item.locked) out[key] = true;
    });
    return out;
  }

  function _readNodeFeatures(kind) {
    const features = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindNodeFeatures(kind || '')
      : [];
    const out = {};
    features.forEach(feature => {
      const ui = feature.ui || {};
      if (ui.type !== 'checkbox-list' || !Array.isArray(ui.items)) return;
      const featureState = {};
      ui.items.forEach(item => {
        const key = String(item.key || '');
        if (!key) return;
        const selector = `[data-node-feature="${_cssEscape(feature.key)}"][data-node-feature-item="${_cssEscape(key)}"]`;
        const input = _panel.querySelector(selector);
        featureState[key] = item.locked ? true : !!(input && input.checked);
      });
      out[feature.key] = featureState;
    });
    return out;
  }

  function _resourcesSection(env) {
    const vcpu = Math.max(1, Number(env.VCPU || env.vcpu || 1) || 1);
    const ram = Math.max(128, Number(env.RAM || env.ram || 2048) || 2048);
    return `
      <fieldset id="node-resources-section" class="props-fieldset node-resources">
        <legend>Resources</legend>
        <div class="props-two-col">
          <label>vCPU
            <input type="number" name="node_vcpu" min="1" step="1"
                   value="${_esc(String(vcpu))}" class="props-input">
          </label>
          <label>RAM MiB
            <input type="number" name="node_ram" min="128" step="128"
                   value="${_esc(String(ram))}" class="props-input">
          </label>
        </div>
      </fieldset>
    `;
  }

  function _nodeExtraWithMgmtPassthrough(nodeData, kind, enabled, vcpuRaw, ramRaw) {
    const currentExtra = (nodeData.extra && typeof nodeData.extra === 'object') ? nodeData.extra : {};
    const catalogEnv = (typeof DeviceCatalog !== 'undefined') ? DeviceCatalog.kindDefaultEnv(kind || nodeData.kind || '') : {};
    const env = (currentExtra.env && typeof currentExtra.env === 'object') ? { ...currentExtra.env } : {};
    if (enabled) {
      env.CLAB_MGMT_PASSTHROUGH = 'true';
    } else {
      delete env.CLAB_MGMT_PASSTHROUGH;
    }
    const vcpu = parseInt(String(vcpuRaw || '').trim(), 10);
    const ram = parseInt(String(ramRaw || '').trim(), 10);
    if (Number.isFinite(vcpu) && vcpu > 0) env.VCPU = String(vcpu);
    else if (catalogEnv.VCPU === undefined) delete env.VCPU;
    if (Number.isFinite(ram) && ram > 0) env.RAM = String(ram);
    else if (catalogEnv.RAM === undefined) delete env.RAM;
    return {
      env: Object.keys(env).length ? env : null,
    };
  }

  function _advancedExtraSection(nodeData) {
    return `
      <fieldset class="props-fieldset node-advanced-extra">
        <legend>Advanced Containerlab YAML</legend>
        <textarea name="advanced_extra_yaml" class="props-input props-yaml"
                  spellcheck="false">${_esc(_advancedExtraYaml(nodeData))}</textarea>
      </fieldset>
    `;
  }

  function _advancedExtraYaml(nodeData) {
    const extra = _advancedExtraObject(nodeData.extra || {});
    return _toYaml(extra).trimEnd();
  }

  function _advancedExtraObject(extra) {
    const out = {};
    Object.entries(extra || {}).forEach(([k, v]) => {
      if (['mgmt-ipv4', 'mgmt-ipv6', 'webui_ports', 'node_overrides'].includes(k)) return;
      if (k === 'env' && v && typeof v === 'object' && !Array.isArray(v)) {
        const env = {};
        Object.entries(v).forEach(([ek, ev]) => {
          if (['VCPU', 'RAM', 'CLAB_MGMT_PASSTHROUGH'].includes(ek)) return;
          env[ek] = ev;
        });
        if (Object.keys(env).length) out.env = env;
        return;
      }
      out[k] = v;
    });
    return out;
  }

  function _toYaml(value, indent = 0) {
    const pad = ' '.repeat(indent);
    if (!value || typeof value !== 'object') return '';
    if (Array.isArray(value)) {
      return value.map(item => {
        if (item && typeof item === 'object') {
          const nested = _toYaml(item, indent + 2).trimEnd();
          return `${pad}-\n${nested}`;
        }
        return `${pad}- ${_yamlScalar(item)}`;
      }).join('\n') + (value.length ? '\n' : '');
    }
    return Object.entries(value).map(([k, v]) => {
      if (v && typeof v === 'object') {
        if (Array.isArray(v) && v.length && v.every(item => !item || typeof item !== 'object')) {
          return `${pad}${k}:\n${_toYaml(v, indent + 2).trimEnd()}`;
        }
        const nested = _toYaml(v, indent + 2).trimEnd();
        return nested ? `${pad}${k}:\n${nested}` : `${pad}${k}: {}`;
      }
      return `${pad}${k}: ${_yamlScalar(v)}`;
    }).join('\n') + (Object.keys(value).length ? '\n' : '');
  }

  function _yamlScalar(value) {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    const s = String(value);
    if (/^[A-Za-z0-9_./:@+-]+$/.test(s) && !/^(true|false|null|yes|no|on|off)$/i.test(s)) return s;
    return JSON.stringify(s);
  }

  function _wireNodeOverrideSection(kind, nodeData) {
    const override = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindOverrides(kind || '')
      : null;
    if (!override || typeof NodeOverridePlugins === 'undefined') return;
    NodeOverridePlugins.wire({ panel: _panel, nodeData, override });
  }

  // ── Web UI ports section ───────────────────────────────────────────
  // Source of truth: `nodeData.webui_state` (sidecar GUI). Catalog
  // defaults are displayed as read-only — they are re-injected on
  // submit, so changing `kind` automatically recalculates the pills.
  // Custom rows (source: user) are editable.
  // `nodeData.webui_runtime` (populated by status-live) annotates
  // the allocated `host_port` for each entry when the lab is running.
  function _webuiPortsSection(nodeData) {
    const defaults = (typeof DeviceCatalog !== 'undefined')
      ? DeviceCatalog.kindWebUI(nodeData.kind || '')
      : [];
    // Custom user entries from the sidecar (filter out entries with
    // `source=catalog`; if for some reason they arrive marked differently,
    // keep them as custom — better to show them than lose them).
    const sidecar = Array.isArray(nodeData.webui_state) ? nodeData.webui_state : [];
    const custom = sidecar.filter(p => (p.source || 'user') !== 'catalog')
      .map(p => ({
        scheme: p.scheme || 'https',
        port:   p.container_port || p.port || '',
        path:   p.path || '/',
        label:  p.label || '',
      }));
    const runtime = Array.isArray(nodeData.webui_runtime) ? nodeData.webui_runtime : [];

    const annotation = (containerPort) => {
      const a = runtime.find(r => Number(r.container_port) === Number(containerPort));
      if (a && a.host_port) {
        return `<span class="webui-host-port">→ master:${a.host_port}</span>`;
      }
      return '<span class="webui-pending" title="Exposed in the next deployment">(pending)</span>';
    };

    const defaultsHtml = defaults.length === 0 ? '' : `
      <div class="webui-defaults">
        ${defaults.map(p => `
          <div class="webui-default-row">
            <span class="webui-pill webui-pill-${_esc(p.scheme)}">${_esc(p.scheme)}:${p.port}</span>
            <span class="webui-label">${_esc(p.label)}</span>
            ${annotation(p.port)}
          </div>`).join('')}
      </div>
    `;
    const customRowsHtml = custom.map((p, i) => _customPortRow(p, i, annotation(p.port))).join('');
    return `
      <fieldset class="webui-ports">
        <legend>Web UI</legend>
        ${defaultsHtml || '<p class="webui-muted">No Web UI by default for this kind.</p>'}
        <div class="webui-custom-header">
          <span>Custom ports</span>
          <button type="button" id="btn-add-webui-port" class="btn btn-sm">+ Add</button>
        </div>
        <div id="webui-custom-rows">${customRowsHtml}</div>
      </fieldset>
    `;
  }

  function _runtimePlacementSection(nodeData) {
    const host = nodeData.runtime_host || '';
    const scheduled = nodeData.scheduled_host || '';
    const state = nodeData.runtime_state || '';
    const container = nodeData.runtime_container || '';
    const topoFile = nodeData.runtime_topology_file || '';
    const lastError = nodeData.runtime_last_error || '';
    const duplicates = Array.isArray(nodeData.duplicate_hosts) ? nodeData.duplicate_hosts : [];
    const mismatch = !!nodeData.placement_mismatch;
    const details = [];
    if (scheduled && scheduled !== host) details.push(`scheduled ${scheduled}`);
    if (duplicates.length) details.push(`duplicates ${duplicates.join(', ')}`);
    const cls = mismatch ? 'webui-pending' : 'webui-host-port';
    const stateLabel = state || 'not deployed';
    const hint = state
      ? ''
      : '<span class="webui-pending">Deploy the lab to enable per-VD actions</span>';
    return `
      <fieldset class="runtime-placement">
        <legend>Runtime</legend>
        <div class="webui-default-row">
          <span>State</span>
          <span class="${_runtimeStateClass(state)}">${_esc(stateLabel)}</span>
          ${hint}
        </div>
        <div class="webui-default-row">
          <span>Host</span>
          <span class="${cls}">${_esc(host || scheduled || 'unknown')}</span>
          ${details.length ? `<span class="webui-pending">${_esc(details.join(' · '))}</span>` : ''}
        </div>
        ${container ? `<div class="webui-default-row"><span>Container</span><span>${_esc(container)}</span></div>` : ''}
        ${topoFile ? `<div class="webui-default-row"><span>Topology</span><span>${_esc(topoFile)}</span></div>` : ''}
        ${lastError ? `<div class="webui-default-row"><span>Error</span><span class="webui-pending">${_esc(lastError)}</span></div>` : ''}
      </fieldset>
    `;
  }

  function _runtimeStateClass(state) {
    if (state === 'running') return 'webui-host-port';
    if (state === 'stopped') return 'webui-pending';
    if (state === 'error') return 'webui-pending';
    return 'webui-pending';
  }

  function _customPortRow(p = {}, idx = 0, annotationHtml = '') {
    const scheme = p.scheme || 'https';
    const port   = p.port || '';
    const path   = p.path || '/';
    const label  = p.label || '';
    return `
      <div class="webui-custom-row" data-idx="${idx}">
        <select class="props-input webui-scheme">
          <option value="https" ${scheme === 'https' ? 'selected' : ''}>https</option>
          <option value="http"  ${scheme === 'http'  ? 'selected' : ''}>http</option>
        </select>
        <input type="number" class="props-input webui-port" min="1" max="65535"
               value="${_esc(String(port))}" placeholder="port">
        <input type="text" class="props-input webui-path" value="${_esc(path)}" placeholder="/">
        <input type="text" class="props-input webui-label" value="${_esc(label)}" placeholder="label">
        <button type="button" class="btn btn-sm btn-danger webui-remove" title="Rimuovi">✕</button>
        <span class="webui-row-runtime">${annotationHtml}</span>
      </div>
    `;
  }

  function _wireWebUIPortsSection() {
    const addBtn = _panel.querySelector('#btn-add-webui-port');
    const rows   = _panel.querySelector('#webui-custom-rows');
    if (!addBtn || !rows) return;
    addBtn.addEventListener('click', () => {
      const idx = rows.children.length;
      rows.insertAdjacentHTML('beforeend', _customPortRow({}, idx));
    });
    rows.addEventListener('click', (e) => {
      const btn = e.target.closest('.webui-remove');
      if (!btn) return;
      const row = btn.closest('.webui-custom-row');
      if (row) row.remove();
    });
  }

  function _readCustomWebUIPorts() {
    const rows = _panel.querySelectorAll('.webui-custom-row');
    const out = [];
    rows.forEach(r => {
      const portStr = (r.querySelector('.webui-port').value || '').trim();
      const port = parseInt(portStr, 10);
      if (!port || port < 1 || port > 65535) return;
      out.push({
        container_port: port,
        scheme: r.querySelector('.webui-scheme').value,
        path:   (r.querySelector('.webui-path').value || '/').trim() || '/',
        label:  (r.querySelector('.webui-label').value || '').trim(),
        source: 'user',
      });
    });
    return out;
  }

  function showEdge(edgeData) {
    _panel.innerHTML = `
      <h3 class="props-title">Link Properties</h3>
      <form id="edge-props-form" class="props-form">
        <label>Source
          <input type="text" value="${edgeData.source}" readonly class="props-input readonly">
        </label>
        <label>Source Interface
          <input type="text" name="source_iface" value="${edgeData.source_iface || ''}" class="props-input">
        </label>
        <label>Target
          <input type="text" value="${edgeData.target}" readonly class="props-input readonly">
        </label>
        <label>Target Interface
          <input type="text" name="target_iface" value="${edgeData.target_iface || ''}" class="props-input">
        </label>
        <div class="props-actions">
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
          <button type="button" id="btn-remove-edge" class="btn btn-danger btn-sm">Remove</button>
        </div>
      </form>
    `;

    _panel.querySelector('#edge-props-form').addEventListener('submit', e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      _emit('edge-update', {
        source:       edgeData.source,
        target:       edgeData.target,
        source_iface: fd.get('source_iface'),
        target_iface: fd.get('target_iface'),
      });
    });

    _panel.querySelector('#btn-remove-edge').addEventListener('click', () => {
      _emit('edge-remove', { source: edgeData.source, target: edgeData.target });
    });
  }

  function showRunningInfo(containerInfo) {
    const ip = containerInfo.ipv4_address || '—';
    const state = containerInfo.state || '—';
    const el = _panel.querySelector('.running-info') || (() => {
      const d = document.createElement('div');
      d.className = 'running-info';
      _panel.appendChild(d);
      return d;
    })();
    el.innerHTML = `
      <div class="info-row"><span>State</span><span class="badge-${state}">${state}</span></div>
      <div class="info-row"><span>Mgmt IP</span><span>${ip}</span></div>
    `;
  }

  function _showEmpty() {
    _panel.innerHTML = `<p class="props-empty">Select a node or link to view properties.</p>`;
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

  function _cssEscape(s) {
    if (window.CSS && typeof window.CSS.escape === 'function') {
      return window.CSS.escape(String(s ?? ''));
    }
    return String(s ?? '').replace(/["\\]/g, '\\$&');
  }

  return { init, setPanelElement, setImages, setRealNetImportOptions, setRealNetRemoteAs, showNode, showRealNet, showEdge, showRunningInfo, on };
})();
