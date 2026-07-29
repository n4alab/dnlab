const CaptureModal = (() => {
  function openEdge(labId, edge, preferredSide = '') {
    _open(labId, targets => _matchEdgeTarget(targets, edge, preferredSide));
  }

  function openMgmt(labId, nodeData) {
    const nodeName = typeof nodeData === 'string' ? nodeData : (nodeData?.id || nodeData?.name || '');
    const kind = typeof nodeData === 'object' && nodeData ? (nodeData.kind || '') : '';
    _open(labId, targets => {
      const target = targets.find(t => t.kind === 'mgmt' && t.node === nodeName);
      return _withDisplayIface(target, kind);
    });
  }

  async function _open(labId, selector) {
    if (!labId) {
      showToast('Open a running lab first', 'warn');
      return;
    }
    const root = document.createElement('div');
    root.dataset.modalSize = 'wide';
    root.className = 'capture-modal';
    root.innerHTML = '<div class="capture-muted">Loading capture target…</div>';
    showModal('Open in Wireshark', root, []);
    _setFooter([{ label: 'Close', class: 'btn-secondary', action: hideModal }]);

    let target;
    try {
      const res = await API.Labs.captureTargets(labId);
      target = selector(res.targets || []);
    } catch (err) {
      root.innerHTML = `<div class="capture-error">${_esc(err.message)}</div>`;
      return;
    }
    if (!target) {
      root.innerHTML = '<div class="capture-error">Capture target not found.</div>';
      return;
    }

    _renderForm(root, labId, target);
  }

  function _renderForm(root, labId, target) {
    root.innerHTML = `
      <div class="capture-summary">
        ${_summaryRow('Node', target.node)}
        ${_summaryRow('Peer', target.peer || '')}
        ${_summaryRow('Capture', _capturePoint(target))}
        ${_summaryRow('Host', target.host || '')}
        ${_summaryRow('Container', target.container || '')}
        ${_summaryRow('Interface', _displayIface(target))}
      </div>
      ${target.enabled ? '' : `<div class="capture-error">${_esc(target.disabled_reason || 'Capture unavailable')}</div>`}
      <label class="capture-label">BPF filter
        <input id="capture-filter" class="props-input" type="text" maxlength="512" placeholder="tcp port 179">
      </label>
      <div class="capture-grid">
        <label class="capture-label">Snap length
          <input id="capture-snaplen" class="props-input" type="number" min="0" max="262144" value="0">
        </label>
        <label class="capture-check">
          <input id="capture-promisc" type="checkbox">
          Promiscuous mode
        </label>
      </div>
      <div class="capture-hint">
        Open Wireshark through the DNLab browser handler. The handler checks the capture before Wireshark starts.
      </div>
      <div id="capture-result"></div>
    `;
    _setFooter([
      {
        label: 'Launch',
        class: 'btn-primary',
        disabled: !target.enabled,
        action: () => _launch(root, labId, target),
      },
      { label: 'Close', class: 'btn-secondary', action: hideModal },
    ]);
  }

  async function _launch(root, labId, target) {
    const result = root.querySelector('#capture-result');
    const filter = root.querySelector('#capture-filter')?.value || '';
    const snaplen = Number(root.querySelector('#capture-snaplen')?.value || 0);
    const promisc = !!root.querySelector('#capture-promisc')?.checked;
    result.innerHTML = '<div class="capture-muted">Preparing capture handler…</div>';
    try {
      const res = await API.Labs.launchCapture(labId, {
        target_id: target.id,
        side: target.side,
        filter,
        snaplen,
        promisc,
      });
      _renderLaunchResult(result, res);
    } catch (err) {
      result.innerHTML = `<div class="capture-error">${_esc(err.message)}</div>`;
    }
  }

  function _renderLaunchResult(el, res) {
    const setup = _handlerSetup();
    el.innerHTML = `
      <div class="capture-hint">
        The capture link expires in 10 minutes. Stop the capture by closing Wireshark or the DNLab capture handler window.
      </div>
      <div class="capture-actions">
        <button class="btn btn-primary" type="button" id="capture-open-handler">Open Wireshark</button>
        <button class="btn btn-secondary" type="button" id="capture-show-setup">Handler setup</button>
      </div>
      <div id="capture-setup" class="capture-setup" hidden>
        <div class="capture-muted">
          If nothing opens, download the local handler on this workstation, install it once, then retry.
        </div>
        <div class="capture-actions">
          <a class="btn btn-secondary" href="${_escAttr(API.Labs.captureHandlerDownloadUrl(setup.platform))}">Download handler</a>
          <button class="btn btn-secondary" type="button" id="capture-copy-setup">Copy commands</button>
        </div>
        <div class="capture-muted">${_esc(setup.label)}</div>
      </div>
    `;
    el.querySelector('#capture-open-handler')?.addEventListener('click', () => {
      if (!res.handler_url) {
        showToast('Capture handler URL missing', 'error');
        return;
      }
      window.location.href = res.handler_url;
      window.dispatchEvent(new CustomEvent('dnlab:capture-launched', { detail: res }));
      setTimeout(() => {
        const setup = el.querySelector('#capture-setup');
        if (setup) setup.hidden = false;
      }, 1200);
    });
    el.querySelector('#capture-show-setup')?.addEventListener('click', () => {
      const setup = el.querySelector('#capture-setup');
      if (setup) setup.hidden = !setup.hidden;
    });
    el.querySelector('#capture-copy-setup')?.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(setup.commands);
        showToast('commands copied to clipboard', 'success');
      } catch (_) {
        showToast('Copy failed', 'warn');
      }
    });
  }

  function _handlerSetup() {
    const os = _clientOS();
    if (os === 'windows') {
      return {
        platform: 'windows-bat',
        label: 'Open Command Prompt in your Windows Downloads folder, then paste the copied commands.',
        install: 'dnlab_capture_handler.bat install',
        doctor: 'dnlab_capture_handler.bat doctor',
        commands: 'cd /d "%USERPROFILE%\\Downloads"\r\ndnlab_capture_handler.bat install\r\ndnlab_capture_handler.bat doctor',
      };
    }
    if (os === 'macos') {
      return {
        platform: 'python',
        label: 'Terminal from the folder where you downloaded dnlab_capture_handler.py:',
        install: 'python3 ./dnlab_capture_handler.py install',
        doctor: 'python3 ./dnlab_capture_handler.py doctor',
        commands: 'cd ~/Downloads\npython3 ./dnlab_capture_handler.py install\npython3 ./dnlab_capture_handler.py doctor',
      };
    }
    return {
      platform: 'python',
      label: 'Terminal from the folder where you downloaded dnlab_capture_handler.py:',
      install: 'python3 ./dnlab_capture_handler.py install',
      doctor: 'python3 ./dnlab_capture_handler.py doctor',
      commands: 'cd ~/Downloads\npython3 ./dnlab_capture_handler.py install\npython3 ./dnlab_capture_handler.py doctor',
    };
  }

  function _clientOS() {
    const uaData = navigator.userAgentData;
    const platform = String((uaData && uaData.platform) || navigator.platform || navigator.userAgent || '').toLowerCase();
    if (platform.includes('win')) return 'windows';
    if (platform.includes('mac')) return 'macos';
    return 'linux';
  }

  function _matchEdgeTarget(targets, edge, preferredSide) {
    const exact = (t) => t.link
      && t.link.source === edge.source
      && t.link.target === edge.target
      && (t.link.source_iface || '') === (edge.source_iface || '')
      && (t.link.target_iface || '') === (edge.target_iface || '');
    if (preferredSide === 'vd') {
      const target = targets.find(t => t.kind === 'realnet' && exact(t));
      return _withDisplayIface(target, _kindForTarget(edge, target));
    }
    const target = targets.find(t => t.kind === 'link' && t.side === preferredSide && exact(t));
    return _withDisplayIface(target, _kindForTarget(edge, target));
  }

  function _summaryRow(k, v) {
    return `<div><span>${_esc(k)}</span><strong>${_esc(v || '-')}</strong></div>`;
  }

  function _capturePoint(target) {
    if (!target) return '';
    return `from VD ${target.node || ''} - interface ${_displayIface(target) || '-'}`;
  }

  function _withDisplayIface(target, kind) {
    if (!target) return target;
    return {
      ...target,
      display_iface: _formatIface(kind || '', target.iface || '') || target.iface || '',
    };
  }

  function _kindForTarget(edge, target) {
    if (!edge || !target) return '';
    if (target.node === edge.source) return edge.source_kind || '';
    if (target.node === edge.target) return edge.target_kind || '';
    return '';
  }

  function _displayIface(target) {
    return target?.display_iface || target?.iface || '';
  }

  function _formatIface(kind, iface) {
    if (typeof Canvas !== 'undefined' && typeof Canvas.formatInterfaceLabel === 'function') {
      return Canvas.formatInterfaceLabel(kind || '', iface || '');
    }
    return iface || '';
  }

  function _setFooter(buttons) {
    const footer = document.getElementById('modal-footer');
    footer.innerHTML = '';
    buttons.forEach(btn => {
      const el = document.createElement('button');
      el.className = `btn ${btn.class || 'btn-secondary'}`;
      el.textContent = btn.label;
      el.disabled = !!btn.disabled;
      el.addEventListener('click', btn.action || hideModal);
      footer.appendChild(el);
    });
  }

  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function _escAttr(s) {
    return _esc(s).replace(/"/g, '&quot;');
  }

  return { openEdge, openMgmt };
})();
