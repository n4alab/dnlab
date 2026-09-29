/**
 * MgmtPanel — pannello che mostra/edita il blocco `mgmt:` della topology.
 *
 * Fields visibili all'user:
 *   - ipv4-subnet (CIDR, es. 172.20.0.0/24)
 *   - ipv4-gw     (read-only, ultimo host della subnet)
 *   - ipv6-subnet (CIDR, default 3fff:<v4-octets>::/64)
 *   - ipv6-gw     (read-only, ultimo host della subnet IPv6)
 *
 * Con DHCP attivo il jumphost offre DHCPv4, RA e DHCPv6 alla rete mgmt.
 * Ogni guest decide autonomamente se usare DHCP o una configurazione statica.
 *
 * Il nome Docker network e il nome Linux bridge sono **generati
 * deterministicamente lato backend dal nome della topology**
 * (network ≤12 char, bridge = "br-" + network ≤15 char) for rispettare
 * the Linux 15-character limit on interface names. L'user non
 * li configura.
 *
 * Il server salva nel topology YAML sotto il key `mgmt:` solo
 * `ipv4-subnet`, `ipv4-gw`, `ipv6-subnet`, `ipv6-gw`, `dhcp`; eventuali
 * `network`/`bridge` residui vengono rimossi al save.
 */
const MgmtPanel = (() => {
  let _panel = null;
  let _topoName = null;
  const listeners = {};

  function init(panelId) {
    _panel = document.getElementById(panelId);
    if (!_panel) return;
    _renderEmpty();
  }

  function setTopology(name, mgmt) {
    _topoName = name || null;
    if (!_topoName) { _renderEmpty(); return; }
    _render(mgmt || {});
  }

  function clear() {
    _topoName = null;
    _renderEmpty();
  }

  function _renderEmpty() {
    if (!_panel) return;
    _panel.innerHTML = `<p class="props-empty">Open a topology to configure the mgmt network.</p>`;
  }

  function _render(mgmt) {
    const subnet    = mgmt['ipv4-subnet'] || '';
    const gw        = _ipv4Gw(subnet) || mgmt['ipv4-gw'] || '';
    const derivedV6 = _deriveIpv6Subnet(subnet);
    const subnet_v6 = mgmt['ipv6-subnet'] || derivedV6;
    const gw_v6     = _ipv6Gw(subnet_v6) || mgmt['ipv6-gw'] || '';
    const dhcp = Boolean(mgmt.dhcp);

    _panel.innerHTML = `
      <h3 class="props-title">Mgmt Network</h3>
      <form id="mgmt-form" class="props-form">
        <label>IPv4 subnet
          <input type="text" name="ipv4_subnet" value="${_esc(subnet)}"
                 placeholder="172.20.0.0/24" class="props-input">
        </label>
        <label>IPv4 gateway
          <input type="text" name="ipv4_gw" value="${_esc(gw)}"
                 placeholder="172.20.0.254" class="props-input" readonly>
        </label>
        <label>IPv6 subnet
          <input type="text" name="ipv6_subnet" value="${_esc(subnet_v6)}"
                 placeholder="3fff:172:20:0::/64" class="props-input">
        </label>
        <label>IPv6 gateway
          <input type="text" name="ipv6_gw" value="${_esc(gw_v6)}"
                 placeholder="3fff:172:20:0:ffff:ffff:ffff:ffff" class="props-input" readonly>
        </label>
        <label class="props-check">
          <input type="checkbox" name="dhcp" ${dhcp ? 'checked' : ''}>
          <span>Abilita DHCPv4 + RA/DHCPv6 per tutta la rete mgmt</span>
        </label>
        <div class="props-actions">
          <button type="submit" class="btn btn-primary btn-sm">Apply</button>
        </div>
        <p class="mgmt-hint">Nome network e bridge sono generati
        automaticamente dal nome lab (limite Linux 15 char sulle
        interfaces). Nodes without <code>mgmt-ipv4</code>/<code>mgmt-ipv6</code>
        receive an IP auto-assegnato dal pool al deploy. Il servizio DHCP, se attivo,
        vale per tutta la rete: la scelta DHCP/statico resta nel guest. I gateway sono
        derivati dagli ultimi indirizzi delle rispettive subnet.</p>
      </form>
    `;

    const form = _panel.querySelector('#mgmt-form');
    const v4Input = form.querySelector('input[name="ipv4_subnet"]');
    const v4GwInput = form.querySelector('input[name="ipv4_gw"]');
    const v6Input = form.querySelector('input[name="ipv6_subnet"]');
    const v6GwInput = form.querySelector('input[name="ipv6_gw"]');
    let v6Touched = !!(mgmt['ipv6-subnet'] && mgmt['ipv6-subnet'] !== derivedV6);
    const refresh = () => {
      const nextGw4 = _ipv4Gw(v4Input.value.trim());
      if (nextGw4) v4GwInput.value = nextGw4;
      if (!v6Touched) {
        const nextV6 = _deriveIpv6Subnet(v4Input.value.trim());
        if (nextV6) v6Input.value = nextV6;
      }
      const nextGw6 = _ipv6Gw(v6Input.value.trim());
      if (nextGw6) v6GwInput.value = nextGw6;
    };
    v4Input.addEventListener('input', refresh);
    v6Input.addEventListener('input', () => { v6Touched = true; refresh(); });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      _emit('mgmt-update', {
        ipv4_subnet: (fd.get('ipv4_subnet') || '').trim(),
        ipv4_gw:     (fd.get('ipv4_gw')     || '').trim(),
        ipv6_subnet: (fd.get('ipv6_subnet') || '').trim(),
        ipv6_gw:     (fd.get('ipv6_gw')     || '').trim(),
        dhcp:        fd.get("dhcp") === "on",
      });
    });
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

  function _ipv4Gw(cidr) {
    const [ip, prefixRaw] = String(cidr || '').split('/');
    const prefix = Number(prefixRaw);
    const addr = _ipToInt(ip);
    if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 29) return '';
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (addr & mask) >>> 0;
    const size = 2 ** (32 - prefix);
    return _intToIp((network + size - 2) >>> 0);
  }
  function _deriveIpv6Subnet(cidr) {
    const [ip, prefixRaw] = String(cidr || '').split('/');
    const prefix = Number(prefixRaw);
    const addr = _ipToInt(ip);
    if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return '';
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const octets = _intToIp((addr & mask) >>> 0).split('.');
    return `3fff:${octets[0]}:${octets[1]}:${octets[2]}::/64`;
  }
  function _ipToInt(ip) {
    const parts = String(ip || '').split('.').map(x => Number(x));
    if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
  }
  function _intToIp(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function _ipv6Gw(cidr) {
    const [addrRaw, prefixRaw] = String(cidr || '').split('/');
    const prefix = Number(prefixRaw);
    const addr = _ipv6ToBigInt(addrRaw);
    if (addr === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return '';
    const size = 1n << (128n - BigInt(prefix));
    if (size < 2n) return '';
    const mask = ((1n << 128n) - 1n) ^ (size - 1n);
    return _bigIntToIpv6((addr & mask) + size - 1n);
  }
  function _ipv6ToBigInt(addr) {
    let raw = String(addr || '').trim().toLowerCase();
    if (!raw) return null;
    if (raw.includes('.')) {
      const lastColon = raw.lastIndexOf(':');
      const v4 = _ipToInt(raw.slice(lastColon + 1));
      if (v4 === null) return null;
      raw = `${raw.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
    }
    if ((raw.match(/::/g) || []).length > 1) return null;
    const parts = raw.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
    const groups = [...left, ...Array(missing).fill('0'), ...right];
    let out = 0n;
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      out = (out << 16n) + BigInt(parseInt(group, 16));
    }
    return out;
  }
  function _bigIntToIpv6(value) {
    const groups = [];
    for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn).toString(16));
    return groups.join(':');
  }

  return { init, setTopology, clear, on };
})();
