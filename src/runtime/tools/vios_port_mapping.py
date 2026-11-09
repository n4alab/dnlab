"""Read-only qualification of vIOS guest names against QEMU NIC MACs."""
import json
import re


def collect_interface_macs(console, root, warm_ports, timeout=20):
    """Checkpoint each bounded query, including partial output on failure."""
    observed = {}
    records = []
    path = root / 'interface-mac-queries.json'
    def save():
        path.touch(mode=0o600, exist_ok=True)
        path.write_text(json.dumps(records, indent=2) + '\n')
        path.chmod(0o600)
    for index in range(warm_ports + 1):
        interface = f'GigabitEthernet0/{index}'
        command = 'show interfaces ' + interface
        record = {'command': command, 'status': 'pending', 'response': ''}
        records.append(record)
        save()
        try:
            response = console.send(command, timeout=timeout)
            record['response'] = response
            macs = interface_macs(response)
            if set(macs) != {interface}:
                raise RuntimeError('vIOS query returned an unexpected interface: ' + interface)
            observed.update(macs)
            record['status'] = 'passed'
            save()
        except Exception as exc:
            if not record['response'] and getattr(console, 'last_command', None) == command:
                record['response'] = getattr(console, 'last_response', '')
            record.update(status='failed', error_type=type(exc).__name__, error=str(exc))
            save()
            raise
    return observed


def interface_macs(output):
    result = {}
    current = None
    for line in output.splitlines():
        header = re.match(r'^(GigabitEthernet\d+/\d+)\s+is\b', line.strip())
        if header:
            current = header[1]
        elif current:
            match = re.search(r'\baddress is\s+([0-9a-fA-F.:]+)', line)
            if match:
                compact = match[1].replace('.', '').replace(':', '').lower()
                if not re.fullmatch(r'[0-9a-f]{12}', compact) or current in result:
                    raise RuntimeError('vIOS interface MAC is invalid or ambiguous')
                result[current] = ':'.join(compact[i:i+2] for i in range(0, 12, 2))
                current = None
    if not result or len(set(result.values())) != len(result):
        raise RuntimeError('vIOS interface MAC inventory is absent or duplicated')
    return result


def match_slots(guest, observed, warm_ports, management_slot=0):
    if type(management_slot) is not int or not 0 <= management_slot <= warm_ports:
        raise RuntimeError('vIOS management slot is outside the candidate profile')
    if len(guest) != 1:
        raise RuntimeError('vIOS port mapping requires a single QEMU VM')
    nics = {}
    for description in guest[0]['nics']:
        values = dict(part.split('=', 1) for part in description.split(',') if '=' in part)
        backend, mac = values.get('netdev'), values.get('mac')
        if backend in nics or not backend or not mac:
            raise RuntimeError('QEMU port MAC inventory is incomplete or duplicated')
        nics[backend] = mac.lower()
    expected = {f'GigabitEthernet0/{index}' for index in range(warm_ports + 1)}
    if set(observed) != expected or set(nics) != {f'p{index:02d}' for index in range(warm_ports + 1)}:
        raise RuntimeError('vIOS guest port inventory differs from the candidate slot profile')
    rows = []
    for index in range(warm_ports + 1):
        interface, backend = f'GigabitEthernet0/{index}', f'p{index:02d}'
        if observed[interface] != nics[backend]:
            raise RuntimeError('vIOS guest MAC does not match the expected QEMU slot: ' + interface)
        rows.append({'guest_iface': interface, 'qemu_backend': backend, 'linux_iface': 'mgmt0' if index == management_slot else f'eth{index}', 'mac': observed[interface]})
    return rows
