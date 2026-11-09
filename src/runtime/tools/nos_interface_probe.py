"""Structural guest/NIC and kernel TC checks; no NOS traffic qualification."""
from __future__ import annotations

import json


def fields(value):
    return dict(part.split('=', 1) for part in value.split(',') if '=' in part)


def tc_signature(rows):
    result = []
    for row in rows:
        options = row.get('options') or {}
        if not options:
            continue  # iproute2 may emit a second summary row for each filter.
        actions = [{key: action[key] for key in ('kind', 'mirred_action', 'direction', 'to_dev', 'csum', 'control_action') if key in action} for action in options.get('actions', [])]
        result.append({'protocol': row.get('protocol'), 'pref': row.get('pref'), 'kind': row.get('kind'), 'keys': options.get('keys', {}), 'actions': actions})
    return result


def snapshot(backend, request, spec, port, warm_ports, data_zero=False):
    container = port.container()
    result = {'links': {}, 'tc': {}}
    names = ['mgmt0', 'dmu0', 'dnlab-mgmt', 'tap0']
    if data_zero:
        names.extend(['eth0', 'wmp0'])
    for index in range(1, warm_ports + 1):
        names.extend([f'eth{index}', f'wmp{index}', f'tap{index}'])
    with backend.namespace(request, spec, container) as ns:
        for name in names:
            link = backend.linux.link(name, ns)
            if link is None:
                raise RuntimeError('guest interface fixture missing: ' + name)
            result['links'][name] = {key: link[key] for key in ('ifindex', 'address', 'link_index', 'master') if key in link}
            result['links'][name]['kind'] = link.get('linkinfo', {}).get('info_kind')
            if name == 'mgmt0' or name.startswith(('tap', 'eth')):
                rows = json.loads(backend.linux.run(['nsenter', f'--net={ns}', '--', 'tc', '-j', 'filter', 'show', 'dev', name, 'ingress'], pass_fds=(ns.fd,)))
                result['tc'][name] = tc_signature(rows)
    return result


def validate_selected(guest, datapath, mac, warm_ports, slot):
    if len(guest) != 1 or type(slot) is not int or not 0 <= slot <= warm_ports:
        raise RuntimeError('selected management requires a single VM and valid slot')
    nics = {fields(nic).get('netdev'): fields(nic) for nic in guest[0]['nics']}
    backends = {fields(value).get('id'): fields(value) for value in guest[0]['netdevs']}
    def redirects(name):
        return {action.get('to_dev') for row in datapath['tc'][name] for action in row['actions'] if action.get('kind') == 'mirred' and action.get('mirred_action') == 'redirect'}
    if nics.get(f'p{slot:02d}', {}).get('mac') != mac:
        raise RuntimeError('selected management guest MAC differs from stable port')
    if redirects('mgmt0') != {f'tap{slot}'} or redirects(f'tap{slot}') != {'mgmt0'}:
        raise RuntimeError('management TC path differs from selected guest slot')
    for index in range(warm_ports + 1):
        expected_script = '/etc/tc-tap-mgmt-ifup' if index == slot else '/etc/tc-tap-ifup'
        backend = backends.get(f'p{index:02d}', {})
        if backend.get('ifname') != f'tap{index}' or backend.get('script') != expected_script:
            raise RuntimeError('selected guest backend differs from reserved slot profile')
        if index == slot:
            if index and redirects(f'eth{index}'):
                raise RuntimeError('reserved management slot also has a data TC path')
            continue
        if redirects(f'eth{index}') != {f'tap{index}'} or redirects(f'tap{index}') != {f'eth{index}'}:
            raise RuntimeError('selected management changed another data TC path')
        if nics.get(f'p{index:02d}', {}).get('mac') != datapath['links'][f'eth{index}']['address']:
            raise RuntimeError('data guest MAC differs from its own endpoint')


def validate_oob(guest, datapath, mac, warm_ports):
    if len(guest) != 1:
        raise RuntimeError('OOB structural probe requires one QEMU VM')
    nics = {fields(nic).get('netdev'): fields(nic) for nic in guest[0]['nics']}
    backends = {fields(value).get('id'): fields(value) for value in guest[0]['netdevs']}
    if nics.get('p00', {}).get('mac') != mac or backends.get('p00', {}).get('ifname') != 'tap0' or backends.get('p00', {}).get('script') != '/etc/tc-tap-mgmt-ifup':
        raise RuntimeError('QEMU management NIC does not map exclusively to tap0')
    for index in range(1, warm_ports + 1):
        if backends.get(f'p{index:02d}', {}).get('ifname') != f'tap{index}' or backends.get(f'p{index:02d}', {}).get('script') != '/etc/tc-tap-ifup':
            raise RuntimeError('data NIC/backend is not separate from management')
    def redirects(name):
        return {action.get('to_dev') for row in datapath['tc'][name] for action in row['actions'] if action.get('kind') == 'mirred' and action.get('mirred_action') == 'redirect'}
    if redirects('mgmt0') != {'tap0'} or redirects('tap0') != {'mgmt0'}:
        raise RuntimeError('stable management TC path does not use only OOB tap0')
    for index in range(1, warm_ports + 1):
        if redirects(f'eth{index}') != {f'tap{index}'} or redirects(f'tap{index}') != {f'eth{index}'}:
            raise RuntimeError('warm data TC path differs from its own data NIC')
    if not any(row['keys'].get('ip_proto') == 'tcp' and row['keys'].get('dst_port') == {'start': 5000, 'end': 5007} and any(action.get('control_action', {}).get('type') == 'pass' for action in row['actions']) for row in datapath['tc']['mgmt0']):
        raise RuntimeError('management console exception missing')
