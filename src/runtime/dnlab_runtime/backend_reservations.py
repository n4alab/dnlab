"""One logical node owner across Docker and libvirt in the existing journal.

Existing operation/birth records are the reservations: no second ownership
ledger is introduced. Mutating callers must check inside BEGIN IMMEDIATE, so
native submission and VM preparation cannot both win on different connections.
Workload resource release is not implemented, so definition, retirement and
stream records stay held even after definition-only undefine.
"""
import json
import re
from xml.etree import ElementTree as ET

from .manifest import Conflict, RuntimeErrorBase, fingerprint


class BackendOwnershipConflict(Conflict):
    pass


def vm_reservations(journal, lab, node):
    with journal.lock:
        tables = {row[0] for row in journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result = []
        for table in ('vm_definition_intents', 'vm_event_streams', 'vm_storage_intents', 'vm_definition_retirements'):
            if table not in tables:continue
            for row in journal.db.execute(f'SELECT * FROM {table} ORDER BY id'):
                try:
                    value = json.loads(row['payload'])
                    if fingerprint(value) != row['fingerprint']:raise ValueError('integrity')
                    from .vm_events import validate_birth
                    birth = value['birth']; validate_birth(birth)
                    if table == 'vm_definition_intents' and (row['lab'] != birth['lab_id']
                            or row['node'] != birth['node_id'] or row['id'] != birth['creator_operation_id']
                            or row['domain_uuid'] != birth['uuid']):raise ValueError('owner')
                    if table == 'vm_event_streams' and row['domain_uuid'] != birth['uuid']:raise ValueError('owner')
                    if table == 'vm_storage_intents' and (row['domain_uuid'] != birth['uuid']
                            or row['id'] != birth['creator_operation_id']):raise ValueError('owner')
                    if table == 'vm_definition_retirements' and (row['id'] != value['id']
                            or row['definition_id'] != birth['creator_operation_id']
                            or value['definition']['birth'] != birth
                            or value['definition_sha256'] != fingerprint(value['definition'])):raise ValueError('owner')
                except (ValueError, KeyError, TypeError, RuntimeErrorBase) as error:
                    raise BackendOwnershipConflict('VM backend reservation requires qualified recovery') from error
                if birth['lab_id'] == lab and birth['node_id'] == node:
                    result.append({'table': table, 'birth': birth, 'fingerprint': row['fingerprint']})
        return result


def tap_keys(xml):
    """Host-local interface reservations, derived from the original request XML."""
    interfaces = ET.fromstring(xml).findall('devices/interface')
    keys = []
    for interface in interfaces:
        targets = interface.findall('target')
        if (interface.get('type') != 'ethernet' or len(targets) != 1
                or targets[0].get('managed') != 'no'):
            raise BackendOwnershipConflict('qualified unmanaged TAP inventory required')
        name = targets[0].get('dev', '')
        if (not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', name)
                or name.startswith(('vnet', 'vif', 'macvtap', 'macvlan'))):
            raise BackendOwnershipConflict('qualified TAP name required')
        keys.append('interface:' + name)
    if not keys or len(set(keys)) != len(keys):
        raise BackendOwnershipConflict('distinct nonempty TAP inventory required')
    return set(keys)


def storage_keys(xml):
    """Reserve writable disk/NVRAM paths, never immutable backing assets."""
    from .libvirt_xml import absolute
    root = ET.fromstring(xml)
    paths = []
    for disk in root.findall('devices/disk'):
        sources = disk.findall('source')
        if (disk.get('type') != 'file' or disk.get('device') != 'disk'
                or len(sources) != 1 or set(sources[0].attrib) != {'file'}
                or disk.find('readonly') is not None or disk.find('shareable') is not None):
            raise BackendOwnershipConflict('exclusive writable VM disk paths required')
        paths.append(absolute(sources[0].get('file')))
    for nvram in root.findall('os/nvram'):
        paths.append(absolute(nvram.text))
    if not paths or len(paths) != len(set(paths)):
        raise BackendOwnershipConflict('distinct writable VM storage paths required')
    return {'storage:' + path for path in paths}


def verify_tap_reservations(journal, birth, xml):
    expected = tap_keys(xml) | storage_keys(xml)
    rows = journal.db.execute('SELECT key,operation_id FROM resources WHERE lab=? AND node=?',
        (birth['lab_id'], birth['node_id'])).fetchall()
    if ({row['key'] for row in rows} != expected
            or any(row['operation_id'] != birth['creator_operation_id'] for row in rows)):
        raise BackendOwnershipConflict('original VM TAP reservations differ or storage reservations changed; qualified recovery required')


def available(journal, lab, node, backend, *, vm_birth=None):
    if backend not in ('docker', 'libvirt'):raise BackendOwnershipConflict('unknown node backend')
    with journal.lock:
        reservations = vm_reservations(journal, lab, node)
        if backend == 'docker':
            if reservations:raise BackendOwnershipConflict('node is reserved by VM definition or recovery')
            return reservations
        if vm_birth is None or any(row['birth'] != vm_birth for row in reservations):
            raise BackendOwnershipConflict('node is reserved by another VM generation')
        current = journal.node(lab, node)
        if current and current['state'] != 'stopped':
            raise BackendOwnershipConflict('node is owned by a container workload')
        pending = journal.db.execute("SELECT 1 FROM operations WHERE lab=? AND node=? AND phase NOT IN ('completed','cancelled','failed') LIMIT 1", (lab,node)).fetchone()
        birth = journal.db.execute('SELECT phase FROM workload_generations WHERE lab=? AND node=? ORDER BY generation DESC LIMIT 1', (lab,node)).fetchone()
        resources = journal.db.execute('SELECT 1 FROM resources WHERE lab=? AND node=? LIMIT 1', (lab,node)).fetchone()
        definitions = [row for row in reservations if row['table'] == 'vm_definition_intents']
        if definitions:
            original = journal.db.execute('SELECT payload FROM vm_definition_intents WHERE id=?',
                (vm_birth['creator_operation_id'],)).fetchone()
            verify_tap_reservations(journal, vm_birth, json.loads(original['payload'])['xml'])
            resources = None
        stop = journal.db.execute('SELECT 1 FROM stop_reservations WHERE lab=? AND node=? LIMIT 1', (lab,node)).fetchone()
        if pending or resources or stop or birth and birth['phase'] != 'cleaned' or current and birth is None:
            raise BackendOwnershipConflict('node container operation or qualified cleanup is still pending')
        return reservations
