"""Immutable console endpoint proof, captured while original QEMU is pinned.

The domain's already durable XML is the creation intent. The caller must hold
the original pidfd and verify socket/peer before and after journal publication.
This reader performs no socket operations, process discovery or adoption.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath
import stat
from xml.etree import ElementTree as ET

from .manifest import fingerprint, canonical
from .qemu_process import validate_process_record
from .vm_template import fields, require


def _candidate(original, directory, endpoint):
    record = validate_process_record(original['boot']['process_record'])
    fields(endpoint,('device','inode','uid','gid','mode'),'original console endpoint identity')
    require(all(type(v) is int and v >= 0 for v in endpoint.values()) and endpoint['inode'] > 0
            and stat.S_ISSOCK(endpoint['mode']) and endpoint['uid'] == record['uid']
            and endpoint['gid'] == record['gid'] and original['boot']['phase'] == 'running'
            and directory['birth'] == original['birth'] and directory['phase'] == 'ready'
            and directory['definition_sha256'] == original['request_fingerprint'],
            'original running console owner and ready directory required')
    serial = ET.fromstring(original['xml']).findall('devices/serial')
    require(len(serial) == 1 and serial[0].get('type') == 'unix', 'one original Unix console required')
    sources = serial[0].findall('source')
    require(len(sources) == 1 and set(sources[0].attrib) == {'mode','path'}
            and sources[0].get('mode') == 'bind', 'original bound console source required')
    path = PurePosixPath(sources[0].get('path'))
    require(str(path.parent) == directory['spec']['path'], 'original console directory differs')
    definition_id = original['birth']['creator_operation_id'];source_id = original['boot']['source_id']
    return dict(id=fingerprint(dict(definition_id=definition_id,source_id=source_id)),
        definition_id=definition_id,source_id=source_id,birth=deepcopy(original['birth']),
        definition_sha256=fingerprint(original),directory_sha256=fingerprint(directory),
        process_record_sha256=fingerprint(record),path=str(path),endpoint=deepcopy(endpoint),
        peer=dict(pid=record['process']['pid'],uid=record['uid'],gid=record['gid']))


def read(journal, original, directory):
    exists = journal.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vm_console_endpoints'").fetchone()
    if exists is None:return None
    row = journal.db.execute('SELECT * FROM vm_console_endpoints WHERE definition_id=? AND source_id=?',
        (original['birth']['creator_operation_id'],original['boot']['source_id'])).fetchone()
    if row is None:return None
    value = json.loads(row['payload'])
    expected = _candidate(original,directory,value['endpoint'])
    require(fingerprint(value) == row['fingerprint'] and fingerprint(value) == fingerprint(expected)
            and value['id'] == row['id'], 'original console endpoint receipt differs')
    return value


def remember(journal, original, directory, endpoint):
    """Inside the caller's verified transaction; existing proof is immutable."""
    value = _candidate(original,directory,endpoint)
    prior = read(journal,original,directory)
    if prior is not None:
        require(fingerprint(prior) == fingerprint(value), 'original console endpoint cannot be replaced')
        return prior
    journal.db.execute('INSERT INTO vm_console_endpoints VALUES(?,?,?,?,?)',
        (value['id'],value['definition_id'],value['source_id'],canonical(value),fingerprint(value)))
    return value
