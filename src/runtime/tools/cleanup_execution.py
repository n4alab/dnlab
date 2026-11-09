"""Authenticate completed synthetic cleanup qualifications for a trusted caller.

Pins come from reviewed local qualification artifacts, never a gate request.
This provider verifies execution evidence only. Current process provenance,
window/hold observations and runtime authorization remain separate requirements.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath, Path
import re

from cleanup_compatibility import ENTRYPOINTS

SOURCES = {
    'daemon': {'cleanup', 'daemon_cli'},
    'multinode': {'cleanup', 'daemon_cli', 'cli', 'api'},
    'native': {'cleanup', 'daemon_cli', 'cli'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def absolute(value):
    return (type(value) is str and value.startswith('/')
            and '..' not in value.split('/') and str(PurePosixPath(value)) == value)


def source_map(value, role):
    require(type(value) is dict and set(value) == SOURCES[role], 'complete callback source set required')
    for row in value.values():
        require(type(row) is dict and set(row) == {'path', 'sha256'}
                and absolute(row['path']) and sha(row['sha256']), 'qualified callback source required')
    require(len({row['path'] for row in value.values()}) == len(value), 'distinct callback source paths required')
    return deepcopy(value)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate qualification JSON key')
        result[key] = value
    return result


def _result(value, role):
    require(type(value) is dict and value.get('status') == 'artifact_callbacks_exercised'
            and value.get('role') == role, 'completed callback execution required')
    entries = value.get('executed_entrypoints')
    require(type(entries) is list and all(type(entry) is str for entry in entries)
            and len(entries) == len(set(entries)) and set(entries) == ENTRYPOINTS[role],
            'cleanup execution coverage incomplete')
    require(value.get('scope') == 'custom-protection-synthetic-v1'
            and value.get('gate_allowed') is False, 'synthetic execution scope differs')
    return source_map(value.get('sources'), role)


def startup_assets(rows, count):
    require(type(rows) is list and len(rows) == count, 'qualified native startup set incomplete')
    result, seen = [], set()
    for row in rows:
        require(type(row) is dict and absolute(row.get('requested'))
                and absolute(row.get('resolved')) and row['requested'] not in seen,
                'distinct native source paths required')
        seen.add(row['requested'])
        kind = row.get('kind')
        require(kind in ('file', 'directory', 'absent'), 'native source kind differs')
        links = row.get('links')
        require(type(links) is list and all(type(link) is dict and absolute(link.get('path'))
                and type(link.get('target')) is str for link in links), 'native link proof incomplete')
        asset = {key: row[key] for key in ('requested', 'resolved', 'kind')}
        asset['links'] = [{'path': link['path'], 'target': link['target']} for link in links]
        if kind == 'file':
            require(sha(row.get('sha256')), 'native file hash required')
            asset['sha256'] = row['sha256']
        elif kind == 'directory':
            names = row.get('names')
            require(type(names) is list and all(type(name) is str for name in names)
                    and len(names) == len(set(names)), 'native directory inventory required')
            asset['names'] = sorted(names)
        result.append(asset)
    # Content/import layout is an artifact; kernel identities belong to the observer's generation proof.
    return sorted(result, key=lambda row: row['requested'])


def read_evidence(path):
    with Path(path).open('rb') as stream:
        return stream.read(2 * 1024 * 1024 + 1)


class ExecutionReceipts:
    """Pinned raw reports -> CleanupAttestation.verify_execution provider.

    The returned artifact descriptor must also be reconstructed by the trusted
    current observer. Reading a historical receipt never proves current state.
    Every call reauthenticates the raw evidence; no acceptance cache or adoption.
    """

    def __init__(self, pins, *, read=read_evidence):
        require(type(pins) is dict and set(pins) == set(ENTRYPOINTS), 'all cleanup receipt pins required')
        for role, pin in pins.items():
            expected = ({'report', 'image'} if role != 'native' else
                        {'report', 'before', 'after', 'process', 'startup_source_count'})
            require(type(pin) is dict and set(pin) == expected, 'complete role receipt pin required')
            for key in expected - {'image', 'startup_source_count'}:
                reference = pin[key]
                require(type(reference) is dict and set(reference) == {'path', 'sha256'}
                        and absolute(reference['path']) and sha(reference['sha256']), 'pinned evidence reference required')
            if role == 'native':
                require(type(pin['startup_source_count']) is int and 0 < pin['startup_source_count'] <= 512,
                        'bounded native startup set required')
            else:
                require(type(pin['image']) is str and pin['image'].startswith('sha256:')
                        and sha(pin['image'][7:]), 'pinned qualified image required')
        require(callable(read), 'trusted evidence reader required')
        self._pins, self._read = deepcopy(pins), read

    def _load(self, reference):
        raw = self._read(reference['path'])
        require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024, 'bounded raw qualification required')
        require(hashlib.sha256(raw).hexdigest() == reference['sha256'], 'qualification evidence digest differs')
        return json.loads(raw, object_pairs_hook=_pairs)

    def describe(self, role):
        require(role in self._pins, 'unknown cleanup role')
        pin = self._pins[role]
        report = self._load(pin['report'])
        require(type(report) is dict and report.get('gate_allowed') is False, 'non-admitting qualification report required')
        if role != 'native':
            require(report.get('status') == 'passed' and report.get('role') == role
                    and report.get('cleanup_verified') is True and report.get('image') == pin['image'],
                    'successful isolated container qualification required')
            proof = report.get('proof', {})
            require(type(proof) is dict and proof.get('role') == role and proof.get('image') == pin['image']
                    and type(proof.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}', proof['nonce']),
                    'container qualification identity differs')
            sources = _result(proof.get('result'), role)
            return {'kind': 'container', 'image': pin['image'], 'sources': sources}
        require(report.get('status') == 'native_role_execution_qualified'
                and report.get('original_file_and_startup_proofs_unchanged') is True,
                'completed native execution and rechecks required')
        process = self._load(pin['process'])
        require(type(process.get('returncode')) is int and process['returncode'] == 0
                and process.get('timed_out') is False, 'native process did not complete successfully')
        before, after = self._load(pin['before']), self._load(pin['after'])
        require(canonical_digest(before) == canonical_digest(after), 'native qualification inputs changed')
        proof = report.get('probe', {})
        require(proof.get('status') == 'native_role_callbacks_exercised' and proof.get('gate_allowed') is False,
                'native callback proof missing')
        require(proof.get('flags') == {'isolated': 1, 'ignore_environment': 1, 'no_site': 0,
                'no_user_site': 1, 'safe_path': True, 'dont_write_bytecode': 1},
                'qualified native startup flags required')
        sources = _result(proof.get('result'), role)
        assets = startup_assets(before.get('sources'), pin['startup_source_count'])
        by_path = {row['requested']: row for row in assets}
        for row in sources.values():
            require(by_path.get(row['path'], {}).get('sha256') == row['sha256'], 'native callback source is not in startup proof')
        bootstrap, binary = before.get('bootstrap', {}), before.get('interpreter', {})
        interpreter = proof.get('interpreter')
        require(type(interpreter) is dict and set(interpreter) == {
            'executable', 'prefix', 'version', 'implementation', 'cache_tag'}, 'native interpreter profile incomplete')
        require(interpreter['executable'] == binary.get('requested') and sha(binary.get('sha256'))
                and by_path.get(binary['requested'], {}).get('sha256') == binary['sha256'],
                'native interpreter is not in qualified sources')
        require(absolute(bootstrap.get('requested')) and sha(proof.get('bootstrap_sha256'))
                and bootstrap.get('sha256') == proof['bootstrap_sha256']
                and by_path.get(bootstrap['requested'], {}).get('sha256') == proof['bootstrap_sha256'],
                'native bootstrap is not in qualified sources')
        return {'kind': 'native', 'sources': sources, 'startup_assets': assets,
                'interpreter': {**deepcopy(interpreter), 'binary_sha256': binary['sha256']},
                'bootstrap': {'path': bootstrap['requested'], 'sha256': bootstrap['sha256']}}

    def __call__(self, role, actor):
        require(role in self._pins, 'unknown cleanup role')
        receipt = self._pins[role]['report']['sha256']
        require(actor.get('qualification_sha256') == receipt, 'actor qualification pin differs')
        descriptor = self.describe(role)
        artifact = canonical_digest(descriptor)
        require(actor.get('artifact_sha256') == artifact, 'executed artifact differs from actor')
        return {'receipt_sha256': receipt, 'artifact_sha256': artifact,
                'executed_entrypoints': sorted(ENTRYPOINTS[role]),
                'scope': 'custom-protection-synthetic-v1'}
