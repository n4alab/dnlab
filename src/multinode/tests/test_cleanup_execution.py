"""Pinned execution receipts only; all current inventories/observers are fake."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_execution import ExecutionReceipts, canonical_digest, SOURCES
from cleanup_compatibility import (
    CleanupAttestation, CleanupCompatibilityError, ENTRYPOINTS, require_qualified_cleanup,
)
from tests.test_cleanup_compatibility_fixture import Engine, daemon


@pytest.fixture
def receipts():
    blobs, pins = {}, {}
    def store(path, value):
        data = json.dumps(value).encode()
        blobs[path] = data
        return {'path': path, 'sha256': hashlib.sha256(data).hexdigest()}
    sources = {role: {name: {'path': '/qualified/' + name + '.py', 'sha256': 'a' * 64}
                      for name in names} for role, names in SOURCES.items()}
    def result(role):
        return {'status': 'artifact_callbacks_exercised', 'role': role,
                'sources': sources[role], 'executed_entrypoints': sorted(ENTRYPOINTS[role]),
                'scope': 'custom-protection-synthetic-v1', 'gate_allowed': False}
    for role in ('daemon', 'multinode'):
        image = 'sha256:' + ('d' if role == 'daemon' else 'e') * 64
        report = {'status': 'passed', 'role': role, 'cleanup_verified': True, 'gate_allowed': False,
                  'image': image, 'proof': {'image': image, 'role': role, 'nonce': '1' * 32,
                                           'result': result(role)}}
        pins[role] = {'report': store('/proof/' + role + '.json', report), 'image': image}
    rows = [{'requested': row['path'], 'resolved': row['path'], 'kind': 'file',
             'sha256': row['sha256'], 'links': [], 'metadata': [1, 2, 33188, 0, 0, 100, 10, 11]}
            for row in sources['native'].values()]
    for path, digest in (('/qualified/python', 'b' * 64), ('/qualified/bootstrap', 'c' * 64)):
        rows.append({'requested': path, 'resolved': path, 'kind': 'file', 'sha256': digest,
                     'links': [], 'metadata': [1, 3, 33261, 0, 0, 100, 10, 11]})
    rows.extend([{'requested': '/qualified/site', 'resolved': '/qualified/site', 'kind': 'directory',
                  'links': [], 'names': ['hook.pth', 'finder.py']},
                 {'requested': '/qualified/site/custom.py', 'resolved': '/qualified/site/custom.py',
                  'kind': 'absent', 'links': []}])
    before = {'sources': rows, 'bootstrap': rows[4], 'interpreter': rows[3]}
    native = {'status': 'native_role_execution_qualified', 'gate_allowed': False,
              'original_file_and_startup_proofs_unchanged': True,
              'probe': {'status': 'native_role_callbacks_exercised', 'gate_allowed': False,
                        'result': result('native'), 'bootstrap_sha256': 'c' * 64,
                        'flags': {'isolated': 1, 'ignore_environment': 1, 'no_site': 0,
                                  'no_user_site': 1, 'safe_path': True, 'dont_write_bytecode': 1},
                        'interpreter': {'executable': '/qualified/python', 'prefix': '/qualified',
                                        'version': [3, 13, 5], 'implementation': 'cpython',
                                        'cache_tag': 'cpython-313'}}}
    pins['native'] = {'report': store('/proof/native.json', native),
                      'before': store('/proof/before.json', before),
                      'after': store('/proof/after.json', before),
                      'process': store('/proof/process.json', {'returncode': 0, 'timed_out': False}),
                      'startup_source_count': 7}
    provider = ExecutionReceipts(pins, read=lambda path: blobs[path])
    actors = {role: {'qualification_sha256': pin['report']['sha256'],
                     'artifact_sha256': canonical_digest(provider.describe(role))}
              for role, pin in pins.items()}
    return provider, pins, blobs, actors, store


def test_all_roles_authenticate_reports_and_recheck_evidence(receipts):
    provider, pins, blobs, actors, _ = receipts
    for role in ENTRYPOINTS:
        proof = provider(role, actors[role])
        assert proof['executed_entrypoints'] == sorted(ENTRYPOINTS[role])
        assert proof['receipt_sha256'] == pins[role]['report']['sha256']
    blobs[pins['daemon']['report']['path']] += b' '
    with pytest.raises(ValueError, match='evidence digest differs'):
        provider('daemon', actors['daemon'])


@pytest.mark.parametrize('field', ['qualification_sha256', 'artifact_sha256'])
def test_actor_cannot_substitute_receipt_or_artifact(receipts, field):
    provider, _, _, actors, _ = receipts
    actors['native'][field] = 'f' * 64
    with pytest.raises(ValueError): provider('native', actors['native'])


@pytest.mark.parametrize('change', ['coverage', 'duplicate-entry', 'image', 'role', 'cleanup', 'status', 'source'])
def test_semantically_invalid_container_report_is_refused(receipts, change):
    _, pins, blobs, _, store = receipts
    pin = pins['multinode']
    report = json.loads(blobs[pin['report']['path']])
    if change == 'coverage': report['proof']['result']['executed_entrypoints'].remove('cli-sync')
    elif change == 'duplicate-entry': report['proof']['result']['executed_entrypoints'].append('cli-sync')
    elif change == 'image': report['proof']['image'] = 'sha256:' + 'f' * 64
    elif change == 'role': report['role'] = 'daemon'
    elif change == 'cleanup': report['cleanup_verified'] = False
    elif change == 'status': report['status'] = 'failed'
    else: report['proof']['result']['sources'].pop('api')
    pin['report'] = store(pin['report']['path'], report)
    with pytest.raises(ValueError): ExecutionReceipts(pins, read=lambda path: blobs[path]).describe('multinode')


@pytest.mark.parametrize('change', ['timeout', 'exit', 'inputs', 'bootstrap', 'binary', 'coverage', 'flags', 'count'])
def test_native_partial_or_changed_execution_is_refused(receipts, change):
    _, pins, blobs, _, store = receipts
    pin = pins['native']
    key = 'process' if change in ('timeout', 'exit') else 'after' if change == 'inputs' else 'report'
    value = json.loads(blobs[pin[key]['path']])
    if change == 'timeout': value['timed_out'] = True
    elif change == 'exit': value['returncode'] = 1
    elif change == 'inputs': value['sources'][0]['metadata'][1] += 1
    elif change == 'bootstrap': value['probe']['bootstrap_sha256'] = 'f' * 64
    elif change == 'binary': value['probe']['interpreter']['executable'] = '/other/python'
    elif change == 'coverage': value['probe']['result']['executed_entrypoints'] = ['cli-cleanup']
    elif change == 'flags': value['probe']['flags']['dont_write_bytecode'] = 0
    else: pin['startup_source_count'] += 1
    pin[key] = store(pin[key]['path'], value)
    with pytest.raises(ValueError): ExecutionReceipts(pins, read=lambda path: blobs[path]).describe('native')


def test_descriptors_preserve_native_import_layout_and_bind_to_existing_attestation(receipts):
    provider, _, _, basic, _ = receipts
    descriptor = provider.describe('native')
    assert {'kind', 'sources', 'startup_assets', 'interpreter', 'bootstrap'} == set(descriptor)
    assert next(r for r in descriptor['startup_assets'] if r['kind'] == 'directory')['names'] == ['finder.py', 'hook.pth']
    context = dict(gate_id='gate', lab_id='lab', host_id='master', coordinator_id='only',
                   boot_id='boot', window_id='window', image_build_hold_sha256='1' * 64)
    actors = {role: {**value, 'container_id': None if role == 'native' else ('a' if role == 'daemon' else 'b') * 64,
                     'generation_sha256': '2' * 64} for role, value in basic.items()}
    current = {'context': context,
               'actors': {role: {k: v for k, v in actor.items() if k != 'qualification_sha256'}
                          for role, actor in actors.items()},
               'window_active': True, 'native_cli_excluded': True, 'image_build_held': True,
               'unexpected_actors': []}
    api = Engine([daemon(), daemon(Id='b' * 64, Names=['/multinode'],
                  Labels={'com.docker.compose.service': 'multinode'}, Command='')])
    with pytest.raises(CleanupCompatibilityError): require_qualified_cleanup(api)
    token = CleanupAttestation(context, actors, verify_execution=provider, observe=lambda: deepcopy(current))
    assert token.recheck(api)['qualified'] is True
    current['actors']['native']['generation_sha256'] = 'f' * 64
    with pytest.raises(CleanupCompatibilityError): token.recheck(api)
