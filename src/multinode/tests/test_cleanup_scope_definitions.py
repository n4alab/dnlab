"""Scope/config binding with synthetic data only, no live Docker or files."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_scope_definitions import ScopeDefinitions, CONFIG_FIELDS, ROOT, TOKEN


@pytest.fixture
def definitions():
    cid = 'a' * 64
    selector = dict(Privileged=False, Devices=None, DeviceCgroupRules=None,
                    CgroupParent='', CgroupnsMode='private', CapAdd=None, CapDrop=None)
    profile = {'configuration': selector,
        'files': {suffix: {'template': text, 'mode': 0o644, 'uid': 0, 'gid': 0}
            for suffix, text in [('', '[Unit]\nDescription=container ' + TOKEN + '\n[Scope]\nDelegate=yes\n'),
             ('.d/50-DeviceAllow.conf', '[Scope]\nDeviceAllow=\n'),
             ('.d/50-DevicePolicy.conf', '[Scope]\nDevicePolicy=strict\n')]},
        'directory': {'mode': 0o755, 'uid': 0, 'gid': 0}}
    privileged = deepcopy(profile)
    privileged['configuration']['Privileged'] = True
    privileged['files']['.d/50-DevicePolicy.conf']['template'] = '[Scope]\nDevicePolicy=auto\n'
    verifier = ScopeDefinitions([profile, privileged])
    scope = ROOT + '/docker-' + cid + '.scope'
    bodies, rows = {}, []
    for suffix, value in profile['files'].items():
        raw = value['template'].replace(TOKEN, cid).encode()
        bodies[scope + suffix] = raw
        rows.append({'source_id': scope + suffix, 'kind': 'file', 'sha256': hashlib.sha256(raw).hexdigest(),
                     'metadata': [1, 2, 0o100644, 0, 0, len(raw), 3, 4]})
    rows.append({'source_id': scope + '.d', 'kind': 'directory', 'metadata': [1, 5, 0o40755, 0, 0, 10, 20, 30],
                 'names': ['50-DeviceAllow.conf', '50-DevicePolicy.conf']})
    inspect = {'Id': cid, 'HostConfig': deepcopy(selector)}
    return verifier, cid, inspect, rows, bodies


def test_exact_profile_is_bound_to_original_container_config_and_rows(definitions):
    verifier, cid, inspect, rows, bodies = definitions
    result = verifier.verify(cid, inspect, rows, bodies)
    assert result['container_id'] == cid and result['definition_profile_sha256'] == verifier.sha256
    assert set(result) == {'container_id', 'definition_profile_sha256', 'rows_sha256'}


@pytest.mark.parametrize('change', ['id', 'privilege', 'devices', 'missing-config', 'directive',
    'owner', 'mode', 'symlink', 'size', 'missing-file', 'extra-file', 'dropin-name'])
def test_config_definition_or_identity_conflicts_are_rejected(definitions, change):
    verifier, cid, inspect, rows, bodies = definitions
    if change == 'id': inspect['Id'] = 'b' * 64
    elif change == 'privilege': inspect['HostConfig']['Privileged'] = True
    elif change == 'devices': inspect['HostConfig']['Devices'] = [{'PathOnHost': '/foreign'}]
    elif change == 'missing-config': inspect['HostConfig'].pop('CgroupnsMode')
    elif change == 'directive':
        path = next(iter(bodies)); bodies[path] += b'\nOnFailure=foreign.service\n'
        rows[0]['sha256'] = hashlib.sha256(bodies[path]).hexdigest()
        rows[0]['metadata'][5] = len(bodies[path])
    elif change == 'owner': rows[0]['metadata'][3] = 1000
    elif change == 'mode': rows[0]['metadata'][2] = 0o100666
    elif change == 'symlink': rows[0]['kind'] = 'symlink'
    elif change == 'size': rows[0]['metadata'][5] += 1
    elif change == 'missing-file': bodies.pop(next(iter(bodies)))
    elif change == 'extra-file': bodies['/foreign'] = b'foreign'
    else: rows[-1]['names'].append('unknown.conf')
    with pytest.raises(ValueError): verifier.verify(cid, inspect, rows, bodies)


def test_unknown_configuration_does_not_learn_new_definition(definitions):
    verifier, cid, inspect, rows, bodies = definitions
    inspect['HostConfig']['CapAdd'] = ['NET_ADMIN']
    with pytest.raises(ValueError, match='not qualified'): verifier.verify(cid, inspect, rows, bodies)
    inspect['HostConfig']['CapAdd'] = None
    assert verifier.verify(cid, inspect, rows, bodies)['definition_profile_sha256'] == verifier.sha256
