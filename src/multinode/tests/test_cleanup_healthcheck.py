"""Original status healthcheck only; all IO is synthetic."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_census import CleanupCensus, processes
from cleanup_container_observer import config_digest
from cleanup_execution import canonical_digest
from cleanup_healthcheck import (ARGV, COMMAND_SHA256, TEST, StatusHealthcheck,
                                qualify_initial_processes, qualify_processes)


@pytest.fixture
def healthcheck():
    context = {'boot_id': 'current', 'namespaces': {'user': {'device': 4, 'inode': 7}}}
    spaces = {key: {'device': 4, 'inode': index, 'link': key + ':[' + str(index) + ']'}
              for index, key in enumerate(('pid', 'mnt', 'net'), 10)}
    profile = dict(container_id='a' * 64, exe='/usr/local/bin/python3.13',
                   exe_sha256='b' * 64, cwd='/opt/dnlab-multinode',
                   import_env_sha256='c' * 64, cmdline_sha256='d' * 64,
                   copies={'/fixture/source.py': 'e' * 64})
    inspect = dict(Id=profile['container_id'], Image='sha256:' + 'f' * 64,
                   Config={'Healthcheck': {'Test': deepcopy(TEST)}}, HostConfig={},
                   Mounts=[], Path='python', Args=['start'],
                   State={'Running': True, 'Pid': 41})
    profile['config_sha256'] = config_digest(inspect)
    descriptor = {'kind': 'container', 'image': inspect['Image'], 'sources': {}}
    original = dict(pid=41, start_ticks='100', cmdline_sha256=profile['cmdline_sha256'],
                    exe=profile['exe'], cwd=profile['cwd'],
                    import_env_sha256=profile['import_env_sha256'],
                    namespaces=spaces, cgroup='0::/system.slice/docker-' + profile['container_id'] + '.scope\n')
    row = dict(pid=99, start_ticks='300', cmdline_sha256=COMMAND_SHA256)
    def capture_for(view):
        return {'process': {**deepcopy(view), 'credentials': {'uid': 0, 'gid': 0},
                            'user_namespace': deepcopy(context['namespaces']['user'])},
                'sources': {path: {'sha256': digest} for path, digest in profile['copies'].items()},
                'executable': {'sha256': profile['exe_sha256']}}
    main = dict(container_id=profile['container_id'], artifact_sha256=canonical_digest(descriptor),
                generation_sha256='1' * 64, evidence={'process': deepcopy(original)})
    captures = {41: capture_for(original), 99: capture_for({**original, **row})}
    calls = []
    class API:
        def inspect(self, identity):
            assert identity == profile['container_id']
            calls.append('inspect')
            return deepcopy(inspect)
    class Process:
        @contextmanager
        def capture(self, pid, identity, copies):
            assert identity == profile['container_id'] and copies == profile['copies']
            calls.append(('pin', pid))
            try:
                yield deepcopy(captures[pid])
            finally:
                calls.append(('unpin', pid))
    current_main = deepcopy(main)
    def observe(*args):
        calls.append('main')
        return deepcopy(current_main)
    proof = StatusHealthcheck(api=API(), profile=profile, descriptor=descriptor,
        expected_main=main, context=context, read_context=lambda: deepcopy(context),
        process=Process(), observe_main=observe)
    return proof, row, captures, inspect, current_main, context, calls


def test_exact_status_is_pinned_with_original_main(healthcheck):
    proof, row, _, _, _, _, calls = healthcheck
    result = proof(row)
    assert result['process'] == row and result['main_process']['pid'] == 41
    assert calls.count('main') == 3 and calls.count('inspect') == 3
    assert calls.index(('pin', 41)) < calls.index(('pin', 99))
    assert calls.index(('unpin', 99)) < calls.index(('unpin', 41))
    assert COMMAND_SHA256 == '0012d256f068da22ae69bce9b7c62bf3951c0e7b1caea39a6c60eceb3a3ffbb8'


@pytest.mark.parametrize('change', [
    'pid', 'start', 'command', 'cgroup', 'namespace', 'user_namespace', 'uid',
    'exe', 'environment', 'cwd', 'binary', 'source', 'missing_source',
    'container', 'image', 'healthcheck', 'config', 'main', 'boot',
])
def test_foreign_or_incomplete_healthcheck_rejected(healthcheck, change):
    proof, row, captures, inspect, main, context, _ = healthcheck
    child = captures[99]
    if change == 'pid': child['process']['pid'] = 98
    elif change == 'start': child['process']['start_ticks'] = '301'
    elif change == 'command': row['cmdline_sha256'] = '9' * 64
    elif change == 'cgroup': child['process']['cgroup'] = 'foreign'
    elif change == 'namespace': child['process']['namespaces']['net']['inode'] += 1
    elif change == 'user_namespace': child['process']['user_namespace']['inode'] += 1
    elif change == 'uid': child['process']['credentials']['uid'] = 1
    elif change == 'exe': child['process']['exe'] = '/other/python'
    elif change == 'environment': child['process']['import_env_sha256'] = '9' * 64
    elif change == 'cwd': child['process']['cwd'] = '/other'
    elif change == 'binary': child['executable']['sha256'] = '9' * 64
    elif change == 'source': child['sources']['/fixture/source.py']['sha256'] = '9' * 64
    elif change == 'missing_source': child['sources'].clear()
    elif change == 'container': inspect['Id'] = '9' * 64
    elif change == 'image': inspect['Image'] = 'sha256:' + '9' * 64
    elif change == 'healthcheck': inspect['Config']['Healthcheck']['Test'] = ['CMD', 'true']
    elif change == 'config': inspect['HostConfig']['Privileged'] = True
    elif change == 'main': main['generation_sha256'] = '9' * 64
    else: context['boot_id'] = 'new'
    with pytest.raises(ValueError): proof(row)


def test_original_rechecked_while_child_pinned_and_after_unpin(healthcheck):
    proof, row, _, _, main, _, calls = healthcheck
    original = proof._observe
    def replace(*args):
        if ('pin', 99) in calls:
            main['generation_sha256'] = '9' * 64
        return original(*args)
    proof._observe = replace
    with pytest.raises(ValueError, match='generation changed'): proof(row)
    assert ('unpin', 99) in calls and ('unpin', 41) in calls


def test_capture_loss_is_conflict_not_implicit_retry(healthcheck):
    proof, row, *_ = healthcheck
    class Gone:
        @contextmanager
        def capture(self, *args):
            raise ValueError('process exited or pidfd observation failed')
            yield
    proof._process = Gone()
    with pytest.raises(ValueError, match='process exited'): proof(row)


@pytest.mark.parametrize('present_second', [True, False])
def test_census_records_healthcheck_without_changing_stable_primary_set(healthcheck, present_second):
    proof, row, _, _, main, context, calls = healthcheck
    rows = [dict(pid=41, start_ticks='100', argv=['dnlab-lab-cleanup', 'start']),
            dict(pid=42, start_ticks='200', argv=['dnlab-multinode-api'])]
    expected = processes(rows)
    # Match the synthetic main invocation to the census's synthetic argv.
    proof._main['evidence']['process']['cmdline_sha256'] = expected[0]['cmdline_sha256']
    main['evidence']['process']['cmdline_sha256'] = expected[0]['cmdline_sha256']
    proof._profile['cmdline_sha256'] = expected[0]['cmdline_sha256']
    healthcheck[2][41]['process']['cmdline_sha256'] = expected[0]['cmdline_sha256']
    sources = {'complete': True, 'candidates': []}
    scans = []
    def inventory():
        scans.append(1)
        return deepcopy(rows) + ([dict(pid=99, start_ticks='300', argv=list(ARGV))]
                                if len(scans) == 1 or present_second else [])
    census = CleanupCensus(context=context, expected_processes=expected,
        scheduled_sha256=canonical_digest(sources), read_context=lambda: deepcopy(context),
        process_inventory=inventory, sources=lambda: sources, qualify_healthcheck=proof)
    assert census()['processes'] == expected
    observations = census.diagnostics['observations']
    assert observations[0]['healthchecks'][0]['process'] == row
    assert len(observations[1]['healthchecks']) == int(present_second)
    assert calls.count(('pin', 99)) == (2 if present_second else 1)
    assert len(observations[0]['groups']['cleanup']) == 3


@pytest.mark.parametrize('exiting', [41, 99])
def test_loss_at_either_pinned_postcheck_prevents_proof(healthcheck, exiting):
    proof, row, *_ = healthcheck
    original = proof._process
    class ExitAtPostcheck:
        @contextmanager
        def capture(self, pid, *args):
            with original.capture(pid, *args) as captured:
                yield captured
                if pid == exiting:
                    raise ValueError('process exited during pinned postcheck')
    proof._process = ExitAtPostcheck()
    with pytest.raises(ValueError, match='pinned postcheck'): proof(row)


@pytest.mark.parametrize('change', ['no_provider', 'missing_main', 'two_extras', 'sync', 'native', 'wrong_proof'])
def test_no_generic_status_exemption(healthcheck, change):
    proof, row, *_ = healthcheck
    main = {key: proof._main['evidence']['process'][key] for key in row}
    other = dict(pid=42, start_ticks='200', cmdline_sha256='8' * 64)
    expected = [main, other]
    observed = expected + [row]
    qualifier = proof
    if change == 'no_provider': qualifier = None
    elif change == 'missing_main': observed = [other, row]
    elif change == 'two_extras': observed.append({**row, 'pid': 98})
    elif change in ('sync', 'native'):
        argv = list(ARGV)
        if change == 'sync': argv[2] = 'sync'
        else: argv[1] = '/root/venv/bin/dnlab-lab-cleanup'
        observed[-1] = {**row, 'cmdline_sha256': hashlib.sha256(b'\0'.join(x.encode() for x in argv) + b'\0').hexdigest()}
    else: qualifier = lambda row: {'kind': 'status-is-safe'}
    with pytest.raises(ValueError): qualify_processes(observed, expected, qualifier)


@pytest.mark.parametrize('uid,gid,accepted', [
    ('0 0 0 0', '0 0 0 0', True),
    ('0 1 0 0', '0 0 0 0', False),
    ('0 0 0 0', '0 0 1 0', False),
    ('0 0 0', '0 0 0 0', False),
])
def test_kernel_credential_reader_requires_all_root_ids(tmp_path, monkeypatch, uid, gid, accepted):
    import cleanup_healthcheck as module
    root = tmp_path / '99'
    (root / 'ns').mkdir(parents=True)
    (root / 'ns/user').write_text('synthetic namespace')
    (root / 'status').write_text('Uid:\t' + uid + '\nGid:\t' + gid + '\n')
    inode = (root / 'ns/user').stat().st_ino
    monkeypatch.setattr(module.LinuxProcess, '_view', lambda self, pid: {})
    monkeypatch.setattr(module, 'Path', lambda path: tmp_path)
    monkeypatch.setattr(module.os, 'readlink', lambda path: 'user:[' + str(inode) + ']')
    if accepted:
        assert module.HealthcheckProcess()._view(99)['credentials'] == {'uid': 0, 'gid': 0}
    else:
        with pytest.raises(ValueError, match='root healthcheck credentials'):
            module.HealthcheckProcess()._view(99)


@pytest.mark.parametrize('available', [True, False])
def test_real_status_callback_uses_only_synthetic_snapshot_and_logging(tmp_path, monkeypatch, available):
    """Exercise current CLI source, not installed CLI or management transports.

    Logging initialization is recorded, not called: status isn't zero-write.
    This is routing coverage, not qualification of live interpreter startup.
    """
    import ast
    import importlib.util
    import json
    from types import ModuleType
    from click.testing import CliRunner
    package = Path(__file__).resolve().parents[1] / 'dnlab_multinode'
    state = tmp_path / 'state.json'
    snapshot = {'updated_at': 'synthetic', 'labs': {}, 'dry_run': True}
    if available:
        state.write_text(json.dumps(snapshot))
    calls = []
    def forbidden(*args, **kwargs):
        raise AssertionError('management provider must not be called')
    tree = ast.parse((package / 'services/lab_cleanup.py').read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'read_state_file')
    namespace = {'json': json, 'Path': Path, 'DEFAULT_STATE_FILE': state}
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<synthetic-state-reader>', 'exec'), namespace)
    cleanup = ModuleType('dnlab_multinode.services.lab_cleanup')
    cleanup.DEFAULT_STATE_FILE = state
    cleanup.LabCleanupDaemon = cleanup.reconcile_once = forbidden
    def read_state(path):
        assert path == state
        calls.append('snapshot')
        return namespace['read_state_file'](path)
    cleanup.read_state_file = read_state
    hosts = ModuleType('dnlab_multinode.services.hosts_config')
    hosts.load_hosts_config = forbidden
    logging = ModuleType('dnlab_multinode.services.logging_config')
    def setup(**kwargs):
        assert kwargs == dict(service='lab-cleanup', filename='dnlab-lab-cleanup.log', debug=False)
        calls.append('logging')
    logging.setup_service_logging = setup
    for module in (cleanup, hosts, logging):
        monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = importlib.util.spec_from_file_location('_synthetic_healthcheck_cli', package / 'lab_cleanup_cli.py')
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    result = CliRunner().invoke(cli.main, ['status', '--json'])
    assert result.exit_code == (0 if available else 1), result.output
    assert calls == ['logging', 'snapshot']
    if available:
        assert json.loads(result.output) == snapshot
    else:
        assert 'state is unavailable' in result.output


def initial_groups(proof, row):
    main = {key: proof._main['evidence']['process'][key] for key in row}
    return dict(cleanup=[main, dict(pid=42, start_ticks='200', cmdline_sha256='8' * 64)],
                image_build=[dict(pid=43, start_ticks='250', cmdline_sha256='7' * 64)],
                unqualified_script=[])


def test_initial_baseline_rechecks_same_healthcheck_without_transient_digest(healthcheck):
    proof, row, *_ = healthcheck
    expected = initial_groups(proof, row)
    original = deepcopy(expected)
    evidence = []
    for present in (True, False, True):
        observed = deepcopy(expected)
        if present:
            observed['cleanup'].append(row)
        result = qualify_initial_processes(observed, expected, proof)
        assert result['groups'] == expected
        assert len(result['healthchecks']) == int(present)
        evidence.append(result)
    assert expected == original and len(evidence[0]['healthchecks']) == 1
    assert healthcheck[-1].count(('pin', 99)) == 2


@pytest.mark.parametrize('change', ['missing_build', 'changed_build', 'extra_build',
                                 'unknown', 'missing_main', 'sync', 'extra_key'])
def test_initial_healthcheck_does_not_exempt_other_actors(healthcheck, change):
    proof, row, *_ = healthcheck
    expected = initial_groups(proof, row)
    observed = deepcopy(expected)
    observed['cleanup'].append(deepcopy(row))
    if change == 'missing_build': observed['image_build'].clear()
    elif change == 'changed_build': observed['image_build'][0]['start_ticks'] = '251'
    elif change == 'extra_build': observed['image_build'].append(dict(pid=44, start_ticks='260', cmdline_sha256='6' * 64))
    elif change == 'unknown': observed['unqualified_script'].append(row)
    elif change == 'missing_main': observed['cleanup'].pop(0)
    elif change == 'sync': observed['cleanup'][-1]['cmdline_sha256'] = '5' * 64
    else: observed['other'] = []
    with pytest.raises(ValueError): qualify_initial_processes(observed, expected, proof)
    assert ('pin', 99) not in healthcheck[-1]
