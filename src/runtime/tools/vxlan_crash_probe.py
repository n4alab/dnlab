"""Opt-in fixture worker and recovery checks for real VXLAN process crashes.

Every killed process is this script's dedicated child. Kernels and guests are
never killed; only fixture-owned veth endpoints can be attached by the worker.
"""
import argparse
from dataclasses import asdict
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.journal import Journal
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.vxlan import VxlanLinux, VxlanManager
from vxlan_smoke import NamespaceLinux


def mutation(argv):
    return (argv[:2] == ['ip', 'link'] and argv[2] in ('add', 'set', 'property', 'delete')
            or argv[:2] in (['tc', 'filter'], ['tc', 'qdisc']) and argv[2] in ('add', 'delete'))


def checkpoint(path, value):
    data = json.dumps(value, indent=2)+'\n'
    temporary = path.with_suffix('.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class CrashLinux(NamespaceLinux):
    def __init__(self, config):
        super().__init__(config['namespace'])
        self.config, self.mutations = config, 0

    def crash(self, argv, when):
        if self.mutations != self.config.get('crash_mutation') or when != self.config.get('crash_when'):
            return
        checkpoint(Path(self.config['trace']), {'pid': os.getpid(), 'mutation': self.mutations,
                                              'when': when, 'argv': argv, 'signal': 'SIGKILL',
                                              'runtime_metadata': self.config.get('runtime_metadata')})
        os.kill(os.getpid(), signal.SIGKILL)
        raise AssertionError('SIGKILL did not terminate worker')

    def run(self, argv, **kwargs):
        mutating = mutation(argv)
        if mutating:
            self.mutations += 1
            self.crash(argv, 'before')
        result = super().run(argv, **kwargs)
        if mutating:
            self.crash(argv, 'after')
        return result


def worker(config_path):
    config = json.loads(config_path.read_text())
    if not config['namespace'].startswith('drsp-') or not config['identity']['lab_id'].startswith('fixture-'):
        raise ValueError('isolated fixture required')
    metadata = {}
    for name in ('backend', 'vxlan', 'journal', 'link_identity', 'endpoint_reservations'):
        module = importlib.import_module('dnlab_runtime.' + name)
        source = Path(module.__file__)
        metadata[name] = {'path': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
        expected = config.get('expected_core_hashes', {}).get(name)
        if expected and metadata[name]['sha256'] != expected:
            raise ValueError('image runtime source digest mismatch: ' + name)
        if config.get('executor_image') and str(source).startswith(str(Path(__file__).resolve().parents[1])):
            raise ValueError('image worker imported host runtime source')
    config['runtime_metadata'] = metadata
    journal = Journal(Path(config['journal']))
    try:
        manager = VxlanManager(journal, VxlanLinux(CrashLinux(config)))
        identity = VxlanIdentity(**config['identity'])
        if config['action'] == 'create':
            manager.create(identity, **config['arguments'])
        elif config['action'] in ('delete', 'recover'):
            manager.delete(identity)
        else:
            raise ValueError('unknown worker action')
        row = manager.row(identity.digest)
        print(json.dumps({'pid': os.getpid(), 'phase': row['phase'], 'runtime_metadata': metadata}))
    finally:
        journal.close()


def run_worker(path, config):
    checkpoint(path, config)
    if config.get('executor_image'):
        from vxlan_container_worker import run_image_worker
        return run_image_worker(path, config)
    return subprocess.run([sys.executable, str(Path(__file__).resolve()), '--execute', '--config', str(path)],
                          text=True, capture_output=True, timeout=15)


def probe(root, report, names, journal, managers, identities, sources, other_payload, *, worker_image=None):
    records = report['crash_recovery'] = []
    key = identities['a'].digest
    config = {'namespace': names['a'], 'journal': str(root/'journal'), 'identity': asdict(identities['a']),
              'arguments': {'source': sources['a'], 'underlay': 'underlay0', 'local': '198.18.201.1',
                            'remote': '198.18.201.2', 'mtu': 1450}}
    if worker_image:
        config['executor_image'] = worker_image
        config['expected_core_hashes'] = {name: hashlib.sha256(Path(importlib.import_module('dnlab_runtime.'+name).__file__).read_bytes()).hexdigest()
                                          for name in ('backend', 'vxlan', 'journal', 'link_identity', 'endpoint_reservations')}
        report['worker_image'] = worker_image
        initial = run_worker(root/'image-create.json', dict(config, action='create', trace=str(root/'image-create-trace.json')))
        assert initial.returncode == 0, initial.stderr
        report['image_create'] = json.loads(initial.stdout)
        managers['a'].verify(identities['a'], managers['a'].row(key)['payload'])
        deleted = run_worker(root/'image-delete.json', dict(config, action='delete', trace=str(root/'image-delete-trace.json')))
        assert deleted.returncode == 0, deleted.stderr
        report['image_delete'] = json.loads(deleted.stdout)
    def assert_clean():
        assert managers['a'].row(key)['phase'] == 'cleaned'
        linux = managers['a'].linux
        assert identities['a'].resolve(linux.links()) is None
        assert not linux.filters(identities['a'].host_endpoint)
        assert not any(x['kind'] in ('ingress', 'clsact') for x in linux.qdiscs(identities['a'].host_endpoint))
        managers['b'].verify(identities['b'], other_payload)
    for action, count in [('create', 9), ('delete', 3)]:
        for position in range(1, count+1):
            for when in ['before', 'after']:
                case = f'{action}-{position}-{when}'
                record = {'case': case, 'status': 'running'}
                records.append(record)
                checkpoint(root/'report.json', report)
                if action == 'delete':
                    managers['a'].create(identities['a'], **config['arguments'])
                trace = root/(case+'-trace.json')
                request = dict(config, action=action, crash_mutation=position, crash_when=when, trace=str(trace))
                result = run_worker(root/(case+'.json'), request)
                record['returncode'] = result.returncode
                record['stderr'] = result.stderr
                assert result.returncode == (137 if worker_image else -signal.SIGKILL), f'{case}: {result.stdout} {result.stderr}'
                record['trace'] = json.loads(trace.read_text())
                record['interrupted_phase'] = managers['a'].row(key)['phase']
                assert record['interrupted_phase'] == ('creating' if action == 'create' else 'deleting')
                # A different process reopens WAL and takes the persisted flock.
                recovered = run_worker(root/(case+'-recover.json'), dict(config, action='recover', trace=str(trace)))
                assert recovered.returncode == 0, f'{case}: {recovered.stdout} {recovered.stderr}'
                record['recovery'] = json.loads(recovered.stdout)
                assert record['recovery']['pid'] != record['trace']['pid']
                assert record['recovery']['phase'] == 'cleaned'
                assert_clean()
                record['status'] = 'passed'
                checkpoint(root/'report.json', report)
    assert_clean()
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    if not args.execute or args.config is None:
        parser.error('fixture worker requires --execute --config')
    worker(args.config)
