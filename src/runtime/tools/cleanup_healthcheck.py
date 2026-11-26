"""Narrow provenance proof for the original cleanup container's status check.

This does not prove parentage or grant management authority. The status route
reads a snapshot and initializes service logging; it is not a zero-write CLI.
All providers and pins are trusted local preparation, never request fields.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path

from cleanup_container_observer import LinuxProcess, config_digest, observe_container
from cleanup_execution import canonical_digest, require, sha


ARGV = ('/usr/local/bin/python3.13', '/usr/local/bin/dnlab-lab-cleanup', 'status', '--json')
COMMAND_SHA256 = hashlib.sha256(b'\0'.join(word.encode() for word in ARGV) + b'\0').hexdigest()
TEST = ['CMD-SHELL', 'dnlab-lab-cleanup status --json >/dev/null']
KIND = 'qualified-daemon-healthcheck-status-v1'


class HealthcheckProcess(LinuxProcess):
    """Extend the existing pidfd observation with root credentials/user NS."""

    def _view(self, pid):
        view = super()._view(pid)
        root = Path('/proc') / str(pid)
        with (root / 'status').open('rb') as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'bounded healthcheck credentials required')
        credentials = {}
        for line in raw.splitlines():
            key, _, value = line.partition(b':')
            if key in (b'Uid', b'Gid'):
                require(key.decode() not in credentials, 'duplicate process credentials')
                credentials[key.decode()] = value.split()
        require(credentials == {'Uid': [b'0'] * 4, 'Gid': [b'0'] * 4},
                'qualified root healthcheck credentials required')
        info = os.stat(root / 'ns/user')
        require(os.readlink(root / 'ns/user') == 'user:[' + str(info.st_ino) + ']',
                'healthcheck user namespace changed')
        view['credentials'] = {'uid': 0, 'gid': 0}
        view['user_namespace'] = {'device': info.st_dev, 'inode': info.st_ino}
        return view


class StatusHealthcheck:
    """Pin child and original main together; reobserve config and provenance.

    expected_main is a freshly qualified observe_container result. Historical
    process generations cannot be reused after a reboot. A disappearing child
    or failed observation is a conflict, never an implicit retry/exemption.
    """

    def __init__(self, *, api, profile, descriptor, expected_main, context,
                 read_context, process=None, observe_main=observe_container):
        self._api = api
        self._profile, self._descriptor = deepcopy(profile), deepcopy(descriptor)
        self._main, self._context = deepcopy(expected_main), deepcopy(context)
        self._read_context, self._observe = read_context, observe_main
        self._process = HealthcheckProcess() if process is None else process
        require(callable(read_context) and callable(observe_main), 'trusted healthcheck readers required')
        require(expected_main['container_id'] == profile['container_id']
                and expected_main['artifact_sha256'] == canonical_digest(descriptor),
                'original daemon artifact required')

    def _original(self):
        require(self._read_context() == self._context, 'healthcheck coordinator context changed')
        require(self._observe(self._api, 'daemon', self._profile, self._descriptor) == self._main,
                'original daemon generation changed')
        value = self._api.inspect(self._profile['container_id'])
        require(value['Id'] == self._profile['container_id']
                and value['Image'] == self._descriptor['image']
                and config_digest(value) == self._profile['config_sha256']
                and value['Config'].get('Healthcheck', {}).get('Test') == TEST
                and value['Config'].get('User', '') in ('', '0', 'root', '0:0', 'root:root')
                and value['State']['Running'] is True
                and value['State']['Pid'] == self._main['evidence']['process']['pid'],
                'original daemon healthcheck configuration differs')

    def _assets(self, captured):
        view, profile = captured['process'], self._profile
        require(all(view[key] == profile[key] for key in ('exe', 'cwd', 'import_env_sha256'))
                and captured['executable']['sha256'] == profile['exe_sha256']
                and set(captured['sources']) == set(profile['copies'])
                and all(captured['sources'][path]['sha256'] == digest
                        for path, digest in profile['copies'].items()),
                'healthcheck interpreter or sources differ')
        require(view['credentials'] == {'uid': 0, 'gid': 0}
                and view['user_namespace'] == self._context['namespaces']['user'],
                'healthcheck credentials or user namespace differ')

    def __call__(self, row):
        require(type(row) is dict and set(row) == {'pid', 'start_ticks', 'cmdline_sha256'}
                and row['cmdline_sha256'] == COMMAND_SHA256,
                'only the exact original status command is eligible')
        original = self._main['evidence']['process']
        require(row['pid'] != original['pid'], 'healthcheck cannot replace original daemon')
        self._original()
        with self._process.capture(original['pid'], self._profile['container_id'],
                                   self._profile['copies']) as main:
            self._assets(main)
            require(all(main['process'].get(key) == value for key, value in original.items()),
                    'original daemon process changed')
            with self._process.capture(row['pid'], self._profile['container_id'],
                                       self._profile['copies']) as child:
                self._assets(child)
                view = child['process']
                require(all(view[key] == value for key, value in row.items()),
                        'healthcheck process identity differs')
                require(view['namespaces'] == original['namespaces']
                        and view['cgroup'] == original['cgroup'],
                        'healthcheck namespace or cgroup differs')
                self._original()
                proof = dict(kind=KIND, process=deepcopy(row),
                             main_process={key: original[key] for key in row},
                             container_id=self._main['container_id'],
                             artifact_sha256=self._main['artifact_sha256'],
                             generation_sha256=self._main['generation_sha256'],
                             process_evidence_sha256=canonical_digest(child))
        self._original()
        return proof


def qualify_processes(observed, expected, qualifier=None):
    """Common for census and future same-session baseline actor verification.

    Both primary generations remain compulsory. Transient status identity is
    retained in diagnostics, not included in the stable actor-set digest.
    """
    require(all(row in observed for row in expected),
            'cleanup process set differs or native CLI is active')
    extra = [row for row in observed if row not in expected]
    if not extra:
        return deepcopy(expected), []
    require(len(extra) == 1 and callable(qualifier)
            and extra[0]['cmdline_sha256'] == COMMAND_SHA256,
            'cleanup process set differs or native CLI is active')
    proof = qualifier(deepcopy(extra[0]))
    require(type(proof) is dict and set(proof) == {
        'kind', 'process', 'main_process', 'container_id', 'artifact_sha256',
        'generation_sha256', 'process_evidence_sha256'}
            and proof['kind'] == KIND and proof['process'] == extra[0]
            and proof['main_process'] in expected,
            'qualified original healthcheck proof required')
    require(all(sha(proof[key]) for key in (
        'container_id', 'artifact_sha256', 'generation_sha256', 'process_evidence_sha256')),
        'complete healthcheck provenance required')
    return deepcopy(expected), [deepcopy(proof)]
