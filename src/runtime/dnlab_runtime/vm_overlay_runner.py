"""Reuse the qualified original-process runner for the constrained formatter."""
from contextlib import contextmanager
from copy import deepcopy
import json
import subprocess

from .libvirt_account_process import AccountWorkerObserver
from .libvirt_account_runner import AccountProcessRunner, source_proof, worker_argv
from .libvirt_account_worker import ENVIRONMENT, binary_proof
from .manifest import Conflict, fingerprint
from .vm_overlay_worker import validate_command


class OverlayWorkerObserver(AccountWorkerObserver):
    process_table = 'vm_overlay_processes'


class OverlayProcessRunner(AccountProcessRunner):
    worker_table = 'vm_overlay_workers'
    command_validator = staticmethod(validate_command)

    def original_reference(self, command):
        """Read the sole original arm receipt after a lost caller response."""
        validate_command(command)
        with self.journal.lock:
            values = []
            for row in self.journal.db.execute('SELECT payload,fingerprint FROM ' + self.worker_table):
                value = json.loads(row['payload'])
                if fingerprint(value) != row['fingerprint']:raise Conflict('original formatter worker journal differs')
                if value['command'] == command:values.append(value)
        if not values:return None
        if len(values) != 1:raise Conflict('ambiguous original formatter arm')
        value = values[0]
        if value['reference'] is None:return None
        original = self._read(value['reference'])
        if original['phase'] != 'armed':raise Conflict('original formatter was not left armed')
        return deepcopy(original['reference'])

    @contextmanager
    def _launch(self, command):
        target = command['target']['fd']
        with (self.opener(command['binary']['path']) as binary,
              self.opener(self.profile['python']['path']) as python,
              self.opener(self.profile['worker']['path']) as worker):
            if target in (binary, python, worker):raise Conflict('distinct original formatter descriptors required')
            binary_proof(binary, command['binary']['sha256'])
            binary_proof(python, self.profile['python']['sha256'])
            source_proof(worker, self.profile['worker']['sha256'])
            argv = worker_argv(self.profile, binary, python, worker) + ['--overlay-fd', str(target)]
            yield self.spawn(argv, executable=f'/proc/self/fd/{python}', pass_fds=(binary, python, worker, target),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=deepcopy(ENVIRONMENT), cwd='/', close_fds=True)
