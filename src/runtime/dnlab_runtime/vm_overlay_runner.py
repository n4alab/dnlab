"""Reuse the qualified original-process runner for the constrained formatter."""
from contextlib import contextmanager
from copy import deepcopy
import subprocess

from .libvirt_account_process import AccountWorkerObserver
from .libvirt_account_runner import AccountProcessRunner, source_proof, worker_argv
from .libvirt_account_worker import ENVIRONMENT, binary_proof
from .manifest import Conflict
from .vm_overlay_worker import validate_command


class OverlayWorkerObserver(AccountWorkerObserver):
    process_table = 'vm_overlay_processes'


class OverlayProcessRunner(AccountProcessRunner):
    worker_table = 'vm_overlay_workers'
    command_validator = staticmethod(validate_command)

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
