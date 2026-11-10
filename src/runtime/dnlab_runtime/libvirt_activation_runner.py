"""Dedicated activation worker runner and strict original-process observer.

Shared blocked-runner/exit mechanics retain their account defaults. Activation
records use separate tables and the fixed service validator. No launch occurs
on construction; native use still requires qualified source/interpreter inputs.
"""
from copy import deepcopy
import hashlib
import os

from .libvirt_account_runner import AccountProcessRunner
from .libvirt_account_process import AccountWorkerObserver
from .libvirt_activation_worker import validate_command
from .manifest import Conflict


class ActivationProcessRunner(AccountProcessRunner):
    worker_table='libvirt_activation_workers'
    command_validator=staticmethod(validate_command)


class ActivationWorkerObserver(AccountWorkerObserver):
    process_table='libvirt_activation_processes'

    def _verify_live(self,live,command,phase):
        validate_command(command)
        original=live['snapshot'];interpreter=original['record']['executable_sha256']
        allowed={interpreter}
        if phase in ('release_requested','released'):allowed.add(command['binary']['sha256'])
        expected_argv=hashlib.sha256(b'\0'.join(os.fsencode(arg) for arg in command['argv'])+b'\0').hexdigest()
        for _ in range(2):
            if self._events(live) or live['process'].poll() is not None:raise Conflict('activation worker is no longer live')
            observed=self._snapshot(live['process']);executable=observed['record']['executable_sha256']
            if executable not in allowed:raise Conflict('original activation worker executable differs')
            expected=deepcopy(original);expected['record']['executable_sha256']=executable
            if executable!=interpreter:expected['cmdline_sha256']=expected_argv
            if observed!=expected or self._events(live) or live['process'].poll() is not None:
                raise Conflict('original activation worker generation or argv differs')
        return True
