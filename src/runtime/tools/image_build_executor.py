"""Compose persistent hold dispatch with original Docker and pidfd actions.

No retries or service discovery. This executor must be installed as the
ImageBuildCommands callback and run under its original execution lock/epoch.
"""
from copy import deepcopy
import time

from image_build_control import ImageBuildEngine, OriginalImageBuildTerm
from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import ImageBuildHold, NO_RESTART
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import require


class ImageBuildExecutor:
    def __init__(self, commands, hold, observation, *, engine=None, term=None,
                 clock=time.monotonic, pause=time.sleep):
        require(isinstance(commands,ImageBuildCommands) and isinstance(hold,ImageBuildHold)
                and commands.journal is hold.journal and hold.commands is commands
                and all(callable(getattr(observation,name,None)) for name in
                        ('__call__','verify_stop','capture_start')), 'original hold/commands and qualified observation required')
        self.commands,self.hold,self.observation=commands,hold,observation
        self.engine=ImageBuildEngine(observation.profile['actor']['container_id']) if engine is None else engine
        self.term=OriginalImageBuildTerm() if term is None else term
        require(callable(clock) and callable(pause), 'bounded observation clock required')
        self.clock,self.pause=clock,pause
        require(self.engine.container_id==observation.profile['actor']['container_id'], 'original Docker engine target required')

    def _current(self, command, reference, *, before=False):
        original=self.commands._read(reference)
        require(original['command']==command and original['phase']=='release_requested',
                'original producer release required for native action')
        self.commands._epoch(command,original)
        value,item=self.commands._bound(command)
        require(item['reference']==reference and item['phase']=='release_requested', 'original parent release required')
        self.hold._window(value)
        if command['action'] in ('start','restore_restart'):
            require(self.hold.cleanup(deepcopy(value))==value['cleanup'], 'original cleanup changed during restore')
        if before:self.commands._pre(command)
        return value

    def _exited(self, command, reference):
        # Docker may publish exit after the original pidfd becomes readable.
        # Wait only for observation; this loop never sends another command.
        deadline=self.clock()+10;generation=self.observation.profile['generation']
        while True:
            self._current(command,reference)
            observed=self.observation._inspect()
            require(observed['State']['StartedAt']==generation['started_at']
                    and observed['RestartCount']==generation['restart_count']
                    and observed['HostConfig']['RestartPolicy']==NO_RESTART,
                    'original generation changed after TERM')
            if observed['State']['Status']=='exited' and observed['State']['Pid']==0:
                return observed
            require(observed['State']['Status']=='running' and observed['State']['Running'] is True,
                    'unexpected lifecycle after original TERM')
            require(self.clock()<deadline, 'original Docker exit observation timed out; no resend')
            self.pause(0.05)

    def __call__(self, command, reference):
        with self.commands.journal.execution_lock:
            original=self.commands._read(reference)
            require(original['command']==command, 'original native command differs')
            require('native_dispatch_started' not in original, 'original native dispatch already attempted; no resend')
            self._current(command,reference,before=True)
            original['native_dispatch_started']=True
            self.commands._save(original)
            return self._execute(command,reference)

    def _execute(self, command, reference):
        # This also prevents use as an unjournalled stand-alone service tool.
        value=self._current(command,reference,before=True);action=command['action']
        require(self.engine.container_id==command['actor']['container_id'], 'original command container differs')
        if action in ('disable_restart','restore_restart'):
            self.engine.update_policy(command['restart_policy'])
            value=self._current(command,reference)
            observed=self.observation(value)
            require(observed['actor']==command['actor'] and observed['running'] is True
                    and observed['restart_policy']==command['restart_policy'], 'original policy update not verified')
            return dict(evidence=dict(policy_verified=True),details=dict(restart_policy=deepcopy(command['restart_policy'])))
        if action=='stop':
            profile=self.observation.profile
            with self.term.pin(profile['capture'],command['actor']['container_id'],profile['copies']) as pinned:
                def preflight():
                    self._current(command,reference,before=True)
                    return True
                exited=pinned.term(preflight=preflight)
            require(exited.get('pidfd_exit_verified') is True and exited.get('term_count')==1
                    and exited.get('force_used') is False, 'original single TERM exit required')
            observed=self._exited(command,reference)
            logs=self.engine.shutdown_logs(profile['generation']['started_at'],exited['namespace_pid'])
            require(logs.get('ordinary_shutdown_log_verified') is True, 'original shutdown logs required')
            value=self._current(command,reference)
            evidence=dict(process_sha256=command['actor']['process_sha256'],pidfd_exit_verified=True,
                          ordinary_shutdown_verified=True,drain_verified=True,term_count=1,force_used=False,
                          exit_code=observed['State']['ExitCode'])
            outcome=dict(reference=deepcopy(reference),command_sha256=fingerprint(command),dispatch_count=1,evidence=evidence)
            snapshot=self.observation.verify_stop(value,outcome)
            require(snapshot['running'] is False and snapshot['restart_policy']==NO_RESTART,
                    'original exited no-restart service required')
            self._current(command,reference)
            return dict(evidence=evidence,details=dict(pidfd=exited,shutdown_logs=logs))
        require(action=='start', 'original image-build action required')
        self.engine.start()  # Only a known HTTP 204 permits capture; no adoption after a lost ACK.
        value=self._current(command,reference)
        proof=self.observation.capture_start(value,reference,check=lambda:self._current(command,reference),
                                             clock=self.clock,pause=self.pause)
        self._current(command,reference)
        return dict(evidence=dict(actor=deepcopy(proof['actor']),original_start_verified=True),
                    details=dict(startup=proof))
