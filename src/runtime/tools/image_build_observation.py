"""Observe an original image-build generation for the persistent hold driver.

Docker/proc inspection is readonly. Namespace API reads, immutable binding/job
ledger, activity census and original stop/start receipts are trusted providers;
none is inferred from a name, stopped state, health or a bare exit code.
"""
from copy import deepcopy
import re
import time

from cleanup_container_observer import LinuxProcess, config_digest
from dnlab_runtime.image_build_hold import ImageBuildHold, NO_RESTART, actor, policy
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError, digest, fields, require


class ImageBuildApiNotReady(TemplateError):
    """Only the pinned loopback API connection was refused during startup."""


def process_digest(capture, generation):
    return fingerprint(dict(capture=capture,generation=generation))


def artifact_digest(image, copies, executable):
    return fingerprint(dict(image_id=image,copies=copies,executable_sha256=executable))


def terminal_jobs_digest(jobs):
    require(type(jobs) is list and len(jobs)<=4096, 'bounded original terminal jobs required')
    rows = []
    for job in jobs:
        require(type(job) is dict and isinstance(job.get('id'),str)
                and re.fullmatch('[0-9a-f]{16}',job['id']) and job.get('status') in ('success','failed'),
                'unique original terminal job IDs/status required')
        rows.append(dict(id=job['id'],status=job['status']))
    require(len({row['id'] for row in rows})==len(rows), 'duplicate original terminal job')
    return fingerprint(sorted(rows,key=lambda row:row['id']))


class ImageBuildObservation:
    def __init__(self, api, profile, *, context, query, binding, ledger, activity,
                 exit_receipt, startup, process=None):
        fields(profile,('actor','context','policy','capture','generation','copies','binding','ledger_sha256','networks'),
               'original image-build observation profile')
        actor(profile['actor']);policy(profile['policy'])
        require(all(callable(fn) for fn in (context,query,binding,ledger,activity,exit_receipt,startup)),
                'qualified readonly image-build providers required')
        fields(profile['generation'],('started_at','restart_count'),'original image-build Docker generation')
        require(profile['binding'].get('state')=='aligned'
                and profile['binding'].get('requested_commit')==profile['binding'].get('current_commit')
                and isinstance(profile['binding'].get('current_commit'),str) and len(profile['binding']['current_commit'])==40,
                'original aligned vrnetlab commit required')
        require(profile['actor']['context_sha256']==fingerprint(profile['context'])
                and profile['actor']['process_sha256']==process_digest(profile['capture'],profile['generation'])
                and profile['actor']['artifact_sha256']==artifact_digest(profile['actor']['image_id'],profile['copies'],
                    profile['capture']['executable']['sha256']) and digest(profile['ledger_sha256']),
                'original image-build process/artifact profile differs')
        self.api,self.profile = api,deepcopy(profile)
        self.profile_sha256 = fingerprint(profile)
        self.context,self.query,self.binding,self.ledger,self.activity = context,query,binding,ledger,activity
        self.exit_receipt,self.startup = exit_receipt,startup
        self.process = LinuxProcess() if process is None else process
        self._capture_artifact(profile['capture'])

    def _capture_artifact(self, capture):
        fields(capture,('process','sources','executable'),'original image-build process capture')
        require(set(capture['sources'])==set(self.profile['copies'])
                and all(capture['sources'][path]['sha256']==digest for path,digest in self.profile['copies'].items())
                and capture['executable']['sha256']==self.profile['capture']['executable']['sha256'],
                'qualified image-build execution artifact differs')

    def _conditions(self, value, *, pid, check_activity=True):
        profile = self.profile
        require(fingerprint(profile)==self.profile_sha256 and self.context()==profile['context'],
                'original image-build observation context/profile changed')
        require(value['actor']==profile['actor'] and value['policy']==profile['policy']
                and value['scope']['host_id']==profile['context']['host_id']
                and value['scope']['boot_id']==profile['context']['boot_id']
                and value['binding_sha256']==fingerprint(profile['binding']), 'original hold observation owner differs')
        require(self.binding(deepcopy(value))==profile['binding'], 'original runtime lock/checkout binding differs')
        require(self.ledger(deepcopy(value))==dict(ledger_sha256=profile['ledger_sha256'],jobs_sha256=value['jobs_sha256']),
                'original terminal job ledger changed')
        if check_activity:
            current = self.activity(deepcopy(value))
            fields(current,('container_pids','host_build_processes','complete'),'complete image-build activity census')
            require(type(current['container_pids']) is list and all(type(v) is int and v>0 for v in current['container_pids'])
                    and current['complete'] is True and current['container_pids']==([] if pid is None else [pid])
                    and current['host_build_processes']==[], 'image-build activity missing, busy or ambiguous')
        require(self.context()==profile['context'], 'image-build context changed during conditions')

    def _inspect(self):
        profile = self.profile;value = self.api.inspect(profile['actor']['container_id'])
        require(type(value) is dict and value.get('Id')==profile['actor']['container_id']
                and value.get('Image')==profile['actor']['image_id'], 'original image-build container missing or replaced')
        normalized = deepcopy(value);normalized['HostConfig']['RestartPolicy'] = profile['policy']
        require(config_digest(normalized)==profile['actor']['config_sha256'],
                'image-build configuration changed beyond tracked restart policy')
        policy(value['HostConfig']['RestartPolicy'])
        require(value['HostConfig']['RestartPolicy'] in (profile['policy'],NO_RESTART)
                and {name:network['NetworkID'] for name,network in value['NetworkSettings']['Networks'].items()}==profile['networks'],
                'original image-build networks or tracked restart policy differ')
        require(type(value['State']['Running']) is bool and not value['State'].get('OOMKilled')
                and not value['State'].get('Error'), 'qualified image-build Docker lifecycle required')
        return value

    def _running(self, value, observed, *, startup_proof=None, starting=False):
        profile = self.profile;start = value['actions'].get('start')
        expected_actor,capture,generation = profile['actor'],profile['capture'],profile['generation']
        if start is not None:
            proof = self.startup(deepcopy(value)) if startup_proof is None else startup_proof
            fields(proof,('reference','command_sha256','capture','generation','actor','original_start_verified'),
                   'original image-build startup receipt')
            require(proof['reference']==start['reference'] and proof['command_sha256']==fingerprint(start['command'])
                    and proof['original_start_verified'] is True, 'original same-command image-build start required')
            expected_actor,capture,generation = proof['actor'],proof['capture'],proof['generation']
            actor(expected_actor);fields(generation,('started_at','restart_count'),'original startup Docker generation')
            require(all(expected_actor[key]==profile['actor'][key] for key in expected_actor if key!='process_sha256')
                    and expected_actor['process_sha256']==process_digest(capture,generation)
                    and expected_actor['process_sha256']!=profile['actor']['process_sha256'],
                    'original startup generation differs')
        require(observed['State']['Status']=='running' and observed['State']['Pid']==capture['process']['pid']
                and observed['State']['StartedAt']==generation['started_at']
                and observed['RestartCount']==generation['restart_count'], 'original running image-build generation differs')
        self._capture_artifact(capture)
        stable_process = lambda row:{key:part for key,part in row.items() if key not in ('pid','start_ticks','namespaces')}
        require(stable_process(capture['process'])==stable_process(profile['capture']['process']),
                'original image-build invocation/import environment differs')
        # Startup may still be awaiting its original subprocesses. No idle or
        # readiness proof is returned until the full census after the API query.
        self._conditions(value,pid=capture['process']['pid'],check_activity=not starting)
        with self.process.capture(capture['process']['pid'],expected_actor['container_id'],profile['copies']) as current:
            require(current==capture, 'original image-build process/source snapshot differs')
            response = self.query(deepcopy(value),deepcopy(capture))
            fields(response,('health','jobs','binding'),'original image-build API observation')
            jobs = response['jobs']
            fields(response['health'],('ok',),'image-build health response')
            require(response['health']['ok'] is True and response['binding']==profile['binding']
                    and terminal_jobs_digest(jobs)==value['jobs_sha256'],
                    'original API health, aligned binding or terminal jobs differ')
            self._conditions(value,pid=capture['process']['pid'])
        return deepcopy(expected_actor)

    def _stopped(self, value, observed, *, stop_outcome=None):
        stop = value['actions'].get('stop')
        require(stop is not None and stop['reference'] is not None and observed['State']['Status']=='exited'
                and observed['State']['Pid']==0 and observed['RestartCount']==self.profile['generation']['restart_count'],
                'original tracked image-build stop required')
        outcome = self.exit_receipt(deepcopy(value)) if stop_outcome is None else stop_outcome
        require(outcome is not None, 'original stop/drain receipt unavailable')
        ImageBuildHold._outcome(stop,outcome)
        proof = outcome['evidence']
        fields(proof,('process_sha256','pidfd_exit_verified','ordinary_shutdown_verified','drain_verified',
                      'term_count','force_used','exit_code'),'original image-build process exit')
        require(proof['process_sha256']==self.profile['actor']['process_sha256']
                and all(proof[key] is True for key in ('pidfd_exit_verified','ordinary_shutdown_verified','drain_verified'))
                and type(proof['term_count']) is int and proof['term_count']==1 and proof['force_used'] is False
                and type(proof['exit_code']) is int and proof['exit_code'] in (0,143)
                and observed['State']['ExitCode']==proof['exit_code'], 'original ordinary image-build shutdown/drain differs')
        self._conditions(value,pid=None)
        return deepcopy(self.profile['actor'])

    def _observe(self, value, *, stop_outcome=None, startup_proof=None, starting=False):
        before = self._inspect()
        current_actor = (self._running(value,before,startup_proof=startup_proof,starting=starting) if before['State']['Running']
                         else self._stopped(value,before,stop_outcome=stop_outcome))
        after = self._inspect()
        stable = lambda row: dict(config_sha256=config_digest(row),Id=row['Id'],Image=row['Image'],RestartCount=row['RestartCount'],
            state={key:row['State'].get(key) for key in ('Pid','Running','Status','StartedAt','FinishedAt','ExitCode','OOMKilled','Error')},
            networks=row['NetworkSettings']['Networks'])
        require(stable(after)==stable(before), 'image-build Docker observation changed')
        self._conditions(value,pid=before['State']['Pid'] if before['State']['Running'] else None)
        return dict(actor=current_actor,running=before['State']['Running'],restart_policy=before['HostConfig']['RestartPolicy'],
                    idle=True,binding_aligned=True,binding_sha256=fingerprint(self.profile['binding']),jobs_sha256=value['jobs_sha256'])

    def verify_stop(self, value, outcome):
        """Qualify the executor's original exit before its durable completion."""
        require(outcome is not None, 'original stop outcome required')
        return self._observe(value,stop_outcome=outcome)

    def capture_start(self, value, reference, *, check, checkpoint=None, timeout=30, clock=time.monotonic, pause=time.sleep):
        """Capture after a known start ACK; never called to adopt an uncertain start.

        Readiness queries must be bounded by their provider. Only the explicit
        loopback-not-listening result permits another readonly observation.
        Failure leaves the command uncertain; start is never repeated.
        """
        start=value['actions'].get('start')
        require(callable(check) and callable(clock) and callable(pause)
                and type(timeout) in (int,float) and 0<timeout<=30, 'bounded original startup observation required')
        require(start is not None and start['reference']==reference and start['phase']=='release_requested',
                'original released start reference required')
        observed=self._inspect();generation=dict(started_at=observed['State']['StartedAt'],restart_count=observed['RestartCount'])
        require(observed['State']['Running'] and observed['State']['Status']=='running'
                and observed['HostConfig']['RestartPolicy']==NO_RESTART
                and generation['started_at']!=self.profile['generation']['started_at']
                and generation['restart_count']==self.profile['generation']['restart_count'],
                'original explicit start generation required')
        with self.process.capture(observed['State']['Pid'],self.profile['actor']['container_id'],self.profile['copies']) as capture:
            capture=deepcopy(capture)
        current_actor=deepcopy(self.profile['actor']);current_actor['process_sha256']=process_digest(capture,generation)
        proof=dict(reference=deepcopy(reference),command_sha256=fingerprint(start['command']),capture=capture,
                   generation=generation,actor=current_actor,original_start_verified=True)
        if checkpoint is not None:
            require(callable(checkpoint), 'original startup checkpoint callback required')
            checkpoint(deepcopy(proof))
        return self.observe_start(value,reference,proof,check=check,timeout=timeout,clock=clock,pause=pause)

    def observe_start(self, value, reference, proof, *, check, timeout=30, clock=time.monotonic, pause=time.sleep):
        """Re-observe the saved first generation; never capture a replacement."""
        require(callable(check) and callable(clock) and callable(pause)
                and type(timeout) in (int,float) and 0<timeout<=30, 'bounded original startup observation required')
        start=value['actions'].get('start')
        require(start is not None and start['reference']==reference and start['phase']=='release_requested'
                and proof['reference']==reference and proof['command_sha256']==fingerprint(start['command']),
                'original startup reference required')
        deadline=clock()+timeout
        while True:
            check()
            require(clock()<deadline, 'original API readiness timed out; no second start')
            try:
                self._observe(value,startup_proof=proof,starting=True)
            except ImageBuildApiNotReady:
                # Only a refused readonly connection is a startup wait. HTTP,
                # binding, ledger, source, generation or census errors refuse.
                require(clock()<deadline, 'original API readiness timed out; no second start')
                pause(0.05)
                continue
            check()
            require(clock()<=deadline, 'original API readiness timed out; no second start')
            return proof

    def __call__(self, value):
        return self._observe(value)
