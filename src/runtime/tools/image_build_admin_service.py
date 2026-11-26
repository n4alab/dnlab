"""Qualify an explicit current generation for policy-only administration.

This is not gate admission, an idle/activity attestation or a startup receipt.
It verifies the original service configuration/artifacts, the separately pinned
current process, health, unchanged terminal jobs, ledger and checkout binding.
The fenced producer and exclusive administrative window are caller obligations.
"""
from copy import deepcopy

from cleanup_container_observer import LinuxProcess, config_digest
from dnlab_runtime.image_build_hold import NO_RESTART, actor, policy
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import require
from image_build_observation import process_digest, terminal_jobs_digest


class AdministrativeService:
    def __init__(self, original_profile, original_hold, *, capture, generation, networks, api,
                 read_context, query_factory, binding, ledger, process=None):
        self.original=deepcopy(original_profile);self.hold=deepcopy(original_hold)
        self.networks=deepcopy(networks)
        self.profile=deepcopy(original_profile)
        self.profile.update(capture=deepcopy(capture),generation=deepcopy(generation))
        self.profile['actor']['process_sha256']=process_digest(capture,generation)
        actor(self.profile['actor']);policy(self.profile['policy'])
        stable=lambda row:{key:value for key,value in row.items() if key not in ('pid','start_ticks','namespaces')}
        require(all(callable(fn) for fn in (read_context,query_factory,binding,ledger))
                and generation['started_at']!=original_profile['generation']['started_at']
                and generation['restart_count']==original_profile['generation']['restart_count']
                and set(capture['sources'])==set(original_profile['copies'])
                and all(capture['sources'][path]['sha256']==digest for path,digest in original_profile['copies'].items())
                and capture['executable']['sha256']==original_profile['capture']['executable']['sha256']
                and {name:row['NetworkID'] for name,row in networks.items()}==original_profile['networks']
                and stable(capture['process'])==stable(original_profile['capture']['process'])
                and original_hold['actor']==original_profile['actor']
                and original_hold['binding_sha256']==fingerprint(original_profile['binding']),
                'explicit administrative generation and original service artifacts required')
        self.api,self.read_context,self.binding,self.ledger=api,read_context,binding,ledger
        self.process=LinuxProcess() if process is None else process
        self.service_sha256=fingerprint(dict(profile=self.profile,networks=self.networks))
        self.original_sha256=fingerprint(dict(profile=self.original,hold=self.hold))
        self.query=query_factory(deepcopy(self.profile))

    def _inspect(self, restart):
        profile=self.profile;value=self.api.inspect(profile['actor']['container_id'])
        require(value is not None and value.get('Id')==profile['actor']['container_id']
                and value.get('Image')==profile['actor']['image_id'], 'administrative service container differs')
        normalized=deepcopy(value);normalized['HostConfig']['RestartPolicy']=profile['policy']
        require(config_digest(normalized)==profile['actor']['config_sha256']
                and value['HostConfig']['RestartPolicy']==restart
                and value['State']['Running'] is True and value['State']['Status']=='running'
                and value['State']['Pid']==profile['capture']['process']['pid']
                and value['State']['StartedAt']==profile['generation']['started_at']
                and value['RestartCount']==profile['generation']['restart_count']
                and not value['State'].get('OOMKilled') and not value['State'].get('Error')
                and value['NetworkSettings']['Networks']==self.networks,
                'administrative service generation/configuration or policy differs')
        return dict(config_sha256=config_digest(value),state={key:value['State'].get(key) for key in
            ('Pid','Running','Status','StartedAt','FinishedAt','ExitCode','OOMKilled','Error')},
            networks=value['NetworkSettings']['Networks'],restart_count=value['RestartCount'])

    def observe(self, restart):
        profile=self.profile
        policy(restart)
        require(restart in (NO_RESTART,profile['policy'])
                and fingerprint(dict(profile=profile,networks=self.networks))==self.service_sha256
                and fingerprint(dict(profile=self.original,hold=self.hold))==self.original_sha256
                and self.read_context()==profile['context'], 'administrative service context/profile differs')
        value=dict(actor=deepcopy(profile['actor']),scope=deepcopy(self.hold['scope']))
        before=self._inspect(restart);capture=profile['capture']
        with self.process.capture(capture['process']['pid'],profile['actor']['container_id'],profile['copies']) as current:
            require(current==capture, 'administrative service process/source differs')
            response=self.query(value,deepcopy(current))
            require(response['health']==dict(ok=True) and response['binding']==profile['binding']
                    and terminal_jobs_digest(response['jobs'])==self.hold['jobs_sha256']
                    and self.binding(deepcopy(self.hold))==profile['binding']
                    and self.ledger(deepcopy(self.hold))==dict(ledger_sha256=profile['ledger_sha256'],
                        jobs_sha256=self.hold['jobs_sha256']), 'administrative service jobs, ledger or binding differs')
        require(self._inspect(restart)==before and self.read_context()==profile['context'],
                'administrative service changed during observation')
        return dict(service_sha256=self.service_sha256,restart_policy=deepcopy(restart),generation_verified=True)
