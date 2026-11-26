"""Readonly native preflight for an original unreleased gate retirement.

Uses the existing original-generation service observer. No discovery, service
start/stop/update, pidfd signal, libvirt connection or Journal construction.
The caller supplies the already-held original physical journal fence and pins
all inputs, including the original full Docker attachment snapshot.
"""
from copy import deepcopy
import os

from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.procfs_context import check as check_procfs
from dnlab_runtime.vm_template import require
from image_build_observation import ImageBuildObservation
from image_build_unreleased_retirement import _observation

DIRECTORY=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC


class UnreleasedObservation:
    def __init__(self, request, original, *, service, networks, fence,
                 verify_sources, read_context, proc_root='/proc'):
        self.original=deepcopy(original);self.request=deepcopy(request)
        self.expected=_observation(self.request,self.original)
        self.context=ImageBuildCommands._context(self.original['epoch'])
        require(isinstance(service,ImageBuildObservation) and callable(getattr(fence,'check',None))
                and callable(verify_sources) and callable(read_context),
                'qualified original service, held physical fence and readonly providers required')
        hold=self.original['hold']
        require(service.profile['actor']==hold['actor'] and service.profile['context']==self.context
                and service.profile['policy']==hold['policy']
                and {key:row['NetworkID'] for key,row in networks.items()}==service.profile['networks'],
                'original unreleased service profile and attachment snapshot required')
        self.service,self.networks,self.fence=service,deepcopy(networks),fence
        self.service_profile_sha256=fingerprint(service.profile)
        self.verify_sources,self.read_context,self.proc_root=verify_sources,read_context,proc_root
        self.proc_identity=dict(zip(('device','inode'),self.original['epoch']['snapshot']['proc_identity'],strict=True))

    def _checks(self, proc):
        self.fence.check()
        require(self.read_context()==self.context and self.verify_sources()==self.request['sources_sha256']
                and fingerprint(self.service.profile)==self.service_profile_sha256
                and _observation(self.request,self.original)==self.expected,
                'original unreleased retirement source/context/profile differs')
        check_procfs(proc,context=self.context,read_context=self.read_context,
                     proc_identity=self.proc_identity,proc_root=self.proc_root)

    def _absent(self, proc):
        self._checks(proc)
        pid=self.original['epoch']['snapshot']['record']['pid']
        try:os.stat(str(pid),dir_fd=proc,follow_symlinks=False)
        except FileNotFoundError:return
        require(False, 'original producer PID is occupied; no process adoption or inferred exit')

    def __call__(self):
        proc=os.open(self.proc_root,DIRECTORY)
        try:
            self._absent(proc)
            hold=deepcopy(self.original['hold']);cid=hold['actor']['container_id']
            before=self.service.api.inspect(cid)
            require(before is not None and before['Id']==cid and before['Image']==hold['actor']['image_id']
                    and before['NetworkSettings']['Networks']==self.networks,
                    'original unreleased service attachments differ')
            proof=self.service(hold)
            wanted=dict(actor=hold['actor'],running=True,restart_policy=hold['policy'],idle=True,
                binding_aligned=True,binding_sha256=hold['binding_sha256'],jobs_sha256=hold['jobs_sha256'])
            require(canonical(proof)==canonical(wanted), 'unchanged original service observation required')
            after=self.service.api.inspect(cid)
            require(after is not None and after['Id']==cid and after['Image']==hold['actor']['image_id']
                    and after['NetworkSettings']['Networks']==self.networks,
                    'original unreleased service attachments changed')
            self._absent(proc)
            return deepcopy(self.expected)
        finally:os.close(proc)
