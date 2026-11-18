"""Explicit assembly for one original image-build hold in the runtime journal.

Construction wires providers only. Observe is readonly; prepare/acquire/restore
are separate calls. Window and gate-cleanup providers have no permissive defaults.
"""
from copy import deepcopy

from image_build_executor import ImageBuildExecutor
from image_build_observation import ImageBuildObservation
from image_build_query import ImageBuildNamespaceQuery
from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import ImageBuildHold
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_runtime_process import RuntimeProcess
from dnlab_runtime.vm_template import digest, require


class ImageBuildSession:
    def __init__(self, runtime, profile, *, jobs_sha256, api, read_context,
                 binding, ledger, activity, window, cleanup, query=None,
                 process=None, engine=None, term=None):
        require(isinstance(runtime,RuntimeProcess) and digest(jobs_sha256)
                and all(callable(fn) for fn in (read_context,binding,ledger,activity,window,cleanup)),
                'original runtime, qualified providers and explicit window/cleanup required')
        epoch=runtime.check()
        require(ImageBuildCommands._context(epoch)==profile['context']
                and read_context()==profile['context'], 'session runtime and original service context differ')
        self.runtime,self.profile,self.jobs_sha256=runtime,deepcopy(profile),jobs_sha256
        self.profile_sha256=fingerprint(profile);self.read_context=read_context
        query=(ImageBuildNamespaceQuery(api,profile,read_context=read_context,process=process)
               if query is None else query)
        self.observation=ImageBuildObservation(api,profile,context=read_context,query=query,
            binding=binding,ledger=ledger,activity=activity,process=process,
            exit_receipt=self._exit_receipt,startup=self._startup)
        self.commands=ImageBuildCommands(runtime,read_hold=lambda operation:self.hold.read(operation),
            preflight=self._preflight,execute=lambda command,reference:self.executor(command,reference))
        self.hold=ImageBuildHold(runtime.journal,observe=self.observation,commands=self.commands,
                                 window=window,cleanup=cleanup)
        self.executor=ImageBuildExecutor(self.commands,self.hold,self.observation,engine=engine,term=term)

    def _check(self):
        require(fingerprint(self.profile)==self.profile_sha256
                and ImageBuildCommands._context(self.runtime.check())==self.profile['context']
                and self.read_context()==self.profile['context'], 'original image-build session profile/context changed')

    def _exit_receipt(self, value):
        return self.commands.outcome(value['actions']['stop']['reference'])

    def _startup(self, value):
        return self.commands.details(value['actions']['start']['reference'])['details']['startup']

    def _preflight(self, command):
        self._check();value=self.hold.read(command['operation_id'])
        self.hold._pre(value,command['action'])
        return dict(command_sha256=fingerprint(command),scope_sha256=fingerprint(command['scope']),
                    actor_sha256=fingerprint(command['actor']),window_active=True)

    def observe(self, scope):
        """No hold intent, resource reservation or service command is created."""
        self._check()
        return self.observation(dict(actor=deepcopy(self.profile['actor']),policy=deepcopy(self.profile['policy']),
            binding_sha256=fingerprint(self.profile['binding']),jobs_sha256=self.jobs_sha256,
            actions={},scope=deepcopy(scope)))

    def prepare(self, operation, *, scope):
        self._check()
        return self.hold.prepare(operation,scope=scope,original_actor=self.profile['actor'],
            restart_policy=self.profile['policy'],binding_sha256=fingerprint(self.profile['binding']),
            jobs_sha256=self.jobs_sha256)

    def acquire(self, operation, *, recover=False):
        self._check();return self.hold.acquire(operation,recover=recover)

    def held(self, operation):
        self._check();return self.hold.held(operation)

    def restore(self, operation, *, recover=False):
        self._check();return self.hold.restore(operation,recover=recover)
