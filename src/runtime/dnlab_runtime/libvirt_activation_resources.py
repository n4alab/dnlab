"""Repeated resource/snapshot preflight for progressive session activation.

Original current directory/account creators remain authoritative. The changing
unit is deliberately excluded here and verified by CompletedExchangeObserver;
all other resources and prerequisites must remain identical. No action provider
or native filesystem/process/service discovery is supplied.
"""
from copy import deepcopy

from .libvirt_configuration import UNIT
from .libvirt_install import targets
from .libvirt_package_policy import prerequisites_for_policy
from .manifest import Conflict,fingerprint,identifier


class ActivationResources:
    def __init__(self,lineage,*,activation_id,snapshot,accounts,directory_dependency,services,state_reader):
        identifier(activation_id,'original resource activation_id');self.activation_id=activation_id
        self.lineage=lineage;self.source=lineage.read()
        if (not callable(snapshot) or not callable(directory_dependency) or not callable(state_reader)
                or not callable(getattr(accounts,'observe',None)) or services.installation!=self.source
                or [item['spec'] for item in self.source['items']]!=targets(self.source['profile'])):
            raise Conflict('complete original activation resource providers required')
        self.snapshot,self.accounts,self.directory_dependency=snapshot,accounts,directory_dependency
        self.services,self.state_reader=services,state_reader

    def _snapshot(self):
        source=self.source;state=self.state_reader();observed=self.snapshot()
        if (not isinstance(state,dict) or set(state)!={'activation','inventory','receipts'}
                or state['activation'].get('id')!=self.activation_id
                or not isinstance(observed,dict) or set(observed)!={'context','prerequisites'}
                or observed['context']!=source['context'] or not isinstance(observed['prerequisites'],dict)
                or state['inventory']!=observed['prerequisites'].get('services')):
            raise Conflict('complete current activation snapshot differs')
        census=self.services.validate(state['activation'],state['inventory'],state['receipts'])
        policy=source['postboot'].get('package_policy')
        expected=prerequisites_for_policy(source['prerequisites'],policy)
        current=prerequisites_for_policy(observed['prerequisites'],policy)
        expected.pop('services');current.pop('services')
        if current!=expected:raise Conflict('original activation static prerequisites differ')
        if self.state_reader()!=state:raise Conflict('activation state changed during resource snapshot')
        normalized=dict(context=deepcopy(source['context']),prerequisites=dict(current,services=deepcopy(state['inventory'])))
        return dict(snapshot=normalized,census=census)

    def _targets(self):
        if self.lineage.read()!=self.source:raise Conflict('original activation source changed')
        base=self.lineage.view.read();proofs={}
        for item in self.source['items']:
            spec=item['spec'];key=spec['key']
            if spec.get('path')==UNIT:continue
            if item['phase']=='dependency':current=self.directory_dependency(deepcopy(spec))
            elif spec['kind'] in ('group','account'):current=self.accounts.observe(deepcopy(item),self.source['id'])
            elif spec['kind'] in ('file','directory'):
                creator=base['postboot']['creators'].get(key)
                if creator is None or item['proof']['intent_id']!=creator:
                    raise Conflict('original activation resource creator differs')
                current=self.lineage.view.files.observe(deepcopy(item),creator)
            else:raise Conflict('unknown activation resource kind')
            if current!=item['proof']:raise Conflict('original activation resource differs: '+key)
            proofs[key]=deepcopy(current)
        return proofs

    def __call__(self,reference):
        if reference!=self.lineage.reference or self.lineage.read()!=self.source:
            raise Conflict('original activation resource revision differs')
        first=self._snapshot();proofs=self._targets()
        if self._targets()!=proofs or self._snapshot()!=first or self.lineage.read()!=self.source:
            raise Conflict('activation resources changed during preflight')
        return dict(revision_sha256=fingerprint(reference),unchanged_sha256=reference['plan']['unchanged_sha256'],
            context=deepcopy(self.source['context']))
