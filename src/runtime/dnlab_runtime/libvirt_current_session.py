"""Explicit post-boot source view and revision path; legacy guards stay intact.

The view reads immutable journal lineage, not current liveness. Its use requires
full current-context preflight. Persistents retain their original creators;
volatile directories use the completed current-boot recovery creator.
"""
from copy import deepcopy

from .libvirt_configuration import ConfigurationRevision,UNIT
from .libvirt_configuration_adapter import ConfigurationFileAdapter
from .libvirt_configuration_preflight import ConfigurationPreflight
from .libvirt_configuration_session import ConfigurationSession
from .libvirt_provisioning import account_request
from .libvirt_package_policy import prerequisites_for_policy
from .manifest import Conflict,fingerprint


class CurrentSessionView:
    def __init__(self,recovery,operation):
        self.recovery,self.operation=recovery,operation
        self.journal,self.files=recovery.journal,recovery.files

    def read(self):
        with self.journal.execution_lock:
            recovered=self.recovery.read(self.operation)
            if recovered['phase']!='directories_qualified':raise Conflict('completed current-boot directory recovery required')
            qualifier=self.recovery.qualification
            qualified=qualifier.read(recovered['qualification_id']);qualifier._source(qualified)
            if qualified['phase']!='persistent_qualified' or recovered['qualification_sha256']!=fingerprint(qualified):
                raise Conflict('original post-boot source lineage differs')
            original=qualified['installation'];result=deepcopy(original)
            result['context']=deepcopy(qualified['context'])
            result['prerequisites']=deepcopy(qualified['receipt']['observation']['prerequisites'])
            replacements={item['spec']['key']:item for item in recovered['items']}
            creators={}
            for index,item in enumerate(result['items']):
                key=item['spec']['key']
                if key in replacements:
                    item=deepcopy(replacements[key]);result['items'][index]=item
                    creators[key]=recovered['id']
                elif item['phase']=='created':creators[key]=original['id']
            result['postboot']=dict(kind='postboot-session-view-v1',source_sha256=fingerprint(original),
                qualification_id=qualified['id'],qualification_sha256=fingerprint(qualified),
                recovery_id=recovered['id'],recovery_sha256=fingerprint(recovered),creators=creators,
                observation_required=True)
            if 'package_policy' in qualified:result['postboot']['package_policy']=qualified['package_policy']
            qualifier._source(qualified)
            return result


class CurrentAccountObserver:
    def __init__(self,view,identity):
        if not callable(identity):raise Conflict('explicit current account identity reader required')
        self.view,self.identity=view,identity

    def observe(self,item,operation):
        view=self.view.read();metadata=view['postboot']
        if operation!=view['id'] or item not in view['items'] or item['spec']['kind'] not in ('group','account'):
            raise Conflict('bound current account view required')
        qualifier=self.view.recovery.qualification;qualified=qualifier.read(metadata['qualification_id'])
        original=next(entry for entry in qualified['installation']['items'] if entry['spec']['key']==item['spec']['key'])
        if qualifier.account_history(deepcopy(original))!=qualified['receipt']['account_history'][item['spec']['key']]:
            raise Conflict('original historical account creation changed')
        request=account_request(original,qualified['installation']['id'])
        if self.identity(deepcopy(request))!=request['expected'] or request['expected']!=item['proof']['identity']:
            raise Conflict('current account identity differs from historical creation')
        return deepcopy(item['proof'])


class CurrentFileObserver:
    def __init__(self,view):self.view=view

    def observe(self,item,operation):
        view=self.view.read()
        if operation!=view['id'] or item not in view['items'] or item['spec']['kind'] not in ('file','directory'):
            raise Conflict('bound current filesystem view required')
        creator=view['postboot']['creators'].get(item['spec']['key'])
        if creator is None or item['proof']['intent_id']!=creator:
            raise Conflict('explicit current filesystem creator required')
        return self.view.files.observe(deepcopy(item),creator)


class CurrentSessionPreflight(ConfigurationPreflight):
    def __init__(self,view,*,snapshot,identity,directory_dependency):
        if not callable(snapshot) or not callable(directory_dependency):raise Conflict('explicit current session readers required')
        self.view=view;self.installation=view.read()
        self.accounts=CurrentAccountObserver(view,identity);self.files=CurrentFileObserver(view)
        self.directory_dependency=directory_dependency
        self.expected=dict(context=deepcopy(self.installation['context']),prerequisites=deepcopy(self.installation['prerequisites']))
        self._inactive(self.expected['prerequisites'].get('services'))
        def current():
            if view.read()!=self.installation:raise Conflict('bound current session lineage changed')
            result=snapshot()
            if view.read()!=self.installation:raise Conflict('current session lineage changed during snapshot')
            if isinstance(result,dict) and isinstance(result.get('prerequisites'),dict):
                result=deepcopy(result)
                result['prerequisites']=prerequisites_for_policy(result['prerequisites'],self.installation['postboot'].get('package_policy'))
            return result
        self.snapshot=current


class CurrentConfigurationSession(ConfigurationSession):
    """Separate versioned source path, never a fallback from legacy preparation."""
    def __init__(self,view,*,snapshot,identity,directory_dependency,window,journal_identity):
        self.view,self.journal,self.window=view,view.journal,window
        if self.journal.identity!=journal_identity:raise Conflict('original current-session journal differs')
        self.original=view.read();metadata=self.original['postboot']
        if (window.receipt['operation_id'] in (self.original['id'],metadata['qualification_id'],metadata['recovery_id'])
                or window.receipt['context']!=self.original['context'] or window.receipt['targets']!=['file:'+UNIT]):
            raise Conflict('separate current-boot unit revision window required')
        self.journal_identity=journal_identity;self.operation=window.receipt['operation_id']
        self.preflight=CurrentSessionPreflight(view,snapshot=snapshot,identity=identity,directory_dependency=directory_dependency)
        self.adapter=ConfigurationFileAdapter(view.files,window=window,preflight=self.preflight)
        self.driver=ConfigurationRevision(self.journal,self.adapter,window=window)

    def _source(self):
        if self.journal.identity!=self.journal_identity or self.view.read()!=self.original:
            raise Conflict('original current-session revision source changed')
