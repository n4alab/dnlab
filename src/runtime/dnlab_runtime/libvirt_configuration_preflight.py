"""Complete readonly preflight for one original inactive installation.

Concrete snapshot, filesystem/account observers and selected dependencies remain
explicit. No source discovery, account creation, service operation or default
host query is supplied. The changing libvirtd unit is qualified by the separate
staging/swap observer; every other original target must remain unchanged.
"""
from copy import deepcopy

from .libvirt_configuration import UNIT,compile_revision
from .libvirt_install import targets,proof
from .libvirt_provisioning import account_request
from .manifest import Conflict,fingerprint


class CompletedAccountObserver:
    """Reuse committed birth/worker evidence without reopening the old window."""
    def __init__(self,accounts):self.accounts=accounts

    def observe(self,item,operation):
        accounts=self.accounts
        with accounts.journal.execution_lock:
            value=accounts._read(item,operation)
            request=account_request(item,operation)
            if value is None or value['phase']!='created':
                raise Conflict('original completed account birth required')
            read=getattr(accounts.helper,'preflight_completion',None)
            if not callable(read):raise Conflict('readonly original account completion required')
            completion=read(deepcopy(request))
            expected=dict(request_sha256=fingerprint(request),exit_code=0,identity=request['expected'])
            if completion!=expected or completion!=value['completion']:
                raise Conflict('original committed account completion differs')
            if accounts.helper.inspect(deepcopy(request))!=request['expected']:
                raise Conflict('original installed account identity differs')
            result=proof(dict(intent_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(item['spec']),
                identity=deepcopy(request['expected'])),item,operation)
            if result!=item['proof'] or accounts._read(item,operation)!=value:
                raise Conflict('original installed account proof changed')
            return result


class ConfigurationPreflight:
    def __init__(self,installation,*,snapshot,accounts,files,directory_dependency):
        compile_revision(installation)
        if (not callable(snapshot) or not callable(directory_dependency)
                or not callable(getattr(accounts,'observe',None)) or not callable(getattr(files,'observe',None))
                or [item['spec'] for item in installation['items']]!=targets(installation['profile'])):
            raise Conflict('complete original configuration observers required')
        self.installation=deepcopy(installation)
        for item in installation['items']:
            if item['phase']=='dependency':
                if (item['spec']['kind']!='directory'
                        or item['proof']!=installation['dependencies'].get(item['spec']['path'])):
                    raise Conflict('original selected directory dependency proof required')
            else:proof(item['proof'],item,installation['id'])
        self.snapshot,self.accounts,self.files,self.directory_dependency=snapshot,accounts,files,directory_dependency
        prerequisites=deepcopy(installation['prerequisites'])
        prerequisites.pop('provisioning_window_sha256',None)
        if prerequisites.get('profile_sha256')!=installation['profile']['profile_sha256']:
            raise Conflict('original profile prerequisite binding required')
        self.expected=dict(context=deepcopy(installation['context']),prerequisites=prerequisites)
        self._inactive(prerequisites.get('services'))

    def _inactive(self,value):
        profile=self.installation['profile']
        names=set(profile['service_order']+profile['forbidden_vendor_activation'])
        if (not isinstance(value,dict) or set(value)!={'units','dedicated_uid','processes'}
                or value['dedicated_uid']!=profile['session']['uid'] or type(value['dedicated_uid']) is not int
                or value['processes']!=[] or not isinstance(value['units'],dict) or set(value['units'])!=names):
            raise Conflict('complete inactive configuration service inventory required')
        for state in value['units'].values():
            if (not isinstance(state,dict) or set(state)!={'active_state','job_id'}
                    or state['active_state']!='inactive' or type(state['job_id']) is not int or state['job_id']!=0):
                raise Conflict('configuration service active, pending or ambiguous')

    def _snapshot(self):
        current=self.snapshot()
        if current!=self.expected:raise Conflict('original configuration host prerequisites differ')
        self._inactive(current['prerequisites']['services'])
        return deepcopy(current)

    def _targets(self):
        original=self.installation;result={}
        for item in original['items']:
            spec=item['spec']
            if spec.get('path')==UNIT:continue
            if item['phase']=='dependency':
                if spec['kind']!='directory':raise Conflict('original directory dependency required')
                current=self.directory_dependency(deepcopy(spec))
            elif spec['kind'] in ('group','account'):
                current=self.accounts.observe(deepcopy(item),original['id'])
            elif spec['kind'] in ('file','directory'):
                current=self.files.observe(deepcopy(item),original['id'])
            else:raise Conflict('unknown original installation resource')
            if current!=item['proof']:raise Conflict('original unchanged configuration resource differs: '+spec['key'])
            result[spec['key']]=deepcopy(current)
        return result

    def __call__(self,value):
        if (value['installation']!=self.installation or value['plan']!=compile_revision(self.installation)
                or value['source_sha256']!=fingerprint(self.installation)):
            raise Conflict('original configuration preflight request differs')
        first=self._snapshot();resources=self._targets()
        if self._targets()!=resources or self._snapshot()!=first:
            raise Conflict('configuration prerequisites changed during complete preflight')
        return dict(context=deepcopy(first['context']),source_sha256=value['source_sha256'],
            unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)
