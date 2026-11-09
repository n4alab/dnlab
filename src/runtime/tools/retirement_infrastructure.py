"""Original fixture infrastructure owners for deletion-only retirement.

Construction only reads private original journals. No automatic gate or
recovery execution. Caller configures the same original service PATHS and host.
"""
from copy import deepcopy
from pathlib import Path

from native_jumphost_stage import read_intent
from management_service_diagnostics import remove_fixture_external
from dnlab_multinode.services import jumphost,dns,runtime_relay,netsetup,state as states
from dnlab_multinode.services.initial_retirement import CleanupSteps
from dnlab_multinode.services.jumphost_network_host import Worker as ExternalWorker
from dnlab_multinode.services.realnet_vni import Registry
from dnlab_multinode.services.runtime_operations import RuntimeOperationError


def original(root,role):
    paths=list((root/role).glob('*.json'))
    if len(paths)!=1:raise RuntimeOperationError('original '+role+' journal ambiguous')
    return read_intent(paths[0],limit=4*1024*1024)


def birth(record):
    return {k:deepcopy(record[k]) for k in ('config','nonce','container_id','image','context','namespace','started_at') if k in record}


class HelperOwner:
    def __init__(self,role,lab,host,record):
        self.role,self.lab,self.host=role,lab,host;self.pin=birth(record)
        self.module={'relay':runtime_relay,'jumphost':jumphost,'dns':dns}[role]
    def call(self,action):
        if self.role=='relay':return self.module._guard(self.host,self.lab,'master',action,generation=self.pin['config']['generation'])
        config={'generation':self.pin['config']['generation']}
        if self.role=='jumphost':config['container']=self.pin['config']['name']
        return self.module._guard(self.host,self.lab,action,config)
    def identity(self):self.preflight(self.pin);return deepcopy(self.pin)
    def preflight(self,pin,*,retiring=False):
        if pin!=self.pin or birth(self.call('preflight-delete'))!=pin:raise RuntimeOperationError('original helper retirement generation changed')
    def cleanup(self,pin):self.preflight(pin,retiring=True);self.call('delete')
    def verify_cleaned(self,pin):
        value=self.call('verify-cleaned')
        if pin!=self.pin or birth(value)!=pin or value['phase']!='cleaned':raise RuntimeOperationError('helper retirement cleanup not verified')


class ManagementOwner:
    def __init__(self,root,lab,host,metadata):
        self.root,self.lab,self.clients=root,lab,{'master':host}
        self.pin={k:deepcopy(metadata[k]) for k in ('plans','networks','reservations')}
    def current(self,pin):
        state=states.load_state(self.lab,self.root)
        if (pin!=self.pin or not state or not state.mgmt
                or any(state.mgmt.infrastructure.get(k)!=v for k,v in pin.items())):
            raise RuntimeOperationError('original management retirement metadata changed')
        return state
    def identity(self):self.preflight(self.pin);return deepcopy(self.pin)
    def preflight(self,pin,*,retiring=False):
        self.current(pin)
        for host,plan in pin['plans'].items():netsetup.invoke(self.clients[host],'preflight',plan)
    def cleanup(self,pin):
        state=self.current(pin)
        netsetup.destroy_management(state,self.clients,checkpoint=lambda:states.save_state(state,self.root),registry=Registry(self.root/'vni'))
    def verify_cleaned(self,pin):
        state=self.current(pin);netsetup.verify_management_cleaned(state,self.clients)
        if state.mgmt.infrastructure.get('phase')!='cleaned':raise RuntimeOperationError('management reservations/cleanup pending')


class ExternalOwner:
    def __init__(self,root,record,api):
        self.worker=ExternalWorker(record['config'],directory=root/'external');self.api=api
        self.pin={k:deepcopy(record[k]) for k in ('config','id','nonce','context','bridge')}
    def identity(self):self.preflight(self.pin);return deepcopy(self.pin)
    def preflight(self,pin,*,retiring=False):
        record=self.worker.read()
        if pin!=self.pin or not record or any(record.get(k)!=v for k,v in pin.items()):
            raise RuntimeOperationError('original external network retirement generation changed')
        if self.worker.docker.inspect(pin['id']) is None and retiring:
            self.verify_cleaned(pin);return
        self.worker.preflight()
    def cleanup(self,pin):
        self.preflight(pin,retiring=True)
        if self.worker.docker.inspect(pin['id']) is not None:remove_fixture_external(self.worker,self.api)
    def verify_cleaned(self,pin):
        record=self.worker.read()
        if (pin!=self.pin or not record or any(record.get(k)!=v for k,v in pin.items()) or self.worker.docker.inspect(pin['id']) is not None
                or self.worker.docker.inspect(pin['config']['network']) is not None or self.worker.bridge() is not None):
            raise RuntimeOperationError('external network retirement absence not verified')


def owners(root,lab,host,state,parent,api):
    root=Path(root)
    if list(root.glob('cli-*')) or (root/'native-jumphost-cli-plan.json').exists():
        raise RuntimeOperationError('original CLI execution requires its qualified cleanup before retirement')
    for module,key,directory in ((jumphost,'jumphost_journal_dir','jump'),(dns,'dns_journal_dir','dns'),
            (runtime_relay,'relay_journal_dir','relay'),(netsetup,'management_journal_dir','management')):
        if Path(getattr(module.PATHS,key))!=root/directory:raise RuntimeOperationError('original fixture journal directory binding required')
    jump=original(root,'jump');dn=original(root,'dns');relay=original(root,'relay');external=original(root,'external')
    receipt=parent.get('services',{}).get('receipt')
    if not receipt:raise RuntimeOperationError('original service materialization receipt required')
    for role,record in (('jumphost',jump),('dns',dn)):
        service=getattr(state,role)
        if ({k:record[k] for k in ('container_id','nonce')}!=receipt[role]
                or record['config']['lab']!=lab or record['config']['name']!=service.container
                or record['config']['generation']!=service.generation):
            raise RuntimeOperationError('original helper materialization receipt differs')
    saved=state.runtime_relays.get('master')
    if (not saved or saved.container_id!=relay['container_id'] or saved.generation!=relay['config']['generation']
            or saved.container!=relay['config']['name'] or receipt['external_network_id']!=external['id']):
        raise RuntimeOperationError('original relay/external retirement binding differs')
    metadata=parent['infrastructure']['snapshot']['infrastructure']
    if set(metadata['plans'])!={'master'}:raise RuntimeOperationError('single-host fixture retirement required')
    return CleanupSteps({'relay':HelperOwner('relay',lab,host,relay),'jumphost':HelperOwner('jumphost',lab,host,jump),
        'dns':HelperOwner('dns',lab,host,dn),'management':ManagementOwner(root,lab,host,metadata),
        'external':ExternalOwner(root,external,api)})
