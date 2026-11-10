"""Match progressive service inventory to original activation acknowledgements.

No process/service is discovered or adopted by name. Fresh generation observers
must bind the original command completion, process and socket before this census
can accept active dedicated services. No query or action transport is supplied.
"""
from copy import deepcopy

from .libvirt_activation import SessionActivation,steps
from .libvirt_service_observer import qualify_service
from .manifest import Conflict,fingerprint


class ActivationServices:
    def __init__(self,installation,*,generation_observer):
        if not callable(generation_observer):raise Conflict('explicit original activation generation observer required')
        self.installation=deepcopy(installation);self.generation_observer=generation_observer

    def validate(self,value,inventory,receipts):
        source=self.installation;profile=source['profile']
        expected_steps=steps(profile)
        if (value['installation']!=source or value['installation_sha256']!=fingerprint(source)
                or [item['spec'] for item in value['items']]!=expected_steps
                or not isinstance(receipts,dict) or set(receipts)!={spec['key'] for spec in expected_steps}):
            raise Conflict('original complete activation service binding required')
        names=set(profile['service_order']+profile['forbidden_vendor_activation'])
        if (not isinstance(inventory,dict) or set(inventory)!={'units','dedicated_uid','processes'}
                or type(inventory['dedicated_uid']) is not int or inventory['dedicated_uid']!=profile['session']['uid']
                or not isinstance(inventory['units'],dict) or set(inventory['units'])!=names
                or not isinstance(inventory['processes'],list)):
            raise Conflict('complete activation service census required')
        units={name:dict(active_state='inactive',job_id=0) for name in names}
        processes={};gap=False;observers=[]
        for item in value['items']:
            receipt=receipts[item['spec']['key']]
            if item['phase'] not in ('prepared','requested','confirmed'):
                raise Conflict('original activation service phase differs')
            if item['phase']=='confirmed' and receipt!=item['proof']:
                raise Conflict('original confirmed activation generation differs')
            if receipt is None:
                if item['phase']=='confirmed':raise Conflict('original confirmed activation proof missing')
                gap=True;continue
            if gap or item['phase']=='prepared':raise Conflict('activation service has no original ordered request')
            SessionActivation._receipt(value,item,receipt)
            if item['spec']['kind']=='reload':continue
            observer=self.generation_observer(deepcopy(value),deepcopy(item),deepcopy(receipt))
            if not callable(observer):raise Conflict('qualified original service observer required')
            observed=observer();unit=item['spec']['unit']
            original=receipt['identity']['service'];socket_path=original['socket']['path']
            qualified=qualify_service(source,unit,socket_path,observed)
            if qualified!=original:raise Conflict('original activation service generation differs')
            observers.append((observer,qualified))
            process=qualified['process'];pid=process['pid']
            if pid in processes:raise Conflict('activation services share an ambiguous process')
            processes[pid]={key:deepcopy(process[key]) for key in ('pid','uids','gids','groups')}
            units[unit]=dict(active_state='active',job_id=0)
        for name,state in inventory['units'].items():
            if (not isinstance(state,dict) or set(state)!={'active_state','job_id'}
                    or type(state['job_id']) is not int or state!=units[name]):
                raise Conflict('activation unit active, pending or unacknowledged: '+name)
        actual={}
        for row in inventory['processes']:
            if (not isinstance(row,dict) or set(row)!={'pid','uids','gids','groups'}
                    or type(row['pid']) is not int or row['pid']<=0 or row['pid'] in actual):
                raise Conflict('ambiguous dedicated activation process census')
            actual[row['pid']]=row
        if actual!=processes:raise Conflict('foreign, missing or changed dedicated activation process')
        for observer,original in observers:
            if observer()!=original:raise Conflict('activation generation changed during census validation')
        return dict(inventory_sha256=fingerprint(inventory),receipts_sha256=fingerprint(receipts),
            installation_sha256=fingerprint(source))
