"""Deletion-only recovery of a local managed batch without a usage handoff.

Infrastructure adapters are the original guarded resource owners, not shell
commands. They must qualify the complete dependent inventory and use ordinary
cleanup after VD absence. No implicit adoption, force, recreation or reopen.
"""
from copy import deepcopy
import json
import re

from .runtime_operations import RuntimeOperationError, digest, encoded
from . import native_public as native, runtime_lab_closure as closure
from ..controllers.runtime_node import RuntimeNodeController


class CleanupSteps:
    """Track ordered ordinary owner cleanup; preserve later dependencies on error.

    Each owner implements identity(), preflight(pin, retiring=False), cleanup(pin), and
verify_cleaned(pin). identity() must read and qualify its original journal.
"""
    ORDER=('relay','jumphost','dns','management','external')

    def __init__(self, owners):
        if set(owners)!=set(self.ORDER):raise RuntimeOperationError('complete infrastructure cleanup owners required')
        self.owners=owners

    def identity(self):return {name:self.owners[name].identity() for name in self.ORDER}

    def preflight(self,pins,progress):
        if set(pins)!=set(self.ORDER) or set(progress)-set(self.ORDER):raise RuntimeOperationError('cleanup inventory differs')
        for name in self.ORDER:
            phase=progress.get(name)
            if phase not in (None,'deleting','cleaned'):raise RuntimeOperationError('cleanup progress differs')
            if phase=='cleaned':self.owners[name].verify_cleaned(pins[name])
            else:self.owners[name].preflight(pins[name],retiring=phase=='deleting')

    def cleanup(self,pins,progress,save):
        self.preflight(pins,progress)
        for name in self.ORDER:
            owner=self.owners[name]
            if progress.get(name)=='cleaned':continue
            progress[name]='deleting';save()
            self.preflight(pins,progress)
            owner.cleanup(pins[name]);owner.verify_cleaned(pins[name])
            progress[name]='cleaned';save()


class Retirement:
    def __init__(self,batch,load_state,checkpoint,network_observer,infrastructure):
        self.batch,self.store=batch,batch.store
        self.load_state,self.checkpoint=load_state,checkpoint
        self.network_observer,self.infrastructure=network_observer,infrastructure

    def get(self,lab,key):
        row=self.store.db.execute('SELECT * FROM initial_retirements WHERE lab=? AND request_id=?',(lab,key)).fetchone()
        if row is None:return None
        value=dict(row);value['intent']=json.loads(value['intent']);value['progress']=json.loads(value['progress'])
        if digest(value['intent'])!=value['fingerprint']:raise RuntimeOperationError('retirement original intent integrity differs')
        return value

    def save(self,lab,key,progress,phase):
        with self.store.transaction():
            self.store.db.execute('UPDATE initial_retirements SET progress=?,phase=? WHERE lab=? AND request_id=?',
                                  (encoded(progress),phase,lab,key))

    def context(self,lab,intent):
        state=self.load_state()
        if (not state or state.lab_name!=lab or state.runtime_mode!='custom' or state.retired_native_nodes
                or set(state.node_runtime)!=set(intent['births']) or state.runtime_links or state.realnets):
            raise RuntimeOperationError('retirement requires complete original local workload inventory')
        views={};allowed={host:{s:{} for s in defs} for host,defs in intent['networks'].items()}
        for node,birth in intent['births'].items():
            runtime=state.node_runtime[node];binding={k:v for k,v in runtime.runtime_binding.items() if k!='stop_request_id'}
            if binding!=birth['binding']:raise RuntimeOperationError('retirement original VD binding changed')
            original=native.source(self.store,state,node);client=self.batch.factory(birth['target']).bound_to(birth['journal_id'])
            view,candidate=native.inspect_owned(self.store,state,node,client)
            if candidate['request_id']!=original['request_id'] or original['request']!=birth['request']:
                raise RuntimeOperationError('retirement workload birth intent changed')
            workload=view.get('workload') or {}
            if (workload.get('container_id')!=binding['container_id'] or workload.get('generation')!=binding['generation']
                    or workload.get('creator_operation_id')!=birth['creator']):
                raise RuntimeOperationError('retirement original generation changed')
            operation=view.get('operation');stop=intent['stops'][node]
            if operation:
                receipt=client.find_node_request(stop,verify_content=True)
                if not receipt or receipt['id']!=operation['id'] or operation.get('action')!='stop':
                    raise RuntimeOperationError('retirement has another pending operation')
            elif view['committed_state'] not in ('running','stopped'):
                raise RuntimeOperationError('retirement workload is not committed')
            stopped=(view['container_state']=='absent' and view['committed_state']=='stopped' and operation is None)
            if stopped or view['container_state']=='stopped':
                receipt=client.find_node_request(stop,verify_content=True)
                if not receipt or not receipt.get('shutdown_verified') or receipt.get('recovery_force'):
                    raise RuntimeOperationError('retirement absence lacks original ordinary shutdown')
            if not stopped:
                spec=birth['request']['spec'];network=spec['management']['network'];host=birth['target']['host']
                segments=[s for s,v in intent['networks'][host].items() if v['network']==network]
                if len(segments)!=1:raise RuntimeOperationError('retirement management segment changed')
                allowed[host][segments[0]][binding['container_id']]={'node':node,'name':spec['container_name'],
                    'image':spec['image'],'spec_fingerprint':binding['spec_fingerprint'],
                    'creator':birth['creator'],
                    'management':deepcopy(spec['management']),'allow_absent':view['container_state']=='stopped'}
            views[node]=view
        return state,views,allowed

    def prepare(self,lab,key,batch_key,stop_keys):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',key):raise RuntimeOperationError('retirement request ID required')
        with self.store.executing(lab,'management-barrier'), self.store.executing(lab,'public-lifecycle'), self.store.executing(lab,'initial-deployment:all'):
            prior=self.get(lab,key)
            if prior:
                if prior['intent']['batch']!=batch_key or {n:r['request_id'] for n,r in prior['intent']['stops'].items()}!=stop_keys:
                    raise RuntimeOperationError('retirement retry manifest changed')
                return prior
            if (self.store.db.execute("SELECT 1 FROM initial_retirements WHERE lab=? AND phase!='cleaned'",(lab,)).fetchone()
                    or any(owner==lab for owner,_ in self.store.pending())
                    or self.store.db.execute("SELECT 1 FROM public_requests WHERE lab=? AND phase='pending'",(lab,)).fetchone()
                    or self.store.db.execute("SELECT 1 FROM public_link_requests WHERE lab=? AND phase NOT IN ('completed','failed','cancelled')",(lab,)).fetchone()):
                raise RuntimeOperationError('another original operation requires recovery before retirement')
            fence=closure.get(self.store,lab)
            if fence and fence['phase']!='open':raise RuntimeOperationError('another lab closure requires recovery')
            batch=self.batch.get(lab,batch_key,private=True);payload=batch['payload']
            if batch['phase']!='completed' or batch['cancel_requested'] or not payload.get('management_parent'):
                raise RuntimeOperationError('original completed managed batch required')
            if self.batch.management_usage.get(lab,batch_key) is not None:
                raise RuntimeOperationError('retirement is only for a missing pre-birth usage intent')
            parent,original=self.batch.released_parent(lab,payload['management_parent']['request_id'])
            if parent!=payload['management_parent'] or len(original['targets'])!=1:
                raise RuntimeOperationError('original single-host retirement scope required')
            metadata=original['infrastructure']['snapshot']['infrastructure'];state=self.load_state();births={};stops={}
            if not state or state.teardown_requested:raise RuntimeOperationError('original deployment state required')
            members=self.batch.members(lab,batch_key)
            if set(stop_keys)!={m['node'] for m in members} or len(set(stop_keys.values()))!=len(stop_keys):
                raise RuntimeOperationError('complete distinct original stop keys required')
            for member in members:
                node=member['node'];view=self.batch.client(member).inspect_node(lab,node)
                b=state.node_runtime[node].runtime_binding
                if member['phase']!='completed' or view['operation'] or view['committed_state']!='running':
                    raise RuntimeOperationError('retirement requires original committed generation')
                if b['container_id']!=view['container_id'] or b['birth_request_id']!=member['request_id']:
                    raise RuntimeOperationError('retirement binding differs from original batch')
                births[node]={'binding':{k:v for k,v in b.items() if k!='stop_request_id'},'target':member['target'],
                              'journal_id':member['journal_id'],'request':member['request'],
                              'creator':view['workload']['creator_operation_id']}
                stop={'schema_version':1,'lab_id':lab,'node_id':node,'action':'stop','stop_mode':'coordinated',
                      'request_id':stop_keys[node],'expected_revision':view['revision'],'lab_generation':parent['generation']}
                plan=self.batch.client(member).plan_node(stop)
                if (plan.get('link_affected_nodes')!=[node] or plan.get('local_links')
                        or not re.fullmatch('[0-9a-f]{64}',str(plan.get('stop_fingerprint','')))):
                    raise RuntimeOperationError('retirement with data links is not qualified')
                stop['expected_stop_fingerprint']=plan['stop_fingerprint'];stops[node]=stop
            intent={'batch':batch_key,'batch_fingerprint':digest(payload),'parent':parent,'births':births,'stops':stops,
                    'networks':metadata['networks'],'infrastructure':self.infrastructure.identity()}
            _,_,allowed=self.context(lab,intent)
            intent['network_proofs']=self.network_observer(allowed)
            proofs=original['infrastructure']['proofs']
            if set(intent['network_proofs'])!=set(original['targets']):raise RuntimeOperationError('all original retirement hosts required')
            for host,observed in intent['network_proofs'].items():
                if (observed['kernel']!=proofs[host]['kernel'] or
                        {s:{k:v for k,v in p.items() if k in ('id','nonce','expected')} for s,p in observed['networks'].items()}
                        !=proofs[host]['networks']['proof']['networks']):
                    raise RuntimeOperationError('retirement network differs from original preparation proof')
            self.infrastructure.preflight(intent['infrastructure'],{})
            with self.store.transaction():
                self.store.db.execute('INSERT INTO initial_retirements VALUES(?,?,?,?,?,?)',
                    (lab,key,encoded(intent),digest(intent),encoded({'cleanup':{}}),'prepared'))
            return self.get(lab,key)

    def advance(self,lab,key):
        with self.store.executing(lab,'management-barrier'), self.store.executing(lab,'public-lifecycle'), self.store.executing(lab,'initial-deployment:all'):
            row=self.get(lab,key)
            if row is None:raise RuntimeOperationError('original retirement intent missing')
            intent,progress,phase=row['intent'],row['progress'],row['phase']
            if digest(self.batch.get(lab,intent['batch'],private=True)['payload'])!=intent['batch_fingerprint']:
                raise RuntimeOperationError('retirement original batch changed')
            parent,_=self.batch.released_parent(lab,intent['parent']['request_id'])
            if parent!=intent['parent']:raise RuntimeOperationError('retirement original management parent changed')
            late=phase in ('infrastructure_cleanup','cleaned')
            if late:
                self.verify_absence(lab,intent,progress)
                state,views,allowed=self.load_state(),{},{}
            else:state,views,allowed=self.context(lab,intent)
            if phase not in ('infrastructure_cleanup','cleaned'):
                observed=self.network_observer(allowed)
                for host,proof in observed.items():
                    original=intent['network_proofs'][host]
                    if proof['kernel']!=original['kernel'] or any({k:v for k,v in value.items() if k!='containers'}!=
                            {k:v for k,v in original['networks'][s].items() if k!='containers'} for s,value in proof['networks'].items()):
                        raise RuntimeOperationError('retirement network generation changed')
            self.infrastructure.preflight(intent['infrastructure'],progress['cleanup'])
            clients={n:self.batch.factory(b['target']).bound_to(b['journal_id']) for n,b in intent['births'].items()}
            if phase=='prepared':
                for node,stop in intent['stops'].items():
                    RuntimeNodeController(self.store,lambda target,c=clients[node]:c).prepare_local_stop(stop,intent['births'][node]['target'],participating_hosts=[intent['births'][node]['target']['host']])
                    state.node_runtime[node].runtime_binding['stop_request_id']=stop['request_id']
                self.checkpoint(state)
                token=closure.begin(self.store,lab,[s['request_id'] for s in intent['stops'].values()])
                progress['closure']=token['closure_id'];self.save(lab,key,progress,'fencing');phase='fencing'
            if phase=='fencing':
                token=closure.get(self.store,lab);first=next(iter(intent['births']));birth=intent['births'][first]
                if token['closure_id']!=progress['closure']:raise RuntimeOperationError('retirement closure changed')
                remote=clients[first].lab_closure(lab,'close',{'closure_id':token['closure_id'],'generation':token['generation'],'stops':list(intent['stops'].values())})
                closure.receipt(self.store,lab,token['closure_id'],birth['target'],birth['journal_id'],remote)
                self.save(lab,key,progress,'stopping');phase='stopping'
            if phase=='stopping':
                for node,stop in intent['stops'].items():
                    if views[node]['committed_state']=='stopped' and views[node]['container_state']=='absent':continue
                    receipt=RuntimeNodeController(self.store,lambda target,c=clients[node]:c).advance_local_stop(lab,stop['request_id'],participating_hosts=[intent['births'][node]['target']['host']])
                    if receipt['phase'] in ('failed','cancelled','recovery_required'):
                        raise RuntimeOperationError('retirement ordinary shutdown requires explicit recovery')
                state,views,allowed=self.context(lab,intent)
                if any(v['operation'] or v['committed_state']!='stopped' or v['container_state']!='absent' for v in views.values()):return self.get(lab,key)
                for runtime in state.node_runtime.values():runtime.state='stopped'
                self.checkpoint(state);progress['absence']=deepcopy(views)
                self.save(lab,key,progress,'closing');phase='closing'
            if phase=='closing':
                first=next(iter(intent['births']));birth=intent['births'][first];token=closure.get(self.store,lab)
                remote=clients[first].lab_closure(lab,'finish',{'closure_id':token['closure_id'],'generation':token['generation']})
                closure.receipt(self.store,lab,token['closure_id'],birth['target'],birth['journal_id'],remote)
                closure.finish(self.store,lab,token['closure_id'],{digest({'target':birth['target'],'journal_id':birth['journal_id']})})
                self.save(lab,key,progress,'infrastructure_cleanup');phase='infrastructure_cleanup'
            if phase=='infrastructure_cleanup':
                self.verify_absence(lab,intent,progress)
                self.infrastructure.cleanup(intent['infrastructure'],progress['cleanup'],lambda:self.save(lab,key,progress,'infrastructure_cleanup'))
                self.verify_absence(lab,intent,progress)
                self.save(lab,key,progress,'cleaned')
            return self.get(lab,key)

    def verify_absence(self,lab,intent,progress):
        token=closure.get(self.store,lab)
        if (not token or token['phase']!='closed' or token['closure_id']!=progress.get('closure')
                or set(progress.get('absence',{}))!=set(intent['births'])):
            raise RuntimeOperationError('retirement closed fence and original absence proof required')
        state=self.load_state()
        if not state or set(state.node_runtime)!=set(intent['births']):raise RuntimeOperationError('retirement state changed')
        for node,birth in intent['births'].items():
            binding={k:v for k,v in state.node_runtime[node].runtime_binding.items() if k!='stop_request_id'}
            if binding!=birth['binding'] or state.node_runtime[node].runtime_binding['stop_request_id']!=intent['stops'][node]['request_id']:
                raise RuntimeOperationError('retirement original stopped binding changed')
            view=progress['absence'][node]
            if (view['operation'] or view['container_state']!='absent' or view['committed_state']!='stopped'
                    or view['workload']['container_id']!=binding['container_id'] or view['workload']['generation']!=binding['generation']):
                raise RuntimeOperationError('retirement stored absence differs')
            saved=self.store.get(lab,intent['stops'][node]['request_id'],private=True)
            client=self.batch.factory(birth['target']).bound_to(birth['journal_id'])
            receipt=client.find_node_request(intent['stops'][node],verify_content=True)
            if (not receipt or saved['request']!=intent['stops'][node] or saved['operation_id']!=receipt['id']
                    or receipt['phase']!='completed' or receipt.get('shutdown_verified') is not True
                    or receipt.get('stop_stage')!='finished' or receipt.get('recovery_force')):
                raise RuntimeOperationError('retirement original shutdown receipt differs')
        # The original management may already have been removed. Do not use
        # inspect() to re-adopt it: require exact Docker ID/name absence through
        # the dedicated read-only observer and retain the closed runtime fence.
        self.network_observer.verify_absent(intent['births'])
