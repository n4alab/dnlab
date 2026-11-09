"""Public lifecycle bridge for already-qualified local native VD bindings.

Placement and initial deployment remain with multinode. No name-based adoption,
Containerlab fallback, implicit recovery/force, or NOS readiness inference.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
import re
import time
import uuid

from .custom_runtime import RuntimeClient
from .runtime_operations import OperationStore,OperationDriver,RuntimeOperationError,digest,encoded,FINAL
from .runtime_cleanup import operation_directory,make_binding
from . import runtime_lab_closure as closure,state as state_svc


class NativeOwnershipError(RuntimeOperationError):pass


def owners(state):return {**state.retired_native_nodes,**state.node_runtime}


def runtime_for(state,node):return owners(state)[node]


FIELDS={'backend','journal_id','birth_request_id','stop_request_id','container_id','generation','spec_fingerprint','revision'}


def backend(state,node=None):
    bindings=[r.runtime_binding for r in owners(state).values()]
    mode=state.runtime_mode
    if mode not in ('','legacy','per-vd','custom'):raise NativeOwnershipError('unknown persisted runtime backend')
    if any(bindings) or mode=='custom':
        if any(not isinstance(b,dict) or set(b)!=FIELDS or b.get('backend')!='custom' for b in bindings):
            raise NativeOwnershipError('native lab contains an incomplete or unknown owner binding')
        if node is not None and node not in owners(state):raise NativeOwnershipError('native spawn requires an original qualified deployment intent')
        return 'custom'
    return 'containerlab'


def store_for(directory):
    path=operation_directory(directory)
    if not (path/'operations.sqlite3').is_file():raise NativeOwnershipError('private native operation ledger missing')
    return OperationStore(path)


@contextmanager
def state_guard(state,directory):
    """Shared with daemon finalization; status inspection never takes this lock."""
    if not any(r.runtime_binding for r in owners(state).values()):yield;return
    store=store_for(directory)
    try:
        with store.executing(state.lab_name,'public-lifecycle'):yield
    finally:store.close()


def source(store,state,node):
    runtime=runtime_for(state,node);b=runtime.runtime_binding
    backend(state,node)
    if (type(b['generation']) is not int or b['generation']<1 or type(b['revision']) is not int or b['revision']<1
            or not isinstance(b['container_id'],str) or not re.fullmatch(r'[0-9a-f]{64}',b['container_id'])):
        raise NativeOwnershipError('invalid native generation binding')
    original=store.get(state.lab_name,b['birth_request_id'],private=True)
    if (original['node']!=node or original['phase']!='completed' or original['request'].get('action')!='start'
            or original['target']['host']!=runtime.host or original['journal_id']!=b['journal_id']
            or original['request']['spec']['container_name']!=runtime.container
            or original['request']['spec'].get('kind')!='linux'
            or runtime.kind not in ('','linux') or digest(original['request']['spec'])!=b['spec_fingerprint']):
        raise NativeOwnershipError('native birth intent, host or specification differs')
    return original


def client_for(ssh,original):
    target=original['target']
    return RuntimeClient(ssh,socket_path=target['socket_path'],container_name=target['container_name'],require_management_identity=bool(original.get('request',{}).get('spec',{}).get('management'))).bound_to(original['journal_id'])


def inspect_owned(store,state,node,client):
    original=source(store,state,node);b=runtime_for(state,node).runtime_binding
    view=client.inspect_node(state.lab_name,node);birth=view.get('workload') or {}
    creator=birth.get('creator_operation_id');candidate=original
    if creator!=original['operation_id']:
        # Transition specs come exclusively from original private intents. A
        # lost submission ACK may require a content-matching read-only lookup.
        candidates=[]
        for row in store.db.execute('SELECT request_id FROM operations WHERE lab=? AND node=?',(state.lab_name,node)).fetchall():
            entry=store.get(state.lab_name,row[0],private=True)
            if entry['request'].get('action')!='start' or entry['target']!=original['target'] or entry['journal_id']!=original['journal_id']:continue
            if digest(entry['request']['spec'])!=birth.get('spec_fingerprint'):continue
            if entry['operation_id'] and entry['operation_id']!=creator:continue
            active=view.get('operation') or {}
            receipt=entry['receipt'] if entry['operation_id']==creator and active.get('id')==creator else client.find_node_request(entry['request'],verify_content=True)
            if receipt and receipt['id']==creator:
                if entry['operation_id'] and entry['operation_id']!=creator:raise NativeOwnershipError('native creator receipt changed')
                candidates.append((entry,receipt))
        if len(candidates)!=1:raise NativeOwnershipError('native workload lacks its original tracked start')
        candidate,receipt=candidates[0]
        if (birth.get('generation',0)<=b['generation'] or candidate['request']['expected_revision']<b['revision']+1
                or candidate['request']['spec']['container_name']!=runtime_for(state,node).container):
            raise NativeOwnershipError('native workload transition differs from its birth intent')
        operation=view.get('operation')
        if operation:
            if operation.get('id')!=creator or operation.get('action')!='start' or view['revision']!=candidate['request']['expected_revision']:
                raise NativeOwnershipError('pending native workload lacks original start context')
        elif (receipt['phase']!='completed' or view['revision']!=candidate['request']['expected_revision']+1
              or view['committed_state']!='running' or birth.get('phase')!='running'):
            if (receipt['phase'] not in ('cancelled','failed') or birth.get('phase')!='cleaned'
                    or view['revision']!=candidate['request']['expected_revision'] or view['container_state']!='absent'
                    or view['committed_state']!='stopped' or view.get('committed_spec_fingerprint')!=b['spec_fingerprint']):
                raise NativeOwnershipError('native transition requires explicit recovery')
            candidate={**candidate,'qualified_abort_receipt':receipt}
    elif (birth.get('generation')!=b['generation'] or birth.get('container_id')!=b['container_id']
          or birth.get('spec_fingerprint')!=b['spec_fingerprint']):
        raise NativeOwnershipError('native workload generation differs')
    if creator==original['operation_id']:
        expected=b['revision']+(view['committed_state']=='stopped')
        if view['revision']!=expected:raise NativeOwnershipError('native committed revision differs from original coordinator intent')
    operation=view.get('operation')
    if operation:
        matches=[]
        for row in store.db.execute('SELECT request_id FROM operations WHERE lab=? AND node=?',(state.lab_name,node)).fetchall():
            value=store.get(state.lab_name,row[0],private=True)
            if value['target']!=original['target'] or value['journal_id']!=original['journal_id']:continue
            if value['operation_id'] and value['operation_id']!=operation['id']:continue
            receipt=value['receipt'] if value['operation_id']==operation['id'] else client.find_node_request(value['request'],verify_content=True)
            if receipt and receipt['id']==operation['id']:
                if operation.get('request_id')!=value['request_id']:raise NativeOwnershipError('native pending request context differs')
                if (value['operation_id'] and value['operation_id']!=operation['id']
                        or value['request']['action']!=operation['action'] or value['request']['expected_revision']!=view['revision']):
                    raise NativeOwnershipError('native pending operation provenance differs')
                matches.append(value)
        if len(matches)!=1:raise NativeOwnershipError('native pending operation lacks original coordinator provenance')
    if view.get('container_id') is not None and view['container_id']!=birth.get('container_id'):
        raise NativeOwnershipError('native container identity differs')
    return view,candidate


def projected(runtime,view):
    result=deepcopy(runtime);operation=view.get('operation')
    if operation:
        phase=operation['phase']
        result.state=('error' if phase=='recovery_required' else 'cancelling' if operation.get('cancel_requested')
                      else 'stopping' if operation['action']=='stop' else 'reconciling' if phase=='verifying' else 'starting')
        result.last_error='Native operation requires explicit recovery' if phase=='recovery_required' else ''
    elif view['committed_state']=='running' and view['container_state']=='running':result.state='running';result.last_error=''
    elif view['committed_state']=='stopped' and view['container_state']=='absent':result.state='stopped';result.last_error=''
    else:result.state='error';result.last_error='Native committed and workload states disagree'
    result.runtime_status={k:deepcopy(view.get(k)) for k in ('journal_id','revision','committed_state','container_state','container_id','workload','operation','guest_readiness')}
    result.runtime_status['backend']='custom';result.runtime_status['qualified']=True
    return result


def project(state,directory,clients):
    result=deepcopy(state.node_runtime);store=store_for(directory)
    try:
        backend(state)
        for node,runtime in state.node_runtime.items():
            try:
                original=source(store,state,node)
                view,_=inspect_owned(store,state,node,client_for(clients[runtime.host],original))
                result[node]=projected(runtime,view)
            except Exception:
                result[node].state='unknown';result[node].last_error='Native identity or status unavailable; recovery required'
                result[node].runtime_status={'backend':'custom','qualified':False,'guest_readiness':'unknown'}
        return result
    finally:store.close()


def observe_abort(store,lab,candidate):
    receipt=candidate['qualified_abort_receipt']
    store.observe(lab,candidate['request_id'],receipt)
    # Seal only a parent whose final start child is exactly the qualified
    # terminal attempt; no implicit cancellation of other pending steps.
    with store.transaction():
        for row in store.db.execute("SELECT * FROM public_requests WHERE lab=? AND node=? AND phase='pending'",(lab,candidate['node'])).fetchall():
            payload=json.loads(row['payload']);index='0' if row['action']=='start' else '1' if row['action']=='restart' else None
            request=payload.get('requests',{}).get(index)
            if request==candidate['request'] and (index=='0' or payload.get('0')=='completed'):
                store.db.execute('UPDATE public_requests SET phase=? WHERE lab=? AND request_id=?',(receipt['phase'],lab,row['request_id']))


class PublicLifecycle:
    def __init__(self,controller,clients,store):
        self.ctrl=controller;self.state=controller.state;self.clients=clients;self.store=store
        self.driver=OperationDriver(store,lambda target:client_for(clients[target['host']],{'target':target,'journal_id':self.journal}))

    def refresh(self,node,*,save=False):
        original=source(self.store,self.state,node);self.journal=original['journal_id'];self.target=original['target']
        self.client=client_for(self.clients[self.target['host']],original)
        view,candidate=inspect_owned(self.store,self.state,node,self.client)
        if candidate.get('qualified_abort_receipt'):
            observe_abort(self.store,self.state.lab_name,candidate)
        if candidate['request_id']!=original['request_id'] and view.get('operation') is None and view['committed_state']=='running':
            receipt=self.client.find_node_request(candidate['request'],verify_content=True)
            self.store.observe(self.state.lab_name,candidate['request_id'],receipt)
            runtime_for(self.state,node).runtime_binding=make_binding(self.store,self.state.lab_name,node,candidate['request_id'],view)
        table=self.state.node_runtime if node in self.state.node_runtime else self.state.retired_native_nodes
        table[node]=projected(runtime_for(self.state,node),view)
        callback=getattr(self.ctrl,'phase_callback',None)
        if callback:callback(table[node].state)
        if save:state_svc.save_state(self.state,self.ctrl.state_dir)
        self.view=view;return view

    def desired_links(self,node):
        result=[]
        for link in self.ctrl.topo.links:
            if node not in (link.source,link.target):continue
            if any(n not in self.state.node_runtime for n in (link.source,link.target)):continue
            endpoints=[];mtus=[]
            for name,iface in ((link.source,link.source_iface),(link.target,link.target_iface)):
                original=source(self.store,self.state,name)
                if original['target']!=self.target:raise NativeOwnershipError('cross-host native public link is not qualified')
                inspect_owned(self.store,self.state,name,client_for(self.clients[self.target['host']],original))
                matches=[e for e in original['request']['spec'].get('endpoints',[]) if e['node_interface']==iface]
                if len(matches)!=1:raise NativeOwnershipError('native desired link lacks its qualified endpoint mapping')
                endpoints.append({'node_id':name,'host_interface':matches[0]['host_interface']})
                mtus.append(matches[0].get('mtu',1500))
            if len(set(mtus))!=1:raise NativeOwnershipError('native local link MTUs differ')
            canonical=sorted(((link.source,link.source_iface),(link.target,link.target_iface)))
            prior=next((entry for entry in self.state.runtime_links if sorted(((entry.endpoint_a.get('node'),entry.endpoint_a.get('iface')),(entry.endpoint_b.get('node'),entry.endpoint_b.get('iface'))))==canonical),None)
            result.append({'link_id':prior.id if prior else 'local-'+digest({'lab':self.state.lab_name,'ports':canonical})[:24],
                'endpoints':endpoints,'spec':{'mtu':mtus[0]},'logical':canonical})
        return result

    def restore_links(self,node,request_key):
        from dnlab_multinode.models.state import RuntimeLinkState
        lab=self.state.lab_name
        for desired in self.desired_links(node):
            endpoints=[]
            for edge in desired['endpoints']:
                intent=source(self.store,self.state,edge['node_id'])
                view,_=inspect_owned(self.store,self.state,edge['node_id'],client_for(self.clients[self.target['host']],intent))
                if view['committed_state']!='running' or view['container_state']!='running' or view['operation']:break
                endpoints.append({**edge,'expected_node_revision':view['revision']})
            if len(endpoints)!=2:continue
            request={'schema_version':1,'kind':'bridge','lab_id':lab,'link_id':desired['link_id'],
                'request_id':'restore-'+digest({'request':request_key,'link':desired['link_id'],'endpoints':endpoints})[:40],
                'action':'create','endpoints':endpoints,'spec':desired['spec']}
            epoch=source(self.store,self.state,node)['request'].get('lab_generation',1)
            if epoch!=1:request['lab_generation']=epoch
            key=request['request_id'];target=encoded(self.target)
            with self.store.transaction():
                prior=self.store.db.execute('SELECT * FROM public_link_requests WHERE lab=? AND request_id=?',(lab,key)).fetchone()
                if prior and (prior['payload']!=encoded(request) or prior['target']!=target or prior['journal_id']!=self.journal):
                    raise NativeOwnershipError('native link restoration intent differs')
                if not prior:self.store.db.execute('INSERT INTO public_link_requests VALUES(?,?,?,?,?,?,?)',(lab,key,encoded(request),target,self.journal,'prepared',''))
            self.store.sync_directory()
            receipt=self.client.submit(request)
            if (receipt.get('lab')!=lab or receipt.get('request_id')!=key or prior and prior['operation_id'] and prior['operation_id']!=receipt['id']):
                raise NativeOwnershipError('native link receipt identity differs')
            with self.store.transaction():self.store.db.execute('UPDATE public_link_requests SET phase=?,operation_id=? WHERE lab=? AND request_id=?',(receipt['phase'],receipt['id'],lab,key))
            deadline=time.monotonic()+30
            while receipt['phase'] not in ('completed','failed','cancelled','recovery_required'):
                if time.monotonic()>=deadline:raise NativeOwnershipError('native link restoration pending; recovery retained')
                receipt=self.client.invoke('link-status',receipt['id']);time.sleep(.1)
            with self.store.transaction():self.store.db.execute('UPDATE public_link_requests SET phase=? WHERE lab=? AND request_id=?',(receipt['phase'],lab,key))
            if receipt['phase']!='completed':raise NativeOwnershipError('native link restoration requires recovery')
            for edge in endpoints:
                actual=self.client.invoke('link-inspect',lab,desired['link_id'],edge['host_interface'])
                if (actual.get('lab_id')!=lab or actual.get('node_id')!=edge['node_id'] or actual.get('committed_state')!='active'
                        or actual.get('runtime_phase')!='active' or actual.get('kernel_state')!='present'):
                    raise NativeOwnershipError('native restored link is not verified active')
            entry=next((r for r in self.state.runtime_links if r.id==desired['link_id']),None)
            if entry is None:
                (a,ia),(b,ib)=desired['logical']
                entry=RuntimeLinkState(id=desired['link_id'],link_type='local',lab_name=lab,endpoint_a={'node':a,'iface':ia},endpoint_b={'node':b,'iface':ib},host_a=self.target['host'],host_b=self.target['host'])
                self.state.runtime_links.append(entry)
            entry.state='up';entry.resource_identities['native_runtime']={'journal_id':self.journal,'request_id':key,'operation_id':receipt['id']}
            state_svc.save_state(self.state,self.ctrl.state_dir)

    def drive(self,node,request):
        lab=self.state.lab_name;key=request['request_id']
        if self.store.contains(lab,key):
            original=self.store.get(lab,key,private=True)['request']
            if {k:v for k,v in original.items() if k not in ('expected_stop_fingerprint','management_preflight')}!={k:v for k,v in request.items() if k not in ('expected_stop_fingerprint','management_preflight')}:
                raise NativeOwnershipError('native request replay differs from its original intent')
            if 'management_preflight' in request and encoded(request['management_preflight'])!=encoded(original.get('management_preflight')):
                raise NativeOwnershipError('native management preflight replay differs from original intent')
            request=original
        elif request['action']=='stop':
            caps=self.client.qualify_node(coordinated_stop=True)
            if caps.get('stop_plan_binding')!='exact preflight footprint fingerprint before shutdown':
                raise NativeOwnershipError('native runtime lacks stop footprint binding')
            plan=self.client.plan_node(request);owners=plan.get('link_affected_nodes')
            if not isinstance(owners,list) or node not in owners or not re.fullmatch(r'[0-9a-f]{64}',str(plan.get('stop_fingerprint',''))):
                raise NativeOwnershipError('native stop preflight is incomplete')
            if any(link.get('kind')!='bridge' for link in plan.get('local_links',[])):
                raise NativeOwnershipError('distributed native stop is not qualified')
            for owner in owners:
                if owner not in self.state.node_runtime or self.state.node_runtime[owner].host!=self.target['host']:
                    raise NativeOwnershipError('native stop preflight owner unavailable')
                intent=source(self.store,self.state,owner)
                inspect_owned(self.store,self.state,owner,client_for(self.clients[self.target['host']],intent))
            request={**request,'expected_stop_fingerprint':plan['stop_fingerprint']}
        self.driver.prepare(request,self.target)
        request=self.store.get(lab,key,private=True)['request']
        self.ctrl._native_intent=(str(self.store.directory),lab,key)
        if request['action']=='stop':
            runtime_for(self.state,node).runtime_binding['stop_request_id']=key
            state_svc.save_state(self.state,self.ctrl.state_dir)
        from dnlab_multinode.controllers.runtime_node import RuntimeNodeController
        local=RuntimeNodeController(self.store,lambda target:self.client)
        deadline=time.monotonic()+max(30,source(self.store,self.state,node)['request']['spec'].get('stop_timeout',30)+10)
        while True:
            if self.ctrl._cancelled() and request['action']=='start':self.store.request_cancel(lab,key)
            current=self.driver.advance(lab,key)
            if current['phase'] in ('awaiting_link_cleanup','awaiting_finalization'):
                # Persisted stop footprint must agree with every owner binding
                # before the first link stage request.
                view=self.refresh(node);op=view['operation'] or {}
                owners=op.get('footprint_nodes')
                if op.get('cleanup_scope')!='local' or not isinstance(owners,list) or node not in owners:
                    raise NativeOwnershipError('distributed or unqualified native stop footprint')
                for owner in owners:
                    if owner not in self.state.node_runtime or self.state.node_runtime[owner].host!=self.target['host']:
                        raise NativeOwnershipError('native stop footprint owner missing')
                    original=source(self.store,self.state,owner)
                    inspect_owned(self.store,self.state,owner,client_for(self.clients[self.target['host']],original))
                current=local.advance_local_stop(lab,key,participating_hosts=[self.target['host']])
            view=self.refresh(node,save=True)
            wanted='running' if request['action']=='start' else 'stopped'
            if current['phase'] not in FINAL and view.get('operation') is None and view['committed_state']==wanted:
                observed=self.client.find_node_request(request,verify_content=True)
                if observed and observed['id']==current['operation_id']:
                    current=self.store.observe(lab,key,observed)
            if current['phase']=='completed':
                if request['action']=='start' and self.ctrl._cancelled():
                    view=self.refresh(node,save=True)
                    shutdown={'schema_version':1,'lab_id':lab,'node_id':node,'action':'stop','stop_mode':'coordinated',
                        'expected_revision':view['revision'],'request_id':'cancel-stop-'+digest({'start':key})[:40]}
                    if request.get('lab_generation',1)!=1:shutdown['lab_generation']=request['lab_generation']
                    job=self.current_job
                    payload=json.loads(self.store.db.execute('SELECT payload FROM public_requests WHERE lab=? AND request_id=?',(lab,job['request_id'])).fetchone()[0])
                    payload['cancellation_stop']=shutdown;self.save_job(job,payload)
                    self.drive(node,shutdown)
                    return {**current,'public_cancelled':True}
                return current
            if (current['phase']=='cancelled' and request['action']=='start'
                    and view['committed_state']=='stopped' and view['container_state']=='absent'
                    and (view.get('workload') or {}).get('phase')=='cleaned'):
                return {**current,'public_cancelled':True}
            if current['phase'] in ('failed','cancelled','recovery_required'):
                raise NativeOwnershipError('Native operation '+current['phase']+'; resources and recovery evidence retained')
            if time.monotonic()>=deadline:raise NativeOwnershipError('Native operation pending; retry the original request')
            time.sleep(.1)

    def existing_job(self,node,action,force,request_id):
        lab=self.state.lab_name
        if request_id is not None and (not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',request_id)):
            raise NativeOwnershipError('invalid public native request_id')
        if request_id is None:
            row=self.store.db.execute("SELECT request_id FROM public_requests WHERE lab=? AND node=? AND action=? AND force=? AND phase='pending'",(lab,node,action,int(force))).fetchone()
            if not row:return None
            request_id=row[0]
        row=self.store.db.execute('SELECT * FROM public_requests WHERE lab=? AND request_id=?',(lab,request_id)).fetchone()
        if not row:return None
        if row['node']!=node or row['action']!=action or bool(row['force'])!=force:
            raise NativeOwnershipError('public native request identity differs')
        result=dict(row);payload=json.loads(result['payload'])
        if payload.get('origin_fingerprint')!=digest({'lab':lab,'request_id':request_id,'node':node,'action':action,'force':force,'origin':payload.get('origin')}):
            raise NativeOwnershipError('public native origin integrity differs')
        return result

    def publication_fence(self,request_id=None):
        for pending in self.store.db.execute("SELECT request_id,payload FROM public_requests WHERE lab=? AND phase='pending'",(self.state.lab_name,)):
            if json.loads(pending['payload']).get('inventory_phase') and pending['request_id']!=request_id:
                raise NativeOwnershipError('native inventory publication pending; retry the original request')

    def job(self,node,action,force,request_id):
        lab=self.state.lab_name
        with self.store.transaction():
            previous=self.existing_job(node,action,force,request_id)
            if previous:
                if previous['phase']=='pending':self.publication_fence(previous['request_id'])
                return previous
            self.publication_fence()
            request_id=request_id or 'public-'+uuid.uuid4().hex
            from .management_barrier import check as management_check
            management_check(self.store,lab)
            value=closure.get(self.store,lab)
            original_stop=None
            stop_key=runtime_for(self.state,node).runtime_binding['stop_request_id']
            if action=='stop' and stop_key and (self.view.get('operation') or {}).get('action')=='stop':
                original_stop=self.store.get(lab,stop_key,private=True)
                if original_stop['operation_id']!=self.view['operation']['id']:raise NativeOwnershipError('original stop operation differs')
            if value and value['phase']!='open' and (not original_stop or value['phase']!='closing'
                    or value['allowed'].get(stop_key)!=digest(original_stop['request'])):
                raise NativeOwnershipError('lab is closing or closed')
            if self.state.teardown_requested and not original_stop:raise NativeOwnershipError('lab teardown intent prevents public mutations')
            birth=self.view['workload']
            origin={'generation':birth['generation'],'container_id':birth['container_id'],'creator':birth['creator_operation_id'],
                    'revision':self.view['revision'],'target':self.target,'journal_id':self.journal}
            payload={'origin':origin,'origin_fingerprint':digest({'lab':lab,'request_id':request_id,'node':node,'action':action,'force':force,'origin':origin})}
            self.store.db.execute('INSERT INTO public_requests VALUES(?,?,?,?,?,?,?)',(lab,request_id,node,action,int(force),'pending',encoded(payload)))
        return {'lab':lab,'request_id':request_id,'node':node,'action':action,'force':int(force),'phase':'pending','payload':encoded(payload)}

    def verify_job_generation(self,payload):
        origin=payload['origin'];birth=self.view['workload']
        if origin['target']!=self.target or origin['journal_id']!=self.journal:
            raise NativeOwnershipError('public operation generation target differs')
        if birth['generation']==origin['generation']:
            if birth['creator_operation_id']!=origin['creator'] or origin['container_id'] is not None and birth['container_id']!=origin['container_id']:
                raise NativeOwnershipError('public operation generation identity differs')
            return
        for request in payload.get('requests',{}).values():
            if request.get('action')!='start' or not self.store.contains(self.state.lab_name,request['request_id']):continue
            original=self.store.get(self.state.lab_name,request['request_id'],private=True)
            if ({k:v for k,v in original['request'].items() if k!='management_preflight'}!={k:v for k,v in request.items() if k!='management_preflight'}
                    or 'management_preflight' in request and encoded(request['management_preflight'])!=encoded(original['request'].get('management_preflight'))
                    or original['target']!=self.target or original['journal_id']!=self.journal):continue
            receipt=self.client.find_node_request(original['request'],verify_content=True)
            if receipt and receipt['id']==birth['creator_operation_id']:return
        raise NativeOwnershipError('public operation generation changed; original request cannot mutate this workload')

    def execute(self,node,action,*,force=False,request_id=None):
        self.refresh(node)
        if action in ('start','restart'):self.desired_links(node)
        previous=self.existing_job(node,action,force,request_id)
        if previous and previous['phase'] in ('completed','cancelled'):return self.state
        self.publication_fence(previous['request_id'] if previous else None)
        previous_payload=json.loads(previous['payload']) if previous else {}
        if previous:self.verify_job_generation(previous_payload)
        marked=False
        if (action in ('start','restart') and self.state.mgmt
                and not previous_payload.get('management_marked') and not previous_payload.get('inventory_phase')):
            from .netsetup import network_action
            network_action(self.state,self.clients,'mark-used',checkpoint=lambda:state_svc.save_state(self.state,self.ctrl.state_dir))
            marked=True
        job=self.job(node,action,force,request_id);payload=json.loads(job['payload']);self.current_job=job
        self.verify_job_generation(payload)
        if marked:payload['management_marked']=True;self.save_job(job,payload)
        if payload.get('cancellation_stop'):
            if self.view['committed_state']!='stopped' or self.view['container_state']!='absent':self.drive(node,payload['cancellation_stop'])
            with self.store.transaction():self.store.db.execute("UPDATE public_requests SET phase='cancelled' WHERE lab=? AND request_id=?",(self.state.lab_name,job['request_id']))
            self.refresh(node,save=True);return self.state
        actions=['stop','start'] if action=='restart' else ['stop'] if action=='remove' else [action]
        for index,step in enumerate(actions):
            key=str(index)
            if payload.get(key)=='completed':continue
            view=self.refresh(node)
            self.verify_job_generation(payload)
            wanted='running' if step=='start' else 'stopped'
            if view.get('operation'):
                op=view['operation'];pending=[]
                for row in self.store.db.execute('SELECT request_id FROM operations WHERE lab=? AND node=?',(self.state.lab_name,node)).fetchall():
                    value=self.store.get(self.state.lab_name,row[0],private=True)
                    if value['operation_id']==op['id']:pending.append(value)
                if len(pending)!=1 or pending[0]['request']['action']!=step:
                    raise NativeOwnershipError('another native operation is pending; reconcile its original intent')
                request=pending[0]['request']
                if force and step=='stop' and op['phase']=='recovery_required':
                    # The durable recovery request is written before sending.
                    self.store.request_native_force(self.state.lab_name,pending[0]['request_id'])
            elif view['committed_state']==wanted and view['container_state']==('running' if step=='start' else 'absent'):
                payload[key]='completed';self.save_job(job,payload);continue
            else:
                original=source(self.store,self.state,node)
                request={'schema_version':1,'lab_id':self.state.lab_name,'node_id':node,
                    'request_id':'public-'+digest({'job':job['request_id'],'step':index})[:40],
                    'expected_revision':view['revision'],'action':step}
                epoch=original['request'].get('lab_generation',1)
                if epoch!=1:request['lab_generation']=epoch
                if step=='start':request['spec']=original['request']['spec']
                else:
                    request['stop_mode']='coordinated'
                    if force:request['force']=True
            payload.setdefault('requests',{})[key]=request
            self.save_job(job,payload)
            try:receipt=self.drive(node,request)
            except Exception:
                if self.store.contains(self.state.lab_name,request['request_id']):
                    phase=self.store.get(self.state.lab_name,request['request_id'])['phase']
                    if phase in ('failed','cancelled'):
                        with self.store.transaction():self.store.db.execute('UPDATE public_requests SET phase=? WHERE lab=? AND request_id=?',(phase,self.state.lab_name,job['request_id']))
                raise
            if receipt.get('public_cancelled'):
                with self.store.transaction():self.store.db.execute("UPDATE public_requests SET phase='cancelled' WHERE lab=? AND request_id=?",(self.state.lab_name,job['request_id']))
                return self.state
            payload[key]='completed';self.save_job(job,payload)
        if action in ('start','restart') and not payload.get('links_restored'):
            self.restore_links(node,job['request_id'])
            payload['links_restored']=True;self.save_job(job,payload)
        if self.state.jumphost or payload.get('inventory_phase'):
            if not self.state.jumphost:raise NativeOwnershipError('original inventory jumphost metadata missing')
            from . import native_inventory
            if 'inventory_phase' not in payload:
                payload['inventory_phase']='preparing';self.save_job(job,payload)
            if 'inventory' not in payload:
                payload['inventory']=native_inventory.prepare(self.state,self.store,self.clients,job['request_id'],
                    exclude=node if action=='remove' else None)
                self.save_job(job,payload)
            native_inventory.apply(self.state,self.store,self.clients,payload['inventory'])
            payload['inventory']['phase']='published';payload['inventory_phase']='published';self.save_job(job,payload)
        if action=='remove':
            # Keep the verified stopped owner as a tombstone until whole-lab
            # cleanup, rather than discarding its birth proof or guest disk.
            if node in self.state.node_runtime:
                self.state.retired_native_nodes[node]=self.state.node_runtime.pop(node)
            self.state.runtime_links=[link for link in self.state.runtime_links if node not in {link.endpoint_a.get('node'),link.endpoint_b.get('node')}]
            self.state.webui_allocations.pop(node,None)
            for schedule in self.state.scheduling.values():schedule.vd=[n for n in schedule.vd if n!=node]
        self.refresh(node,save=True)
        with self.store.transaction():
            self.store.db.execute("UPDATE public_requests SET phase='completed',payload=? WHERE lab=? AND request_id=?",(encoded(payload),self.state.lab_name,job['request_id']))
        return self.state

    def save_job(self,job,payload):
        with self.store.transaction():
            self.store.db.execute('UPDATE public_requests SET payload=? WHERE lab=? AND request_id=?',(encoded(payload),self.state.lab_name,job['request_id']))


def run(controller,action,node,*,force=False,request_id=None):
    from .ssh import create_clients
    backend(controller.state,node)
    store=store_for(controller.state_dir);clients={}
    try:
        with store.executing(controller.state.lab_name,'public-lifecycle'):
            fresh=state_svc.load_state(controller.state.lab_name,controller.state_dir)
            if not fresh:raise NativeOwnershipError('native deployment state missing; recovery required')
            controller.state=fresh;backend(fresh,node)
            original=source(store,fresh,node)
            required={r.host for r in owners(fresh).values()}
            if fresh.jumphost:required.add(fresh.jumphost.node)
            if fresh.mgmt:required.update(fresh.mgmt.infrastructure.get('plans',{}))
            if required-set(controller.topo.all_hosts):raise NativeOwnershipError('native placement host unavailable')
            if fresh.realnets or getattr(controller.topo,'real_net_links',[]):raise NativeOwnershipError('native RealNet lifecycle requires its qualified data attachment coordinator')
            factory=getattr(controller,'_native_clients_factory',create_clients)
            clients=factory({h:controller.topo.all_hosts[h] for h in required})
            controller._set_active_clients(clients)
            for client in clients.values():client.connect()
            handler=PublicLifecycle(controller,clients,store)
            if action=='start' and node in fresh.retired_native_nodes:
                handler.refresh(node)
                job=handler.job(node,action,force,request_id)
                if job['phase'] in ('completed','cancelled'):return controller.state
                request_id=job['request_id']
                if handler.view['committed_state']!='stopped' or handler.view['container_state']!='absent':
                    raise NativeOwnershipError('retired native owner is not verified clean')
                fresh.node_runtime[node]=fresh.retired_native_nodes.pop(node)
                state_svc.save_state(fresh,controller.state_dir)
            if action=='reconcile':
                publications=[dict(row) for row in store.db.execute("SELECT * FROM public_requests WHERE lab=? AND phase='pending'",(fresh.lab_name,))
                              if json.loads(row['payload']).get('inventory_phase')]
                if len(publications)>1:raise NativeOwnershipError('ambiguous native inventory publication')
                if publications:
                    job=publications[0]
                    if job['node']!=node:raise NativeOwnershipError('native inventory publication pending; reconcile the original node')
                    return handler.execute(node,job['action'],force=bool(job['force']),request_id=job['request_id'])
                handler.refresh(node,save=True)
                pending=handler.view.get('operation')
                if pending:
                    record=next((store.get(fresh.lab_name,k,private=True) for lab,k in store.pending()
                                 if lab==fresh.lab_name and store.get(lab,k)['operation_id']==pending['id']),None)
                    if not record:raise NativeOwnershipError('native pending operation lacks original coordinator intent')
                    handler.drive(node,record['request'])
                handler.restore_links(node,'reconcile-'+uuid.uuid4().hex)
                return controller.state
            return handler.execute(node,action,force=force,request_id=request_id)
    finally:
        controller._native_intent=None;controller._clear_active_clients(clients)
        for client in clients.values():client.close()
        store.close()
