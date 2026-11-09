"""HTTP fixture using the original managed initial batch, without a new scheduler."""
from copy import deepcopy
from pathlib import Path
import json
import time
import uuid

from http_workload_fixture import Workload, program
from dnlab_multinode.controllers.runtime_deploy import RuntimeInitialDeployment
from dnlab_multinode.services.runtime_manifest import compile_initial
from dnlab_multinode.services.runtime_operations import digest
from dnlab_runtime.backend import Docker


class ManagedWorkload(Workload):
    def __init__(self,root,topo,schedule,node,image,management,target,runtime,store,management_key,*,management_clients=None,gate_context=None):
        self.path=Path(root)/'managed-http-workload.json';self.runtime=runtime;self.store=store;self.api=Docker()
        self.batch=RuntimeInitialDeployment(store,lambda actual:runtime if actual==target else self.wrong_target(),management_clients=management_clients)
        self.driver=self.batch.driver
        self.topo,self.schedule=deepcopy(topo),deepcopy(schedule)
        self.management_key=management_key
        prior=json.loads(self.path.read_text()) if self.path.exists() else None
        nonce=prior['nonce'] if prior else uuid.uuid4().hex
        self.key='http-batch-'+nonce
        parent,original=self.batch.released_parent(topo.name,management_key)
        if original['targets']!={target['host']:{'target':target,'journal_id':runtime.expected_journal_id}}:
            raise RuntimeError('single-host original management parent required for this fixture')
        self.options={'targets':{target['host']:deepcopy(target)},
                      'node_options':{node:{'command':['python3','-u','-c',program(nonce)],'stop_timeout':5}}}
        compiled=compile_initial(self.topo,self.schedule,batch_id=self.key,**self.options,
                                 management_plan=original['plan']['services']['management_plan'],
                                 lab_generation=parent['generation'])
        if len(compiled['members'])!=1 or compiled['members'][0]['request']['node_id']!=node:
            raise RuntimeError('one original compiled HTTP workload required')
        member=compiled['members'][0]
        self.start=member['request'];self.spec=self.start['spec']
        if self.spec['image']!=image or self.spec['management']!=management or member['target']!=target:
            raise RuntimeError('compiled HTTP workload differs from original management identity')
        intent={'nonce':nonce,'lab':topo.name,'node':node,'image':image,'management':management,
                'target':target,'journal_id':runtime.expected_journal_id,'start':self.start,'spec':self.spec,
                'admission':{'batch_id':self.key,'parent':parent,'compilation_fingerprint':compiled['fingerprint']}}
        if prior and any(prior.get(key)!=value for key,value in intent.items()):
            raise RuntimeError('managed HTTP workload original intent differs')
        self.record=prior or {**deepcopy(intent),'phase':'planned','cleanup_verified':False}
        from native_scope_registration import bind_gate_context
        bind_gate_context(self.record,gate_context,existing=prior is not None)
        self.save()

    def drive(self,request):
        if request!=self.start:return super().drive(request)
        parent,_=self.batch.released_parent(self.record['lab'],self.management_key)
        if parent!=self.record['admission']['parent']:
            raise RuntimeError('managed HTTP workload original parent differs')
        self.batch.prepare_managed_topology(self.topo,self.schedule,self.key,self.management_key,**self.options)
        payload=self.batch.get(self.record['lab'],self.key,private=True)['payload']
        if payload['compilation']['fingerprint']!=self.record['admission']['compilation_fingerprint']:
            raise RuntimeError('managed HTTP workload original compilation differs')
        deadline=time.monotonic()+45
        while True:
            result=self.batch.advance(self.record['lab'],self.key)
            if result['phase']=='completed':return result
            if result['phase'] in ('cancelled','recovery_required'):
                raise RuntimeError('managed HTTP workload batch '+result['phase'])
            if time.monotonic()>=deadline:raise RuntimeError('managed HTTP workload batch still pending')
            time.sleep(.05)

    def cleanup(self):
        exists=self.store.db.execute('SELECT 1 FROM initial_batches WHERE lab=? AND request_id=?',
                                     (self.record['lab'],self.key)).fetchone()
        if exists and self.batch.get(self.record['lab'],self.key)['phase']!='completed':
            self.record.update(phase='cleanup_pending',cleanup_verified=False);self.save()
            self.batch.cancel(self.record['lab'],self.key)
            deadline=time.monotonic()+45
            while self.batch.advance(self.record['lab'],self.key)['phase']!='cancelled':
                if time.monotonic()>=deadline:raise RuntimeError('managed HTTP cancellation still pending')
                time.sleep(.05)
            children=self.batch.members(self.record['lab'],self.key)
            if len(children)!=1:raise RuntimeError('original managed HTTP cancellation member required')
            child=children[0]
            if ({k:v for k,v in child['request'].items() if k!='management_preflight'}!=self.start
                    or child['target']!=self.record['target'] or child['journal_id']!=self.record['journal_id']):
                raise RuntimeError('managed HTTP cancellation original intent differs')
            absent=False
            if child['phase']=='cancelled':
                plan=self.batch.client(child).plan_node(child['request'])
                view=plan.get('node_preflight') or {}
                if view.get('committed_state')=='absent':
                    expected={'journal_id':child['journal_id'],'lab_id':self.record['lab'],'node_id':self.record['node'],
                              'request_fingerprint':digest(self.start),'revision':0,'committed_state':'absent',
                              'container_state':'absent','container_id':None,'pending_operation_id':None,'workload_phase':None}
                    if (plan.get('mutations_performed') is not False or plan.get('affected_nodes')!=[self.record['node']]
                            or plan.get('expected_revision')!=0 or not expected.keys()<=view.keys()
                            or any(view[k]!=v for k,v in expected.items())):
                        raise RuntimeError('managed HTTP cancellation absence not verified')
                    self.record['cancelled_absence']=deepcopy(view);absent=True
            if not absent:
                view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
                if view['operation'] is not None or view['container_state']!='absent':
                    raise RuntimeError('managed HTTP cancellation absence not verified')
            self.record.update(phase='cleaned',cleanup_verified=True);self.save();return
        return super().cleanup()
