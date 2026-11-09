"""Opt-in initial Linux workload batches; caller retains placement and links.

This ledger is an operation barrier, not a second topology store or scheduler.
Production deploy selection and network/service generation are not enabled here.
"""
import hashlib
import ipaddress
import json
import re

from dnlab_multinode.services.runtime_operations import OperationDriver,RuntimeOperationError,encoded,digest,FINAL
from dnlab_multinode.services.runtime_cleanup import make_binding


def claims(request,target):
    spec=request['spec'];host=target['host'];result=[('name',host,'container',spec['container_name'])]
    for endpoint in spec.get('endpoints',[]):
        name=endpoint['host_interface'];stage='drp'+hashlib.sha256(name.encode()).hexdigest()[:12]
        result.extend([('name',host,'interface',name),('name',host,'interface',stage)])
    for port in spec.get('ports',[]):
        result.append(('port',host,port['protocol'],port['host_port'],str(ipaddress.ip_address(port['host_ip']))))
    management=spec.get('management') or {}
    if management.get('mac'):result.append(('management-mac',request['lab_id'],management['network'],management['mac']))
    for field in ('ipv4','ipv6'):
        if management.get(field):result.append(('management',request['lab_id'],management['network'],str(ipaddress.ip_address(management[field]))))
    return result


def overlap(left,right):
    return left==right or (left[0]==right[0]=='port' and left[:4]==right[:4]
                          and (ipaddress.ip_address(left[4]).is_unspecified or ipaddress.ip_address(right[4]).is_unspecified))


class RuntimeInitialDeployment:
    def __init__(self,store,client_factory,*,management_clients=None):
        self.store,self.factory=store,client_factory;self.driver=OperationDriver(store,client_factory)
        self.management_clients=management_clients
        from ..services.initial_management_usage import InitialManagementUsage
        self.management_usage=InitialManagementUsage(self)

    def get(self,lab,key,*,private=False):
        with self.store.lock:row=self.store.db.execute('SELECT * FROM initial_batches WHERE lab=? AND request_id=?',(lab,key)).fetchone()
        if row is None:raise RuntimeOperationError('initial deployment batch missing')
        value=dict(row);payload=json.loads(value.pop('payload'))
        if digest(payload)!=value.pop('fingerprint'):raise RuntimeOperationError('initial deployment batch integrity differs')
        value['cancel_requested']=bool(value['cancel_requested']);value['nodes']=[m['request']['node_id'] for m in payload['members']]
        if private:value['payload']=payload
        return value

    def phase(self,lab,key,phase,error=''):
        with self.store.transaction():
            self.get(lab,key);self.store.db.execute('UPDATE initial_batches SET phase=?,error=? WHERE lab=? AND request_id=?',(phase,error,lab,key))
        return self.get(lab,key)

    def members(self,lab,key):
        result=[]
        for member in self.get(lab,key,private=True)['payload']['members']:
            value=self.store.get(lab,member['request']['request_id'],private=True)
            if any(encoded(value[k])!=encoded(member[k]) for k in ('request','target','journal_id')):
                raise RuntimeOperationError('initial deployment child intent differs')
            result.append(value)
        return result

    def released_parent(self,lab,management_key):
        from dnlab_multinode.services.runtime_cleanup import management_cleanup_check
        value=management_cleanup_check(self.store,lab)
        if (not value or value['request_id']!=management_key or value['phase']!='released'
                or not value['plan'].get('services',{}).get('management_plan')
                or value.get('services',{}).get('phase')!='materialized'
                or any(p.get('scope')!='management-network-services-v1' for p in value['readiness']['hosts'].values())):
            raise RuntimeOperationError('original released management network services required')
        parent={k:value[k] for k in ('request_id','barrier_id','generation','plan_fingerprint','readiness_fingerprint')}
        parent['operation_fingerprint']=digest(value)
        return parent,value

    def check_parent(self,lab,parent,compilation,members,*,observe=False):
        if parent is None:return
        if not isinstance(parent,dict) or set(parent)!={'request_id','barrier_id','generation','plan_fingerprint','readiness_fingerprint','operation_fingerprint'}:
            raise RuntimeOperationError('complete original management parent required')
        observed,original=self.released_parent(lab,parent['request_id'])
        if observed!=parent:raise RuntimeOperationError('initial deployment management parent changed')
        if (not compilation or compilation.get('management_plan')!=original['plan']['services']['management_plan']
                or compilation.get('management_services')!=original['plan']['services'].get('services')):
            raise RuntimeOperationError('initial deployment ledger differs from original management parent')
        for member in members:
            request,target=member['request'],member['target'];host=target['host']
            owner=original['targets'].get(host)
            if (not owner or owner['target']!=target or request.get('lab_generation',1)!=parent['generation']
                    or 'journal_id' in member and member['journal_id']!=owner['journal_id']):
                raise RuntimeOperationError('initial deployment runtime differs from original management parent')
        if observe:
            # Include original hosts without a VD in this batch. This is a
            # read-only observation outside the local admission transaction.
            for host,owner in sorted(original['targets'].items()):
                client=self.factory(owner['target']).bound_to(owner['journal_id'])
                caps=client.qualify_node(inspection=True)
                if caps.get('journal_id')!=owner['journal_id']:
                    raise RuntimeOperationError('management parent runtime journal changed')

    def check_saved_parent(self,lab,key,*,observe=False):
        payload=self.get(lab,key,private=True)['payload']
        self.check_parent(lab,payload.get('management_parent'),payload.get('compilation'),payload['members'],observe=observe)

    def prepare_managed_topology(self,topo,plan,key,management_key,**options):
        """Consume the existing coordinator's release, placement and ledger."""
        parent,original=self.released_parent(topo.name,management_key)
        model=original['plan']['services']['management_plan']
        if 'management_plan' in options and options['management_plan']!=model:
            raise RuntimeOperationError('requested initial ledger differs from original management parent')
        if 'lab_generation' in options and options['lab_generation']!=parent['generation']:
            raise RuntimeOperationError('requested initial generation differs from original management parent')
        options={**options,'management_plan':model,'lab_generation':parent['generation']}
        return self.prepare_topology(topo,plan,key,management_parent=parent,**options)

    def prepare_topology(self,topo,plan,key,*,management_parent=None,**options):
        from dnlab_multinode.services.runtime_manifest import compile_initial
        compiled=compile_initial(topo,plan,batch_id=key,**options)
        with self.store.lock:
            prior=self.store.db.execute('SELECT 1 FROM initial_batches WHERE lab=? AND request_id=?',(topo.name,key)).fetchone()
        if prior and 'management_services' in compiled:
            original=self.get(topo.name,key,private=True)['payload'].get('compilation')
            if original is not None and 'management_services' not in original:
                # An old batch retains its original optional metadata contract.
                # Retrying it must not add a new service intent implicitly.
                del compiled['management_services']
                compiled['fingerprint']=digest({k:v for k,v in compiled.items() if k!='fingerprint'})
        return self.prepare(topo.name,key,compiled['members'],compilation=compiled,management_parent=management_parent)

    def prepare(self,lab,key,members,*,compilation=None,management_parent=None):
        if (not all(isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',v) for v in (lab,key))
                or not isinstance(members,list) or not members):raise RuntimeOperationError('complete initial deployment manifest required')
        original=json.loads(encoded(members));nodes=set();keys=set();epoch=None
        if compilation is not None:
            compilation=json.loads(encoded(compilation))
            if (not isinstance(compilation,dict) or set(compilation) not in ({'members','links','image_resolutions','webui_wishlist','webui_allocations','fingerprint'},
                        {'members','links','image_resolutions','webui_wishlist','webui_allocations','management_plan','fingerprint'},
                        {'members','links','image_resolutions','webui_wishlist','webui_allocations','management_plan','management_services','fingerprint'})
                    or compilation['fingerprint']!=digest({k:v for k,v in compilation.items() if k!='fingerprint'})
                    or encoded(compilation['members'])!=encoded(original)):
                raise RuntimeOperationError('initial compilation provenance differs')
        if compilation is not None and 'management_plan' in compilation:
            from dnlab_multinode.services.management_segments import validate_compilation, SegmentError
            try:
                validate_compilation(compilation, lab)
                if 'management_services' in compilation:
                    from dnlab_multinode.services.management_services import validate_compilation as validate_services
                    validate_services(compilation)
            except (ValueError,KeyError,TypeError,RuntimeError,SegmentError) as error:
                raise RuntimeOperationError('initial management compilation differs') from error
        for m in original:
            if not isinstance(m,dict) or set(m)!={'request','target'}:raise RuntimeOperationError('invalid initial deployment member')
            r=m['request']
            if (not isinstance(r,dict) or r.get('action')!='start' or r.get('lab_id')!=lab
                    or type(r.get('expected_revision')) is not int or r['expected_revision']<0 or r.get('spec',{}).get('kind')!='linux'):
                raise RuntimeOperationError('initial deployment requires explicit Linux starts')
            if r.get('node_id') in nodes or r.get('request_id') in keys:raise RuntimeOperationError('duplicate initial deployment node or request')
            nodes.add(r.get('node_id'));keys.add(r.get('request_id'));generation=r.get('lab_generation',1)
            if type(generation) is not int or generation<1 or epoch is not None and epoch!=generation:raise RuntimeOperationError('initial deployment generation differs')
            epoch=generation
        with self.store.executing(lab,'initial-deployment:all'):
            with self.store.lock:prior=self.store.db.execute('SELECT 1 FROM initial_batches WHERE lab=? AND request_id=?',(lab,key)).fetchone()
            if prior:
                if encoded(self.get(lab,key,private=True)['payload']['original'])!=encoded(original):raise RuntimeOperationError('initial deployment manifest changed')
                if encoded(self.get(lab,key,private=True)['payload'].get('compilation'))!=encoded(compilation):raise RuntimeOperationError('initial compilation changed')
                if self.get(lab,key,private=True)['payload'].get('management_parent')!=management_parent:raise RuntimeOperationError('initial management parent cannot be replaced')
                self.check_saved_parent(lab,key,observe=True)
                self.members(lab,key);return self.get(lab,key)
            self.check_parent(lab,management_parent,compilation,original,observe=True)
            planned=[];targets={};journals={};used=[]
            for member in original:
                r,t=member['request'],member['target']
                if self.store.contains(lab,r['request_id']):raise RuntimeOperationError('initial deployment cannot adopt an existing intent')
                p=self.driver.preflight(r,t);client=self.factory(t).bound_to(p['journal_id']);client.qualify_node(initial_deployment=True)
                view=p.get('node_preflight') or {}
                if (view.get('committed_state') not in ('absent','stopped') or view.get('container_state')!='absent'
                        or view.get('revision')!=r['expected_revision'] or view.get('pending_operation_id') is not None
                        or view.get('journal_id')!=p['journal_id'] or view.get('lab_id')!=lab or view.get('node_id')!=r['node_id']
                        or view.get('request_fingerprint')!=digest({k:v for k,v in r.items() if k!='management_preflight'})):
                    raise RuntimeOperationError('initial deployment requires a verified absent or stopped node')
                if compilation is not None and 'management_plan' in compilation:
                    from dnlab_multinode.services.management_segments import validate_observed_network, SegmentError
                    try: validate_observed_network(compilation['management_plan'], r['node_id'], p['request']['management_preflight']['network'])
                    except (ValueError,KeyError,TypeError,SegmentError) as error:
                        raise RuntimeOperationError('runtime management segment differs from compiled plan') from error
                identity=encoded({'target':t,'journal_id':p['journal_id']});host=t['host']
                if (host in targets and targets[host]!=identity or p['journal_id'] in journals and journals[p['journal_id']]!=host):
                    raise RuntimeOperationError('initial deployment host/runtime mapping is ambiguous')
                targets[host]=identity;journals[p['journal_id']]=host
                for claim in claims(r,t):
                    if any(overlap(claim,other) for other in used):raise RuntimeOperationError('initial deployment members have conflicting resources')
                    used.append(claim)
                planned.append(p)
            payload={'original':original,'members':planned}
            if compilation is not None:payload['compilation']=compilation
            if management_parent is not None:payload['management_parent']=json.loads(encoded(management_parent))
            with self.store.transaction():
                self.check_parent(lab,management_parent,compilation,planned)
                if any(self.store.contains(lab,k) for k in keys):raise RuntimeOperationError('initial deployment intent appeared during preflight')
                for row in self.store.db.execute("SELECT lab,request_id FROM operations WHERE phase NOT IN ('completed','failed','cancelled')").fetchall():
                    pending=self.store.get(row['lab'],row['request_id'],private=True)
                    if pending['request']['action']=='start' and any(overlap(c,o) for c in used for o in claims(pending['request'],pending['target'])):
                        raise RuntimeOperationError('initial deployment resources have an unfinished coordinator owner')
                for p in planned:self.store._prepare_locked(p['request'],p['target'],p['journal_id'])
                self.store.db.execute('INSERT INTO initial_batches(lab,request_id,payload,fingerprint,phase) VALUES(?,?,?,?,?)',(lab,key,encoded(payload),digest(payload),'prepared'))
            return self.get(lab,key)

    def client(self,value):
        client=self.factory(value['target']).bound_to(value['journal_id'])
        caps=client.qualify_node(inspection=True,request_controls=True,resource_preflight=True,management_identity=bool(value['request'].get('spec',{}).get('management')),data_endpoints=bool(value['request'].get('spec',{}).get('endpoints')))
        if caps.get('journal_id')!=value['journal_id']:raise RuntimeOperationError('initial deployment runtime journal changed')
        return client

    def binding(self,value):
        return make_binding(self.store,value['lab'],value['node'],value['request_id'],self.client(value).inspect_node(value['lab'],value['node']))

    def observe(self,lab,key):
        self.check_saved_parent(lab,key,observe=True)
        result=[]
        for value in self.members(lab,key):
            client=self.client(value)
            receipt=client.node_operation(value['operation_id']) if value['operation_id'] else client.find_node_request(value['request'],verify_content=True)
            if receipt is not None:self.store.observe(lab,value['request_id'],receipt)
            value=self.store.get(lab,value['request_id'],private=True)
            if value['phase']=='completed':self.binding(value)
            elif value['phase'] in ('failed','cancelled','recovery_required'):raise RuntimeOperationError('initial deployment child requires recovery or cancellation')
            elif not value['operation_id']:
                plan=client.plan_node(value['request'])
                if (plan.get('mutations_performed') is not False or plan.get('affected_nodes')!=[value['node']]
                        or plan.get('expected_revision')!=value['request']['expected_revision']):raise RuntimeOperationError('initial deployment preflight changed')
            result.append(value)
        return result

    def advance(self,lab,key):
        with self.store.executing(lab,'management-barrier'), self.store.executing(lab,'initial-deployment:all'):
            batch=self.get(lab,key)
            if batch['phase']=='recovery_required':raise RuntimeOperationError('initial deployment requires explicit recovery')
            if batch['phase']=='cancelled':return batch
            if batch['cancel_requested']:return self.cancel_advance(lab,key)
            if batch['phase']=='completed':return batch
            try:
                self.store.sync_directory();values=self.observe(lab,key)
                self.management_usage.ensure(lab,key)
                active=[v for v in values if v['phase']!='completed']
                if not active:return self.phase(lab,key,'completed')
                self.phase(lab,key,'applying')
                result=self.driver.advance(lab,active[0]['request_id'])
                if result['phase'] in ('failed','cancelled','recovery_required'):raise RuntimeOperationError('initial deployment child requires recovery or cancellation')
                if result['phase']=='completed' and all(v['phase']=='completed' for v in self.observe(lab,key)):
                    return self.phase(lab,key,'completed')
                return self.get(lab,key)
            except Exception as error:
                self.phase(lab,key,'recovery_required','initial deployment incomplete ('+type(error).__name__+')');raise

    def recover(self,lab,key):
        with self.store.executing(lab,'management-barrier'), self.store.executing(lab,'initial-deployment:all'):
            batch=self.get(lab,key)
            if batch['phase']!='recovery_required':raise RuntimeOperationError('initial deployment has no pending recovery')
            self.store.sync_directory()
            self.check_saved_parent(lab,key,observe=True)
            if not batch['cancel_requested']:self.observe(lab,key)
            return self.phase(lab,key,'cancelling' if batch['cancel_requested'] else 'applying')

    def cancel(self,lab,key):
        with self.store.executing(lab,'initial-deployment:all'):
            if self.get(lab,key)['phase']=='cancelled':return self.get(lab,key)
            values=self.members(lab,key)
            with self.store.transaction():
                self.store.db.execute("UPDATE initial_batches SET cancel_requested=1,phase='cancelling' WHERE lab=? AND request_id=?",(lab,key))
                for v in values:self.store.db.execute('UPDATE operations SET cancel_requested=1 WHERE lab=? AND request_id=?',(lab,v['request_id']))
            return self.get(lab,key)

    def cancel_advance(self,lab,key):
        try:
            self.check_saved_parent(lab,key,observe=True)
            self.store.sync_directory();stops=[]
            for v in self.members(lab,key):
                if v['phase']!='completed':
                    self.driver.advance(lab,v['request_id']);v=self.store.get(lab,v['request_id'],private=True)
                if v['phase']=='completed':
                    stop_key='initial-stop-'+digest({'batch':key,'node':v['node']})[:40]
                    r={k:value for k,value in v['request'].items() if k not in ('spec','management_preflight')}
                    r.update(action='stop',request_id=stop_key,expected_revision=r['expected_revision']+1)
                    if not self.store.contains(lab,stop_key):
                        self.binding(v);self.driver.prepare(r,v['target'])
                    saved=self.store.get(lab,stop_key,private=True)
                    if (encoded(saved['request'])!=encoded(r) or encoded(saved['target'])!=encoded(v['target'])
                            or saved['journal_id']!=v['journal_id']):raise RuntimeOperationError('initial deployment stop intent differs')
                    stops.append((v,stop_key))
                elif v['phase'] in ('failed','cancelled'):
                    view=self.client(v).plan_node(v['request']).get('node_preflight') or {}
                    if view.get('container_state')!='absent' or view.get('pending_operation_id') is not None:raise RuntimeOperationError('initial deployment cancellation not verified')
                elif v['phase']=='recovery_required':raise RuntimeOperationError('initial deployment cancellation requires recovery')
                else:return self.get(lab,key)
            for v,stop_key in stops:
                stopped=self.driver.advance(lab,stop_key)
                if stopped['phase']=='recovery_required':raise RuntimeOperationError('ordinary shutdown requires recovery; no force sent')
                if stopped['phase']!='completed':return self.get(lab,key)
                view=self.client(v).inspect_node(lab,v['node']);birth=view.get('workload') or {}
                if (view.get('committed_state')!='stopped' or view.get('container_state')!='absent' or view.get('operation') is not None
                        or birth.get('creator_operation_id')!=v['operation_id'] or view.get('revision')!=v['request']['expected_revision']+2):
                    raise RuntimeOperationError('initial deployment stopped generation not verified')
            return self.phase(lab,key,'cancelled')
        except Exception as error:
            self.phase(lab,key,'recovery_required','initial deployment cancellation incomplete ('+type(error).__name__+')');raise

    def bindings(self,lab,key):
        if self.get(lab,key)['phase']!='completed':raise RuntimeOperationError('initial deployment is not complete')
        self.check_saved_parent(lab,key,observe=True)
        return {v['node']:self.binding(v) for v in self.members(lab,key)}
