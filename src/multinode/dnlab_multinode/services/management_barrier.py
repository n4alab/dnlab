"""Durable coordinator admission for offline management preparation.

The caller supplies the existing placement/host roster and a complete desired
plan. Service readiness must be observed by its qualified provisioning worker;
this module never schedules workloads or infers topology from resource names.
"""
from copy import deepcopy
from contextlib import contextmanager
import json
import re
import uuid

from .runtime_operations import RuntimeOperationError,encoded,digest

CONTRACT='offline workload fence v2; read-only preflight; acquisition cancellation tombstones; provisioning seal'


def get(store,lab):
    with store.lock:
        row=store.db.execute('SELECT payload FROM management_barriers WHERE lab=?',(lab,)).fetchone()
    value=json.loads(row[0]) if row else None
    if value and value['plan_fingerprint']!=digest(value['plan']):
        raise RuntimeOperationError('offline management plan integrity differs')
    return value


def put(store,lab,value):
    store.db.execute('INSERT INTO management_barriers VALUES(?,?) ON CONFLICT(lab) DO UPDATE SET payload=excluded.payload',(lab,encoded(value)))


def check(store,lab):
    value=get(store,lab)
    if value and value['phase'] not in ('released','cancelled'):
        raise RuntimeOperationError('offline management operation fences coordinator mutations')


def no_pending(store,lab):
    for table in ('operations','public_requests','public_link_requests','initial_batches'):
        if store.db.execute(f"SELECT 1 FROM {table} WHERE lab=? AND phase NOT IN ('completed','cancelled','failed')",(lab,)).fetchone():
            raise RuntimeOperationError('offline management requires all coordinator operations concluded')


def validate(lab,key,plan,targets,generation):
    if (any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',v) for v in (lab,key))
            or type(generation) is not int or generation<1 or not isinstance(plan,dict) or not plan
            or not isinstance(targets,dict) or not targets):
        raise RuntimeOperationError('complete offline management intent required')
    plan,targets=json.loads(encoded(plan)),json.loads(encoded(targets))
    # The host roster is explicit and immutable, including hosts with no VD.
    if not isinstance(plan.get('hosts'),dict) or set(plan['hosts'])!=set(targets):
        raise RuntimeOperationError('complete offline management host roster required')
    journals=set()
    for host,entry in targets.items():
        target=entry.get('target') if isinstance(entry,dict) else None
        if (not isinstance(entry,dict) or set(entry)!={'target','journal_id'} or not isinstance(target,dict)
                or set(target)!={'host','socket_path','container_name'} or target['host']!=host
                or not isinstance(host,str) or not host or not isinstance(target['socket_path'],str) or not target['socket_path'].startswith('/')
                or target['container_name'] is not None and (not isinstance(target['container_name'],str) or not target['container_name'])
                or not isinstance(entry['journal_id'],str) or not re.fullmatch('[0-9a-f]{32}',entry['journal_id'])
                or entry['journal_id'] in journals):
            raise RuntimeOperationError('offline management target identity differs')
        journals.add(entry['journal_id'])
    return plan,targets


def prepare(store,lab,key,plan,targets,*,generation=1,barrier_id=None,preflights=None):
    plan,targets=validate(lab,key,plan,targets,generation)
    with store.transaction():
        from .runtime_lab_closure import get as closure
        closed=closure(store,lab)
        if generation!=(closed['generation'] if closed else 1) or closed and closed['phase']!='open':
            raise RuntimeOperationError('lab generation or teardown closure differs')
        previous=get(store,lab)
        if previous and previous['request_id']==key:
            if previous['plan']!=plan or previous['targets']!=targets or previous['generation']!=generation:
                raise RuntimeOperationError('offline management original intent changed')
            return previous
        check(store,lab);no_pending(store,lab)
        if (not isinstance(barrier_id,str) or not re.fullmatch('[0-9a-f]{32}',barrier_id)
                or not isinstance(preflights,dict) or set(preflights)!=set(targets)):
            raise RuntimeOperationError('all read-only offline management preflights required')
        for host,proof in preflights.items():
            if (not isinstance(proof,dict) or proof.get('lab_id')!=lab or proof.get('journal_id')!=targets[host]['journal_id']
                    or proof.get('barrier_id')!=barrier_id or type(proof.get('generation')) is not int or proof.get('generation')!=generation
                    or proof.get('plan_fingerprint')!=digest(plan) or proof.get('phase')!='planned'
                    or proof.get('mutations_performed') is not False
                    or not isinstance(proof.get('workload_fingerprint'),str)
                    or not re.fullmatch('[0-9a-f]{64}',proof['workload_fingerprint'])):
                raise RuntimeOperationError('offline management preflight identity differs')
        if store.db.execute('SELECT 1 FROM management_barrier_history WHERE lab=? AND request_id=?',(lab,key)).fetchone():
            raise RuntimeOperationError('offline management request already retired')
        for row in store.db.execute('SELECT request_id FROM operations WHERE lab=?',(lab,)).fetchall():
            original=store.get(lab,row[0],private=True)
            entry=targets.get(original['target']['host'])
            if entry!={'target':original['target'],'journal_id':original['journal_id']}:
                raise RuntimeOperationError('offline management roster omits an original runtime')
        if previous:
            store.db.execute('INSERT INTO management_barrier_history VALUES(?,?,?)',(lab,previous['request_id'],encoded(previous)))
        value={'request_id':key,'barrier_id':barrier_id,'generation':generation,'plan':plan,
               'plan_fingerprint':digest(plan),'targets':targets,'phase':'acquiring','preflights':json.loads(encoded(preflights)),'receipts':{},'released':{},'cancelled':{},'activated':{}}
        put(store,lab,value)
    return value


class Driver:
    def __init__(self,store,client_factory):self.store,self.factory=store,client_factory

    def prepare(self,lab,key,plan,targets,*,generation=1):
        plan,targets=validate(lab,key,plan,targets,generation)
        with self.store.executing(lab,'management-barrier'):
            with self.store.lock:
                prior=get(self.store,lab)
                if prior and prior['request_id']==key:
                    return prepare(self.store,lab,key,plan,targets,generation=generation)
                check(self.store,lab);no_pending(self.store,lab)
            token=uuid.uuid4().hex;proofs={}
            payload={'barrier_id':token,'generation':generation,'plan_fingerprint':digest(plan)}
            for host,entry in sorted(targets.items()):
                client=self.factory(entry['target']).bound_to(entry['journal_id'])
                proofs[host]=client.management_barrier(lab,'plan',payload)
            return prepare(self.store,lab,key,plan,targets,generation=generation,barrier_id=token,preflights=proofs)

    def original(self,lab,key):
        value=get(self.store,lab)
        if not value or value['request_id']!=key:raise RuntimeOperationError('offline management operation missing or replaced')
        self.store.sync_directory()
        return value

    @contextmanager
    def provisioning(self,lab,key):
        """Hold the same cross-process lock used by release/cancel while applying."""
        with self.store.executing(lab,'management-barrier'):
            value=self.original(lab,key)
            if value['phase']!='provisioning':
                raise RuntimeOperationError('sealed management provisioning required')
            yield value

    def remote(self,lab,value,host,action):
        entry=value['targets'][host]
        client=self.factory(entry['target']).bound_to(entry['journal_id'])
        payload={k:value[k] for k in ('barrier_id','generation','plan_fingerprint')}
        payload['workload_fingerprint']=value['preflights'][host]['workload_fingerprint']
        if action=='release':payload['readiness_fingerprint']=value['readiness_fingerprint']
        receipt=client.management_barrier(lab,action,payload)
        if (not isinstance(receipt,dict) or type(receipt.get('generation')) is not int or receipt.get('lab_id')!=lab or receipt.get('journal_id')!=entry['journal_id']
                or any(receipt.get(k)!=payload[k] for k in payload)
                or receipt.get('phase')!={'acquire':'held','activate':'applying','cancel':'cancelled','release':'released'}[action]
                or not isinstance(receipt.get('workload_fingerprint'),str) or not re.fullmatch('[0-9a-f]{64}',receipt['workload_fingerprint'])):
            raise RuntimeOperationError('offline management runtime receipt differs')
        original=value['receipts'].get(host)
        if action=='cancel' and original and receipt.get('acquisition_observed') is not True:
            raise RuntimeOperationError('offline management acquisition proof disappeared')
        if original and original['workload_fingerprint']!=receipt['workload_fingerprint']:
            raise RuntimeOperationError('offline management workload inventory changed')
        return receipt

    def acquire(self,lab,key):
        with self.store.executing(lab,'management-barrier'):
            value=self.original(lab,key)
            if value['phase'] in ('releasing','released'):return value
            if value['phase'] not in ('acquiring','held'):raise RuntimeOperationError('offline management acquisition is no longer admissible')
            for host in sorted(value['targets']):
                receipt=self.remote(lab,value,host,'acquire')
                with self.store.transaction():
                    current=self.original(lab,key)
                    if current!=value:raise RuntimeOperationError('offline management intent changed during acquisition')
                    value=deepcopy(value);value['receipts'][host]=receipt;put(self.store,lab,value)
            with self.store.transaction():
                value={**value,'phase':'held'};put(self.store,lab,value)
            return value

    def cancel(self,lab,key):
        """Cancel acquisition only, even on hosts whose acquire ACK was lost.

        Every original host must durably retire the token. No timeout, empty
        receipt map or unavailable worker is proof that acquisition never ran.
        """
        with self.store.executing(lab,'management-barrier'):
            value=self.original(lab,key)
            if value['phase']=='cancelled':return value
            if value['phase'] not in ('acquiring','held','cancelling'):
                raise RuntimeOperationError('only acquisition before provisioning can be cancelled')
            if value['phase']!='cancelling':
                with self.store.transaction():
                    value={**value,'phase':'cancelling'};put(self.store,lab,value)
            for host in sorted(value['targets']):
                receipt=self.remote(lab,value,host,'cancel')
                with self.store.transaction():
                    if self.original(lab,key)!=value:raise RuntimeOperationError('offline management cancellation changed')
                    value=deepcopy(value);value['cancelled'][host]=receipt;put(self.store,lab,value)
            with self.store.transaction():
                no_pending(self.store,lab)
                value={**value,'phase':'cancelled'};put(self.store,lab,value)
            return value

    def begin_provisioning(self,lab,key):
        """Seal cancellation on every original runtime before any allocation."""
        with self.store.executing(lab,'management-barrier'):
            value=self.original(lab,key)
            if value['phase'] not in ('held','activating','provisioning'):
                raise RuntimeOperationError('complete acquisition required before provisioning')
            if value['phase']=='held':
                with self.store.transaction():
                    value={**value,'phase':'activating'};put(self.store,lab,value)
            for host in sorted(value['targets']):
                receipt=self.remote(lab,value,host,'activate')
                with self.store.transaction():
                    if self.original(lab,key)!=value:raise RuntimeOperationError('offline management activation changed')
                    value=deepcopy(value);value['activated'][host]=receipt;put(self.store,lab,value)
            with self.store.transaction():
                value={**value,'phase':'provisioning'};put(self.store,lab,value)
            return value

    def release(self,lab,key,verify_ready):
        """Seal one attestation; reobserve it before each remote release.

        Recovery retains the original proof and rechecks current readiness.
        Completed releases are idempotent; partially released hosts are never
        implicitly fenced again or replaced with a new desired generation.
        """
        with self.store.executing(lab,'management-barrier'):
            value=self.original(lab,key)
            if value['phase']=='released':return value
            def observe():
                evidence=verify_ready(deepcopy(value['plan']),deepcopy(value['targets']))
                if (not isinstance(evidence,dict) or set(evidence)!={'plan_fingerprint','hosts'}
                        or evidence['plan_fingerprint']!=value['plan_fingerprint'] or not isinstance(evidence['hosts'],dict)
                        or set(evidence['hosts'])!=set(value['targets'])
                        or any(not isinstance(proof,dict) or not proof for proof in evidence['hosts'].values())):
                    raise RuntimeOperationError('complete observed management readiness evidence required')
                evidence=json.loads(encoded(evidence))
                if self.original(lab,key)!=value:
                    raise RuntimeOperationError('offline management intent changed during verification')
                return evidence
            if value['phase'] in ('held','provisioning'):
                evidence=observe()
                with self.store.transaction():
                    if self.original(lab,key)!=value:raise RuntimeOperationError('offline management intent changed during verification')
                    value={**value,'phase':'releasing','readiness':evidence,'readiness_fingerprint':digest(evidence)}
                    put(self.store,lab,value)
            elif value['phase']!='releasing':raise RuntimeOperationError('all runtime fences required before readiness')
            for host in sorted(value['targets']):
                evidence=observe()
                if (digest(value['readiness'])!=value['readiness_fingerprint']
                        or evidence!=value['readiness'] or digest(evidence)!=value['readiness_fingerprint']):
                    raise RuntimeOperationError('original management readiness attestation differs')
                with self.store.transaction():
                    if self.original(lab,key)!=value:raise RuntimeOperationError('offline management intent changed during verification')
                    value=deepcopy(value)
                    value.setdefault('release_checks',{})[host]=value.get('release_checks',{}).get(host,0)+1
                    put(self.store,lab,value)
                receipt=self.remote(lab,value,host,'release')
                with self.store.transaction():
                    current=self.original(lab,key)
                    if current!=value:raise RuntimeOperationError('offline management intent changed during release')
                    value=deepcopy(value);value['released'][host]=receipt;put(self.store,lab,value)
            with self.store.transaction():
                no_pending(self.store,lab)
                value={**value,'phase':'released'};put(self.store,lab,value)
            return value
