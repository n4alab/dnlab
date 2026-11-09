"""Private coordinator fence; runtime receipts are bound to immutable targets."""
import json
import uuid

from .runtime_operations import RuntimeOperationError,digest,encoded,FINAL


def get(store,lab):
    with store.lock:
        row=store.db.execute('SELECT payload FROM lab_closures WHERE lab=?',(lab,)).fetchone()
    return json.loads(row[0]) if row else None


def put(store,lab,value):
    store.db.execute('INSERT INTO lab_closures VALUES(?,?) ON CONFLICT(lab) DO UPDATE SET payload=excluded.payload',(lab,encoded(value)))


def check(store,request):
    from .management_barrier import check as management_check
    management_check(store,request['lab_id'])
    value=get(store,request['lab_id']);epoch=request.get('lab_generation',1)
    if type(epoch) is not int or epoch<1 or epoch!=(value['generation'] if value else 1):
        raise RuntimeOperationError('coordinator lab generation differs')
    if not value or value['phase']=='open':return
    if value['phase']=='closing' and value['allowed'].get(request['request_id'])==digest(request):return
    raise RuntimeOperationError('coordinator lab is closing or closed')


def begin(store,lab,keys):
    with store.transaction():
        from .management_barrier import check as management_check
        management_check(store,lab)
        previous=get(store,lab);epoch=previous['generation'] if previous else 1;allowed={}
        if not keys or len(set(keys))!=len(keys):raise RuntimeOperationError('complete distinct teardown intents required')
        for key in keys:
            current=store.get(lab,key,private=True);request=current['request']
            if request.get('action')!='stop' or request.get('stop_mode')!='coordinated' or request.get('lab_generation',1)!=epoch:
                raise RuntimeOperationError('qualified current-generation teardown intent required')
            allowed[key]=digest(request)
        if previous and previous['phase']!='open':
            if previous['allowed']!=allowed:raise RuntimeOperationError('coordinator closure manifest changed')
            return previous
        if store.db.execute("SELECT 1 FROM public_link_requests WHERE lab=? AND phase NOT IN ('completed','failed','cancelled')",(lab,)).fetchone():
            raise RuntimeOperationError('public native link recovery still pending')
        for job in store.db.execute("SELECT action,payload FROM public_requests WHERE lab=? AND phase='pending'",(lab,)):
            requests=json.loads(job['payload']).get('requests',{})
            if job['action']!='stop' or not requests or any(r['request_id'] not in allowed for r in requests.values()):
                raise RuntimeOperationError('public native operation still pending')
        if any(owner==lab and key not in allowed for owner,key in store.pending()):
            raise RuntimeOperationError('lab has an intent outside qualified teardown')
        value={'closure_id':uuid.uuid4().hex,'generation':epoch,'phase':'closing','allowed':allowed,'receipts':{}}
        put(store,lab,value)
    return value


def receipt(store,lab,token,target,journal,remote):
    with store.transaction():
        value=get(store,lab)
        if (not value or value['closure_id']!=token or remote.get('lab_id')!=lab or remote.get('journal_id')!=journal
                or remote.get('closure_id')!=token or remote.get('generation')!=value['generation']
                or remote.get('phase') not in ('closing','closed')):
            raise RuntimeOperationError('runtime lab closure receipt differs')
        key=digest({'target':target,'journal_id':journal})
        value['receipts'][key]={'target':target,'journal_id':journal,'receipt':remote}
        put(store,lab,value)


def finish(store,lab,token,targets):
    with store.transaction():
        value=get(store,lab)
        if not value or value['closure_id']!=token or set(value['receipts'])!=set(targets):
            raise RuntimeOperationError('incomplete runtime lab closure receipts')
        if any(v['receipt']['phase']!='closed' for v in value['receipts'].values()) or any(owner==lab for owner,key in store.pending()):
            raise RuntimeOperationError('runtime lab closure still pending')
        value['phase']='closed';put(store,lab,value)
    return value


def reopen(store,lab,token,request_id,client_factory,*,deployment_state_absent):
    """Explicit local reopen. Never infer it from start or daemon reconciliation.

    Caller must qualify absence of old deployment state under its lifecycle lock.
    The ledger stays fenced through partial/unknown remote acknowledgements.
    """
    if deployment_state_absent is not True:raise RuntimeOperationError('old deployment state must be absent')
    if not isinstance(request_id,str) or not request_id:raise RuntimeOperationError('reopen request identity required')
    with store.transaction():
        value=get(store,lab)
        if not value or value['closure_id']!=token:raise RuntimeOperationError('coordinator closure changed')
        if value['phase']=='open':
            if value.get('reopen_request_id')!=request_id:raise RuntimeOperationError('coordinator reopening identity differs')
            return value
        if len(value['receipts'])!=1:raise RuntimeOperationError('distributed reopening is not qualified')
        if value['phase'] not in ('closed','reopening'):raise RuntimeOperationError('verified closed lab required')
        if value.get('reopen_request_id',request_id)!=request_id:raise RuntimeOperationError('coordinator reopening identity differs')
        value.update(phase='reopening',reopen_request_id=request_id);put(store,lab,value)
    original=next(iter(value['receipts'].values()))
    client=client_factory(original['target']).bound_to(original['journal_id'])
    remote=client.lab_closure(lab,'reopen',{'closure_id':token,'generation':value['generation'],'request_id':request_id})
    if (remote.get('lab_id')!=lab or remote.get('journal_id')!=original['journal_id'] or remote.get('closure_id')!=token
            or remote.get('generation')!=value['generation']+1 or remote.get('phase')!='open' or remote.get('reopen_request_id')!=request_id):
        raise RuntimeOperationError('runtime reopening receipt differs')
    with store.transaction():
        current=get(store,lab)
        if current!=value:raise RuntimeOperationError('coordinator closure changed during reopening')
        store.db.execute('INSERT INTO lab_closure_history VALUES(?,?,?)',(lab,value['generation'],encoded(value)))
        value.update(phase='open',generation=value['generation']+1);put(store,lab,value)
    return value
