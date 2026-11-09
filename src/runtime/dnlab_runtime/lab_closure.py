"""Durable local lab closure. No scheduling or distributed topology authority."""
import json
import re

from .manifest import Conflict,canonical,fingerprint,identifier,validate_request

CONTRACT='durable closing fence; qualified stop children only; explicit generation reopen'
DONE={'completed','cancelled','failed'}


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS lab_closures (lab TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS lab_closure_history (lab TEXT NOT NULL,generation INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,generation))')


def get(journal,lab):
    with journal.lock:
        row=journal.db.execute('SELECT payload FROM lab_closures WHERE lab=?',(lab,)).fetchone()
    return json.loads(row[0]) if row else None


def generation(journal,lab):
    value=get(journal,lab)
    return value['generation'] if value else 1


def put(journal,lab,value):
    journal.db.execute('INSERT INTO lab_closures VALUES(?,?) ON CONFLICT(lab) DO UPDATE SET payload=excluded.payload',(lab,canonical(value)))


def check(journal,request,*,stop_parent=None):
    """Called inside the submission transaction and before workload mutations."""
    lab=request['lab_id']
    from .management_barrier import check as management_check
    management_check(journal,lab)
    value=get(journal,lab)
    epoch=request.get('lab_generation',1)
    if type(epoch) is not int or epoch<1 or epoch!=(value['generation'] if value else 1):
        raise Conflict('lab generation differs; explicit reopening context required')
    if not value or value['phase']=='open':return
    if value['phase']=='closing':
        if fingerprint(request) in value['stops']:return
        if stop_parent is not None:
            parent=journal.get(stop_parent,private=True)
            if parent['lab']==lab and parent['hash'] in value['stops']:
                # The stop protocol additionally checks the exact child body,
                # original endpoint proofs and verified process exit.
                return
    raise Conflict('lab is closing or closed; new mutations are fenced')


def public(journal,lab,value):
    return {'lab_id':lab,'journal_id':journal.identity,
            **{k:value[k] for k in ('closure_id','generation','phase')},
            'reopen_request_id':value.get('reopen_request_id')}


def clean(engine,lab):
    from .inspection import cleanup_inventory
    value=cleanup_inventory(engine.journal,lab)
    if value['blocked']:raise Conflict('lab cleanup still pending: '+','.join(value['blocked']))
    for row in engine.journal.db.execute('SELECT node FROM nodes WHERE lab=?',(lab,)).fetchall():
        node=row[0]
        view=engine.inspect(lab,node)
        if view['committed_state']!='stopped' or view['container_state']!='absent' or view['operation'] is not None:
            raise Conflict('lab workload absence is not verified')
    return value


def control(engine,lab,action,raw):
    lab=identifier(lab,'lab_id');journal=engine.journal
    allowed={'closure_id','generation','stops'} if action=='close' else {'closure_id','generation'} if action=='finish' else {'closure_id','generation','request_id'}
    if not isinstance(raw,dict) or set(raw)!=allowed:raise Conflict('invalid lab closure fields')
    token=raw['closure_id'];epoch=raw['generation']
    if not isinstance(token,str) or not re.fullmatch(r'[0-9a-f]{32}',token) or type(epoch) is not int or epoch<1:
        raise Conflict('invalid lab closure identity')
    if action=='reopen':identifier(raw['request_id'],'reopen request_id')
    stops={}
    if action=='close':
        if not isinstance(raw['stops'],list) or not raw['stops']:raise Conflict('complete teardown intents required')
        nodes=set()
        for original in raw['stops']:
            request=validate_request(original)
            if (request['lab_id']!=lab or request['action']!='stop' or request.get('stop_mode')!='coordinated'
                    or request.get('lab_generation',1)!=epoch or request['node_id'] in nodes):
                raise Conflict('lab closure requires distinct qualified stop intents')
            nodes.add(request['node_id']);stops[fingerprint(request)]=request['node_id']
    # Serialize against actual execution in other workers as well as new SQL
    # submissions. A crash can release this lock, never the durable fence.
    with journal.execution_lock, journal.transaction():
        from .management_barrier import check as management_check
        management_check(journal,lab)
        value=get(journal,lab)
        if action=='close':
            if value and value['phase']!='open':
                if value['closure_id']!=token or value['generation']!=epoch or value['stops']!=stops:
                    raise Conflict('lab closure identity or teardown manifest differs')
                return public(journal,lab,value)
            if epoch!=(value['generation'] if value else 1):raise Conflict('lab closure generation differs')
            from .inspection import cleanup_inventory
            inventory=cleanup_inventory(journal,lab)
            if not set(inventory['nodes'])<=nodes:raise Conflict('lab contains an unqualified workload')
            db=journal.db
            for row in db.execute('SELECT id,hash,phase FROM operations WHERE lab=?',(lab,)):
                if row['phase'] not in DONE and row['hash'] not in stops:
                    raise Conflict('lab has an operation outside the qualified teardown')
            for row in db.execute("SELECT id FROM link_operations WHERE lab=? AND phase NOT IN ('completed','cancelled','failed')",(lab,)):
                child=db.execute('SELECT parent_id FROM stop_link_children WHERE operation_id=?',(row[0],)).fetchone()
                if not child or journal.get(child[0],private=True)['hash'] not in stops:
                    raise Conflict('lab has an unqualified pending link operation')
            if 'management_moves' in inventory['blocked'] or 'management_assignments' in inventory['blocked'] and any(
                    json.loads(row[0]).get('phase')=='pending' for row in db.execute('SELECT payload FROM management_assignments WHERE lab=?',(lab,))):
                raise Conflict('management requires recovery before lab closure')
            value={'closure_id':token,'generation':epoch,'phase':'closing','stops':stops}
            put(journal,lab,value)
        else:
            if not value or value['closure_id']!=token:raise Conflict('lab closure not found or changed')
            if action=='reopen' and value['phase']=='open':
                if value.get('reopen_request_id')!=raw['request_id'] or value['generation']!=epoch+1:
                    raise Conflict('lab reopening identity differs')
                return public(journal,lab,value)
            if value['generation']!=epoch:raise Conflict('lab closure generation differs')
            clean(engine,lab)
            if action=='finish':
                if value['phase'] not in ('closing','closed'):raise Conflict('lab is not closing')
                value={**value,'phase':'closed'};put(journal,lab,value)
            elif action=='reopen':
                if value['phase']!='closed':raise Conflict('verified closed lab required for reopening')
                journal.db.execute('INSERT INTO lab_closure_history VALUES(?,?,?) ON CONFLICT(lab,generation) DO NOTHING',(lab,epoch,canonical(value)))
                value={**value,'phase':'open','generation':epoch+1,'reopen_request_id':raw['request_id']};put(journal,lab,value)
            else:raise Conflict('invalid lab closure action')
        return public(journal,lab,value)
