"""Read-only, optimistic node inspection across committed and pending births."""
import json

from .manifest import Conflict, NotFound, RuntimeErrorBase, fingerprint, validate_request
from .management_authority import assignment
from .workload_generation import latest
from .workload_identity import container_reference


CONTRACT='consistent committed node, qualified workload and pending operation'


def snapshot(engine,lab,node):
    journal=engine.journal
    # A read savepoint gives all metadata queries the same SQLite snapshot,
    # including when another daemon process commits between those queries.
    with journal.lock:
        journal.db.execute('SAVEPOINT node_inspection')
        try:
            from .backend_reservations import vm_reservations
            rows=journal.db.execute("SELECT id FROM operations WHERE lab=? AND node=? AND phase NOT IN ('completed','cancelled','failed') ORDER BY rowid",(lab,node)).fetchall()
            if len(rows)>1:raise Conflict('ambiguous pending node operation')
            return {'node':journal.node(lab,node),
                    'birth':latest(journal,{'lab_id':lab,'node_id':node}),
                    'operation':journal.get(rows[0]['id'],private=True) if rows else None,
                    'management':assignment(journal,lab,node),
                    'stop_session':engine.stops.session(rows[0]['id']) if rows else None,
                    'backend_reservations':vm_reservations(journal,lab,node),
                    'cleanup_inventory':cleanup_inventory(journal,lab)}
        finally:journal.db.execute('RELEASE node_inspection')


def select_spec(value,lab,node):
    current,birth,operation=value['node'],value['birth'],value['operation']
    revision=current['revision'] if current else 0
    request=None
    if operation:
        request=validate_request(operation['payload'])
        if (fingerprint(request)!=operation['hash'] or operation['lab']!=lab or operation['node']!=node
                or request['lab_id']!=lab or request['node_id']!=node
                or request['request_id']!=operation['request_id'] or request['expected_revision']!=revision):
            raise Conflict('inspection operation context or revision changed')
    if not current and not request:raise NotFound('node not found')
    if birth and birth['phase'] in ('reserved','bound'):
        if (not request or request['action']!='start' or operation['id']!=birth['creator']
                or fingerprint(request['spec'])!=birth['spec']
                or request['spec']['container_name']!=birth['container_name']
                or current and current['state']!='stopped'):
            raise Conflict('pending workload birth lacks its original start operation')
        return request['spec']
    if current:
        if birth and birth['phase']=='running' and birth['spec']!=fingerprint(current['spec']):
            raise Conflict('committed workload birth spec changed')
        return current['spec']
    if request['action']!='start':raise Conflict('pending node has no committed specification')
    return request['spec']


def container_signature(container):
    if container is None:return None
    state=container['State']
    return {'id':container['Id'],'name':container.get('Name'),
            'state':{k:state.get(k) for k in ('Running','Pid','StartedAt','FinishedAt','Status','Paused','Restarting','Dead')}}


def inspect(engine,lab,node):
    for _ in range(3):
        before=snapshot(engine,lab,node)
        try:
            from .backend_reservations import available
            available(engine.journal,lab,node,'docker')
            spec=select_spec(before,lab,node)
            owner={'lab_id':lab,'node_id':node}
            first=engine.backend.inspect(owner,spec)
            container=engine.backend.inspect(owner,spec)
        except RuntimeErrorBase:
            if snapshot(engine,lab,node)!=before:continue
            raise
        if snapshot(engine,lab,node)!=before or container_signature(first)!=container_signature(container):continue
        current,birth,operation=before['node'],before['birth'],before['operation']
        result={'lab_id':lab,'node_id':node,'journal_id':engine.journal.identity,
                'revision':current['revision'] if current else 0,
                'committed_state':current['state'] if current else 'absent',
                'committed_spec_fingerprint':fingerprint(current['spec']) if current else None,
                'container_state':'absent' if container is None else 'running' if container['State']['Running'] else 'stopped',
                'container_id':container['Id'] if container else None,'guest_readiness':'unknown',
                'workload':None,'operation':None,'cleanup_inventory':before['cleanup_inventory']}
        # Additive backend-neutral view. The Docker fields remain unchanged
        # while VM execution is still unsupported by the request validator.
        result['workload_ref']=container_reference(container)
        result['workload_state']=result['container_state']
        if birth:
            result['workload']={'generation':birth['generation'],'phase':birth['phase'],
                'container_id':birth['container_id'],'creator_operation_id':birth['creator'],
                'spec_fingerprint':birth['spec'],'committed_revision':birth['committed_revision']}
        if operation:
            result['operation']={k:operation[k] for k in ('id','request_id','phase','cancel_requested','recovery_force','stop_stage','shutdown_verified') if k in operation}
            result['operation']['action']=operation['payload']['action']
            session=before['stop_session']
            if session:
                result['operation']['cleanup_scope']='local' if all(r.get('kind','vxlan')=='bridge' for r in session['links']) else 'distributed'
                result['operation']['footprint_nodes']=sorted(session['owners'])
        management=before['management']
        if management:result['management']={'state':management['phase'],'connection':management['connection'],'node_revision':result['revision']}
        return result
    raise Conflict('node inspection changed concurrently; retry')


def cleanup_inventory(journal,lab):
    """Journal-only finalization veto; physical absence still needs node guards.

    Called within the inspection read snapshot. Unscoped legacy primitives are
    deliberately not adopted or assumed unrelated to this lab.
    """
    db=journal.db
    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    blocked=[]
    checks={'operations':"phase NOT IN ('completed','cancelled','failed')",
            'nodes':"state != 'stopped'",'workload_generations':"phase != 'cleaned'",
            'resources':'1','stop_reservations':'1',
            'link_operations':"phase NOT IN ('completed','cancelled','failed')",
            'committed_links':"state != 'deleted'"}
    for table,predicate in checks.items():
        if table in tables and db.execute(f'SELECT 1 FROM {table} WHERE lab=? AND ({predicate})',(lab,)).fetchone():
            blocked.append(table)
    if any(json.loads(r[0]).get('phase')!='stopped' for r in db.execute('SELECT payload FROM management_assignments WHERE lab=?',(lab,))):
        blocked.append('management_assignments')
    if 'management_move_requests' in tables and db.execute("SELECT 1 FROM management_move_requests r JOIN management_moves m ON m.id=r.operation_id WHERE r.lab=? AND m.phase NOT IN ('completed','rolled_back','rejected')",(lab,)).fetchone():
        blocked.append('management_moves')
    for table in ('local_bridges','local_vxlans'):
        if table not in tables:continue
        for row in db.execute(f"SELECT payload FROM {table} WHERE phase != 'cleaned'"):
            owner=json.loads(row[0]).get('lab_id')
            if owner is None or owner==lab:
                blocked.append(table);break
    nodes=sorted({r[0] for table,predicate in (('nodes',"state != 'stopped'"),
                  ('workload_generations',"phase != 'cleaned'"),('operations',"phase NOT IN ('completed','cancelled','failed')"))
                  for r in db.execute(f'SELECT DISTINCT node FROM {table} WHERE lab=? AND ({predicate})',(lab,))})
    for table in ('vm_event_streams','vm_definition_intents','vm_storage_intents'):
        if table not in tables:continue
        # VM retirement is not enabled yet. Definition intents and event
        # streams veto owner finalization even before a QEMU process exists.
        for row in db.execute(f'SELECT payload,fingerprint FROM {table}'):
            try:
                value=json.loads(row['payload'])
                if fingerprint(value)!=row['fingerprint']:raise ValueError('integrity')
                from .vm_events import validate_birth
                validate_birth(value['birth'])
            except (ValueError,KeyError,TypeError,RuntimeErrorBase) as error:
                raise Conflict('VM event inventory requires qualified recovery') from error
            if value['birth']['lab_id']==lab:
                if table not in blocked:blocked.append(table)
                nodes.append(value['birth']['node_id'])
        nodes=sorted(set(nodes))
    return {'nodes':nodes,'blocked':sorted(blocked)}
