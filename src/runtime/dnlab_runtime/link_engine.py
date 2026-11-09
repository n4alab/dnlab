"""Local, journalled link requests referencing committed runtime node endpoints."""
import ipaddress
import json
import uuid

from .backend import Backend
from .bridge import BridgeLinux, BridgeManager
from .bridge_identity import BridgeIdentity
from .bridge_request import endpoints, transport_spec, validate as validate_bridge
from .journal import TERMINAL
from .link_identity import VxlanIdentity
from .manifest import Conflict, NotFound, RuntimeErrorBase, canonical, fingerprint, identifier
from .vxlan import VxlanLinux, VxlanManager


class LinkCancelled(RuntimeErrorBase):
    pass


def validate(raw):
    if not isinstance(raw, dict):
        raise RuntimeErrorBase('link request must be an object')
    if raw.get('kind')=='bridge':return validate_bridge(raw)
    allowed = {'schema_version', 'request_id', 'lab_id', 'node_id', 'link_id', 'host_interface',
               'expected_node_revision', 'action', 'spec', 'lab_generation'}
    if set(raw) - allowed or type(raw.get('schema_version')) is not int or raw['schema_version'] != 1:
        raise RuntimeErrorBase('unsupported link request schema or fields')
    for key in ('request_id', 'lab_id', 'node_id', 'link_id', 'host_interface'):
        identifier(raw.get(key), key)
    if len(raw['host_interface']) > 15:
        raise RuntimeErrorBase('host interface exceeds kernel name limit')
    if type(raw.get('expected_node_revision')) is not int or raw['expected_node_revision'] < 1:
        raise RuntimeErrorBase('committed node revision required')
    if raw.get('action') not in ('create', 'delete', 'recover'):
        raise RuntimeErrorBase('unsupported link action')
    if raw['action'] == 'create':
        spec = raw.get('spec')
        if not isinstance(spec, dict) or set(spec) != {'vni', 'underlay', 'local', 'remote', 'mtu'}:
            raise RuntimeErrorBase('complete VXLAN transport specification required')
        VxlanIdentity(raw['lab_id'], raw['link_id'], raw['host_interface'], spec['vni'])
        identifier(spec['underlay'], 'underlay')
        if len(spec['underlay']) > 15 or type(spec['mtu']) is not int or spec['mtu'] < 68:
            raise RuntimeErrorBase('invalid underlay or MTU')
        for key in ('local', 'remote'):
            if not isinstance(spec[key], str) or ipaddress.ip_address(spec[key]).version != 4:
                raise RuntimeErrorBase('IPv4 VXLAN underlay required')
    elif 'spec' in raw:
        raise RuntimeErrorBase('delete/recover use the committed link specification')
    return json.loads(canonical(raw))


class LinkEngine:
    def __init__(self, engine, manager=None, bridge_manager=None):
        self.engine, self.journal = engine, engine.journal
        self.manager = manager or VxlanManager(self.journal, VxlanLinux(engine.backend.linux))
        self.bridge_manager = bridge_manager or BridgeManager(self.journal, BridgeLinux(engine.backend.linux))
        with self.journal.transaction():
            self.journal.db.execute('''CREATE TABLE IF NOT EXISTS link_operations (
                id TEXT PRIMARY KEY, lab TEXT NOT NULL, node TEXT NOT NULL, request_id TEXT NOT NULL,
                payload TEXT NOT NULL, hash TEXT NOT NULL, phase TEXT NOT NULL,
                cancel_requested INTEGER NOT NULL DEFAULT 0, prior_active INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
                UNIQUE(lab,request_id))''')
            self.journal.db.execute('''CREATE TABLE IF NOT EXISTS committed_links (
                lab TEXT NOT NULL, link_id TEXT NOT NULL, endpoint TEXT NOT NULL,
                node TEXT NOT NULL, spec TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY(lab,link_id,endpoint))''')

    def get(self, operation_id, *, private=False):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM link_operations WHERE id=?', (operation_id,)).fetchone()
        if row is None:
            raise NotFound('link operation not found')
        value = dict(row)
        value['cancel_requested'] = bool(value['cancel_requested'])
        payload=json.loads(value['payload'])
        if payload.get('kind')=='bridge':
            value['kind']='bridge';value['affected_nodes']=sorted({e['node_id'] for e in endpoints(payload)})
            value['endpoints']=endpoints(payload)
        if private:
            value['payload'] = json.loads(value['payload'])
        else:
            value.pop('payload'); value.pop('hash')
        return value

    def state(self, lab, link_id, endpoint):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM committed_links WHERE lab=? AND link_id=? AND endpoint=?', (lab,link_id,endpoint)).fetchone()
        if row is None:
            return None
        value = dict(row); value['spec'] = json.loads(value['spec'])
        return value

    def pending(self):
        with self.journal.lock:
            rows = self.journal.db.execute('SELECT id,phase FROM link_operations ORDER BY rowid').fetchall()
        return [x['id'] for x in rows if x['phase'] not in TERMINAL]

    def node_free(self, lab, node):
        with self.journal.lock:
            active = self.journal.db.execute("SELECT 1 FROM committed_links WHERE lab=? AND node=? AND state != 'deleted'", (lab,node)).fetchone()
            rows = self.journal.db.execute('SELECT payload,phase FROM link_operations WHERE lab=?', (lab,)).fetchall()
        if active or any(x['phase'] not in ('completed', 'cancelled', 'failed')
                         and any(e['node_id']==node for e in endpoints(json.loads(x['payload']))) for x in rows):
            raise Conflict('remove or recover local links before stopping the node')

    def owner(self, request, *, creating=False):
        from .management_authority import available
        available(self.journal,request['lab_id'],request['node_id'])
        node = self.journal.node(request['lab_id'], request['node_id'])
        if node is None or node['revision'] != request['expected_node_revision']:
            raise Conflict('link node revision changed or missing')
        if creating and node['spec'].get('kind') != 'linux':
            raise Conflict('link API node kind is not qualified')
        if creating and node['state'] != 'running':
            raise Conflict('link source node is not running')
        endpoints = node['spec'].get('endpoints', [])
        if not any(x['host_interface'] == request['host_interface'] for x in endpoints):
            raise Conflict('link endpoint is not owned by the committed node')
        current = self.state(request['lab_id'], request['link_id'], request['host_interface'])
        if current and current['node'] != request['node_id']:
            raise Conflict('link belongs to another node')
        return node, current

    def plan(self, raw):
        request = validate(raw)
        owners=[self.owner(dict(request,**edge),creating=request['action']=='create') for edge in endpoints(request)]
        node,current=owners[0]
        kind=request.get('kind','vxlan')
        for _,state in owners:
            if state and state['spec'].get('kind','vxlan')!=kind and (state['state']!='deleted' or request['action']!='create'):
                raise Conflict('active link uses another transport')
        if kind=='bridge':
            persisted=[state for _,state in owners]
            if request['action']!='create' and any(state is None for state in persisted):
                raise NotFound('bridge has no complete persisted specification')
            expected=[{key:e[key] for key in ('node_id','host_interface')} for e in endpoints(request)]
            for state in persisted:
                if state and state['state']!='deleted' and state['spec'].get('endpoints')!=expected:
                    raise Conflict('bridge endpoints cannot be implicitly reconfigured')
            if current and (request['action']!='create' or any(state and state['state']!='deleted' for state in persisted)):
                if any(state is None or state['spec']!=current['spec'] or state['state']!=current['state'] for state in persisted):
                    raise Conflict('bridge persisted endpoint states disagree')
        if request['action'] != 'create' and current is None:
            raise NotFound('link has no persisted specification')
        if current and current['state'] != 'deleted' and request['action']=='create' and current['spec'] != transport_spec(request):
            raise Conflict('active link cannot be implicitly reconfigured')
        names={e['host_interface'] for e in endpoints(request)}
        with self.journal.lock:
            rows=self.journal.db.execute("SELECT lab,link_id,endpoint,spec FROM committed_links WHERE state != 'deleted'").fetchall()
        for row in rows:
            same=(row['lab'],row['link_id'])==(request['lab_id'],request['link_id'])
            if row['endpoint'] in names and not same:
                raise Conflict('link endpoint already committed to another link')
            if same and (kind=='bridge' or json.loads(row['spec']).get('kind')=='bridge') and row['endpoint'] not in names:
                raise Conflict('bridge endpoints cannot be implicitly reconfigured')
        if kind=='bridge':
            return {'schema_version':1,'mutations_performed':False,'kind':'bridge',
                    'affected_nodes':sorted({e['node_id'] for e in endpoints(request)}),
                    'link_id':request['link_id'],'endpoints':endpoints(request),'action':request['action']}
        return {'schema_version':1,'mutations_performed':False,'affected_nodes':[request['node_id']],
                'link_id':request['link_id'],'host_interface':request['host_interface'],
                'action':request['action'],'expected_node_revision':node['revision']}

    def submit(self, raw, *, max_pending=128, stop_parent=None):
        request = validate(raw)
        digest = fingerprint(request)
        with self.journal.transaction():
            prior = self.journal.db.execute('SELECT id,hash FROM link_operations WHERE lab=? AND request_id=?', (request['lab_id'],request['request_id'])).fetchone()
            if prior:
                if prior['hash'] != digest:
                    raise Conflict('link request_id already used with different content')
                if stop_parent is not None:
                    self.engine.stops.authorize_child(stop_parent,request)
                    child=self.journal.db.execute('SELECT parent_id,hash FROM stop_link_children WHERE operation_id=?',(prior['id'],)).fetchone()
                    if not child or child['parent_id']!=stop_parent or child['hash']!=digest:raise Conflict('stop cleanup child identity differs')
                    if self.get(prior['id'])['phase'] in ('recovery_required','failed','cancelled'):
                        self.journal.db.execute("UPDATE link_operations SET phase='applying',error='' WHERE id=?",(prior['id'],))
                return self.get(prior['id'])
            from .lab_closure import check
            check(self.journal,request,stop_parent=stop_parent)
            if stop_parent is not None:self.engine.stops.authorize_child(stop_parent,request)
            self.plan(request)
            if len(self.pending()) >= max_pending:
                raise Conflict('local link queue is full')
            rows = self.journal.db.execute('SELECT lab,payload,phase FROM link_operations').fetchall()
            for row in rows:
                other = json.loads(row['payload'])
                shared={e['host_interface'] for e in endpoints(other)} & {e['host_interface'] for e in endpoints(request)}
                same=(other['lab_id'],other['link_id'],other.get('kind','vxlan'),endpoints(other))==(request['lab_id'],request['link_id'],request.get('kind','vxlan'),endpoints(request))
                if shared and row['phase'] not in ('completed','cancelled','failed'):
                    if request['action'] != 'recover' or not same or row['phase'] != 'recovery_required':
                        raise Conflict('link endpoint is busy or requires recovery')
            for edge in endpoints(request):
                from .stop_protocol import unreserved
                unreserved(self.journal,request['lab_id'],edge['node_id'],parent=stop_parent)
                node_operations = self.journal.db.execute('SELECT id,phase FROM operations WHERE lab=? AND node=?', (request['lab_id'],edge['node_id'])).fetchall()
                if any(x['id']!=stop_parent and (x['phase'] not in TERMINAL or x['phase']=='recovery_required') for x in node_operations):
                    raise Conflict('node has a pending operation or requires recovery')
            identity = uuid.uuid4().hex
            self.journal.db.execute('INSERT INTO link_operations(id,lab,node,request_id,payload,hash,phase) VALUES(?,?,?,?,?,?,?)',
                (identity,request['lab_id'],endpoints(request)[0]['node_id'],request['request_id'],canonical(request),digest,'queued'))
            if stop_parent is not None:
                self.journal.db.execute('INSERT INTO stop_link_children VALUES(?,?,?)',(identity,stop_parent,digest))
        return self.get(identity)

    def phase(self, operation_id, phase, error=''):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE link_operations SET phase=?,error=? WHERE id=?', (phase,error,operation_id))

    def cancel(self, operation_id):
        with self.journal.transaction():
            if self.get(operation_id)['phase'] not in TERMINAL:
                self.journal.db.execute('UPDATE link_operations SET cancel_requested=1 WHERE id=?', (operation_id,))
        return self.get(operation_id)

    def check_cancel(self, operation_id):
        if self.get(operation_id)['cancel_requested']:
            raise LinkCancelled('link cancellation requested')

    def inspect(self, lab, link_id, endpoint):
        current = self.state(lab,link_id,endpoint)
        if current is None:
            raise NotFound('link not found')
        bridge=current['spec'].get('kind')=='bridge'
        manager=self.bridge_manager if bridge else self.manager
        identity = BridgeIdentity(lab,link_id) if bridge else VxlanIdentity(lab,link_id,endpoint,current['spec']['vni'])
        row = manager.row(identity.digest)
        kernel = 'absent'
        if row:
            try:
                observed = manager.bridge(identity,row['payload']) if bridge else manager.tunnel(identity,row['payload'],complete=row['phase']=='active')
                kernel = 'present' if observed else 'absent'
            except RuntimeErrorBase:
                kernel = 'identity_mismatch'
        result={'lab_id':lab,'link_id':link_id,'host_interface':endpoint,'node_id':current['node'],
                'committed_state':current['state'],'runtime_phase':row['phase'] if row else 'absent',
                'kernel_state':kernel,
                'guest_readiness':'unknown'}
        if bridge:result.update(kind='bridge',endpoints=current['spec']['endpoints'])
        return result

    def update_state(self,request,state):
        for edge in endpoints(request):
            self.journal.db.execute('UPDATE committed_links SET state=? WHERE lab=? AND link_id=? AND endpoint=?',
                (state,request['lab_id'],request['link_id'],edge['host_interface']))

    def create_link(self,operation_id,request,spec,manager,identity,owners):
        sources=[]
        for edge,(node,_) in zip(endpoints(request),owners):
            owner={'lab_id':request['lab_id'],'node_id':edge['node_id']}
            self.engine.backend.verify(owner,node['spec'])
            source=next((x for x in manager.linux.links() if x['ifname']==edge['host_interface']),None)
            if not source or source.get('ifalias')!=Backend.alias(owner,node['spec']):
                raise Conflict('source kernel ownership does not match committed node')
            sources.append(source)
        manager.check=lambda:self.check_cancel(operation_id)
        if request.get('kind')=='bridge':manager.create(identity,sources=sources,mtu=spec['mtu'])
        else:manager.create(identity,source=sources[0],underlay=spec['underlay'],local=spec['local'],remote=spec['remote'],mtu=spec['mtu'])

    def execute(self, operation_id):
        with self.journal.execution_lock:
            operation = self.get(operation_id, private=True)
            if operation['phase'] in TERMINAL:
                return self.get(operation_id)
            request = operation['payload']
            child=self.journal.db.execute('SELECT parent_id,hash FROM stop_link_children WHERE operation_id=?',(operation_id,)).fetchone()
            manager=self.bridge_manager if request.get('kind')=='bridge' else self.manager
            identity = None
            previous = None
            replaying = operation['phase'] != 'queued'
            try:
                from .lab_closure import check
                check(self.journal,request,stop_parent=child['parent_id'] if child else None)
                if child:
                    if child['hash']!=fingerprint(request):raise Conflict('stop cleanup child content differs')
                    self.engine.stops.authorize_child(child['parent_id'],request)
                if not replaying:
                    self.check_cancel(operation_id)
                owners=[self.owner(dict(request,**edge),creating=request['action']=='create') for edge in endpoints(request)]
                node,current=owners[0]
                spec = transport_spec(request) if request['action']=='create' else current['spec']
                identity = (BridgeIdentity(request['lab_id'],request['link_id']) if request.get('kind')=='bridge'
                            else VxlanIdentity(request['lab_id'],request['link_id'],request['host_interface'],spec['vni']))
                previous = manager.row(identity.digest)
                if replaying:
                    # A daemon restart compensates the interrupted operation;
                    # it never recreates resources as a side effect of replay.
                    if operation['prior_active']:
                        if not previous or previous['phase'] != 'active':
                            raise Conflict('previously active link needs explicit recovery')
                        manager.verify(identity, previous['payload'])
                    elif previous and previous['phase'] != 'cleaned':
                        manager.delete(identity)
                    with self.journal.transaction():
                        self.update_state(request,'active' if operation['prior_active'] else 'deleted')
                        cancelled = self.get(operation_id)['cancel_requested']
                        phase = ('cancelled' if cancelled else 'failed') if request['action']=='create' else 'completed'
                        error = ('link cancellation requested' if cancelled else 'interrupted create reconciled; submit a new request') if request['action']=='create' else ''
                        self.journal.db.execute('UPDATE link_operations SET phase=?,error=? WHERE id=?', (phase,error,operation_id))
                    return self.get(operation_id)
                with self.journal.transaction():
                    self.journal.db.execute('UPDATE link_operations SET prior_active=? WHERE id=?', (int(bool(request['action']=='create' and previous and previous['phase']=='active' and current and current['state']=='active')),operation_id))
                    for edge in endpoints(request):
                        self.journal.db.execute('INSERT INTO committed_links VALUES(?,?,?,?,?,?) ON CONFLICT(lab,link_id,endpoint) DO UPDATE SET state=excluded.state,spec=excluded.spec',
                            (request['lab_id'],request['link_id'],edge['host_interface'],edge['node_id'],canonical(spec),'applying'))
                    self.journal.db.execute("UPDATE link_operations SET phase='applying' WHERE id=?", (operation_id,))
                if request['action']=='create':
                    self.create_link(operation_id,request,spec,manager,identity,owners)
                    self.check_cancel(operation_id)
                    state = 'active'
                else:
                    manager.delete(identity)
                    state = 'deleted'
                with self.journal.transaction():
                    if request['action']=='create':
                        self.check_cancel(operation_id)
                    self.update_state(request,state)
                    self.journal.db.execute("UPDATE link_operations SET phase='completed' WHERE id=?", (operation_id,))
                    if request['action']=='recover':
                        rows = self.journal.db.execute("SELECT id,payload FROM link_operations WHERE lab=? AND phase='recovery_required'", (request['lab_id'],)).fetchall()
                        for row in rows:
                            other = json.loads(row['payload'])
                            if other['link_id']==request['link_id'] and other.get('kind','vxlan')==request.get('kind','vxlan') and endpoints(other)==endpoints(request):
                                self.journal.db.execute("UPDATE link_operations SET phase='failed',error='recovered by explicit link cleanup' WHERE id=?", (row['id'],))
            except Exception as error:
                if child:
                    self.phase(operation_id,'recovery_required',str(error) if isinstance(error,RuntimeErrorBase) else 'stop link cleanup requires recovery')
                    return self.get(operation_id)
                if replaying:
                    # A replay cannot safely infer a clean terminal outcome
                    # after failed ownership verification or compensation.
                    self.phase(operation_id,'recovery_required','interrupted link cleanup requires explicit recovery')
                    return self.get(operation_id)
                cancelled = self.get(operation_id)['cancel_requested']
                try:
                    row = manager.row(identity.digest) if identity else None
                    if identity and row and row['phase'] != 'cleaned' and (request['action']!='create' or not previous or previous['phase']!='active'):
                        manager.delete(identity)
                    if identity and (request['action']!='create' or not previous or previous['phase']!='active'):
                        with self.journal.transaction():
                            self.update_state(request,'deleted')
                    elif identity and previous and previous['phase']=='active':
                        with self.journal.transaction():
                            self.update_state(request,'active')
                    self.phase(operation_id,'cancelled' if cancelled else 'failed',str(error) if isinstance(error,RuntimeErrorBase) else f'link operation failed ({type(error).__name__})')
                except Exception:
                    self.phase(operation_id,'recovery_required','link cleanup requires explicit recovery')
            finally:
                manager.check = lambda: None
            return self.get(operation_id)
