"""Local stop phases. The existing coordinator authorizes cleanup/finalization.

No topology scheduling or remote-host authority lives here. A parked stop holds
its local footprint until verified cleanup and the final node commit.
"""
import json

from .bridge_identity import BridgeIdentity
from .bridge_request import endpoints
from .link_identity import VxlanIdentity
from .manifest import Conflict, RuntimeErrorBase, canonical, fingerprint

class StopPlanChanged(Conflict):pass


DONE = {'completed', 'cancelled', 'failed'}
STAGES = ['prepared', 'shutdown_requested', 'exit_verified', 'cleanup_requested', 'links_cleaned', 'finalizing', 'finished']


def unreserved(journal, lab, node, *, parent=None):
    with journal.lock:
        row = journal.db.execute('SELECT operation_id FROM stop_reservations WHERE lab=? AND node=?', (lab,node)).fetchone()
    if row and row[0] != parent:
        raise Conflict('node is reserved by a coordinated stop')


class StopProtocol:
    def __init__(self, engine):
        self.engine, self.journal = engine, engine.journal

    def session(self, operation_id):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT payload FROM stop_sessions WHERE operation_id=?', (operation_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, operation_id, value, *, phase=None):
        with self.journal.transaction():
            self.journal.db.execute('INSERT INTO stop_sessions VALUES(?,?) ON CONFLICT(operation_id) DO UPDATE SET payload=excluded.payload',
                                    (operation_id,canonical(value)))
            if phase:
                self.journal.db.execute("UPDATE operations SET phase=?,error='',updated=unixepoch() WHERE id=?", (phase,operation_id))

    def graph(self, lab, node):
        with self.journal.lock:
            rows = self.journal.db.execute("SELECT * FROM committed_links WHERE lab=? AND state!='deleted' ORDER BY link_id,endpoint", (lab,)).fetchall()
        selected = {(r['link_id'], json.loads(r['spec']).get('kind','vxlan')) for r in rows if r['node']==node}
        result=[]
        for link,kind in sorted(selected):
            group=[dict(r) for r in rows if r['link_id']==link and json.loads(r['spec']).get('kind','vxlan')==kind]
            if any(r['state']!='active' for r in group):raise Conflict('stop link requires recovery before shutdown')
            if kind=='bridge':
                spec=json.loads(group[0]['spec'])
                if len(group)!=2 or any(json.loads(r['spec'])!=spec for r in group):raise Conflict('stop bridge endpoint records disagree')
                edges=spec['endpoints']
            else:
                # One per-host VXLAN endpoint can share a logical link ID.
                edges=[{'node_id':r['node'],'host_interface':r['endpoint']} for r in group if r['node']==node]
            for edge_group in ([edges] if kind=='bridge' else [[e] for e in edges]):
                request={'schema_version':1,'request_id':'pending','lab_id':lab,'link_id':link,'action':'delete'}
                from .lab_closure import generation
                epoch=generation(self.journal,lab)
                if epoch!=1:request['lab_generation']=epoch
                qualified=[]
                for edge in edge_group:
                    owner=self.journal.node(lab,edge['node_id'])
                    if owner is None:raise Conflict('stop link node owner missing')
                    qualified.append({**edge,'expected_node_revision':owner['revision']})
                if kind=='bridge':request.update(kind='bridge',endpoints=qualified)
                else:request.update(qualified[0])
                result.append(request)
        return result

    def resource(self, request):
        edge=endpoints(request)[0]
        state=self.engine.links.state(request['lab_id'],request['link_id'],edge['host_interface'])
        if not state:raise Conflict('stop link record missing')
        bridge=request.get('kind')=='bridge'
        identity=(BridgeIdentity(request['lab_id'],request['link_id']) if bridge else
                  VxlanIdentity(request['lab_id'],request['link_id'],edge['host_interface'],state['spec']['vni']))
        manager=self.engine.links.bridge_manager if bridge else self.engine.links.manager
        row=manager.row(identity.digest)
        if row is None:raise Conflict('stop link proof missing')
        value=row['payload']
        keys=('config','creator','creator_mac','network_identity','bridge_index','tc_proofs') if bridge else ('config','creator','creator_mac','network_identity','tunnel_index','source','underlay_identity','tc_proofs')
        proof=fingerprint({key:value.get(key) for key in keys})
        return manager,identity,row,proof

    def idle(self, lab, nodes, *, parent=None):
        with self.journal.lock:
            for node in nodes:
                from .backend_reservations import available
                available(self.journal,lab,node,'docker')
                unreserved(self.journal,lab,node,parent=parent)
                rows=self.journal.db.execute('SELECT id,phase FROM operations WHERE lab=? AND node=?', (lab,node)).fetchall()
                if any(r['id']!=parent and r['phase'] not in DONE for r in rows):raise Conflict('stop footprint node operation pending or requires recovery')
            rows=self.journal.db.execute('SELECT id,payload,phase FROM link_operations WHERE lab=?', (lab,)).fetchall()
            for row in rows:
                if row['phase'] in DONE:continue
                child=self.journal.db.execute('SELECT parent_id FROM stop_link_children WHERE operation_id=?',(row['id'],)).fetchone()
                if child and child[0]==parent:continue
                if any(e['node_id'] in nodes for e in endpoints(json.loads(row['payload']))):raise Conflict('stop footprint link operation pending or requires recovery')

    def snapshot(self, request, *, parent=None):
        links=self.graph(request['lab_id'],request['node_id'])
        nodes=sorted({request['node_id']} | {e['node_id'] for r in links for e in endpoints(r)})
        self.idle(request['lab_id'],nodes,parent=parent)
        owners={}
        for node in nodes:
            current=self.journal.node(request['lab_id'],node)
            if current is None or current['state']!='running':raise Conflict('coordinated stop requires committed running owners')
            owner={'lab_id':request['lab_id'],'node_id':node}
            container=self.engine.backend.verify(owner,current['spec'])
            if not container:container=self.engine.backend.inspect(owner,current['spec'])
            if not container or not container['State']['Running']:raise Conflict('stop owner not running')
            owners[node]={'revision':current['revision'],'spec':fingerprint(current['spec']),'container_id':container['Id']}
        proofs=[]
        for link in links:
            self.engine.links.plan(link)
            manager,identity,row,proof=self.resource(link)
            if row['phase']!='active':raise Conflict('stop link primitive is not active')
            manager.verify(identity,row['payload'])
            manager.cleanup_preflight(identity,row['payload'])
            proofs.append(proof)
        return {'stage':'prepared','lab':request['lab_id'],'node':request['node_id'],
                'network_identity':self.engine.backend.linux.network_identity(),'owners':owners,'links':links,'proofs':proofs}

    def plan(self, request):
        value=self.snapshot(request)
        if value['owners'][request['node_id']]['revision']!=request['expected_revision']:raise Conflict('stop revision differs')
        return {'stop_fingerprint':fingerprint(value),'steps':['preflight','verify_process_exit','await_link_cleanup','await_finalization','commit'],
                'link_affected_nodes':sorted(value['owners']),
                'local_links':[{'link_id':r['link_id'],'kind':r.get('kind','vxlan'),'endpoints':endpoints(r)} for r in value['links']]}

    def prepare(self, operation_id, request):
        value=self.snapshot(request,parent=operation_id)
        if request.get('expected_stop_fingerprint') is not None and request['expected_stop_fingerprint']!=fingerprint(value):
            raise StopPlanChanged('coordinated stop footprint changed; prepare a new verified request')
        if value['owners'][request['node_id']]['revision']!=request['expected_revision']:raise Conflict('stop revision differs')
        for index,link in enumerate(value['links']):link['request_id']='stop-'+operation_id+'-'+str(index)
        with self.journal.transaction():
            self.idle(value['lab'],value['owners'],parent=operation_id)
            if self.graph(value['lab'],value['node']) != [{**r,'request_id':'pending'} for r in value['links']]:
                raise Conflict('stop link footprint changed before reservation')
            for node,owner in value['owners'].items():
                current=self.journal.node(value['lab'],node)
                if current['revision']!=owner['revision'] or fingerprint(current['spec'])!=owner['spec']:raise Conflict('stop owner changed before reservation')
                self.journal.db.execute('INSERT INTO stop_reservations VALUES(?,?,?)', (value['lab'],node,operation_id))
            self.journal.db.execute('INSERT INTO stop_sessions VALUES(?,?)', (operation_id,canonical(value)))
        return value

    def check(self, operation_id, value, *, before_exit=False):
        if self.engine.backend.linux.network_identity()!=value['network_identity']:raise Conflict('stop host boot or namespace changed')
        for node,owner in value['owners'].items():
            from .backend_reservations import available
            available(self.journal,value['lab'],node,'docker')
            current=self.journal.node(value['lab'],node)
            if not current or current['revision']!=owner['revision'] or fingerprint(current['spec'])!=owner['spec']:
                raise Conflict('stop owner revision or specification changed')
            with self.journal.lock:
                row=self.journal.db.execute('SELECT operation_id FROM stop_reservations WHERE lab=? AND node=?',(value['lab'],node)).fetchone()
            if not row or row[0]!=operation_id:raise Conflict('stop resource reservation changed')
            container=self.engine.backend.inspect({'lab_id':value['lab'],'node_id':node},current['spec'])
            if node==value['node'] and value['stage']=='finalizing' and container is None:continue
            if not container or container['Id']!=owner['container_id']:raise Conflict('stop container generation changed or disappeared')
            if node!=value['node'] and not container['State']['Running']:raise Conflict('other stop footprint workload is no longer running')
            if before_exit:self.engine.backend.verify({'lab_id':value['lab'],'node_id':node},current['spec'])
        for index,link in enumerate(value['links']):
            self.engine.links.plan(link)
            manager,identity,row,proof=self.resource(link)
            if proof!=value['proofs'][index]:raise Conflict('stop link proof generation changed')
            if before_exit:manager.verify(identity,row['payload'])
            if row['phase']!='cleaned':manager.cleanup_preflight(identity,row['payload'])

    def authorize_child(self, parent, request):
        value=self.session(parent)
        if not value or value['stage']!='cleanup_requested' or request not in value['links']:
            raise Conflict('link cleanup is not authorized by the stopped workload')
        self.check(parent,value)
        self.exited(value)
        return value

    def exited(self, value):
        current=self.journal.node(value['lab'],value['node'])
        container=self.engine.backend.inspect({'lab_id':value['lab'],'node_id':value['node']},current['spec'])
        if not container or container['Id']!=value['owners'][value['node']]['container_id'] or container['State']['Running']:
            raise Conflict('stop process exit is not verified')

    def request_stage(self, operation_id, lab, node, stage):
        if stage not in ('cleanup','finalize'):raise Conflict('invalid coordinated stop stage')
        with self.journal.transaction():
            operation=self.journal.get(operation_id,private=True);value=self.session(operation_id)
            if operation['lab']!=lab or operation['node']!=node or operation['payload'].get('stop_mode')!='coordinated':raise Conflict('coordinated stop context differs')
            if not value:raise Conflict('coordinated shutdown has not been verified')
            if value['stage']=='cancelled':raise Conflict('coordinated stop was cancelled before shutdown')
            required='exit_verified' if stage=='cleanup' else 'links_cleaned'
            target='cleanup_requested' if stage=='cleanup' else 'finalizing'
            if STAGES.index(value['stage'])>=STAGES.index(target):return self.journal.get(operation_id)
            if operation['phase']=='recovery_required' or value['stage']!=required:raise Conflict('coordinated stop stage requires verification or recovery')
            value['stage']=target
            self.journal.db.execute('UPDATE stop_sessions SET payload=? WHERE operation_id=?',(canonical(value),operation_id))
            self.journal.db.execute("UPDATE operations SET phase='queued',updated=unixepoch() WHERE id=?",(operation_id,))
        return self.journal.get(operation_id)

    def execute(self, operation_id):
        operation=self.journal.get(operation_id,private=True);request=operation['payload']
        try:
            value=self.session(operation_id)
            if value is None:
                if operation['cancel_requested']:
                    self.journal.phase(operation_id,'cancelled');return self.journal.get(operation_id)
                value=self.prepare(operation_id,request)
            self.check(operation_id,value,before_exit=value['stage']=='prepared')
            current=self.journal.node(value['lab'],value['node']);spec=current['spec']
            if value['stage']=='prepared':
                if self.journal.get(operation_id)['cancel_requested']:
                    value['stage']='cancelled'
                    with self.journal.transaction():
                        self.journal.db.execute('UPDATE stop_sessions SET payload=? WHERE operation_id=?',(canonical(value),operation_id))
                        self.journal.db.execute('DELETE FROM stop_reservations WHERE operation_id=?',(operation_id,))
                        self.journal.db.execute("UPDATE operations SET phase='cancelled' WHERE id=?",(operation_id,))
                    return self.journal.get(operation_id)
                value['stage']='shutdown_requested';self.save(operation_id,value,phase='applying')
            if value['stage']=='shutdown_requested':
                container=self.engine.backend.inspect(request,spec)
                if container and container['State']['Running']:self.check(operation_id,value,before_exit=True)
                from .management_authority import stop_allowed
                stop_allowed(self.journal,request,spec,container)
                self.engine.backend.stop(request,spec,force=request.get('force',False) or self.journal.get(operation_id)['recovery_force'])
                self.exited(value)
                value['stage']='exit_verified';self.save(operation_id,value,phase='awaiting_link_cleanup')
                return self.journal.get(operation_id)
            if value['stage']=='cleanup_requested':
                self.exited(value)
                for link in value['links']:
                    child=self.engine.links.submit(link,stop_parent=operation_id)
                    result=self.engine.links.execute(child['id'])
                    if result['phase']!='completed':raise Conflict('coordinated stop link cleanup requires recovery')
                self.engine.links.node_free(value['lab'],value['node'])
                value['stage']='links_cleaned';self.save(operation_id,value,phase='awaiting_finalization')
                return self.journal.get(operation_id)
            if value['stage']=='finalizing':
                self.engine.links.node_free(value['lab'],value['node'])
                container=self.engine.backend.inspect(request,spec)
                if container is not None:self.exited(value)
                self.engine.backend.delete_endpoints(request,spec)
                self.engine.backend.remove(request,spec)
                self.journal.finish(operation_id,spec,'stopped',stop_finished=True)
            elif value['stage'] in ('exit_verified','links_cleaned'):
                self.journal.phase(operation_id,'awaiting_link_cleanup' if value['stage']=='exit_verified' else 'awaiting_finalization')
        except StopPlanChanged as error:
            # No stop reservation or host mutation exists yet. Leave the
            # committed running workload and its resource ownership intact.
            self.journal.phase(operation_id,'failed',str(error))
        except Exception as error:
            self.journal.phase(operation_id,'recovery_required',self.engine._error(error))
        return self.journal.get(operation_id)
