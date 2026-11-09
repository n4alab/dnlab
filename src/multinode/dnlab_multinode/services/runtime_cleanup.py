"""Conservative VD cleanup delegation; topology/placement remain with multinode."""
import re
from contextlib import contextmanager
from pathlib import Path

from dnlab_multinode.controllers.runtime_node import RuntimeNodeController
from .custom_runtime import RuntimeClient
from .paths import PATHS
from .runtime_operations import OperationStore,RuntimeOperationError,digest


class CleanupBlocked(RuntimeOperationError):pass


def operation_directory(state_directory):
    # This ledger is private state adjacent to the existing topology state,
    # not a configurable host installation path or an arbitrary path from JSON.
    if PATHS.runtime_operations_dir:
        path=Path(PATHS.runtime_operations_dir)
        if not path.is_absolute():raise CleanupBlocked('runtime intent path must be absolute')
        return path
    return Path(state_directory)/'.runtime-operations'


def management_cleanup_check(store,lab):
    """An empty VD ledger never concludes an original management operation."""
    from . import management_barrier as barrier
    value=barrier.get(store,lab)
    if value is None:return None
    barrier.validate(lab,value['request_id'],value['plan'],value['targets'],value['generation'])
    if not re.fullmatch('[0-9a-f]{32}',value.get('barrier_id','')):
        raise CleanupBlocked('management cleanup requires original barrier identity')
    if value.get('phase') not in ('released','cancelled'):
        raise CleanupBlocked('management operation active; original intent recovery required before cleanup')
    terminal='released' if value['phase']=='released' else 'cancelled'
    receipts=value.get(terminal,{})
    if set(receipts)!=set(value['targets']):
        raise CleanupBlocked('management terminal receipts incomplete; state retained')
    for host,entry in value['targets'].items():
        receipt=receipts[host]
        expected={'lab_id':lab,'journal_id':entry['journal_id'],'barrier_id':value['barrier_id'],
            'generation':value['generation'],'plan_fingerprint':value['plan_fingerprint'],'phase':terminal,
            'workload_fingerprint':value['preflights'][host]['workload_fingerprint']}
        if terminal=='released':
            evidence=value.get('readiness')
            if (not isinstance(evidence,dict) or evidence.get('plan_fingerprint')!=value['plan_fingerprint']
                    or set(evidence.get('hosts',{}))!=set(value['targets'])
                    or value.get('readiness_fingerprint')!=digest(evidence)):
                raise CleanupBlocked('management readiness evidence incomplete; state retained')
            expected['readiness_fingerprint']=value['readiness_fingerprint']
        if not isinstance(receipt,dict) or any(receipt.get(k)!=v for k,v in expected.items()):
            raise CleanupBlocked('management terminal receipt identity differs; state retained')
    if value.get('services') and value['services'].get('phase') not in ('materialized','ready'):
        raise CleanupBlocked('management service recovery pending; state retained')
    return value


@contextmanager
def management_cleanup_guard(lab,state,state_directory):
    """Exclude provisioning for the complete daemon mutation/finalization span.

    No barrier cancellation, release or remote recovery is inferred here. The
    existing coordinator must first conclude its original operation explicitly.
    """
    if state_directory is None:
        if state and state.runtime_mode=='custom':
            raise CleanupBlocked('management cleanup requires original intent directory')
        yield;return
    path=operation_directory(state_directory)
    if not (path/'operations.sqlite3').is_file():
        if state and state.runtime_mode=='custom':
            raise CleanupBlocked('management cleanup private intent ledger missing')
        yield;return
    store=OperationStore(path)
    try:
        with store.executing(lab,'management-barrier'):
            management_cleanup_check(store,lab)
            store.sync_directory()
            yield
    except RuntimeOperationError as error:
        if isinstance(error,CleanupBlocked):raise
        raise CleanupBlocked('management cleanup guard refused: '+str(error)) from error
    finally:store.close()


def make_binding(store,lab,node,birth_request_id,view,*,stop_request_id=''):
    original=store.get(lab,birth_request_id,private=True)
    birth=view.get('workload') or {}
    if (original['node']!=node or original['request']['action']!='start'
            or original['phase']!='completed' or view.get('lab_id')!=lab or view.get('node_id')!=node
            or view.get('journal_id')!=original['journal_id'] or view.get('committed_state')!='running'
            or view.get('container_state')!='running' or view.get('operation') is not None
            or birth.get('creator_operation_id')!=original['operation_id']
            or birth.get('spec_fingerprint')!=digest(original['request']['spec'])
            or birth.get('container_id')!=view.get('container_id') or birth.get('phase')!='running'):
        raise CleanupBlocked('cannot bind cleanup to an unqualified committed workload')
    return {'backend':'custom','journal_id':original['journal_id'],'birth_request_id':birth_request_id,
            'stop_request_id':stop_request_id,'container_id':birth['container_id'],
            'generation':birth['generation'],'spec_fingerprint':birth['spec_fingerprint'],'revision':view['revision']}


class Delegate:
    def __init__(self,state,clients,state_directory):
        self.state,self.clients=state,clients
        path=operation_directory(state_directory)
        if not (path/'operations.sqlite3').is_file():raise CleanupBlocked('private runtime intent ledger missing')
        self.store=OperationStore(path);self.entries={}

    def close(self):self.store.close()

    def preflight(self,artifacts):
        state=self.state
        bindings={name:r for name,r in {**state.retired_native_nodes,**state.node_runtime}.items() if r.runtime_binding}
        if not bindings and self.store.db.execute('SELECT 1 FROM operations WHERE lab=?',(state.lab_name,)).fetchone():
            raise CleanupBlocked('runtime intents exist without qualified VD bindings')
        for node,runtime in bindings.items():
            b=runtime.runtime_binding
            if (not isinstance(b,dict) or set(b)!={'backend','journal_id','birth_request_id','stop_request_id','container_id','generation','spec_fingerprint','revision'}
                    or b['backend']!='custom' or runtime.host not in self.clients
                    or type(b['generation']) is not int or b['generation']<1
                    or type(b['revision']) is not int or b['revision']<1
                    or not isinstance(b['container_id'],str) or not re.fullmatch(r'[0-9a-f]{64}',b['container_id'])):
                raise CleanupBlocked('invalid or unavailable VD runtime binding')
            original=self.store.get(state.lab_name,b['birth_request_id'],private=True)
            if (original['node']!=node or original['request']['action']!='start' or original['phase']!='completed'
                    or original['target']['host']!=runtime.host or original['journal_id']!=b['journal_id']
                    or original['request']['spec']['container_name']!=runtime.container
                    or digest(original['request']['spec'])!=b['spec_fingerprint']):
                raise CleanupBlocked('VD birth intent or target differs from binding')
            client=RuntimeClient(self.clients[runtime.host],socket_path=original['target']['socket_path'],
                                 container_name=original['target']['container_name'],require_management_identity=bool(original['request']['spec'].get('management'))).bound_to(b['journal_id'])
            client.qualify_node(cleanup=True,inspection=True,coordinated_stop=True,request_controls=True)
            view=client.inspect_node(state.lab_name,node);birth=view.get('workload') or {}
            if (birth.get('container_id')!=b['container_id'] or birth.get('generation')!=b['generation']
                    or birth.get('creator_operation_id')!=original['operation_id']
                    or birth.get('spec_fingerprint')!=b['spec_fingerprint']):
                from .native_public import inspect_owned
                verified,attempt=inspect_owned(self.store,state,node,client)
                if verified!=view or not attempt.get('qualified_abort_receipt'):
                    raise CleanupBlocked('VD workload generation differs from binding')
            else:attempt=None
            if view['container_id'] is not None:
                records=[a for a in artifacts if a.kind=='container' and a.host==runtime.host
                         and a.name==runtime.container and a.metadata.get('container_id')==b['container_id']]
                if len(records)!=1 or records[0].metadata.get('runtime_owner',{}).get('node')!=node:
                    raise CleanupBlocked('live VD inventory lacks its exact runtime identity')
            entry={'runtime':runtime,'binding':b,'client':client,'view':view,'done':False,'ready':False,'target':original['target'],'aborted_attempt':attempt}
            key=b['stop_request_id']
            if key:
                stop=self.store.get(state.lab_name,key,private=True);request=stop['request']
                if (stop['node']!=node or request.get('action')!='stop' or request.get('stop_mode')!='coordinated'
                        or request.get('expected_revision')!=b['revision'] or stop['target']!=original['target']
                        or stop['journal_id']!=b['journal_id']):raise CleanupBlocked('cleanup stop intent differs from binding')
                remote=client.find_node_request(request,verify_content=True)
                if remote and stop['operation_id'] and remote['id']!=stop['operation_id']:
                    raise CleanupBlocked('cleanup operation generation changed')
                if remote and remote['phase']=='completed':
                    entry['done']=(view['revision']==b['revision']+1 and view['committed_state']=='stopped'
                                   and view['container_state']=='absent' and birth['phase']=='cleaned'
                                   and view['operation'] is None and remote.get('stop_stage')=='finished'
                                   and remote.get('shutdown_verified') is True)
                    if not entry['done']:raise CleanupBlocked('completed cleanup is not verified absent')
                elif remote:
                    if remote['phase'] in ('failed','cancelled','recovery_required'):
                        raise CleanupBlocked('VD cleanup requires explicit recovery')
                    operation=view['operation'] or {}
                    entry['ready']=(remote['phase'] in ('awaiting_link_cleanup','awaiting_finalization')
                        and operation.get('id')==remote['id'] and operation.get('cleanup_scope')=='local'
                        and operation.get('shutdown_verified') is True and view['container_state']=='stopped')
                    if entry['ready']:
                        owners=operation.get('footprint_nodes')
                        if (not isinstance(owners,list) or node not in owners or len(set(owners))!=len(owners)
                                or any(n not in bindings or bindings[n].host!=runtime.host for n in owners)):
                            raise CleanupBlocked('cleanup footprint includes an unqualified VD or host')
                entry['key']=key;entry['receipt']=remote;entry['stop_request']=request
            elif view['revision']!=b['revision'] or view['committed_state']!='running' or view.get('operation') is not None:
                raise CleanupBlocked('VD revision changed without its cleanup intent')
            self.entries[node]=entry
        for entry in self.entries.values():
            inventory=entry['view'].get('cleanup_inventory')
            if (not isinstance(inventory,dict) or set(inventory)!={'nodes','blocked'}
                    or not isinstance(inventory['nodes'],list) or not isinstance(inventory['blocked'],list)
                    or any(node not in bindings for node in inventory['nodes'])):
                raise CleanupBlocked('runtime lab contains an unqualified workload or inventory')
        for lab,key in self.store.pending():
            if lab!=state.lab_name:continue
            original=self.store.get(lab,key,private=True)
            entry=self.entries.get(original['node'])
            if entry and entry.get('aborted_attempt') and key==entry['aborted_attempt']['request_id']:continue
            if not entry or key!=entry['binding']['stop_request_id']:
                raise CleanupBlocked('another runtime intent still requires recovery')
        return self

    def fence(self):
        from . import runtime_lab_closure as closure
        if not self.entries:return
        if any(not e['binding']['stop_request_id'] for e in self.entries.values()):
            raise CleanupBlocked('complete teardown intents required before closing lab')
        lab=self.state.lab_name
        from .native_public import observe_abort
        for entry in self.entries.values():
            if entry.get('aborted_attempt'):observe_abort(self.store,lab,entry['aborted_attempt'])
        self.closure=closure.begin(self.store,lab,[e['key'] for e in self.entries.values()])
        self.targets={}
        for entry in self.entries.values():
            key=digest({'target':entry['target'],'journal_id':entry['binding']['journal_id']})
            group=self.targets.setdefault(key,{'entry':entry,'stops':[]})
            group['stops'].append(entry['stop_request'])
        for key,group in self.targets.items():
            entry=group['entry']
            remote=entry['client'].lab_closure(lab,'close',{'closure_id':self.closure['closure_id'],
                'generation':self.closure['generation'],'stops':sorted(group['stops'],key=lambda r:r['node_id'])})
            closure.receipt(self.store,lab,self.closure['closure_id'],entry['target'],entry['binding']['journal_id'],remote)

    def seal(self):
        from . import runtime_lab_closure as closure
        if not self.verified():raise CleanupBlocked('lab closure cleanup not verified')
        lab=self.state.lab_name
        for entry in self.entries.values():self.store.observe(lab,entry['key'],entry['receipt'])
        for key,group in self.targets.items():
            entry=group['entry']
            remote=entry['client'].lab_closure(lab,'finish',{'closure_id':self.closure['closure_id'],'generation':self.closure['generation']})
            closure.receipt(self.store,lab,self.closure['closure_id'],entry['target'],entry['binding']['journal_id'],remote)
        closure.finish(self.store,lab,self.closure['closure_id'],self.targets)

    def advance(self):
        # All entries have been checked before the first remote stage request.
        for entry in self.entries.values():
            if entry['done']:
                self.store.observe(self.state.lab_name,entry['key'],entry['receipt'])
            if entry['ready']:
                RuntimeNodeController(self.store,lambda target,e=entry:e['client']).advance_local_stop(
                    self.state.lab_name,entry['key'],participating_hosts=[entry['runtime'].host])
        return self.verified()

    def verified(self):
        if not self.entries or not all(e['done'] for e in self.entries.values()):return False
        for entry in self.entries.values():
            inventory=entry['view'].get('cleanup_inventory')
            if (not isinstance(inventory,dict) or set(inventory)!={'nodes','blocked'}
                    or inventory['blocked']!=[] or not isinstance(inventory['nodes'],list)
                    or any(node not in self.entries for node in inventory['nodes'])):
                raise CleanupBlocked('runtime journal contains unresolved or unqualified lab resources')
        return True
