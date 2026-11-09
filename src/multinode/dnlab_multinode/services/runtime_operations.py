"""Private coordinator intents/receipts. Placement remains a caller decision."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading


class RuntimeOperationError(RuntimeError):
    pass


FINAL={'completed','cancelled','failed'}


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def digest(value):return hashlib.sha256(encoded(value).encode()).hexdigest()


class OperationStore:
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(exist_ok=True,mode=0o700)
        info=self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise RuntimeOperationError('coordinator runtime directory ownership differs')
        parent_fd=os.open(self.directory.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
        path=self.directory/'operations.sqlite3'
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise RuntimeOperationError('coordinator runtime journal ownership differs')
        finally:os.close(fd)
        self.lock=threading.RLock();self.db=sqlite3.connect(path,isolation_level=None,check_same_thread=False);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS operations (
            lab TEXT NOT NULL,request_id TEXT NOT NULL,node TEXT NOT NULL,request TEXT NOT NULL,
            target TEXT NOT NULL,journal_id TEXT NOT NULL,fingerprint TEXT NOT NULL,
            phase TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,
            operation_id TEXT NOT NULL DEFAULT '',receipt TEXT NOT NULL DEFAULT '{}',error TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(lab,request_id))''')
        if 'stop_requested_stage' not in {row[1] for row in self.db.execute('PRAGMA table_info(operations)')}:
            self.db.execute("ALTER TABLE operations ADD COLUMN stop_requested_stage TEXT NOT NULL DEFAULT ''")
        self.db.execute('CREATE TABLE IF NOT EXISTS public_link_requests (lab TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,target TEXT NOT NULL,journal_id TEXT NOT NULL,phase TEXT NOT NULL,operation_id TEXT NOT NULL,PRIMARY KEY(lab,request_id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS public_requests (lab TEXT NOT NULL,request_id TEXT NOT NULL,node TEXT NOT NULL,action TEXT NOT NULL,force INTEGER NOT NULL,phase TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,request_id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS gate_scope_births (lab TEXT NOT NULL,gate_id TEXT NOT NULL,container_id TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,PRIMARY KEY(lab,gate_id,container_id))')
        if 'native_force_requested' not in {row[1] for row in self.db.execute('PRAGMA table_info(operations)')}:
            self.db.execute('ALTER TABLE operations ADD COLUMN native_force_requested INTEGER NOT NULL DEFAULT 0')
        self.db.execute('CREATE TABLE IF NOT EXISTS management_barriers (lab TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS management_barrier_history (lab TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,request_id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS lab_closures (lab TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS lab_closure_history (lab TEXT NOT NULL,generation INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,generation))')
        self.db.execute("CREATE TABLE IF NOT EXISTS initial_batches (lab TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,phase TEXT NOT NULL,cancel_requested INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',PRIMARY KEY(lab,request_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS initial_management_usage (lab TEXT NOT NULL,request_id TEXT NOT NULL,intent TEXT NOT NULL,fingerprint TEXT NOT NULL,progress TEXT NOT NULL,phase TEXT NOT NULL,PRIMARY KEY(lab,request_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS initial_retirements (lab TEXT NOT NULL,request_id TEXT NOT NULL,intent TEXT NOT NULL,fingerprint TEXT NOT NULL,progress TEXT NOT NULL,phase TEXT NOT NULL,PRIMARY KEY(lab,request_id))")
        self.sync_directory()

    def sync_directory(self):
        fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:yield;self.db.execute('COMMIT');self.sync_directory()
            except BaseException:
                if self.db.in_transaction:self.db.execute('ROLLBACK')
                raise

    def close(self):self.db.close()

    def contains(self,lab,key):
        with self.lock:return self.db.execute('SELECT 1 FROM operations WHERE lab=? AND request_id=?',(lab,key)).fetchone() is not None

    def pending(self):
        with self.lock:return [tuple(row) for row in self.db.execute("SELECT lab,request_id FROM operations WHERE phase NOT IN ('completed','cancelled','failed')")]

    def get(self,lab,key,*,private=False):
        with self.lock:row=self.db.execute('SELECT * FROM operations WHERE lab=? AND request_id=?',(lab,key)).fetchone()
        if row is None:raise RuntimeOperationError('coordinator runtime operation missing')
        value=dict(row);value['cancel_requested']=bool(value['cancel_requested']);value['receipt']=json.loads(value['receipt'])
        if private:
            value['request']=json.loads(value['request']);value['target']=json.loads(value['target'])
            if value['fingerprint']!=digest({'request':value['request'],'target':value['target'],'journal_id':value['journal_id']}):
                raise RuntimeOperationError('coordinator journal intent integrity differs')
        else:
            for field in ('request','target','fingerprint'):value.pop(field)
        return value

    def prepare(self,request,target,journal_id):
        with self.transaction():
            self._prepare_locked(request,target,journal_id)
        return self.get(request['lab_id'],request['request_id'])

    def gate_scope_birth(self,lab,gate_id,container_id):
        with self.lock:
            row=self.db.execute('SELECT payload,fingerprint FROM gate_scope_births WHERE lab=? AND gate_id=? AND container_id=?',
                                (lab,gate_id,container_id)).fetchone()
        if row is None:return None
        payload=json.loads(row['payload'])
        if (digest(payload)!=row['fingerprint'] or set(payload)!={'birth','rows'}
                or payload['birth']['context']['lab_id']!=lab or payload['birth']['context']['gate_id']!=gate_id
                or payload['birth']['container_id']!=container_id):
            raise RuntimeOperationError('original gate scope birth integrity differs')
        return payload

    def save_gate_scope_birth(self,lab,gate_id,container_id,payload):
        """Insert an immutable operation proof, never replace an earlier birth."""
        value=json.loads(encoded(payload))
        if (not isinstance(value,dict) or set(value)!={'birth','rows'} or not isinstance(value['rows'],list)
                or not isinstance(value['birth'],dict) or not isinstance(value['birth'].get('context'),dict)
                or value['birth']['context'].get('lab_id')!=lab or value['birth']['context'].get('gate_id')!=gate_id
                or value['birth'].get('container_id')!=container_id
                or not isinstance(container_id,str) or not re.fullmatch('[0-9a-f]{64}',container_id)):
            raise RuntimeOperationError('complete original gate scope birth required')
        with self.transaction():
            prior=self.gate_scope_birth(lab,gate_id,container_id)
            if prior is not None:
                if encoded(prior)!=encoded(value):raise RuntimeOperationError('original gate scope birth cannot change')
            else:
                self.db.execute('INSERT INTO gate_scope_births VALUES(?,?,?,?,?)',
                                (lab,gate_id,container_id,encoded(value),digest(value)))
        return self.gate_scope_birth(lab,gate_id,container_id)

    def _prepare_locked(self,request,target,journal_id):
        if not self.db.in_transaction:raise RuntimeOperationError('coordinator admission transaction required')
        request=json.loads(encoded(request));target=json.loads(encoded(target))
        if (not isinstance(target,dict) or set(target)!={'host','socket_path','container_name'}
                or not isinstance(target['host'],str) or not target['host']
                or not isinstance(target['socket_path'],str) or not target['socket_path'].startswith('/')
                or not isinstance(journal_id,str) or not re.fullmatch(r'[0-9a-f]{32}',journal_id)):
            raise RuntimeOperationError('invalid runtime operation target or journal identity')
        for key in ('lab_id','node_id','request_id'):
            if not isinstance(request.get(key),str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',request[key]):
                raise RuntimeOperationError('invalid runtime request context')
        lab,key,node=request['lab_id'],request['request_id'],request['node_id'];fingerprint=digest({'request':request,'target':target,'journal_id':journal_id})
        prior=self.db.execute('SELECT fingerprint FROM operations WHERE lab=? AND request_id=?',(lab,key)).fetchone()
        if prior:
            if prior[0]!=fingerprint:raise RuntimeOperationError('coordinator request identity differs')
        else:
            from .runtime_lab_closure import check
            check(self,request)
            busy=self.db.execute("SELECT 1 FROM operations WHERE lab=? AND node=? AND phase NOT IN ('completed','cancelled','failed')",(lab,node)).fetchone()
            if busy:raise RuntimeOperationError('node has an unfinished coordinator operation')
            self.db.execute('INSERT INTO operations(lab,request_id,node,request,target,journal_id,fingerprint,phase) VALUES(?,?,?,?,?,?,?,?)',
                (lab,key,node,encoded(request),encoded(target),journal_id,fingerprint,'prepared'))

    def request_native_force(self,lab,key):
        with self.transaction():
            value=self.get(lab,key,private=True);receipt=value['receipt']
            if (value['request'].get('action')!='stop' or receipt.get('phase')!='recovery_required'
                    or receipt.get('stop_stage')!='shutdown_requested' or receipt.get('shutdown_verified')):
                raise RuntimeOperationError('explicit force requires the original unverified shutdown')
            self.db.execute('UPDATE operations SET native_force_requested=1 WHERE lab=? AND request_id=?',(lab,key))

    def request_cancel(self,lab,key):
        with self.transaction():
            self.get(lab,key)
            self.db.execute('UPDATE operations SET cancel_requested=1 WHERE lab=? AND request_id=?',(lab,key))
        return self.get(lab,key)

    def request_stop_stage(self,lab,key,stage):
        with self.transaction():
            current=self.get(lab,key,private=True)
            if (stage not in ('cleanup','finalize') or current['request'].get('stop_mode')!='coordinated'
                    or current['request']['action']!='stop' or not current['operation_id']):
                raise RuntimeOperationError('coordinated stop receipt required')
            observed=current['receipt'].get('stop_stage')
            allowed={'exit_verified','cleanup_requested','links_cleaned','finalizing','finished'} if stage=='cleanup' else {'links_cleaned','finalizing','finished'}
            if observed not in allowed:raise RuntimeOperationError('coordinated stop stage is not verified')
            if current['stop_requested_stage']=='finalize' and stage=='cleanup':return self.get(lab,key)
            self.db.execute('UPDATE operations SET stop_requested_stage=? WHERE lab=? AND request_id=?',(stage,lab,key))
        return self.get(lab,key)

    @contextmanager
    def executing(self,lab,key):
        path=self.directory/('op-'+digest({'lab':lab,'key':key})+'.lock')
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise RuntimeOperationError('coordinator operation lock ownership differs')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise RuntimeOperationError('coordinator operation already executing') from None
            yield
        finally:os.close(fd)

    def observe(self,lab,key,receipt):
        with self.transaction():
            current=self.get(lab,key,private=True)
            if (not isinstance(receipt,dict) or not isinstance(receipt.get('id'),str) or not re.fullmatch(r'[0-9a-f]{32}',receipt['id'])
                    or any(receipt.get(field)!=current[other] for field,other in (('lab','lab'),('node','node'),('request_id','request_id')))
                    or current['operation_id'] and current['operation_id']!=receipt['id']):
                raise RuntimeOperationError('runtime operation receipt identity differs')
            if receipt.get('phase') not in FINAL|{'queued','validating','applying','verifying','cancelling','compensating','recovery_required','awaiting_link_cleanup','awaiting_finalization'}:
                raise RuntimeOperationError('runtime operation receipt phase differs')
            receipt={field:receipt[field] for field in ('id','lab','node','request_id','phase','cancel_requested','recovery_force','error','created','updated','stop_stage','shutdown_verified') if field in receipt}
            self.db.execute('UPDATE operations SET operation_id=?,receipt=?,phase=?,error=? WHERE lab=? AND request_id=?',
                (receipt['id'],encoded(receipt),receipt['phase'],receipt.get('error',''),lab,key))
        return self.get(lab,key)


class OperationDriver:
    def __init__(self,store,client_factory):self.store=store;self.client_factory=client_factory

    def prepare(self,request,target):
        value=self.preflight(request,target)
        return self.store.prepare(value['request'],value['target'],value['journal_id'])

    def preflight(self,request,target):
        plan=None
        client=self.client_factory(target)
        caps=client.qualify_node(kind=request.get('spec',{}).get('kind','linux'),request_controls=True,coordinated_stop=request.get('stop_mode')=='coordinated',management_identity=bool(request.get('spec',{}).get('management')),data_endpoints=bool(request.get('spec',{}).get('endpoints')),resource_preflight=request.get('action')=='start')
        client=client.bound_to(caps.get('journal_id'))
        if self.store.contains(request['lab_id'],request['request_id']):
            original=self.store.get(request['lab_id'],request['request_id'],private=True)['request']
            if (encoded({k:v for k,v in original.items() if k!='management_preflight'})!=encoded({k:v for k,v in request.items() if k!='management_preflight'})
                    or 'management_preflight' in request and encoded(request['management_preflight'])!=encoded(original.get('management_preflight'))):
                raise RuntimeOperationError('coordinator request identity differs')
            request=original
        else:
            plan=client.plan_node(request)
            if (plan.get('mutations_performed') is not False or plan.get('affected_nodes')!=[request['node_id']]
                    or plan.get('expected_revision')!=request['expected_revision']):
                raise RuntimeOperationError('runtime plan does not match coordinator request')
            proof=plan.get('management_preflight')
            if proof is not None or request.get('spec',{}).get('management'):
                if (caps.get('management_preflight')!='read-only management proof; request-bound apply and recovery before allocation'
                        or not isinstance(proof,dict) or set(proof)!={'journal_id','request_fingerprint','management','network'}
                        or proof['journal_id']!=caps.get('journal_id')
                        or proof['request_fingerprint']!=digest({k:v for k,v in request.items() if k!='management_preflight'})
                        or not isinstance(proof['network'],dict) or not isinstance(proof['management'],dict)
                        or 'management_preflight' in request and encoded(request['management_preflight'])!=encoded(proof)):
                    raise RuntimeOperationError('runtime management preflight does not match original request')
                request={**request,'management_preflight':proof}
        return {'request':json.loads(encoded(request)),'target':json.loads(encoded(target)),'journal_id':caps.get('journal_id'),'node_preflight':plan.get('node_preflight') if plan else None}

    def advance(self,lab,key):
        with self.store.executing(lab,key):
            current=self.store.get(lab,key,private=True)
            if current['phase'] in FINAL:return self.store.get(lab,key)
            from .runtime_lab_closure import check
            check(self.store,current['request'])
            # Re-establish directory durability after any earlier post-commit
            # sync failure before acting on a saved intent.
            self.store.sync_directory()
            client=self.client_factory(current['target']).bound_to(current['journal_id'])
            try:
                caps=client.qualify_node(request_controls=True,management_identity=bool(current['request'].get('spec',{}).get('management')),data_endpoints=bool(current['request'].get('spec',{}).get('endpoints')),resource_preflight=current['request'].get('action')=='start')
                if caps.get('journal_id')!=current['journal_id']:raise RuntimeOperationError('runtime journal identity changed')
                if current['native_force_requested'] and not current['receipt'].get('shutdown_verified'):
                    receipt=client.node_operation(current['operation_id'])
                    if receipt['phase']=='recovery_required':receipt=client.node_operation(current['operation_id'],action='reconcile',force=True)
                elif current['stop_requested_stage']:
                    receipt=client.node_stop_stage(current['operation_id'],lab,current['node'],current['stop_requested_stage'])
                elif current['cancel_requested']:receipt=client.cancel_node_request(current['request'])
                elif current['operation_id']:receipt=client.node_operation(current['operation_id'])
                else:
                    receipt=client.find_node_request(current['request'],verify_content=True)
                    if receipt is None:
                        with self.store.transaction():
                            self.store.db.execute("UPDATE operations SET phase='submit_unknown' WHERE lab=? AND request_id=?",(lab,key))
                        # Cancellation may be persisted by another process during lookup.
                        if self.store.get(lab,key)['cancel_requested']:receipt=client.cancel_node_request(current['request'])
                        else:receipt=client.submit_node(current['request'])
                observed=self.store.observe(lab,key,receipt)
                if observed['cancel_requested'] and observed['phase'] not in FINAL:
                    observed=self.store.observe(lab,key,client.cancel_node_request(current['request']))
                return observed
            except Exception as error:
                with self.store.transaction():
                    self.store.db.execute('UPDATE operations SET error=? WHERE lab=? AND request_id=?',
                        ('runtime observation incomplete ('+type(error).__name__+')',lab,key))
                raise
