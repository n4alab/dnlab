"""Local data-only RealNet attachment worker; shares the custom link ledger/lock.

Proofs must originate from provisioning. This worker never adopts by name.
Interrupted operations retain their endpoint reservation until explicit recovery.
"""
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import shutil
import tempfile
import uuid
import stat
import subprocess
import sys


class AttachmentError(RuntimeError):
    pass


def signature(value):
    return {key:value.get(key) for key in ('ifname','ifindex','ifalias','address','link_index')}


def execute(argv,*,pass_fds=()):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=30,pass_fds=pass_fds)
    if result.returncode:raise AttachmentError('RealNet attachment command failed: '+argv[0])
    return result.stdout


def context():
    info=os.stat('/proc/self/ns/net')
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'device':info.st_dev,'inode':info.st_ino}


def validate(proof):
    if not isinstance(proof,dict) or set(proof)!={'lab','node','realnet','host','link','context','source','peer','namespace','container','bridge','management_interface'}:
        raise AttachmentError('complete provisioned data attachment proof required')
    for key in ('lab','node','realnet','host','link'):
        if not isinstance(proof[key],str) or not proof[key] or '\x00' in proof[key]:raise AttachmentError('invalid attachment identity')
    for key in ('source','peer','bridge'):
        value=proof[key]
        if (not isinstance(value,dict) or set(value)!=set(signature({}))
                or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',value.get('ifname') or '')
                or type(value.get('ifindex')) is not int or value['ifindex']<=0
                or not re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}',value.get('address') or '')):
            raise AttachmentError('invalid kernel endpoint proof')
    if not re.fullmatch('eth[1-9][0-9]*',proof['peer']['ifname']):raise AttachmentError('RealNet requires a data port')
    if (not isinstance(proof['management_interface'],str) or not proof['management_interface']
            or proof['peer']['ifname']==proof['management_interface']):raise AttachmentError('reserved management port cannot attach to RealNet')
    if not (proof['source']['ifalias'] or '').startswith('dnlab-runtime:'):raise AttachmentError('unqualified data endpoint')
    scope=hashlib.sha256(json.dumps(['realnet-cleanup-v1',proof['lab'],proof['realnet'],proof['host']],separators=(',',':')).encode()).hexdigest()
    if not re.fullmatch('dnlab-runtime:realnet:'+scope+':[0-9a-f]{32}',proof['bridge']['ifalias'] or ''):
        raise AttachmentError('unqualified RealNet bridge')
    container=proof['container']
    if (not isinstance(container,dict) or set(container)!={'id','name','image','labels','started_at'}
            or not re.fullmatch('[0-9a-f]{64}',container.get('id') or '')
            or not re.fullmatch('sha256:[0-9a-f]{64}',container.get('image') or '')
            or not isinstance(container['labels'],dict) or not container['started_at']):
        raise AttachmentError('complete immutable VD identity required')
    if set(proof['namespace'])!={'device','inode'} or set(proof['context'])!={'boot_id','device','inode'}:
        raise AttachmentError('namespace identity required')
    if (proof['source']['link_index']!=proof['peer']['ifindex'] or proof['peer']['link_index']!=proof['source']['ifindex']):
        raise AttachmentError('data veth peer proof differs')


class Worker:
    def __init__(self,proof,*,directory='/var/lib/dnlab-runtime',run=execute,host_context=context,open_ns=None):
        validate(proof)
        self.proof,self.directory,self.run,self.host_context=proof,Path(directory),run,host_context
        self.open_ns=open_ns or (lambda pid:os.open(f'/proc/{pid}/ns/net',os.O_RDONLY))
        self.key=hashlib.sha256(json.dumps(['realnet-data-v1',proof['lab'],proof['link'],proof['host']],separators=(',',':')).encode()).hexdigest()

    def preflight(self,fd):
        p=self.proof
        if self.host_context()!=p['context']:raise AttachmentError('host boot or namespace changed')
        c=p['container'];values=json.loads(self.run(['docker','inspect',c['id']]))
        if not isinstance(values,list) or len(values)!=1:raise AttachmentError('VD inspection differs')
        v=values[0];state=v.get('State',{})
        if (v.get('Id')!=c['id'] or v.get('Name')!='/'+c['name'] or v.get('Image')!=c['image']
                or (v.get('Config',{}).get('Labels') or {})!=c['labels'] or state.get('StartedAt')!=c['started_at']
                or state.get('Running') is not True or type(state.get('Pid')) is not int or state['Pid']<=0):
            raise AttachmentError('VD identity or lifecycle changed')
        current=self.open_ns(state['Pid'])
        try:
            expected=p['namespace'];a=os.fstat(fd);b=os.fstat(current)
            if {'device':a.st_dev,'inode':a.st_ino}!=expected or (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino):
                raise AttachmentError('VD namespace replaced')
        finally:os.close(current)
        links=json.loads(self.run(['ip','-j','-d','link','show']))
        def find(values,expected,kind):
            found=[x for x in values if x.get('ifname')==expected['ifname']]
            if len(found)!=1 or signature(found[0])!=expected or found[0].get('linkinfo',{}).get('info_kind')!=kind:
                raise AttachmentError('kernel data/bridge identity changed: '+expected['ifname'])
            return found[0]
        source=find(links,p['source'],'veth');bridge=find(links,p['bridge'],'bridge')
        peers=json.loads(self.run(['nsenter','--net=/proc/self/fd/'+str(fd),'ip','-j','-d','link','show'],pass_fds=(fd,)))
        find(peers,p['peer'],'veth')
        if source.get('master') not in (None,bridge['ifname'],bridge['ifindex']):
            raise AttachmentError('data endpoint belongs to another bridge')
        return source

    @staticmethod
    def attempt_id(payload):
        return payload.get('attempt') or 'legacy-'+hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    @staticmethod
    def proof_hash(proof,warm):
        return hashlib.sha256(json.dumps([proof,warm],sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def archive(self,db,payload,phase):
        db.execute('INSERT INTO realnet_attachment_attempts VALUES(?,?,?,?,?) ON CONFLICT(attempt) DO UPDATE SET payload=excluded.payload,phase=excluded.phase',
                   (self.attempt_id(payload),self.key,json.dumps(payload,sort_keys=True,separators=(',',':')),phase,self.proof_hash(payload['proof'],payload['warm'])))

    def save(self,db,payload,phase,*,previous=None):
        with db:
            if previous is not None:self.archive(db,previous,'cleaned')
            self.archive(db,payload,phase)
            db.execute('INSERT INTO realnet_attachments VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,phase=excluded.phase',
                       (self.key,json.dumps(payload,sort_keys=True,separators=(',',':')),phase))

    def available(self,db):
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('local_vxlans','local_bridges','realnet_attachments'):
            if table not in tables:continue
            for key,raw in db.execute(f"SELECT id,payload FROM {table} WHERE phase != 'cleaned'"):
                if table=='realnet_attachments' and key==self.key:continue
                try:
                    p=json.loads(raw)
                    sources=p['config']['sources'] if table=='local_bridges' else [p['source']]
                    names={s['ifname'] for s in sources}
                    if not names or any(not isinstance(n,str) or not n for n in names):raise ValueError()
                except (ValueError,KeyError,TypeError):raise AttachmentError('unverifiable endpoint reservation') from None
                if self.proof['source']['ifname'] in names:raise AttachmentError('data endpoint already reserved')

    def operate(self,action,*,warm=False,set_carriers=True,expected_attempt=None):
        if type(set_carriers) is not bool:raise AttachmentError('invalid carrier control')
        if type(warm) is not bool:raise AttachmentError('invalid carrier mode')
        if action not in ('create','delete','recover'):raise AttachmentError('unsupported data attachment action')
        d=self.directory
        if d.resolve()!=d.absolute():raise AttachmentError('journal path is a symlink')
        d.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=d.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise AttachmentError('journal directory ownership differs')
        lock=os.open(d/'vxlan.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        db=None;fd=None
        try:
            info=os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise AttachmentError('shared resource lock ownership differs')
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise AttachmentError('local link worker busy') from None
            path=d/'journal.sqlite3'
            if os.path.lexists(path) and (path.is_symlink() or path.stat().st_uid!=os.getuid() or stat.S_IMODE(path.stat().st_mode)!=0o600):
                raise AttachmentError('shared journal ownership differs')
            db=sqlite3.connect(path);os.chmod(path,0o600)
            db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS realnet_attachments(id TEXT PRIMARY KEY,payload TEXT NOT NULL,phase TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS realnet_attachment_attempts(attempt TEXT PRIMARY KEY,logical_id TEXT NOT NULL,payload TEXT NOT NULL,phase TEXT NOT NULL,proof_hash TEXT NOT NULL)');db.commit()
            row=db.execute('SELECT payload,phase FROM realnet_attachments WHERE id=?',(self.key,)).fetchone()
            prior=json.loads(row[0]) if row else None
            expected=expected_attempt if expected_attempt is not None else getattr(self,'attempt',None)
            if row and expected!=self.attempt_id(prior):raise AttachmentError('stale or missing attachment attempt')
            if not row and expected is not None:raise AttachmentError('attachment attempt is missing')
            changed=bool(prior and (prior['proof']!=self.proof or prior['warm']!=warm))
            if changed and (action!='create' or row[1]!='cleaned'):
                raise AttachmentError('attachment generation or carrier mode differs')
            if action=='create' and prior and row[1]=='cleaned':
                if prior.get('cleanup_verified') is not True and prior.get('step') not in ('detach','restore_down'):
                    raise AttachmentError('previous attachment cleanup is not verified')
                if changed and db.execute('SELECT 1 FROM realnet_attachment_attempts WHERE logical_id=? AND proof_hash=?',
                                          (self.key,self.proof_hash(self.proof,warm))).fetchone():
                    raise AttachmentError('obsolete attachment generation')
            # Pin the namespace before inspection and all carrier/bridge mutations.
            values=json.loads(self.run(['docker','inspect',self.proof['container']['id']]))
            fd=self.open_ns(values[0]['State']['Pid'])
            source=self.preflight(fd);self.available(db)
            if action=='create':
                if row and row[1]=='active':
                    if source.get('master') not in (self.proof['bridge']['ifname'],self.proof['bridge']['ifindex']):raise AttachmentError('active attachment missing')
                    self.attempt=self.attempt_id(prior)
                    return {'phase':'active','key':self.key,'attempt':self.attempt_id(prior)}
                if row and row[1]!='cleaned':raise AttachmentError('explicit attachment recovery required')
                if source.get('master') is not None:raise AttachmentError('refusing adoption of existing attachment')
                payload={'attempt':uuid.uuid4().hex,'cleanup_verified':False,'proof':self.proof,'source':self.proof['source'],'warm':warm,'was_up':'UP' in source.get('flags',[]),'step':'reserved'}
                phase='applying'
            else:
                if not row:raise AttachmentError('attachment journal missing; refusing detach')
                if row[1]=='cleaned':
                    if source.get('master') is not None:raise AttachmentError('cleaned endpoint unexpectedly attached')
                    self.attempt=self.attempt_id(prior)
                    return {'phase':'cleaned','key':self.key,'attempt':self.attempt_id(prior)}
                payload=prior;payload.setdefault('attempt',self.attempt_id(prior));phase='cleanup_pending'
            self.save(db,payload,phase,previous=prior if action=='create' else None)
            self.attempt=self.attempt_id(payload)
            def step(name,argv):
                self.preflight(fd);payload['step']=name;self.save(db,payload,phase)
                self.run(argv);self.preflight(fd)
            port=self.proof['source']['ifname'];bridge=self.proof['bridge']['ifname']
            try:
                if action=='create':
                    step('up',['ip','link','set',port,'up'])
                    step('bind',['ip','link','set',port,'master',bridge])
                    if warm:step('carrier_up',['docker','exec',self.proof['container']['id'],'dnlab-linkctl',self.proof['peer']['ifname'],'up'])
                    if self.preflight(fd).get('master') not in (bridge,self.proof['bridge']['ifindex']):raise AttachmentError('data attachment not confirmed')
                    self.save(db,payload,'active');return {'phase':'active','key':self.key,'attempt':self.attempt_id(payload)}
                if warm and set_carriers:step('carrier_down',['docker','exec',self.proof['container']['id'],'dnlab-linkctl',self.proof['peer']['ifname'],'down'])
                step('detach',['ip','link','set',port,'nomaster'])
                if not payload['was_up']:step('restore_down',['ip','link','set',port,'down'])
                if self.preflight(fd).get('master') is not None:raise AttachmentError('data detach not confirmed')
                payload['cleanup_verified']=True
                self.save(db,payload,'cleaned');return {'phase':'cleaned','key':self.key,'attempt':self.attempt_id(payload)}
            except Exception:
                self.save(db,payload,'recovery_required');raise
        finally:
            if fd is not None:os.close(fd)
            if db is not None:db.close()
            os.close(lock)


def main():
    if os.getuid()!=0:raise AttachmentError('root worker required')
    request=json.loads(sys.argv[1])
    print(json.dumps(Worker(request['proof']).operate(request['action'],warm=request['warm'],set_carriers=request.get('set_carriers',True),expected_attempt=request.get('expected_attempt'))))


if __name__=='__main__':main()


class InfrastructureAttachments:
    """Read existing root intents; VD veths never enter destructive inventory."""
    def __init__(self,plan,*,directory='/var/lib/dnlab-runtime',run=execute,host_context=context):
        self.plan,self.directory,self.run,self.host_context=plan,Path(directory),run,host_context

    @contextmanager
    def execution(self,*,read_only=False):
        if getattr(self,'locked',False):
            yield;return
        d=self.directory
        if d.resolve()!=d.absolute():raise AttachmentError('attachment lock directory is a symlink')
        if not d.exists():
            if read_only:
                yield;return
            d.mkdir(parents=True,mode=0o700)
        info=d.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise AttachmentError('attachment lock directory ownership differs')
        try:fd=os.open(d/'vxlan.lock',os.O_RDONLY|os.O_NOFOLLOW if read_only else os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        except FileNotFoundError:
            if os.path.lexists(d/'journal.sqlite3'):raise AttachmentError('shared resource lock missing') from None
            yield;return
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise AttachmentError('shared attachment lock ownership differs')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise AttachmentError('local link worker busy') from None
            self.locked=True
            try:yield
            finally:self.locked=False
        finally:os.close(fd)

    @contextmanager
    def snapshot(self,path):
        # SQLite WAL readers can create/write SHM even with mode=ro. Work on
        # a private disposable copy instead, rejecting concurrent DB/WAL edits.
        # The shared resource lock excludes all attachment/link mutations.
        def inventory():
            result={}
            for source in (path,Path(str(path)+'-wal')):
                if not os.path.lexists(source):continue
                st=source.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600:
                    raise AttachmentError('attachment snapshot file ownership differs')
                result[source]=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
            return result
        before=inventory()
        with tempfile.TemporaryDirectory(prefix='dnlab-attachment-preflight-') as temporary:
            target=Path(temporary)/path.name
            for source in before:shutil.copyfile(source,Path(temporary)/source.name)
            if inventory()!=before:raise AttachmentError('attachment journal changed during read-only snapshot')
            db=sqlite3.connect(target)
            try:yield db
            finally:db.close()

    def records(self):
        d=self.directory
        if d.resolve()!=d.absolute():raise AttachmentError('attachment journal path is a symlink')
        if not d.exists():return []
        info=d.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise AttachmentError('attachment directory ownership differs')
        path=d/'journal.sqlite3'
        if not os.path.lexists(path):return []
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
            raise AttachmentError('attachment journal ownership differs')
        with self.snapshot(path) as db:
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'realnet_attachments' not in tables:return []
            rows=[]
            for key,raw,phase in db.execute('SELECT id,payload,phase FROM realnet_attachments'):
                value=json.loads(raw);proof=value['proof'];validate(proof)
                bridge=proof['bridge']['ifname'];expected=self.plan['links'].get(bridge)
                if proof['bridge']['ifalias'].split(':')[2]!=self.plan['scope']:continue
                if (value['source']!=proof['source'] or type(value['warm']) is not bool
                        or key!=Worker(proof,directory=d,run=self.run,host_context=self.host_context).key
                        or phase not in ('applying','active','cleanup_pending','recovery_required','cleaned')):
                    raise AttachmentError('attachment/infrastructure proof differs')
                same_generation=(expected and expected['kind']=='bridge' and proof['context']==self.plan['context']
                        and {k:proof['bridge'][k] for k in ('ifindex','address','ifalias','link_index')}==expected['identity'])
                if not same_generation:
                    if phase=='cleaned' and value.get('cleanup_verified') is True:continue
                    raise AttachmentError('attachment/infrastructure generation differs')
                rows.append((key,value,phase))
            return rows

    def preflight(self):
        qualified={}
        for key,value,phase in self.records():
            if phase=='cleaned':continue
            worker=Worker(value['proof'],directory=self.directory,run=self.run,host_context=self.host_context)
            values=json.loads(self.run(['docker','inspect',value['proof']['container']['id']]))
            fd=worker.open_ns(values[0]['State']['Pid'])
            try:
                source=worker.preflight(fd)
                if phase=='active' and source.get('master') not in (value['proof']['bridge']['ifname'],value['proof']['bridge']['ifindex']):
                    raise AttachmentError('active data attachment disappeared')
                if source['ifname'] in qualified:raise AttachmentError('duplicate attachment reservation')
                qualified[source['ifname']]=signature(source)
            finally:os.close(fd)
        return qualified

    def detach(self):
        # Caller completes every host preflight first. Each local operation
        # repeats proof checks under the shared resource lock and journals.
        for key,value,phase in self.records():
            if phase!='cleaned':
                Worker(value['proof'],directory=self.directory,run=self.run,host_context=self.host_context).operate('recover',warm=value['warm'],expected_attempt=Worker.attempt_id(value))
        if any(phase!='cleaned' for _,_,phase in self.records()):raise AttachmentError('attachment recovery remains pending')
        return {'status':'detached','attempts':{key:{'attempt':Worker.attempt_id(value),'proof_hash':Worker.proof_hash(value['proof'],value['warm']),'phase':phase}
                    for key,value,phase in self.records()}}
