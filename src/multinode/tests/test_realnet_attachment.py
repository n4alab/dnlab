"""Data attachment identity, reservation and interrupted mutation contracts."""
import copy
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest

from dnlab_multinode.services.realnet_attachment_host import AttachmentError,Worker,context,signature
from dnlab_multinode.services.realnet_cleanup import scope


class Host:
    def __init__(self):
        self.source={'ifname':'drsp-data','ifindex':30,'link_index':31,'ifalias':'dnlab-runtime:vd:fixture',
                     'address':'02:00:00:00:00:30','flags':[],'linkinfo':{'info_kind':'veth'}}
        self.peer={'ifname':'eth1','ifindex':31,'link_index':30,'ifalias':None,'address':'02:00:00:00:00:31','linkinfo':{'info_kind':'veth'}}
        self.bridge={'ifname':'drsp-br','ifindex':40,'ifalias':'dnlab-runtime:realnet:'+scope('lab','access','master')+':'+'a'*32,
                     'address':'02:00:00:00:00:40','linkinfo':{'info_kind':'bridge'}}
        self.container={'Id':'a'*64,'Name':'/vd','Image':'sha256:'+'b'*64,'Config':{'Labels':{'fixture':'owned'}},
                        'State':{'Running':True,'Pid':os.getpid(),'StartedAt':'start'}}
        info=os.stat('/proc/self/ns/net')
        self.proof={'lab':'lab','node':'r1','realnet':'access','host':'master','link':'rn0','management_interface':'eth0','context':context(),
                    'source':signature(self.source),'peer':signature(self.peer),'bridge':signature(self.bridge),
                    'namespace':{'device':info.st_dev,'inode':info.st_ino},
                    'container':{'id':self.container['Id'],'name':'vd','image':self.container['Image'],
                                 'labels':self.container['Config']['Labels'],'started_at':'start'}}
        self.mutations=[];self.fail=None

    def run(self,args,**kwargs):
        if args[0]=='iptables-save':return ''
        if args[:2]==['docker','inspect']:return json.dumps([self.container])
        if args[:2]==['ip','-j']:return json.dumps([self.source,self.bridge])
        if args[0]=='nsenter':return json.dumps([self.peer])
        self.mutations.append(args)
        if args[:3]==['ip','link','set']:
            if args[4]=='up':self.source['flags']=['UP']
            elif args[4]=='down':self.source['flags']=[]
            elif args[4]=='master':self.source['master']=args[5]
            elif args[4]=='nomaster':self.source.pop('master',None)
            else:raise AssertionError(args)
        elif args[:2]!=['docker','exec']:raise AssertionError(args)
        if self.fail==len(self.mutations):raise RuntimeError('lost acknowledgement')
        return ''


@pytest.fixture
def fixture(tmp_path):
    h=Host();return h,Worker(h.proof,directory=tmp_path/'journal',run=h.run)


def phase(worker):
    with closing(sqlite3.connect(worker.directory/'journal.sqlite3')) as db, db:
        return db.execute('SELECT phase FROM realnet_attachments WHERE id=?',(worker.key,)).fetchone()[0]


def test_repeatable_create_delete_preserves_endpoint(fixture):
    h,w=fixture;before=copy.deepcopy(h.source)
    assert w.operate('create')['phase']=='active'
    count=len(h.mutations);w.operate('create');assert len(h.mutations)==count
    assert w.operate('delete')['phase']=='cleaned' and h.source==before
    count=len(h.mutations);w.operate('delete');assert len(h.mutations)==count


@pytest.mark.parametrize('failure',range(1,4))
def test_interrupted_create_reserves_until_explicit_recovery(fixture,failure):
    h,w=fixture;h.fail=failure
    with pytest.raises(RuntimeError,match='lost'):w.operate('create',warm=True)
    assert phase(w)=='recovery_required'
    h.fail=None
    with pytest.raises(AttachmentError,match='recovery'):w.operate('create',warm=True)
    other=copy.deepcopy(h.proof);other['link']='rn1'
    with pytest.raises(AttachmentError,match='reserved'):Worker(other,directory=w.directory,run=h.run).operate('create')
    assert Worker(h.proof,directory=w.directory,run=h.run).operate('recover',warm=True,expected_attempt=w.attempt)['phase']=='cleaned'
    assert 'master' not in h.source and h.source['flags']==[]


@pytest.mark.parametrize('failure',range(4,7))
def test_interrupted_cleanup_retry(fixture,failure):
    h,w=fixture;w.operate('create',warm=True);h.fail=failure
    with pytest.raises(RuntimeError):w.operate('delete',warm=True)
    assert phase(w)=='recovery_required'
    h.fail=None;w.operate('recover',warm=True);assert phase(w)=='cleaned'


@pytest.mark.parametrize('field',['source','peer','bridge','container_id','image','labels','start','running','namespace','context','foreign_master'])
@pytest.mark.parametrize('action',['create','delete'])
def test_replaced_resources_refused_before_carrier_or_mutation(fixture,field,action):
    h,w=fixture
    if action=='delete':w.operate('create',warm=True)
    if field in ('source','peer','bridge'):getattr(h,field)['address']='02:ff:ff:ff:ff:ff'
    elif field=='container_id':h.container['Id']='c'*64
    elif field=='image':h.container['Image']='sha256:'+'c'*64
    elif field=='labels':h.container['Config']['Labels']={'fixture':'foreign'}
    elif field=='start':h.container['State']['StartedAt']='new-start'
    elif field=='running':h.container['State']['Running']=False
    elif field=='namespace':w.proof['namespace']['inode']+=1
    elif field=='context':w.proof['context']['boot_id']='other'
    else:h.source['master']='foreign-bridge'
    count=len(h.mutations)
    with pytest.raises(AttachmentError):w.operate(action,warm=True)
    assert len(h.mutations)==count


def test_delete_without_journal_refuses_even_matching_bridge(fixture):
    h,w=fixture;h.source['master']=h.bridge['ifname']
    with pytest.raises(AttachmentError,match='journal missing'):w.operate('delete')
    assert not h.mutations


@pytest.mark.parametrize('table',['local_vxlans','local_bridges'])
def test_pending_custom_link_reservation_prevents_attachment(fixture,table):
    h,w=fixture;w.directory.mkdir(mode=0o700)
    path=w.directory/'journal.sqlite3'
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(f'CREATE TABLE {table}(id TEXT,payload TEXT,phase TEXT)')
        p={'source':h.proof['source']} if table=='local_vxlans' else {'config':{'sources':[h.proof['source']]}}
        db.execute(f'INSERT INTO {table} VALUES(?,?,?)',('foreign',json.dumps(p),'recovery_required'))
    path.chmod(0o600)
    with pytest.raises(AttachmentError,match='reserved'):w.operate('create',warm=True)
    assert not h.mutations


def test_management_port_rejected(fixture):
    h,w=fixture;h.proof['peer']['ifname']='eth0'
    with pytest.raises(AttachmentError,match='data port'):Worker(h.proof,directory=w.directory,run=h.run)


def test_carrier_uses_persisted_container_id(fixture):
    h,w=fixture;w.operate('create',warm=True);w.operate('delete',warm=True)
    carriers=[v for v in h.mutations if v[:2]==['docker','exec']]
    assert carriers==[['docker','exec',h.container['Id'],'dnlab-linkctl','eth1',state] for state in ('up','down')]


def test_selected_data_management_port_cannot_attach(fixture):
    h,w=fixture;h.proof['management_interface']='eth1'
    with pytest.raises(AttachmentError,match='management'):Worker(h.proof,directory=w.directory,run=h.run)
    assert not h.mutations


from dnlab_multinode.services.realnet_cleanup_host import Worker as CleanupWorker,OwnershipError,link_identity

def test_cleanup_preflight_accepts_guarded_active_vd_attachment_read_only(tmp_path):
    host=Host()
    Worker(host.proof,directory=tmp_path/'journal',run=host.run).operate('create')
    plan={'scope':host.bridge['ifalias'].split(':')[2],'context':host.proof['context'],
          'links':{host.bridge['ifname']:{'kind':'bridge','identity':link_identity(host.bridge),'config':{}}},
          'router':None,'firewall':[]}
    count=len(host.mutations)
    guard=CleanupWorker(plan,run=host.run,attachment_directory=tmp_path/'journal')
    before=(tmp_path/'journal'/'journal.sqlite3').read_bytes()
    assert guard.preflight()['status']=='verified'
    assert (tmp_path/'journal'/'journal.sqlite3').read_bytes()==before
    assert len(host.mutations)==count and host.source['master']==host.bridge['ifname']


def test_teardown_preserves_explicit_carrier_skip_with_full_guard(fixture):
    host,worker=fixture;worker.operate('create',warm=True)
    count=len([v for v in host.mutations if v[:2]==['docker','exec']])
    worker.operate('delete',warm=True,set_carriers=False)
    assert phase(worker)=='cleaned' and 'master' not in host.source
    assert len([v for v in host.mutations if v[:2]==['docker','exec']])==count


class InfrastructureHost(Host):
    def __init__(self):super().__init__();self.bridge_exists=True
    def run(self,args,**kwargs):
        if args[:2]==['ip','-j']:
            return json.dumps([self.source]+([self.bridge] if self.bridge_exists else []))
        if args[:3]==['ip','link','delete']:
            assert args[-1]==self.bridge['ifname']
            self.mutations.append(args);self.bridge_exists=False
            if self.fail==len(self.mutations):raise RuntimeError('lost bridge delete acknowledgement')
            return ''
        return super().run(args,**kwargs)


def infrastructure_fixture(tmp_path,warm=False):
    host=InfrastructureHost();before=copy.deepcopy(host.source)
    attachment=Worker(host.proof,directory=tmp_path/'links',run=host.run)
    attachment.operate('create',warm=warm)
    plan={'scope':scope('lab','access','master'),'context':host.proof['context'],
          'links':{host.bridge['ifname']:{'kind':'bridge','identity':link_identity(host.bridge),'config':{}}},
          'router':None,'firewall':[]}
    guard=CleanupWorker(plan,run=host.run,directory=tmp_path/'cleanup',attachment_directory=tmp_path/'links')
    return host,attachment,guard,before


def test_infrastructure_cleanup_requires_detach_and_never_deletes_vd_veth(tmp_path):
    host,attachment,guard,before=infrastructure_fixture(tmp_path)
    count=len(host.mutations)
    with pytest.raises(OwnershipError,match='must be detached'):guard.cleanup()
    assert len(host.mutations)==count
    guard.detach_attachments();guard.cleanup();guard.verify_cleaned()
    assert host.source==before and signature(host.peer)==host.proof['peer'] and host.container['State']['Running']
    deletes=[v for v in host.mutations if v[:3]==['ip','link','delete']]
    assert deletes==[['ip','link','delete','dev','drsp-br']]
    assert phase(attachment)=='cleaned'


@pytest.mark.parametrize('failure',[4,5,6])
def test_detach_failure_preserves_infrastructure_and_recovers(tmp_path,failure):
    host,attachment,guard,before=infrastructure_fixture(tmp_path,warm=True);host.fail=failure
    with pytest.raises(OwnershipError,match='recovery pending'):guard.detach_attachments()
    assert host.bridge_exists and phase(attachment)=='recovery_required'
    assert not any(v[:3]==['ip','link','delete'] for v in host.mutations)
    host.fail=None;guard.detach_attachments();guard.cleanup()
    assert host.source==before and phase(attachment)=='cleaned' and not host.bridge_exists


def test_cleanup_retry_after_bridge_delete_does_not_require_vd_namespace(tmp_path):
    host,attachment,guard,before=infrastructure_fixture(tmp_path)
    guard.detach_attachments();host.fail=len(host.mutations)+1
    with pytest.raises(RuntimeError,match='bridge delete'):guard.cleanup()
    host.fail=None;host.container['State']['Running']=False;host.container['State']['Pid']=0
    guard.cleanup();guard.verify_cleaned()
    assert host.source==before and phase(attachment)=='cleaned'


@pytest.mark.parametrize('change',['alias','peer','namespace','record','missing_ledger','foreign_port'])
def test_infrastructure_preflight_refuses_foreign_or_unjournalled_ports(tmp_path,change):
    host,attachment,guard,before=infrastructure_fixture(tmp_path)
    if change=='alias':host.source['ifalias']='foreign'
    elif change=='peer':host.peer['address']='02:ff:ff:ff:ff:ff'
    elif change=='namespace':
        with closing(sqlite3.connect(attachment.directory/'journal.sqlite3')) as db, db:
            raw=db.execute('SELECT payload FROM realnet_attachments').fetchone()[0];record=json.loads(raw)
            record['proof']['namespace']['inode']+=1
            db.execute('UPDATE realnet_attachments SET payload=?',(json.dumps(record),))
    elif change=='record':
        with closing(sqlite3.connect(attachment.directory/'journal.sqlite3')) as db, db:
            db.execute("UPDATE realnet_attachments SET phase='unknown'")
    elif change=='missing_ledger':(attachment.directory/'journal.sqlite3').unlink()
    else:host.source['ifname']='foreign'
    count=len(host.mutations)
    with pytest.raises(OwnershipError):guard.preflight()
    assert len(host.mutations)==count


def test_read_only_preflight_leaves_directory_and_journal_unchanged(tmp_path):
    import hashlib
    host,attachment,guard,_=infrastructure_fixture(tmp_path)
    def inventory():return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in attachment.directory.iterdir()}
    before=inventory();guard.preflight();assert inventory()==before


def test_infrastructure_cleanup_holds_shared_lock_until_bridge_deleted(tmp_path):
    host,attachment,guard,before=infrastructure_fixture(tmp_path);guard.detach_attachments()
    original=host.run;observed=[]
    def run(args,**kwargs):
        if args[:3]==['ip','link','delete']:
            other=copy.deepcopy(host.proof);other['link']='new-link'
            with pytest.raises(AttachmentError,match='worker busy'):
                Worker(other,directory=attachment.directory,run=original).operate('create')
            observed.append('exclusive')
        return original(args,**kwargs)
    guard.run=run;guard._attachments.run=lambda args,**kwargs:run(args,**kwargs)
    guard.cleanup();assert observed==['exclusive'] and host.source==before


def test_cleaned_generation_allows_new_qualified_vd_attempt(tmp_path):
    host,attachment,guard,before=infrastructure_fixture(tmp_path)
    guard.detach_attachments();assert phase(attachment)=='cleaned'
    # Simulate a newly provisioned VD generation with a fresh immutable proof.
    host.container['Id']='c'*64;host.container['State']['StartedAt']='new-generation'
    next_proof=copy.deepcopy(host.proof)
    next_proof['container']['id']=host.container['Id']
    next_proof['container']['started_at']='new-generation'
    next_worker=Worker(next_proof,directory=attachment.directory,run=host.run)
    count=len(host.mutations)
    result=next_worker.operate('create',expected_attempt=attachment.attempt)
    assert result['phase']=='active' and result['attempt']!=attachment.attempt and len(host.mutations)>count
    next_worker.operate('delete');assert host.source==before


def attempts(worker):
    with closing(sqlite3.connect(worker.directory/'journal.sqlite3')) as db, db:
        return [(token,json.loads(payload),phase) for token,payload,phase in db.execute(
            'SELECT attempt,payload,phase FROM realnet_attachment_attempts WHERE logical_id=? ORDER BY rowid',(worker.key,))]


def next_generation(host,worker):
    host.container['Id']='d'*64;host.container['State']['StartedAt']='generation-two'
    proof=copy.deepcopy(host.proof);proof['container']['id']=host.container['Id'];proof['container']['started_at']='generation-two'
    return Worker(proof,directory=worker.directory,run=host.run)


def test_attempt_history_preserves_cleaned_proof_and_rejects_stale_actions(tmp_path):
    host,old,guard,_=infrastructure_fixture(tmp_path);old_token=old.attempt
    guard.detach_attachments();current=next_generation(host,old)
    new_token=current.operate('create',expected_attempt=old_token)['attempt']
    records=attempts(current)
    assert records[0][0]==old_token and records[0][1]['proof']==old.proof and records[0][2]=='cleaned'
    assert records[0][1]['cleanup_verified'] is True and records[1][0]==new_token and records[1][2]=='active'
    count=len(host.mutations)
    for action in ('create','delete','recover'):
        with pytest.raises(AttachmentError,match='stale'):old.operate(action)
        with pytest.raises(AttachmentError,match='generation'):old.operate(action,expected_attempt=new_token)
    assert len(host.mutations)==count and host.source['master']==host.bridge['ifname']
    current.operate('delete');assert all(phase=='cleaned' for _,_,phase in attempts(current))
    with pytest.raises(AttachmentError,match='obsolete'):old.operate('create',expected_attempt=new_token)


@pytest.mark.parametrize('pending',['active','applying','cleanup_pending','recovery_required'])
def test_new_generation_cannot_replace_active_or_pending_attempt(tmp_path,pending):
    host,old,_,_=infrastructure_fixture(tmp_path);new=next_generation(host,old)
    with closing(sqlite3.connect(old.directory/'journal.sqlite3')) as db, db:
        db.execute('UPDATE realnet_attachments SET phase=?',(pending,))
    count=len(host.mutations)
    with pytest.raises(AttachmentError,match='generation'):new.operate('create',expected_attempt=old.attempt)
    assert phase(old)==pending and len(host.mutations)==count


def test_new_generation_requires_verified_cleanup_marker(tmp_path):
    host,old,guard,_=infrastructure_fixture(tmp_path);guard.detach_attachments();new=next_generation(host,old)
    with closing(sqlite3.connect(old.directory/'journal.sqlite3')) as db, db:
        raw=db.execute('SELECT payload FROM realnet_attachments').fetchone()[0];payload=json.loads(raw)
        payload['cleanup_verified']=False;payload['step']='bind'
        db.execute('UPDATE realnet_attachments SET payload=?',(json.dumps(payload),))
    with pytest.raises(AttachmentError,match='not verified'):new.operate('create',expected_attempt=old.attempt)


def test_identical_proof_new_attempt_rejects_old_attempt_token(fixture):
    host,worker=fixture;first=worker.operate('create')['attempt'];worker.operate('delete')
    second=worker.operate('create')['attempt'];assert second!=first
    count=len(host.mutations)
    for action in ('create','delete','recover'):
        with pytest.raises(AttachmentError,match='stale'):worker.operate(action,expected_attempt=first)
    assert len(host.mutations)==count
    assert len(attempts(worker))==2


def test_fresh_worker_requires_explicit_attempt_binding(fixture):
    host,worker=fixture;token=worker.operate('create')['attempt']
    fresh=Worker(host.proof,directory=worker.directory,run=host.run)
    with pytest.raises(AttachmentError,match='missing'):fresh.operate('delete')
    assert fresh.operate('create',expected_attempt=token)['attempt']==token
    fresh.operate('delete');assert phase(worker)=='cleaned'


def test_lost_create_ack_recovery_receipt_updates_exact_runtime_link(monkeypatch,tmp_path):
    import shlex
    from dnlab_multinode.models.state import RuntimeLinkState,RealNetState
    from dnlab_multinode.services import realnet_attachment,realnet_cleanup
    from dnlab_multinode.controllers.destroy import DestroyController
    host=Host();directory=tmp_path/'links'
    link=RuntimeLinkState(id='rn0',link_type='real_net',lab_name='lab',host_a='master',host_b='master',
        endpoint_a={'node':'r1','iface':'eth1'},endpoint_b={'real_net':'access'},host_endpoint_a='drsp-data',
        host_endpoint_b='drsp-br',container_a='vd',resource_identities={'realnet_attachment_v1':host.proof})
    class SSH:
        def run(self,command):
            request=json.loads(shlex.split(command)[3])
            Worker(request['proof'],directory=directory,run=host.run).operate(request['action'],
                warm=request['warm'],expected_attempt=request['expected_attempt'])
            raise RuntimeError('SSH response lost after commit')
    with pytest.raises(AttachmentError,match='recovery'):realnet_attachment.attachment(link,{'master':SSH()},'create')
    assert link.resource_identities['realnet_attachment_operation']['attempt'] is None
    plan={'scope':scope('lab','access','master'),'context':host.proof['context'],
          'links':{host.bridge['ifname']:{'kind':'bridge','identity':link_identity(host.bridge),'config':{}}},'router':None,'firewall':[]}
    state=RealNetState(name='access',bridge='drsp-br',vxlan_id=42,hosts=['master'],router_container='',vxlan_ifaces={'master':[]},
                       resource_identities={'realnet_cleanup_v1':{'master':plan}})
    guard=CleanupWorker(plan,run=host.run,directory=tmp_path/'cleanup',attachment_directory=directory)
    monkeypatch.setattr(realnet_cleanup,'invoke',lambda client,action,proof:getattr(guard,action)())
    realnet_cleanup.detach_realnet_attachments('lab',{'master':SSH()},[state],runtime_links=[link])
    ack=link.resource_identities['realnet_attachment_operation']
    assert ack['phase']=='cleaned' and len(ack['attempt'])==32 and link.state=='down'
    # The controller may later remove a VD; its current-run receipt avoids a
    # second namespace inspection after an already verified data detach.
    from dnlab_multinode.models.state import DeploymentState
    controller=DestroyController('/tmp/fixture.yml');controller._state=DeploymentState(lab_name='lab',topology_file='/tmp/fixture.yml',runtime_links=[link])
    controller._clients={'master':SSH()};controller._realnet_detach_verified=True
    count=len(host.mutations);host.container['State']['Running']=False
    controller._destroy_runtime_links();assert not controller._errors and len(host.mutations)==count


@pytest.mark.parametrize('attempt',['','invalid'])
def test_adapter_rejects_ack_without_valid_attempt(fixture,attempt):
    from dnlab_multinode.services.realnet_attachment import attachment
    from dnlab_multinode.models.state import RuntimeLinkState
    host,worker=fixture
    link=RuntimeLinkState(id='rn0',link_type='real_net',lab_name='lab',host_a='master',host_b='master',
        endpoint_a={'node':'r1','iface':'eth1'},endpoint_b={'real_net':'access'},host_endpoint_a='drsp-data',
        host_endpoint_b='drsp-br',container_a='vd',resource_identities={'realnet_attachment_v1':host.proof})
    class SSH:
        def run(self,command):return json.dumps({'phase':'active','attempt':attempt})
    with pytest.raises(AttachmentError):attachment(link,{'master':SSH()},'create')
    assert link.resource_identities['realnet_attachment_operation']['phase']=='recovery_required'


@pytest.mark.parametrize('pending',[False,True])
def test_old_bridge_generation_is_history_only_after_verified_cleanup(tmp_path,pending):
    host,attachment,guard,_=infrastructure_fixture(tmp_path)
    if not pending:guard.detach_attachments()
    new_plan=copy.deepcopy(guard.plan);new_plan['links']['drsp-br']['identity']['ifalias']='dnlab-runtime:realnet:'+scope('lab','access','master')+':'+'b'*32
    from dnlab_multinode.services.realnet_attachment_host import InfrastructureAttachments
    inventory=InfrastructureAttachments(new_plan,directory=attachment.directory,run=host.run)
    if pending:
        with pytest.raises(AttachmentError,match='generation'):inventory.records()
    else:assert inventory.records()==[] and attempts(attachment)[0][2]=='cleaned'
