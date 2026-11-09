"""Real inode-preserving writes; simulated service-exit and operation journal."""
from copy import deepcopy
import os

import pytest

from dnlab_multinode.services import jumphost_host as module


class World:
    def __init__(self, path, old='interface=eth1\n'+'#old\n'*3000, new='interface=eth1\ninterface=jmblue\n'):
        self.path=path;path.mkdir(mode=0o755);path.chmod(0o755)
        self.file=path/'main';self.file.write_text(old);self.file.chmod(0o644)
        self.container={'id':'c'*64,'image':'sha256:'+'b'*64,'started_at':'original'}
        receipt={'exit_verified':True,'service':{'container':deepcopy(self.container),'host_pid':123,'start':'original'}}
        self.intent={'nonce':'a'*32,'container':deepcopy(self.container),'service_exit':receipt,
            'directory':module.JournaledDHCPMain.identity(path.stat(),directory=True),
            'file':module.JournaledDHCPMain.identity(self.file.stat()),'old':old,'new':new,
            'phase':'intent','offset':0,'pending_end':None}
        self.saved=deepcopy(self.intent);self.fail_save=None;self.conflict=False

    def save(self):
        if self.fail_save and self.fail_save(self.intent):raise OSError('journal sync failed')
        self.saved=deepcopy(self.intent)

    def reopen(self):self.intent=deepcopy(self.saved)

    def preflight(self):
        if self.conflict:raise module.JumphostError('original attachments differ')
        return {'container':deepcopy(self.container),'service_exit':deepcopy(self.intent['service_exit'])}

    def runner(self):return module.JournaledDHCPMain(self.path,self.intent,self.save,self.preflight)


@pytest.mark.parametrize('old,new',[('old main\n'*4000,'new\n'),('old\n','new main\n'*4000),
                                  ('same\n','same\n'),('','interface=eth1\n'),('é'*4000,'新'*3000)])
def test_write_and_retry_preserve_original_inode_and_an_already_open_bind(tmp_path,old,new):
    w=World(tmp_path/'assets',old,new);identity=w.file.stat().st_ino
    fd=os.open(w.file,os.O_RDONLY)
    try:
        result=w.runner().run()
        assert w.file.stat().st_ino==identity and result['identity']['inode']==identity
        assert os.pread(fd,100000,0)==new.encode() and w.saved['phase']=='ready'
        assert w.runner().run()==result
    finally:os.close(fd)


@pytest.mark.parametrize('boundary',['writing','pending','confirmed','truncating','ready'])
def test_save_failure_keeps_the_last_persisted_boundary_recoverable(tmp_path,boundary):
    w=World(tmp_path/'assets',new='new\n'*4000)
    def fail(intent):
        if boundary=='pending':return intent['pending_end'] is not None
        if boundary=='confirmed':return intent['phase']=='writing' and intent['offset']>0 and intent['pending_end'] is None
        return intent['phase']==boundary
    w.fail_save=fail
    with pytest.raises(OSError):w.runner().run()
    if boundary in ('writing','pending'):assert w.file.read_text()==w.saved['old']
    w.reopen();w.fail_save=None
    assert w.runner().run()['content']==w.intent['new'] and w.file.read_text()==w.intent['new']


@pytest.mark.parametrize('boundary',['pwrite','truncate','file-sync','directory-sync'])
def test_lost_mutation_acknowledgement_recovers_without_replacing_the_file(tmp_path,monkeypatch,boundary):
    w=World(tmp_path/'assets');original=w.file.stat().st_ino;armed=[True]
    with monkeypatch.context() as patch:
        if boundary in ('pwrite','truncate'):
            name='pwrite' if boundary=='pwrite' else 'ftruncate';operation=getattr(os,name)
            def interrupted(*args):
                result=operation(*args)
                if armed[0]:armed[0]=False;raise OSError('lost write reply')
                return result
            patch.setattr(os,name,interrupted)
        else:
            sync=os.fsync
            def interrupted(fd):
                result=sync(fd)
                directory=module.stat.S_ISDIR(os.fstat(fd).st_mode)
                if armed[0] and directory==(boundary=='directory-sync'):
                    armed[0]=False;raise OSError('sync reply lost')
                return result
            patch.setattr(os,'fsync',interrupted)
        with pytest.raises(OSError):w.runner().run()
    assert not armed[0]
    w.reopen();w.runner().run()
    assert w.file.stat().st_ino==original and w.file.read_text()==w.intent['new']


def test_short_writes_are_completed_from_the_confirmed_offset(tmp_path,monkeypatch):
    w=World(tmp_path/'assets');write=os.pwrite
    monkeypatch.setattr(os,'pwrite',lambda fd,data,offset:write(fd,data[:3],offset))
    w.runner().run();assert w.file.read_text()==w.intent['new']


@pytest.mark.parametrize('change',['file','directory','symlink','hardlink','mode','content','container','attachment','shutdown'])
def test_unqualified_generation_is_preserved_without_writes(tmp_path,change):
    w=World(tmp_path/'assets');other=tmp_path/'other';other.write_text('foreign');other.chmod(0o644)
    if change=='file':w.file.rename(tmp_path/'old-main');w.file.write_text('foreign');w.file.chmod(0o644)
    if change=='directory':
        w.path.rename(tmp_path/'old-assets');w.path.mkdir(mode=0o755);w.path.chmod(0o755)
        w.file.write_text('foreign');w.file.chmod(0o644)
    if change=='symlink':w.file.unlink();w.file.symlink_to(other)
    if change=='hardlink':os.link(w.file,tmp_path/'alias')
    if change=='mode':w.file.chmod(0o666)
    if change=='content':w.file.write_text('foreign')
    if change=='container':w.container['id']='f'*64
    if change=='attachment':w.conflict=True
    if change=='shutdown':w.intent['service_exit']['exit_verified']=False
    before=w.file.read_bytes();foreign=other.read_bytes()
    with pytest.raises((module.JumphostError,OSError)):w.runner().run()
    assert w.file.read_bytes()==before and other.read_bytes()==foreign


def test_foreign_content_outside_pending_chunk_is_not_recovered(tmp_path):
    w=World(tmp_path/'assets',new='new main\n'*3000)
    w.intent.update(phase='writing',pending_end=4096);w.save()
    data=bytearray(w.file.read_bytes());data[-1]=ord('X');w.file.write_bytes(data)
    with pytest.raises(module.JumphostError,match='pending chunk'):w.runner().run()
    assert w.file.read_bytes()==data


@pytest.mark.parametrize('written',[0,1,127,4096])
def test_recovery_accepts_only_a_possible_prefix_of_the_persisted_chunk(tmp_path,written):
    w=World(tmp_path/'assets',new='interface=jmblue\n'*1000)
    w.intent.update(phase='writing',pending_end=4096);w.save()
    old=w.file.read_bytes();new=w.intent['new'].encode();w.file.write_bytes(new[:written]+old[written:])
    w.runner().run();assert w.file.read_bytes()==new


def test_replacement_after_descriptor_open_does_not_touch_the_new_file(tmp_path):
    w=World(tmp_path/'assets');preflight=w.preflight;armed=[True]
    def substitute():
        if armed[0]:
            armed[0]=False;w.file.rename(tmp_path/'original');w.file.write_text('foreign');w.file.chmod(0o644)
        return preflight()
    w.preflight=substitute
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.file.read_text()=='foreign' and (tmp_path/'original').read_text()==w.intent['old']


def test_ready_retry_rejects_modified_content(tmp_path):
    w=World(tmp_path/'assets');w.runner().run();w.file.write_text('foreign')
    with pytest.raises(module.JumphostError,match='committed'):w.runner().run()
    assert w.file.read_text()=='foreign'
