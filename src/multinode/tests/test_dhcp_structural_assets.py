"""All-files structural preflight with real bytes/inodes and durable recovery."""
from copy import deepcopy
import os
from unittest.mock import Mock

import pytest
from dnlab_multinode.services import jumphost_host as module


class World:
    def __init__(self,path,empty=False):
        path.mkdir(mode=0o755);path.chmod(0o755);self.path=path
        self.old={'main':'port=0\n'+'#old\n'*1000,'hosts':'#hosts old\n','options':'#opts old\n'}
        self.new={'main':'port=0\n#new\n','hosts':'' if empty else '#hosts new\n'*500,
                  'options':'' if empty else '#opts new\n'*500}
        previous={}
        for name,value in self.old.items():
            target=path/name;target.write_text(value);target.chmod(0o644)
            st=target.stat();previous[name]={'identity':{'device':st.st_dev,'inode':st.st_ino},'content':value}
        self.container={'id':'c'*64,'started_at':'original'}
        self.receipt={'service':{'container':deepcopy(self.container),'host_pid':123,'start':'1'},'exit_verified':True}
        self.intent=module.JournaledDHCPAssets.prepare(path,previous,self.new,self.container,self.receipt,'a'*32)
        self.saved=deepcopy(self.intent);self.fail_save=None;self.conflict=False
    def save(self):
        if self.fail_save and self.fail_save(self.intent):raise OSError('fsync failed')
        self.saved=deepcopy(self.intent)
    def reopen(self):self.intent=deepcopy(self.saved)
    def preflight(self):
        if self.conflict:raise module.JumphostError('attachment changed')
        return {'container':deepcopy(self.container),'service_exit':deepcopy(self.receipt)}
    def runner(self):return module.JournaledDHCPAssets(self.path,self.intent,self.save,self.preflight)
    def contents(self):return {name:(self.path/name).read_text() for name in self.old}


@pytest.mark.parametrize('empty',[False,True])
def test_all_files_commit_on_original_inodes_and_empty_reservations_are_allowed(tmp_path,empty):
    w=World(tmp_path/'assets',empty);before={name:(w.path/name).stat().st_ino for name in w.old}
    result=w.runner().run()
    assert w.contents()==w.new and w.intent['phase']=='ready'
    assert {name:proof['identity']['inode'] for name,proof in result.items()}==before
    save=Mock(side_effect=AssertionError('committed retry saved again'))
    assert module.JournaledDHCPAssets(w.path,w.intent,save,w.preflight).run()==result


@pytest.mark.parametrize('target',['main','hosts','options'])
def test_preflight_checks_every_file_before_the_first_mutation(tmp_path,target):
    w=World(tmp_path/'assets');(w.path/target).write_text('foreign');before=w.contents()
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.contents()==before and w.saved['phase']=='prepared'


@pytest.mark.parametrize('target',['main','hosts','options'])
@pytest.mark.parametrize('fault',['pwrite','truncate','save'])
def test_partial_or_lost_acknowledgement_recovers_all_files_from_original_intent(tmp_path,monkeypatch,target,fault):
    w=World(tmp_path/'assets');inode=(w.path/target).stat().st_ino;armed=[True]
    if fault=='save':
        w.fail_save=lambda value:value['files'][target]['phase']=='ready'
        with pytest.raises(OSError):w.runner().run()
    else:
        name='pwrite' if fault=='pwrite' else 'ftruncate';operation=getattr(os,name)
        def interrupted(fd,*args):
            chosen=os.fstat(fd).st_ino==inode and armed[0]
            if chosen and fault=='pwrite':result=operation(fd,args[0][:3],args[1])
            else:result=operation(fd,*args)
            if chosen:armed[0]=False;raise OSError('reply lost')
            return result
        with monkeypatch.context() as patch:
            patch.setattr(os,name,interrupted)
            with pytest.raises(OSError):w.runner().run()
        assert not armed[0]
    w.reopen();w.fail_save=None;before=deepcopy(w.intent);save=Mock(side_effect=AssertionError('verify saved'))
    observed=module.JournaledDHCPAssets(w.path,w.intent,save,w.preflight).verify()
    assert set(observed)==set(w.old) and w.intent==before
    w.runner().run();assert w.contents()==w.new and w.intent['phase']=='ready'


def test_a_file_replaced_between_phases_is_preserved_and_no_later_file_is_written(tmp_path):
    w=World(tmp_path/'assets');save=w.save;armed=[True]
    def replaced():
        save()
        if armed[0] and w.intent['files']['main']['phase']=='ready':
            armed[0]=False;(w.path/'hosts').rename(w.path/'old-hosts')
            (w.path/'hosts').write_text('foreign');(w.path/'hosts').chmod(0o644)
    w.save=replaced
    with pytest.raises(module.JumphostError):w.runner().run()
    assert (w.path/'hosts').read_text()=='foreign' and (w.path/'options').read_text()==w.old['options']
    assert w.saved['phase']=='writing'


@pytest.mark.parametrize('change',['target','identity','receipt','filename','parent-phase','extra-entry','attachment','container'])
def test_corrupt_or_conflicting_original_intent_never_allocates_or_writes(tmp_path,change):
    w=World(tmp_path/'assets');runner=w.runner();before=w.contents()
    if change=='target':w.intent['files']['hosts']['new']='foreign'
    if change=='identity':w.intent['files']['main']['file']['inode']+=1
    if change=='receipt':w.intent['service_exit']['exit_verified']=False
    if change=='filename':w.intent['files']['main']['filename']='hosts'
    if change=='parent-phase':w.intent['phase']='ready'
    if change=='extra-entry':(w.path/'foreign').write_text('foreign')
    if change=='attachment':w.conflict=True
    if change=='container':w.container['id']='d'*64
    with pytest.raises(module.JumphostError):runner.run()
    assert w.contents()==before


def test_planning_rejects_an_invalid_later_target_before_any_write(tmp_path):
    w=World(tmp_path/'assets');before=w.contents();previous={name:{'identity':{key:w.intent['files'][name]['file'][key] for key in ('device','inode')},'content':value} for name,value in w.old.items()}
    with pytest.raises(module.JumphostError):
        module.JournaledDHCPAssets.prepare(w.path,previous,dict(w.new,options='bad\0'),w.container,w.receipt,'a'*32)
    assert w.contents()==before
