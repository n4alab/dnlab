"""Durable shutdown intent and replay after TERM with a lost exit receipt."""
from copy import deepcopy
import pytest
from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_host_identity import proof


class World:
    def __init__(self):
        self.service=proof();self.alive=True;self.calls=[];self.fault=None;self.fail_save=None
        self.intent={'id':'a'*32,'service':deepcopy(self.service),'phase':'intent','attempted':False,'receipt':None}
        self.saved=deepcopy(self.intent)
    def save(self):
        if self.fail_save==self.intent['phase']:raise OSError('journal fsync failed')
        self.saved=deepcopy(self.intent)
    def reopen(self):self.intent=deepcopy(self.saved)
    def probe(self, expected):
        self.calls.append('probe')
        if self.fault=='probe':raise module.JumphostError('inspection incomplete')
        if expected!=self.service:raise module.JumphostError('foreign service')
        if self.alive:return {'state':'running','service':deepcopy(self.service)}
        return {'state':'stopped','service':deepcopy(self.service),'exit_verified':True}
    def stop(self, expected):
        assert self.saved['phase']=='stopping' and self.saved['attempted'] and self.saved['service']==expected
        self.calls.append('TERM')
        if self.fault=='before-term':raise module.JumphostError('signal not delivered')
        self.alive=False
        if self.fault=='after-term':raise module.JumphostError('exit receipt lost')
        return {'service':deepcopy(self.service),'exit_verified':True}
    def runner(self):return module.JournaledDHCPStop(self.intent,self.save,self.probe,self.stop)


def test_stop_and_replay_keep_one_signal_and_revalidate_original_exit():
    w=World();receipt=w.runner().run();assert w.intent['phase']=='stopped'
    assert w.runner().run()==receipt and w.calls.count('TERM')==1 and w.calls.count('probe')==3


@pytest.mark.parametrize('fault',['before-term','after-term'])
def test_lost_signal_or_exit_reply_recovers_original_intent(fault):
    w=World();w.fault=fault
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.saved['phase']=='stopping'
    w.reopen();w.fault=None;assert w.runner().run()['exit_verified'] and w.saved['phase']=='stopped'
    assert w.calls.count('TERM')==(2 if fault=='before-term' else 1)


@pytest.mark.parametrize('phase',['stopping','stopped'])
def test_save_failure_preserves_last_durable_boundary(phase):
    w=World();w.fail_save=phase
    with pytest.raises(OSError):w.runner().run()
    assert w.calls.count('TERM')==(0 if phase=='stopping' else 1)
    w.reopen();w.fail_save=None;w.runner().run();assert w.calls.count('TERM')==1


def test_probe_conflict_prevents_signal_and_preserves_intent():
    w=World();w.fault='probe';before=deepcopy(w.saved)
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.saved==before and 'TERM' not in w.calls


def test_replacement_after_commit_is_refused_without_another_signal():
    w=World();w.runner().run();w.service['start']='foreign'
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.calls.count('TERM')==1


def test_already_exited_original_needs_no_signal():
    w=World();w.alive=False;assert w.runner().run()['exit_verified'] and 'TERM' not in w.calls


@pytest.mark.parametrize('change',['id','container','phase','attempted','receipt','fake-commit'])
def test_inconsistent_intent_refused_before_observation(change):
    w=World()
    if change=='id':w.intent['id']='bad'
    if change=='container':w.intent['service']['container']['id']='bad'
    if change=='phase':w.intent['phase']='ready'
    if change=='attempted':w.intent['attempted']=True
    if change=='receipt':w.intent['receipt']={'exit_verified':True}
    if change=='fake-commit':w.intent['phase']='stopped'
    with pytest.raises(module.JumphostError):w.runner()
    assert w.calls==[]


def test_running_service_after_committed_exit_is_refused_without_signal():
    w=World();w.runner().run();w.alive=True
    with pytest.raises(module.JumphostError):w.runner().run()
    assert w.calls.count('TERM')==1
