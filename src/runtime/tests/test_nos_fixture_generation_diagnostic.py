"""Standalone NOS fixture intent, birth, recovery and guarded cleanup regressions."""
import importlib
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
fixture_module=importlib.import_module('nos_fixture')
from dnlab_runtime.backend import Backend,labels,LABEL
from dnlab_runtime.journal import Journal
from dnlab_runtime.stable_management import Handoff,StablePort
from dnlab_runtime.workload_generation import GenerationConflict,latest
from fakes import FakeDocker,FakeLinux,FakeClock


class Docker(FakeDocker):
    def inspect(self,name):
        value=super().inspect(name)
        if value is not None:return value
        return next((deepcopy(c) for c in self.containers.values() if c['Id']==name),None)


@pytest.fixture
def fixture(tmp_path):
    journal=Journal(tmp_path/'state');docker=Docker();clock=FakeClock()
    backend=Backend(docker,FakeLinux(),clock=clock.clock,sleep=clock.sleep)
    request={'lab_id':'nos-fixture','node_id':'cisco_n9kv'}
    spec={'kind':'linux','image':'sha256:'+'a'*64,'container_name':'drsp-nos-fixture','stop_timeout':1}
    config={'Image':spec['image'],'Labels':{**labels(request,spec),'io.dnlab.spike':'nos-fixture'},
            'Env':['FIXTURE_TOKEN=private-fixture-marker'],'HostConfig':{'NetworkMode':'none','PortBindings':{},'Privileged':True}}
    fixture=fixture_module.NosFixture(journal,backend,request,spec)
    yield fixture,journal,backend,config
    journal.close()


def test_complete_original_intent_and_nonce_are_durable_before_create(fixture):
    owner,journal,backend,config=fixture;original=deepcopy(config)
    create=backend.docker.create
    def checked(name,effective):
        intent=owner.get();birth=latest(journal,owner.request)
        assert intent['phase']=='create_pending' and intent['container_id'] is None
        assert intent['original']['config']==original and intent['effective_config']==effective
        assert birth['creator']==intent['id'] and birth['nonce']==effective['Labels'][LABEL+'.birth']
        assert effective['Labels'][LABEL+'.creator']==intent['id']
        assert birth['container_id'] is None
        return create(name,effective)
    backend.docker.create=checked
    identity=owner.create(config)
    assert config==original and latest(journal,owner.request)['container_id']==identity
    assert backend.docker.calls==[('create',owner.spec['container_name'])]
    assert owner.get()['phase']=='bound'
    owner.start()
    port=StablePort(backend,owner.request,owner.spec,'02:da:ab:00:00:03')
    Handoff(journal,backend,owner.request,owner.spec,port,spike_owner='nos-fixture')
    assert port.container()['Id']==identity
    owner.cleanup(force=True)
    assert owner.get()['phase']=='cleaned' and backend.docker.containers=={}
    assert latest(journal,owner.request)['phase']=='cleaned'
    assert journal.db.execute('SELECT count(*) FROM nodes').fetchone()[0]==0


@pytest.mark.parametrize('exists',[False,True])
def test_lost_create_ack_cannot_adopt_or_cleanup_by_name(fixture,exists):
    owner,journal,backend,config=fixture;create=backend.docker.create
    def lost(*args):
        if exists:create(*args)
        raise TimeoutError('create ACK lost')
    backend.docker.create=lost
    with pytest.raises(TimeoutError):owner.create(config)
    original=deepcopy(owner.get());before=list(backend.docker.calls)
    for action in (lambda:owner.create(config),owner.recover,lambda:owner.cleanup(force=True)):
        with pytest.raises(GenerationConflict,match='response unknown'):action()
    assert owner.get()['container_id'] is None
    assert owner.get()['original']==original['original']
    assert backend.docker.calls==before
    assert latest(journal,owner.request)['container_id'] is None


def test_crash_after_recorded_response_binds_original_id_on_reopen(fixture,monkeypatch):
    owner,journal,backend,config=fixture;bind=fixture_module.bind
    def crash(*args):raise SystemExit('before birth bind')
    monkeypatch.setattr(fixture_module,'bind',crash)
    with pytest.raises(SystemExit):owner.create(config)
    value=owner.get();assert value['phase']=='response_recorded' and value['container_id']
    path=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    before=list(backend.docker.calls);journal.close();reopened=Journal(path)
    try:
        monkeypatch.setattr(fixture_module,'bind',bind)
        fresh=fixture_module.NosFixture(reopened,backend,owner.request,owner.spec)
        assert fresh.recover()==value['container_id'] and backend.docker.calls==before
        fresh.start();fresh.cleanup(force=True)
        assert fresh.get()['phase']=='cleaned'
    finally:reopened.close()


def test_recreated_container_same_labels_remains_untouched(fixture):
    owner,journal,backend,config=fixture
    identity=owner.create(config);owner.start()
    container=backend.docker.containers[owner.spec['container_name']]
    container['Id']='foreign-replacement'
    before=list(backend.docker.calls)
    with pytest.raises(GenerationConflict,match='response identity changed'):owner.cleanup(force=True)
    with pytest.raises(GenerationConflict):owner.start()
    assert backend.docker.calls==before and container['State']['Running']
    assert latest(journal,owner.request)['container_id']==identity
    assert owner.get()['phase']=='recovery_required'


def test_lost_start_ack_recovers_same_generation_without_second_start(fixture):
    owner,journal,backend,config=fixture;owner.create(config);start=backend.docker.start
    def lost(identity):start(identity);raise TimeoutError('start ACK lost')
    backend.docker.start=lost
    with pytest.raises(TimeoutError):owner.start()
    assert owner.get()['phase']=='recovery_required'
    before=list(backend.docker.calls);backend.docker.start=start
    owner.recover();owner.start()
    assert backend.docker.calls==before
    owner.cleanup(force=True)


def test_changed_original_configuration_is_rejected_before_mutation(fixture):
    owner,journal,backend,config=fixture;owner.create(config)
    changed=deepcopy(config);changed['Env'].append('OTHER=value')
    before=list(backend.docker.calls)
    with pytest.raises(GenerationConflict,match='request changed'):owner.create(changed)
    assert backend.docker.calls==before
    owner.cleanup(force=True)


def test_storage_failure_before_allocation_never_calls_docker_create(fixture,monkeypatch):
    owner,journal,backend,config=fixture
    def fail():raise OSError('directory sync failed')
    monkeypatch.setattr(owner,'sync',fail)
    with pytest.raises(OSError):owner.create(config)
    assert backend.docker.calls==[] and owner.get()['phase']=='prepared'


def test_recorded_response_sync_failure_still_has_guarded_cleanup(fixture,monkeypatch):
    owner,journal,backend,config=fixture;sync=owner.sync
    def fail():
        if owner.get()['phase']=='response_recorded':raise OSError('response directory sync failed')
        sync()
    monkeypatch.setattr(owner,'sync',fail)
    with pytest.raises(OSError):owner.create(config)
    assert owner.get()['container_id'] and all(c[0]!='start' for c in backend.docker.calls)
    monkeypatch.setattr(owner,'sync',sync)
    owner.cleanup(force=True)
    assert backend.docker.containers=={} and owner.get()['phase']=='cleaned'


def test_cleanup_retry_does_not_restart_after_an_incomplete_remove(fixture,monkeypatch):
    owner,journal,backend,config=fixture;owner.create(config);owner.start()
    remove=backend.docker.remove
    def fail(identity):raise TimeoutError('remove failed')
    monkeypatch.setattr(backend.docker,'remove',fail)
    with pytest.raises(TimeoutError):owner.cleanup(force=True)
    before=list(backend.docker.calls)
    with pytest.raises(GenerationConflict,match='cannot start'):owner.start()
    assert backend.docker.calls==before
    monkeypatch.setattr(backend.docker,'remove',remove);owner.cleanup(force=True)
    assert owner.get()['phase']=='cleaned'
