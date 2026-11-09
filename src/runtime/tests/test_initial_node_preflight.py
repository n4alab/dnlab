"""Initial batch admission needs an absent-node view without weakening inspect."""
import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, fingerprint
from fakes import FakeDocker, FakeLinux


@pytest.fixture
def fixture(tmp_path):
    journal=Journal(tmp_path/'state');docker=FakeDocker()
    engine=Engine(journal,Backend(docker,FakeLinux()))
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'initial',
             'action':'start','expected_revision':0,'spec':{'kind':'linux',
             'container_name':'native-r1','image':'sha256:'+'a'*64}}
    yield engine,journal,docker,request
    journal.close()


def test_fresh_preflight_is_read_only_and_request_bound(fixture):
    engine,journal,docker,request=fixture;changes=journal.db.total_changes
    view=engine.plan(request)['node_preflight']
    assert view=={'journal_id':journal.identity,'lab_id':'demo','node_id':'R1',
        'request_fingerprint':fingerprint(request),'revision':0,'committed_state':'absent',
        'container_state':'absent','container_id':None,'pending_operation_id':None,'workload_phase':None}
    assert journal.db.total_changes==changes and docker.calls==[]


def test_pending_request_is_visible_before_any_workload_birth(fixture):
    engine,journal,docker,request=fixture
    op=journal.submit(request);changes=journal.db.total_changes
    view=engine.plan(request)['node_preflight']
    assert view['pending_operation_id']==op['id'] and view['container_state']=='absent'
    assert journal.db.total_changes==changes and docker.calls==[]


def test_metadata_change_during_remote_observation_refuses_mixed_snapshot(fixture,monkeypatch):
    engine,journal,docker,request=fixture;original=engine.backend.inspect
    def inspect(*args):
        result=original(*args)
        journal.submit(request)
        return result
    monkeypatch.setattr(engine.backend,'inspect',inspect)
    with pytest.raises(Conflict,match='changed during read-only planning'):
        engine.plan(request)
    assert docker.calls==[]
