"""Read-only management plan and original-observation apply/recovery regression."""
from copy import deepcopy
from pathlib import Path

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from fakes import FakeDocker,FakeLinux


@pytest.fixture
def fixture(tmp_path):
    journal=Journal(tmp_path/'native');docker=FakeDocker();reads=[]
    original=docker.network
    def network(name):reads.append(name);return original(name)
    docker.network=network
    engine=Engine(journal,Backend(docker,FakeLinux()))
    raw={'schema_version':1,'lab_id':'demo','node_id':'R1','action':'start','expected_revision':0,'request_id':'initial',
         'spec':{'kind':'linux','container_name':'native-r1','image':'sha256:'+'a'*64,
                 'management':{'network':'mgmt','ipv4':'192.0.2.2'}}}
    yield engine,journal,docker,raw,reads
    journal.close()


@pytest.mark.parametrize('problem',['missing','foreign_owner','wrong_driver'])
def test_initial_plan_rejects_invalid_management_without_mutation(fixture,problem):
    engine,journal,docker,raw,reads=fixture
    if problem=='missing':docker.networks.clear()
    elif problem=='foreign_owner':docker.networks['mgmt']['Labels']['io.dnlab.lab']='another-lab'
    else:docker.networks['mgmt']['Driver']='bridge'
    changes=journal.db.total_changes
    with pytest.raises(RuntimeErrorBase):engine.plan(raw)
    assert reads==['mgmt'] and docker.calls==[] and journal.db.total_changes==changes


def test_plan_returns_original_proof_without_pinning_or_creating_intent(fixture):
    engine,journal,docker,raw,reads=fixture;changes=journal.db.total_changes
    first=engine.plan(raw);second=engine.plan({**raw,'management_preflight':first['management_preflight']})
    assert first['management_preflight']==second['management_preflight']
    assert first['mutations_performed'] is False and first['affected_nodes']==['R1']
    assert first['management_preflight']['network']['Id']=='mgmt-id'
    assert first['management_preflight']['journal_id']==journal.identity
    assert journal.db.total_changes==changes and docker.calls==[]
    assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
    assert journal.db.execute('SELECT count(*) FROM management_network_proofs').fetchone()[0]==0


def test_management_apply_without_preflight_refuses_before_reserving_resources(fixture):
    engine,journal,docker,raw,_=fixture;changes=journal.db.total_changes
    with pytest.raises(Conflict,match='original preflight'):journal.submit(raw)
    assert journal.db.total_changes==changes and docker.calls==[]


@pytest.mark.parametrize('change',['id','ipam','options'])
def test_first_apply_rejects_drift_since_plan_without_creating_a_pin(fixture,change):
    engine,journal,docker,raw,_=fixture
    proof=engine.plan(raw)['management_preflight'];bound={**raw,'management_preflight':proof}
    operation=journal.submit(bound)
    if change=='id':docker.networks['mgmt']['Id']='replacement'
    elif change=='ipam':docker.networks['mgmt']['IPAM']['Options']={'foreign':'yes'}
    else:docker.networks['mgmt']['Options']={'bridge':'foreign'}
    result=engine.execute(operation['id'])
    assert result['phase']=='recovery_required' and docker.calls==[]
    assert journal.get(operation['id'],private=True)['payload']['management_preflight']==proof
    assert journal.db.execute('SELECT count(*) FROM management_network_proofs').fetchone()[0]==0


def test_recovery_keeps_original_plan_across_reopened_journal(fixture):
    engine,journal,docker,raw,_=fixture;path=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    original=deepcopy(docker.networks['mgmt']);proof=engine.plan(raw)['management_preflight']
    op=journal.submit({**raw,'management_preflight':proof});docker.networks['mgmt']['Id']='replacement'
    assert engine.execute(op['id'])['phase']=='recovery_required';journal.close()
    reopened=Journal(path)
    try:
        recovered=Engine(reopened,Backend(docker,FakeLinux()))
        assert recovered.reconcile(op['id'])['phase']=='recovery_required' and docker.calls==[]
        assert reopened.get(op['id'],private=True)['payload']['management_preflight']==proof
        docker.networks['mgmt']=original
        assert recovered.reconcile(op['id'])['phase']=='completed'
    finally:reopened.close()


@pytest.mark.parametrize('field,value',[('node_id','R2'),('request_id','another'),('expected_revision',1),('lab_generation',2)])
def test_plan_proof_cannot_be_reused_for_another_context(fixture,field,value):
    engine,journal,docker,raw,_=fixture;proof=engine.plan(raw)['management_preflight']
    with pytest.raises(RuntimeErrorBase,match='preflight context'):
        journal.submit({**raw,field:value,'management_preflight':proof})
    assert docker.calls==[]


@pytest.mark.parametrize('case',['outside','gateway','broadcast','invalid_gateway','overlap','missing_pool','ipv6_disabled'])
def test_plan_rejects_unusable_ipam_before_any_mutation(fixture,case):
    engine,journal,docker,raw,_=fixture
    if case=='outside':raw['spec']['management']['ipv4']='198.51.100.2'
    if case=='gateway':raw['spec']['management']['ipv4']='192.0.2.1'
    if case=='broadcast':raw['spec']['management']['ipv4']='192.0.2.255'
    if case=='invalid_gateway':docker.networks['mgmt']['IPAM']['Config'][0]['Gateway']='198.51.100.1'
    if case=='overlap':docker.networks['mgmt']['IPAM']['Config'].append({'Subnet':'192.0.2.0/25','Gateway':'192.0.2.1'})
    if case=='missing_pool':docker.networks['mgmt']['IPAM']['Config']=[]
    if case=='ipv6_disabled':
        docker.networks['mgmt']['EnableIPv6']=False
        raw['spec']['management']['ipv6']='2001:db8::2'
    changes=journal.db.total_changes
    with pytest.raises(Conflict):engine.plan(raw)
    assert journal.db.total_changes==changes and docker.calls==[]


def test_apply_proof_compares_canonical_json_types_not_python_boolean_equality(fixture):
    engine,journal,docker,raw,_=fixture;proof=engine.plan(raw)['management_preflight']
    assert proof['network']['EnableIPv6'] is True
    forged=deepcopy(proof);forged['network']['EnableIPv6']=1
    operation=journal.submit({**raw,'management_preflight':forged})
    assert engine.execute(operation['id'])['phase']=='recovery_required' and docker.calls==[]
