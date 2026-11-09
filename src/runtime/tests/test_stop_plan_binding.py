from dnlab_runtime.manifest import fingerprint
from test_coordinated_stop import stopped_runtime,request
from test_bridge_link_engine import fixture,request as link_request


def test_changed_graph_after_stop_preflight_is_rejected_before_guest_shutdown(stopped_runtime):
    engine,docker,linux=stopped_runtime
    deletion=engine.links.submit(link_request(action='delete',request_id='remove-before-plan'))
    assert engine.links.execute(deletion['id'])['phase']=='completed'
    raw=request();plan=engine.plan(raw)
    assert plan['link_affected_nodes']==['vd1']
    raw['expected_stop_fingerprint']=plan['stop_fingerprint']
    creation=engine.links.submit(link_request(request_id='added-after-plan'))
    assert engine.links.execute(creation['id'])['phase']=='completed'
    before=list(docker.calls);links_before=list(linux.records)
    result=engine.execute(engine.journal.submit(raw)['id'])
    assert result['phase']=='failed' and 'footprint changed' in result['error']
    assert docker.calls==before and docker.inspect('vd1')['State']['Running']
    assert linux.records==links_before and engine.stops.session(result['id']) is None
    assert engine.journal.node('lab','vd1')['state']=='running'


def test_original_fingerprint_allows_verified_stop_and_cleanup(stopped_runtime):
    engine,docker,linux=stopped_runtime
    raw=request();raw['expected_stop_fingerprint']=engine.plan(raw)['stop_fingerprint']
    result=engine.execute(engine.journal.submit(raw)['id'])
    assert result['phase']=='awaiting_link_cleanup'
    assert engine.stops.session(result['id'])['owners'].keys()=={'vd1','vd2'}
