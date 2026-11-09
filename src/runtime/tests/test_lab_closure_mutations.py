from copy import deepcopy

import pytest

from dnlab_runtime.lab_closure import control
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.manifest import Conflict
from test_management_authority import managed
from test_bridge_link_engine import fixture,request


def shutdown(node):
    return {'schema_version':1,'lab_id':'lab','node_id':node,'request_id':'stop-'+node,
            'expected_revision':1,'action':'stop','stop_mode':'coordinated'}


def test_management_handoff_is_rejected_before_any_mutation_while_closing(managed):
    handoff,engine,docker,port,spec=managed
    control(engine,'lab','close',{'closure_id':'c'*32,'generation':1,'stops':[shutdown('R1')]})
    before=deepcopy(docker.endpoints);calls=list(docker.calls)
    with pytest.raises(Conflict,match='closing or closed'):
        handoff.submit('late-move','red','198.51.100.2',expected_node_revision=1)
    assert docker.endpoints==before and docker.calls==calls
    assert engine.journal.db.execute('SELECT count(*) FROM management_moves').fetchone()[0]==0


def test_link_and_direct_bridge_creation_cannot_cross_closure(fixture):
    links,linux,engine,verified=fixture
    control(engine,'lab','close',{'closure_id':'c'*32,'generation':1,'stops':[shutdown('vd1'),shutdown('vd2')]})
    before=deepcopy(linux.records);calls=list(linux.calls)
    with pytest.raises(Conflict,match='closing or closed'):links.submit(request())
    with pytest.raises(Conflict,match='closing or closed'):
        links.bridge_manager.create(BridgeIdentity('lab','l0'),sources=deepcopy(linux.records),mtu=1450)
    assert linux.records==before and linux.calls==calls and verified==[]
    assert engine.journal.db.execute('SELECT count(*) FROM link_operations').fetchone()[0]==0
