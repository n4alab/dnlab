"""Record that the current remote driver does not implement port publication."""
from types import SimpleNamespace

import pytest

from dnlab_multinode.vrf_plugin import VRFRequestHandler


class Unused:
    def __getattr__(self,name):raise AssertionError('unexpected external-connectivity implementation: '+name)


@pytest.mark.parametrize('action',['ProgramExternalConnectivity','RevokeExternalConnectivity'])
def test_external_connectivity_currently_acknowledges_without_effect(action):
    handler=object.__new__(VRFRequestHandler)
    handler.path='/NetworkDriver.'+action
    handler.server=SimpleNamespace(store=Unused(),ops=Unused())
    assert handler._dispatch({'NetworkID':'fixture-network','EndpointID':'fixture-endpoint',
        'Options':{'com.docker.network.portmap':[{'Proto':6,'Port':8080,'HostIP':'127.0.0.1','HostPort':8456}]}})=={}
