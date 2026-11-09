"""Original replacement regressions, now exercised through the durable host guard."""
import copy
from unittest.mock import MagicMock
from types import SimpleNamespace
import pytest
from tests.test_management_network_host import fixture
from dnlab_multinode.services import mgmt_network,netsetup


def replacement(fixture,monkeypatch):
    h,w,d,g=fixture;g.operate('ensure');old=next(iter(d.networks));value=copy.deepcopy(d.networks[old]);d.remove_external(old)
    value['Id']='b'*64;d.networks[value['Id']]=value
    monkeypatch.setattr(mgmt_network,'_qualified_context',lambda *args:{})
    monkeypatch.setattr(netsetup,'network_action',lambda state,clients,action,**kwargs:g.operate(action))
    return SimpleNamespace(name='breakout-alpha'),MagicMock(),d


def test_network_recreated_with_same_name_labels_and_config_is_not_silently_reused(fixture,monkeypatch):
    topo,client,d=replacement(fixture,monkeypatch)
    with pytest.raises(mgmt_network.MgmtNetworkError,match='replaced'):mgmt_network.ensure_mgmt_network(topo,client,state=object())
    assert len(d.calls)==1


def test_cleanup_does_not_remove_replacement_network_after_prior_ensure(fixture,monkeypatch):
    topo,client,d=replacement(fixture,monkeypatch)
    with pytest.raises(mgmt_network.MgmtNetworkError,match='replaced'):mgmt_network.destroy_mgmt_network(topo,client,state=object())
    assert len(d.calls)==1 and 'b'*64 in d.networks
