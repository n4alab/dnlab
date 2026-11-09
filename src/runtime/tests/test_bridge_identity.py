from pathlib import Path

import pytest

from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.manifest import Conflict


def bridge(identity):
    return {'ifname':identity.kernel_name,'ifalias':identity.alias,'address':identity.mac,
            'ifindex':20,'linkinfo':{'info_kind':'bridge'}}


def test_bridge_identity_matches_multinode_contract(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2]/'multinode'))
    from dnlab_multinode.utils.naming import runtime_bridge_name
    for lab in ('bridge-lab-a','bridge-lab-b'):
        identity=BridgeIdentity(lab,'l0')
        assert identity.kernel_name==runtime_bridge_name(lab,'l0')
        assert len(identity.kernel_name)<=15
    assert BridgeIdentity('bridge-lab-a','l0').kernel_name!=BridgeIdentity('bridge-lab-b','l0').kernel_name


@pytest.mark.parametrize('field,value',[
    ('ifalias',''),('ifalias','foreign'),('address','02:00:00:00:00:00'),
    ('linkinfo',{'info_kind':'dummy'}),('ifindex',True),
])
def test_bridge_name_alone_does_not_authorize_adoption(field,value):
    identity=BridgeIdentity('lab','l0')
    observed=bridge(identity);observed[field]=value
    with pytest.raises(Conflict):identity.resolve([observed])


def test_bridge_replaced_index_and_duplicate_owner_rejected():
    identity=BridgeIdentity('lab','l0');observed=bridge(identity)
    assert identity.resolve([observed],expected_index=20)==observed
    with pytest.raises(Conflict):identity.resolve([observed],expected_index=21)
    with pytest.raises(Conflict):identity.resolve([observed,{**observed,'ifname':'other'}])
    assert identity.resolve([]) is None
