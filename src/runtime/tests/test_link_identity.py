import pytest

from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.manifest import Conflict


def record(identity):
    return {'ifname': identity.kernel_name, 'ifindex': 20,
            'altnames': [identity.altname, identity.ownership],
            'linkinfo': {'info_kind': 'vxlan', 'info_data': {'id': identity.vni}}}


def test_long_endpoint_and_lab_scoped_identity():
    a = VxlanIdentity('lab-a', 'link1', 'rt-0123456789ab', 3001)
    b = VxlanIdentity('lab-b', 'link1', a.host_endpoint, 3001)
    assert len(a.kernel_name) == 15
    assert len(a.altname) > 15
    assert a.kernel_name != b.kernel_name and a.ownership != b.ownership
    with pytest.raises(Conflict):
        a.resolve([record(b)])


@pytest.mark.parametrize('field,value', [('ifname', 'foreign'), ('altnames', []), ('ifindex', '20'), ('linkinfo', {'info_kind': 'dummy'})])
def test_name_alone_cannot_authorize_adoption(field, value):
    identity = VxlanIdentity('lab-a', 'link1', 'long-endpoint', 3001)
    link = record(identity)
    link[field] = value
    # Retain one selector so the foreign resource cannot be treated as absent.
    if field == 'ifname':
        assert identity.ownership in link['altnames']
    with pytest.raises(Conflict):
        identity.resolve([link])


def test_duplicate_selector_and_replaced_index_rejected():
    identity = VxlanIdentity('lab-a', 'link1', 'long-endpoint', 3001)
    link = record(identity)
    with pytest.raises(Conflict):
        identity.resolve([link, dict(link)])
    with pytest.raises(Conflict):
        identity.resolve([link], expected_index=21)
    assert identity.resolve([link], expected_index=20) == link
    assert identity.resolve([]) is None


def test_wrong_vni_or_ownership_rejected():
    identity = VxlanIdentity('lab-a', 'link1', 'long-endpoint', 3001)
    link = record(identity)
    link['linkinfo']['info_data']['id'] = 3002
    with pytest.raises(Conflict):
        identity.resolve([link])
    link = record(identity)
    link['altnames'] = [identity.altname, 'dnr-o-foreign']
    with pytest.raises(Conflict):
        identity.resolve([link])


@pytest.mark.parametrize('vni', [0, 16777216, True])
def test_invalid_vni(vni):
    with pytest.raises(Conflict):
        VxlanIdentity('lab-a', 'link1', 'endpoint', vni)
