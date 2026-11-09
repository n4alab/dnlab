"""Static diagnostic of emitted range filters, not a wire/RFC compliance test.

Dnsmasq's primary manual: tag:<name> matches an existing transaction tag;
set:<name> on the selected range sets it. IPv4 range selection is not a
precondition for an independent DHCPv6 request. Restrict this check to the
renderer subset under investigation, not to dnsmasq's entire tag language.
https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
"""
import ipaddress
import pytest

from dnlab_multinode.models.topology import VDNode
from dnlab_multinode.services.jumphost import render_dhcp_config


def eligible_rendered_ranges(content,family,transaction_tags):
    assert not any(line.startswith('tag-if=') for line in content.splitlines()), 'extend diagnostic for tag-if semantics'
    result=[]
    for line in content.splitlines():
        if not line.startswith('dhcp-range='):continue
        fields=line.split('=',1)[1].split(',');required=set()
        while fields and fields[0].startswith(('tag:','set:')):
            value=fields.pop(0)
            if value.startswith('tag:'):required.add(value[4:])
        if fields and ipaddress.ip_address(fields[0]).version==family and required<=transaction_tags:
            result.append(line)
    return result


def rendered(topo_factory, subnet='2001:db8:1::/64'):
    topo=topo_factory(nodes={'vd':VDNode(name='vd',kind='linux',image='fixture',mgmt_ipv4='172.20.0.11',
        mgmt_ipv6='2001:db8:1::11',mgmt_mac='02:00:00:00:00:11',
        mgmt_duid='00:04:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:11')},links=[],num_workers=0)
    topo.mgmt.dhcp=True;topo.mgmt.ipv6_subnet=subnet;topo.mgmt.ipv6_gw='2001:db8:1::fe'
    return render_dhcp_config(topo,'172.20.0.53')


def test_ipv4_reservation_has_an_eligible_range_without_a_previous_transaction(topo_factory):
    content=rendered(topo_factory)
    assert eligible_rendered_ranges(content,4,{'eth1','known'})


def test_dhcpv6_reservation_does_not_require_a_tag_from_an_ipv4_transaction(topo_factory):
    content=rendered(topo_factory)
    assert 'dhcp-host=id:' in content and 'enable-ra' in content
    assert not any('set:' in line for line in content.splitlines() if line.startswith('dhcp-host='))
    assert eligible_rendered_ranges(content,6,{'eth1','known'}), (
        'no emitted IPv6 range accepts an independent known DHCPv6 client on eth1; '
        'verify with the pinned dnsmasq image before choosing a correction')


@pytest.mark.parametrize('subnet,expected', [
    ('2001:db8:1::/64','2001:db8:1::,static,64'),
    ('fd42:99::abcd/64','fd42:99::,static,64'),
    ('2001:db8:2::1234/80','2001:db8:2::,static,80'),
])
def test_dhcpv6_range_uses_the_configured_network_not_the_unspecified_address(topo_factory,subnet,expected):
    content=rendered(topo_factory,subnet)
    assert 'dhcp-range=set:mgmt,'+expected+',12h' in content
    assert 'dhcp-range=tag:mgmt,::,' not in content
