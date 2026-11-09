"""Different resource names must not hide a shared RealNet tunnel identifier."""
from dnlab_multinode.models.topology import RealNet,RealNetLink
from dnlab_multinode.services.realnet import setup_bridges
from tests.test_realnet import FakeSSH


def planned_fabric(topo_factory,lab,directory):
    topo=topo_factory(num_workers=1);topo.name=lab
    topo.real_nets={'access':RealNet(name='access',ipv4='192.0.2.1/24')}
    topo.real_net_links=[RealNetLink(real_net='access',node='R1',iface='eth1',host='worker1')]
    clients={'master':FakeSSH(),'worker1':FakeSSH()}
    state=setup_bridges(topo,clients,{'master':'198.18.0.1','worker1':'198.18.0.2'},vni_directory=directory)[0]
    return state,clients


def test_two_labs_on_same_underlay_require_distinct_realnet_tunnel_identity(topo_factory,tmp_path):
    first,_=planned_fabric(topo_factory,'vni-lab-16',tmp_path/'vni')
    second,_=planned_fabric(topo_factory,'vni-lab-54',tmp_path/'vni')
    assert first.bridge!=second.bridge
    assert first.vxlan_ifaces!=second.vxlan_ifaces
    assert first.vxlan_id!=second.vxlan_id,{
        'labs':['vni-lab-16','vni-lab-54'],'vnis':[first.vxlan_id,second.vxlan_id],
        'same_underlay':['198.18.0.1','198.18.0.2'],'same_udp_port':14789,
        'distinct_bridges':[first.bridge,second.bridge]}


def test_multiple_master_peer_devices_do_not_share_kernel_binding(topo_factory,tmp_path):
    import re
    topo=topo_factory(num_workers=2);topo.name='multi-worker-vni'
    topo.real_nets={'access':RealNet(name='access',ipv4='192.0.2.1/24')}
    topo.real_net_links=[RealNetLink(real_net='access',node='R1',iface='eth1',host='worker1'),
                         RealNetLink(real_net='access',node='R2',iface='eth1',host='worker2')]
    clients={host:FakeSSH() for host in ('master','worker1','worker2')}
    setup_bridges(topo,clients,{'master':'198.18.0.1','worker1':'198.18.0.2','worker2':'198.18.0.3'},vni_directory=tmp_path/'vni')
    peers=[]
    for command in clients['master'].commands:
        match=re.search(r'ip link add (\S+) type vxlan id (\d+) remote (\S+) local (\S+) dstport (\d+) dev ([^\s;]+)',command)
        if match:peers.append(match.groups())
    assert len(peers)==2 and peers[0][0]!=peers[1][0] and peers[0][2]!=peers[1][2]
    # Native canary establishes that distinct remote addresses do not permit
    # two devices with the same VNI/local/port/underlay on one host.
    bindings={(vni,local,port,device) for _,vni,remote,local,port,device in peers}
    assert len(bindings)==len(peers),{'master_peer_devices':peers,'kernel_bindings':sorted(bindings)}
