import yaml

from dnlab_multinode.services.config import parse_topology
from dnlab_multinode.services.scheduler import compute_schedule
from dnlab_multinode.models.schedule import VDResources, HostResources


def test_parse_topology_extracts_realnet_pseudonode(tmp_path):
    hosts = tmp_path / "hosts.yml"
    hosts.write_text("""
infrastructure:
  master:
    host: 10.0.0.10
    ssh_user: root
    ssh_key: ~/.ssh/id
  workers: {}
  underlay_iface: eth0
""")
    topo_file = tmp_path / "topo.yml"
    topo_file.write_text(yaml.safe_dump({
        "name": "lab",
        "topology": {
            "nodes": {
                "r1": {"kind": "linux", "image": "alpine"},
                "real_net1": {
                    "kind": "_real_net",
                    "image": "",
                    "extra": {
                        "ipv4": "192.168.50.1/24",
                        "ospf": True,
                        "nat": False,
                    },
                },
            },
            "links": [
                {"endpoints": ["r1:eth1", "real_net1:real"]},
            ],
        },
    }))

    topo = parse_topology(topo_file, hosts_file=hosts)

    assert "r1" in topo.nodes
    assert "real_net1" not in topo.nodes
    assert topo.real_nets["real_net1"].bgp is True
    assert topo.real_net_links[0].node == "r1"


def test_scheduler_assigns_realnet_link_host(topo_factory):
    from dnlab_multinode.models.topology import RealNet, RealNetLink

    topo = topo_factory(num_workers=0)
    topo.real_nets = {
        "real_net1": RealNet(name="real_net1", ipv4="192.168.50.1/24")
    }
    topo.real_net_links = [
        RealNetLink(real_net="real_net1", node="R1", iface="eth1")
    ]
    vd = {
        name: VDResources(name=name, image=node.image, cpu=1, ram_mb=64)
        for name, node in topo.nodes.items()
    }
    hosts = {
        "master": HostResources(
            name="master", host="10.0.0.10",
            cpu_available=8, ram_mb_available=8192, is_master=True,
        )
    }

    plan = compute_schedule(topo, vd, hosts)

    assert plan.host_for_vd("R1") == "master"
    assert topo.real_net_links[0].host == "master"
    assert topo.real_net_links[0].bridge_iface


class FakeSSH:
    def __init__(self):
        self.commands = []

    def run(self, cmd, check=True):
        self.commands.append(cmd)
        if 'subprocess.check_output' in cmd:
            import json
            return json.dumps({'context':{'boot_id':'fixture','device':1,'inode':2},'links':[]})
        return ""

    def run_no_check(self, cmd):
        self.commands.append(cmd)
        return 0, "", ""


def test_reconciling_one_lab_preserves_existing_shared_route_reflector(topo_factory):
    from dnlab_multinode.services import realnet

    from tests.test_realnet_reflector import ReflectorSSH,configured_topology
    topo=configured_topology(topo_factory);topo.name='lab-b'
    client=ReflectorSSH(realnet._rr_frr_config(topo.realnet_infra)).managed()
    identity=client.container['Id']
    realnet.deploy_route_reflector(topo,client)
    assert client.container['Id']==identity
    assert not client.mutations and not client.uploads


def test_realnet_setup_orders_bridges_before_vxlan_and_adds_forwarding(topo_factory,tmp_path):
    from dnlab_multinode.models.topology import RealNet, RealNetLink
    from dnlab_multinode.services import realnet

    topo = topo_factory(num_workers=1)
    topo.real_nets = {
        "real_net1": RealNet(name="real_net1", ipv4="192.168.50.1/24")
    }
    topo.real_net_links = [
        RealNetLink(real_net="real_net1", node="R1", iface="eth1", host="worker1")
    ]
    clients = {"master": FakeSSH(), "worker1": FakeSSH()}

    realnet.setup_bridges(
        topo, clients, {"master": "10.0.0.10", "worker1": "10.0.0.11"},vni_directory=tmp_path/'vni'
    )

    master_cmds = clients["master"].commands
    bridge_idx = next(i for i, c in enumerate(master_cmds) if "type bridge" in c)
    peer_idx = next(i for i, c in enumerate(master_cmds) if "type vxlan" in c)

    assert bridge_idx < peer_idx
    from dnlab_multinode.utils import naming
    bridge=naming.realnet_bridge_name(topo.name,'real_net1')
    assert any(f"iptables -C FORWARD -i {bridge}" in c for c in master_cmds)
    assert any(f"iptables -C FORWARD -o {bridge}" in c for c in master_cmds)


def test_realnet_destroy_refuses_unqualified_legacy_without_firewall_changes():
    import pytest
    from dnlab_multinode.models.state import RealNetState
    from dnlab_multinode.services import realnet
    from dnlab_multinode.services.realnet_cleanup_host import OwnershipError
    clients={'master':FakeSSH(),'worker1':FakeSSH()}
    state=RealNetState(name='real_net1',bridge='brlabreal',vxlan_id=5001,
                       hosts=list(clients),router_container='dnlab-lab-real_net1-realnet')
    with pytest.raises(OwnershipError,match='explicit qualification'):
        realnet.destroy_realnets('lab',clients,[state])
    assert all(not client.commands for client in clients.values())


def test_realnet_bgp_writes_frr_config(topo_factory,monkeypatch):
    from dnlab_multinode.models.state import RealNetState
    from dnlab_multinode.models.topology import RealNet
    from dnlab_multinode.services import realnet
    from dnlab_multinode.services import realnet_bootstrap
    bootstrap_calls=[]
    def bootstrap(topo,rn,state,master,image,network):
        bootstrap_calls.append((image,network))
        return {'container_id':'a'*64,'wan_ip':rn.bgp_router_ip}
    monkeypatch.setattr(realnet_bootstrap,'bootstrap_router',bootstrap)

    class DeploySSH(FakeSSH):
        def run_no_check(self, cmd):
            self.commands.append(cmd)
            if "docker network inspect" in cmd:
                return 1, "", ""
            return 0, "", ""

        def run(self, cmd, check=True):
            self.commands.append(cmd)
            if ".State.Pid" in cmd:
                return "1234"
            if ".NetworkSettings.Networks" in cmd:
                return "192.168.101.2"
            return ""

    topo = topo_factory(num_workers=0)
    rn = RealNet(
        name="real_net1",
        ipv4="192.168.50.1/24",
        bgp=True,
        bgp_as=64513,
        bgp_router_ip="10.0.0.21",
        bgp_password="router-secret",
    )
    topo.realnet_infra.rr_as = 64512
    topo.realnet_infra.rr_ip = "10.0.0.10"
    topo.realnet_infra.host_net = "10.0.0.0/24"
    topo.realnet_infra.wan_iface = "br-host"
    topo.realnet_infra.rr_password = "rr-secret"
    state = RealNetState(
        name="real_net1",
        bridge="brlabreal",
        vxlan_id=5001,
        hosts=["master"],
        router_container="dnlab-lab-real_net1-realnet",
        lan_ipv4=rn.ipv4,
        bgp=True,
        bgp_as=64513,
        bgp_router_ip="10.0.0.21",
    )

    ssh = DeploySSH()
    deployed = realnet.deploy_router(topo, rn, state, ssh)

    assert deployed.router_wan_ip == "10.0.0.21"
    assert bootstrap_calls[0][1]=='dnlab-realnet-bgp'
    assert any("/etc/frr/frr.conf" in cmd and "router bgp 64512" in cmd for cmd in ssh.commands)
    assert any("neighbor 10.0.0.10 password rr-secret" in cmd for cmd in ssh.commands)
    assert any("neighbor VD password router-secret" in cmd for cmd in ssh.commands)


def _deploy_rr_for_image_test(topo_factory):
    from dnlab_multinode.services import realnet

    from tests.test_realnet_reflector import ReflectorSSH,configured_topology
    topo=configured_topology(topo_factory)
    ssh=ReflectorSSH(realnet._rr_frr_config(topo.realnet_infra),existing=False)
    realnet.deploy_route_reflector(topo,ssh)
    return ssh.commands


def test_realnet_rr_defaults_to_latest_image(monkeypatch, topo_factory):
    monkeypatch.delenv("DNLAB_VERSION", raising=False)
    monkeypatch.delenv("DNLAB_RUNTIME_IMAGE_PREFIX", raising=False)

    commands = _deploy_rr_for_image_test(topo_factory)

    assert any("docker image inspect dnlab-realnet-rr:latest" in cmd for cmd in commands)
    assert any(cmd.endswith('sha256:'+'a'*64) and '--name dnlab-realnet-rr' in cmd for cmd in commands)


def test_realnet_rr_uses_release_image(monkeypatch, topo_factory):
    monkeypatch.setenv("DNLAB_VERSION", "0.1.0")
    monkeypatch.setenv("DNLAB_RUNTIME_IMAGE_PREFIX", "dnlab-")

    commands = _deploy_rr_for_image_test(topo_factory)

    assert any("docker image inspect dnlab-realnet-rr:0.1.0" in cmd for cmd in commands)
    assert any(cmd.endswith('sha256:'+'a'*64) and '--name dnlab-realnet-rr' in cmd for cmd in commands)
    assert not any("dnlab-realnet-rr:latest" in cmd for cmd in commands)


def test_realnet_router_veth_name_is_unique_per_lab():
    from dnlab_multinode.utils import naming

    first = naming.realnet_router_veth_name("1a1fc20b0f7e", "net1")
    second = naming.realnet_router_veth_name("5f9eb562b4ce", "net1")

    assert first.startswith('vh-')
    assert second.startswith('vh-')
    assert first != second
    assert len(first) <= 15
    assert len(second) <= 15


def test_realnet_teardown_retains_unqualified_persisted_names_on_all_hosts():
    import pytest
    from dnlab_multinode.models.state import RealNetState
    from dnlab_multinode.services import realnet
    from dnlab_multinode.services.realnet_cleanup_host import OwnershipError
    clients={'master':FakeSSH(),'worker1':FakeSSH(),'worker2':FakeSSH()}
    state=RealNetState(name='access',bridge='br-persisted',vxlan_id=3001,
                       hosts=list(clients),router_container='router',router_veth='vh-persisted',
                       vxlan_ifaces={'master':['vx-peer-one','vx-peer-two'],
                                     'worker1':['vx-worker-one'],'worker2':['vx-worker-two']})
    with pytest.raises(OwnershipError):realnet.destroy_realnets('lab',clients,[state])
    assert all(not client.commands for client in clients.values())
    assert state.bridge=='br-persisted' and state.router_veth=='vh-persisted'


def test_realnet_lifecycle_reconcile_redeploys_router(monkeypatch, topo_factory):
    from dnlab_multinode.controllers import realnet as realnet_ctrl
    from dnlab_multinode.models.state import DeploymentState, RealNetState
    from dnlab_multinode.models.topology import RealNet

    topo = topo_factory(num_workers=0)
    topo.real_nets = {
        "net1": RealNet(
            name="net1",
            ipv4="100.64.1.1/24",
            nat=False,
            bgp=True,
            bgp_as=64513,
            bgp_router_ip="192.168.10.2",
            bgp_password="router-secret",
        )
    }
    topo.realnet_infra.rr_ip = "192.168.10.1"
    topo.realnet_infra.host_net = "192.168.10.0/24"
    state = DeploymentState(lab_name="lab", topology_file="/tmp/lab.yml")
    state.realnets = [
        RealNetState(
            name="net1",
            bridge="brlabnet1",
            vxlan_id=5001,
            hosts=["master"],
            router_container="dnlab-lab-net1-realnet",
            nat=True,
            bgp=False,
        )
    ]
    calls = []

    class FakeMaster:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def connect(self):
            calls.append(("connect", self.kwargs["host"]))

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(realnet_ctrl, "parse_topology", lambda *a, **k: topo)
    monkeypatch.setattr(realnet_ctrl, "load_state", lambda *a, **k: state)
    monkeypatch.setattr(realnet_ctrl, "save_state", lambda saved, directory: calls.append(("save", saved.lab_name)))
    monkeypatch.setattr(realnet_ctrl, "SSHClient", FakeMaster)
    monkeypatch.setattr(realnet_ctrl.realnet_svc, "deploy_route_reflector", lambda t, c: calls.append(("rr", t.name)))
    monkeypatch.setattr(realnet_ctrl.realnet_svc, "deploy_router", lambda t, rn, rn_state, c: calls.append(("router", rn.name, rn_state.bgp)))

    out = realnet_ctrl.RealNetLifecycleController("/tmp/lab.yml").reconcile("net1")

    assert out is state
    assert ("rr", "lab") in calls
    assert ("router", "net1", True) in calls
    assert ("save", "lab") in calls
    assert state.realnets[0].nat is False
    assert state.realnets[0].bgp is True
    assert state.realnets[0].bgp_as == 64513
