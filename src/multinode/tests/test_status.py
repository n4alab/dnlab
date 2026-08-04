"""Tests for the StatusController (M1.4)."""

from __future__ import annotations

from pathlib import Path

from dnlab_multinode.controllers.status import (
    StatusController, _parse_docker_uptime,
)
from dnlab_multinode.controllers.node import (
    NodeLifecycleController, NodeLifecycleError,
)
from dnlab_multinode.models.state import (
    DeploymentState, HostScheduleState, JumphostState, DnsState,
    NodeRuntimeState, RuntimeRelayState,
)
from dnlab_multinode.services import state as state_svc

from tests.conftest import make_topology


HOSTS_YML = """\
infrastructure:
  master:
    host: 10.0.0.10
    ssh_user: root
    ssh_key: ~/.ssh/id
  workers:
    worker1:
      host: 10.0.0.11
      ssh_user: root
      ssh_key: ~/.ssh/id
    worker2:
      host: 10.0.0.12
      ssh_user: root
      ssh_key: ~/.ssh/id
  underlay_iface: eth0

jumphost:
  image: jh:latest
  host_ip: 192.168.100.1/24

defaults:
  mgmt:
    ipv4_subnet: 172.20.0.0/24
    ipv4_gw: 172.20.0.1
"""


TOPO_YML = """\
name: lab
topology:
  nodes:
    R1:
      kind: linux
      image: alpine
      mgmt-ipv4: 172.20.0.11
    R2:
      kind: linux
      image: alpine
      mgmt-ipv4: 172.20.0.12
  links:
    - endpoints: ["R1:eth1", "R2:eth1"]
"""


def _write_inputs(tmp_path: Path) -> Path:
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(HOSTS_YML)
    topo = tmp_path / "lab.yml"
    topo.write_text(TOPO_YML)
    return topo


def test_status_when_not_deployed(tmp_path):
    topo = _write_inputs(tmp_path)
    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.deployed is False
    assert report.lab_name == "lab"
    assert set(report.hosts) == {"master", "worker1", "worker2"}
    assert set(report.nodes) == {"R1", "R2"}
    for ns in report.nodes.values():
        assert ns.state == "missing"


def test_status_unreachable_hosts_marked(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)

    # Fabricate a deployment state pinning R1→master, R2→worker1.
    st = DeploymentState(lab_name="lab", topology_file=str(topo), deployed_at="2026-01-01")
    st.scheduling = {
        "master": HostScheduleState(
            host="10.0.0.10", topology_file="lab-master.yml",
            vd=["R1"], resources_used={"cpu": 1, "ram_mb": 512},
        ),
        "worker1": HostScheduleState(
            host="10.0.0.11", topology_file="lab-worker1.yml",
            vd=["R2"], resources_used={"cpu": 1, "ram_mb": 512},
        ),
    }
    st.jumphost = JumphostState(
        node="master", container="jh-lab", mgmt_ip="172.20.0.250",
        host_ip="192.168.100.1/24", ext_network="ext-lab",
    )
    st.dns = DnsState(node="master", container="dns-lab", mgmt_ip="172.20.0.2", entries=3)
    st.runtime_relays = {
        "worker1": RuntimeRelayState(
            host="worker1",
            container="dnlab-lab-runtime-relay",
            bind_ip="10.0.0.11",
            port=23042,
            api_key="secret",
            allowed=["clab-dnlab-lab-R2-R2"],
        ),
    }
    state_svc.save_state(st, Path(topo).parent)

    # All SSH connect attempts fail → hosts must be flagged unreachable.
    def _fake_connect(self):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(
        "dnlab_multinode.services.ssh.SSHClient.connect", _fake_connect
    )

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.deployed is True
    assert report.deployed_at == "2026-01-01"
    assert all(not h.reachable for h in report.hosts.values())

    # Scheduling snapshot still surfaces even if hosts are offline.
    assert report.hosts["master"].vd_count == 1
    assert report.hosts["worker1"].cpu_used == 1

    # VDs mapped to unreachable hosts report "unreachable".
    assert report.nodes["R1"].host == "master"
    assert report.nodes["R1"].state == "unreachable"
    assert report.nodes["R2"].host == "worker1"
    assert report.nodes["R2"].state == "unreachable"
    assert report.infra.runtime_relays["worker1"]["container"] == "dnlab-lab-runtime-relay"
    assert report.infra.runtime_relays["worker1"]["allowed"] == 1
    assert report.infra.runtime_relays["worker1"]["running"] is None
    assert report.to_dict()["infra"]["runtime_relays"]["worker1"]["port"] == 23042


def _save_state_with_r1_on(topo: Path, host_name: str) -> None:
    st = DeploymentState(lab_name="lab", topology_file=str(topo), deployed_at="2026-01-01")
    st.scheduling = {
        host_name: HostScheduleState(
            host=f"10.0.0.{11 if host_name == 'worker1' else 12}",
            topology_file=f"lab-{host_name}.yml",
            vd=["R1"],
            resources_used={"cpu": 1, "ram_mb": 512},
        ),
    }
    state_svc.save_state(st, Path(topo).parent)


def _fake_reachable_docker(monkeypatch, containers_by_host: dict[str, str]) -> None:
    def _fake_connect(self):
        self._client = object()

    def _fake_close(self):
        self._client = None

    def _fake_run_no_check(self, command, timeout=30):
        if "docker ps -a" in command:
            return 0, containers_by_host.get(self.name, ""), ""
        if "docker inspect" in command:
            return 1, "", ""
        return 0, "", ""

    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.connect", _fake_connect)
    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.close", _fake_close)
    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.run_no_check", _fake_run_no_check)


def test_status_uses_live_host_when_state_is_stale(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker2")
    _fake_reachable_docker(
        monkeypatch,
        {
            "worker1": "clab-lab-R1\trunning\tUp 3 minutes",
            "worker2": "",
        },
    )

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.nodes["R1"].host == "worker1"
    assert report.nodes["R1"].scheduled_host == "worker2"
    assert report.nodes["R1"].placement_mismatch is True
    assert report.nodes["R1"].state == "running"
    assert report.hosts["worker1"].live_vd_count == 1


def test_status_has_no_mismatch_when_live_matches_state(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker1")
    _fake_reachable_docker(
        monkeypatch,
        {
            "worker1": "clab-lab-R1\trunning\tUp 3 minutes",
            "worker2": "",
        },
    )

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.nodes["R1"].host == "worker1"
    assert report.nodes["R1"].scheduled_host == "worker1"
    assert report.nodes["R1"].placement_mismatch is False
    assert report.nodes["R1"].state == "running"


def test_status_marks_new_node_startable_only_for_per_vd_runtime(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    state = DeploymentState(
        lab_name="lab", topology_file=str(topo), runtime_mode="per-vd",
    )
    state.node_runtime = {
        "R1": NodeRuntimeState(
            node="R1", host="worker1",
            container="clab-dnlab-lab-R1-R1",
            topology_file="/tmp/dnlab-lab-R1-worker1.clab.yml",
        ),
    }
    state.scheduling = {
        "worker1": HostScheduleState(
            host="10.0.0.11", topology_file="", vd=["R1"],
        ),
    }
    state_svc.save_state(state, topo.parent)
    _fake_reachable_docker(monkeypatch, {"worker1": ""})

    report = StatusController(
        str(topo), hosts_file=str(tmp_path / "hosts.yml"),
    ).run()

    assert report.nodes["R2"].state == "missing"
    assert report.nodes["R2"].can_start is True
    assert report.nodes["R1"].can_start is False


def test_status_resolves_new_node_alias_to_live_runtime(tmp_path, monkeypatch):
    hosts = tmp_path / "hosts.yml"
    hosts.write_text(HOSTS_YML)
    topo = tmp_path / "lab.yml"
    topo.write_text("""\
name: lab
topology:
  nodes:
    SERVER:
      kind: linux
      image: alpine
      mgmt-ipv4: 172.20.0.30
  links: []
""")
    state = DeploymentState(
        lab_name="lab", topology_file=str(topo), runtime_mode="per-vd",
    )
    state.node_runtime = {
        "NEW-SERVER": NodeRuntimeState(
            node="NEW-SERVER",
            state="running",
            host="worker1",
            container="clab-dnlab-lab-NEW-SERVER-NEW-SERVER",
            topology_file="/tmp/dnlab-lab-NEW-SERVER-worker1.clab.yml",
            mgmt_ipv4="172.20.0.30",
        ),
    }
    state.scheduling = {
        "worker1": HostScheduleState(
            host="10.0.0.11", topology_file="", vd=["NEW-SERVER"],
        ),
    }
    state_svc.save_state(state, topo.parent)
    _fake_reachable_docker(monkeypatch, {
        "worker1": "clab-dnlab-lab-NEW-SERVER-NEW-SERVER\trunning\tUp 2 minutes",
    })

    report = StatusController(str(topo), hosts_file=str(hosts)).run()

    node = report.nodes["SERVER"]
    assert node.state == "running"
    assert node.container == "clab-dnlab-lab-NEW-SERVER-NEW-SERVER"
    assert node.host == "worker1"


def test_status_preserves_reconciling_over_live_docker_state(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    state = DeploymentState(
        lab_name="lab", topology_file=str(topo), runtime_mode="per-vd",
    )
    state.node_runtime = {
        "R1": NodeRuntimeState(
            node="R1", state="reconciling", host="worker1",
            container="clab-dnlab-lab-R1-R1",
            topology_file="/tmp/dnlab-lab-R1-worker1.clab.yml",
        ),
    }
    state_svc.save_state(state, topo.parent)
    _fake_reachable_docker(monkeypatch, {
        "worker1": "clab-dnlab-lab-R1-R1\trunning\tUp 2 minutes",
    })

    report = StatusController(
        str(topo), hosts_file=str(tmp_path / "hosts.yml"),
    ).run()

    node = report.nodes["R1"]
    assert node.state == "reconciling"
    assert node.operation_active is True
    assert node.can_start is False
    assert node.can_stop is True


def test_legacy_runtime_status_still_finds_legacy_container(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker1")
    commands = []

    def _fake_connect(self):
        self._client = object()

    def _fake_close(self):
        self._client = None

    def _fake_run_no_check(self, command, timeout=30):
        commands.append(command)
        if "docker ps -a" in command:
            return 0, "clab-lab-R1\trunning\tUp 3 minutes", ""
        if "docker inspect" in command:
            return 1, "", ""
        return 0, "", ""

    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.connect", _fake_connect)
    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.close", _fake_close)
    monkeypatch.setattr("dnlab_multinode.services.ssh.SSHClient.run_no_check", _fake_run_no_check)

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.nodes["R1"].state == "running"
    assert report.nodes["R1"].container == "clab-lab-R1"
    assert all("clab-dnlab-lab-" not in command for command in commands)


def test_node_lifecycle_rejects_legacy_per_host_runtime(tmp_path):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker1")

    ctrl = NodeLifecycleController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))

    try:
        ctrl.stop("R1")
    except NodeLifecycleError as exc:
        assert "per-VD runtime" in str(exc)
    else:
        raise AssertionError("legacy runtime stop must be rejected")


def test_status_keeps_missing_when_container_absent_everywhere(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker1")
    _fake_reachable_docker(monkeypatch, {"worker1": "", "worker2": ""})

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.nodes["R1"].host == "worker1"
    assert report.nodes["R1"].scheduled_host == "worker1"
    assert report.nodes["R1"].placement_mismatch is False
    assert report.nodes["R1"].state == "missing"


def test_status_reports_duplicate_container_hosts(tmp_path, monkeypatch):
    topo = _write_inputs(tmp_path)
    _save_state_with_r1_on(topo, "worker2")
    _fake_reachable_docker(
        monkeypatch,
        {
            "worker1": "clab-lab-R1\trunning\tUp 3 minutes",
            "worker2": "clab-lab-R1\trunning\tUp 2 minutes",
        },
    )

    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()

    assert report.nodes["R1"].host == "worker2"
    assert report.nodes["R1"].duplicate_hosts == ["worker1", "worker2"]
    assert report.nodes["R1"].placement_mismatch is True
    assert report.nodes["R1"].state == "running"


def test_status_report_to_dict_is_json_safe(tmp_path):
    import json
    topo = _write_inputs(tmp_path)
    ctrl = StatusController(str(topo), hosts_file=str(tmp_path / "hosts.yml"))
    report = ctrl.run()
    blob = json.dumps(report.to_dict())
    assert '"lab_name": "lab"' in blob
    assert '"deployed": false' in blob


def test_parse_docker_uptime():
    assert _parse_docker_uptime("Up 5 seconds") == 5
    assert _parse_docker_uptime("Up 3 minutes") == 180
    assert _parse_docker_uptime("Up 2 hours") == 7200
    assert _parse_docker_uptime("Up About 1 hour") == 3600
    assert _parse_docker_uptime("Exited (0) 3 minutes ago") == 0
