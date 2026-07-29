"""Tests for remote-driver dNLab management network provisioning."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dnlab_multinode.services import mgmt_network


def _actual_network(expected: dict) -> dict:
    configs = [{
        "Subnet": expected["ipv4_subnet"],
        "Gateway": expected["ipv4_gateway"],
    }]
    if expected.get("ipv6_subnet"):
        configs.append({
            "Subnet": expected["ipv6_subnet"],
            "Gateway": expected["ipv6_gateway"],
        })
    return {
        "Driver": expected["driver"],
        "IPAM": {
            "Driver": expected["ipam_driver"],
            "Options": {
                mgmt_network.IPAM_TENANT_OPTION: expected["network"],
                mgmt_network.IPAM_RESERVED_OPTION: ",".join(expected["reserved"]),
                mgmt_network.IPAM_HOST_INDEX_OPTION: str(expected["host_index"]),
                mgmt_network.IPAM_HOST_COUNT_OPTION: str(expected["host_count"]),
            },
            "Config": configs,
        },
        "Options": {
            mgmt_network.BRIDGE_OPTION: expected["bridge"],
            mgmt_network.VRF_OPTION: expected["vrf"],
            mgmt_network.LAB_OPTION: expected["lab"],
        },
        "Labels": expected["labels"],
    }


def test_create_command_uses_single_remote_network_and_ipam_driver(topo_factory):
    topo = topo_factory(name="lab", num_workers=0)
    topo.mgmt.docker_ipv4_gw = "172.20.0.1"

    expected = mgmt_network._expected_network(topo)
    command = mgmt_network._create_network_command(expected)

    assert f"--driver {mgmt_network.NETWORK_DRIVER}" in command
    assert f"--ipam-driver {mgmt_network.IPAM_DRIVER}" in command
    assert f"{mgmt_network.IPAM_TENANT_OPTION}={topo.mgmt.network}" in command
    assert f"{mgmt_network.IPAM_HOST_INDEX_OPTION}=0" in command
    assert f"{mgmt_network.IPAM_HOST_COUNT_OPTION}=1" in command
    assert f"{mgmt_network.BRIDGE_OPTION}={expected['bridge']}" in command
    assert f"{mgmt_network.VRF_OPTION}={expected['vrf']}" in command
    assert f"{mgmt_network.LAB_OPTION}={topo.name}" in command
    assert "com.docker.network.bridge" not in command
    assert "172.20.0.1" in command
    assert command.endswith(topo.mgmt.network)


def test_expected_network_uses_stable_host_partition(topo_factory):
    topo = topo_factory(name="lab", num_workers=1)

    master = mgmt_network._expected_network(topo, "master")
    worker = mgmt_network._expected_network(topo, "worker1")

    assert master["host_index"] == 0
    assert worker["host_index"] == 1
    assert master["host_count"] == worker["host_count"] == 2


def test_ensure_creates_and_verifies_network(monkeypatch, topo_factory):
    topo = topo_factory(name="lab", num_workers=0)
    client = MagicMock(name="master")
    client.name = "master"
    expected = mgmt_network._expected_network(topo)
    observed = []

    monkeypatch.setattr(mgmt_network, "ensure_vrf_plugin", lambda candidate: observed.append(("plugin", candidate.name)))
    inspections = iter([None, _actual_network(expected)])
    monkeypatch.setattr(mgmt_network, "_inspect_network", lambda *_args: next(inspections))

    mgmt_network.ensure_mgmt_network(topo, client)

    assert observed == [("plugin", "master")]
    command = client.run.call_args.args[0]
    assert command.startswith("docker network create")
    assert mgmt_network.IPAM_DRIVER in command
    assert mgmt_network.NETWORK_DRIVER in command


def test_ensure_rejects_existing_network_with_unexpected_ipam(monkeypatch, topo_factory):
    topo = topo_factory(name="lab", num_workers=0)
    client = MagicMock()
    client.name = "master"
    actual = _actual_network(mgmt_network._expected_network(topo))
    actual["IPAM"]["Driver"] = "default"

    monkeypatch.setattr(mgmt_network, "ensure_vrf_plugin", lambda _client: None)
    monkeypatch.setattr(mgmt_network, "_inspect_network", lambda *_args: actual)

    with pytest.raises(mgmt_network.MgmtNetworkError, match="ipam-driver"):
        mgmt_network.ensure_mgmt_network(topo, client)
    client.run.assert_not_called()


def test_destroy_removes_only_exact_dnlab_network(monkeypatch, topo_factory):
    topo = topo_factory(name="lab", num_workers=0)
    client = MagicMock()
    client.name = "master"
    expected = mgmt_network._expected_network(topo)

    monkeypatch.setattr(mgmt_network, "_inspect_network", lambda *_args: _actual_network(expected))
    mgmt_network.destroy_mgmt_network(topo, client)
    assert client.run.call_args.args[0] == f"docker network rm {topo.mgmt.network}"

    client.reset_mock()
    unsafe = _actual_network(expected)
    unsafe["Labels"] = {}
    monkeypatch.setattr(mgmt_network, "_inspect_network", lambda *_args: unsafe)
    mgmt_network.destroy_mgmt_network(topo, client)
    client.run.assert_not_called()


def test_remote_plugin_service_runs_as_stock_docker_extension():
    unit = mgmt_network._service_unit()

    assert "dnlab_vrf_plugin.py" in unit
    assert "Before=docker.service" in unit
    assert "DynamicUser" not in unit
    assert "dnlab-vrf-ipam" not in unit


def test_ensure_plugin_installs_combined_driver_and_removes_legacy_service():
    client = MagicMock()
    client.name = "master"
    client.run_no_check.side_effect = [
        (1, "", ""),
        (1, "", ""),
        (1, "", ""),
        (0, "", ""),
    ]

    mgmt_network.ensure_vrf_plugin(client)

    uploaded = [call.args[0] for call in client.upload_text.call_args_list]
    assert any('"NetworkDriver"' in content and '"IpamDriver"' in content for content in uploaded)
    assert any(content == f"unix://{mgmt_network.PLUGIN_SOCKET}\n" for content in uploaded)
    commands = [call.args[0] for call in client.run.call_args_list]
    assert f"systemctl disable --now dnlab-vrf-ipam.service" in commands
    assert f"systemctl enable --now {mgmt_network.PLUGIN_SERVICE}" in commands
