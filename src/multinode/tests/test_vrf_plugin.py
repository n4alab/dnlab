"""Unit tests for the dNLab remote Docker network/IPAM driver."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from dnlab_multinode.vrf_plugin import (
    BRIDGE_OPTION,
    GENERIC_OPTIONS_KEY,
    HOST_COUNT_OPTION,
    HOST_INDEX_OPTION,
    IPAMError,
    LAB_OPTION,
    NetworkDriverError,
    PluginStore,
    RESERVED_OPTION,
    TENANT_OPTION,
    VRF_OPTION,
    VRFRequestHandler,
    _endpoint_interface_names,
)


class FakeNetworkOps:
    def __init__(self) -> None:
        self.links: dict[str, str] = {}
        self.validated: list[tuple[str, str]] = []

    def validate_bridge_vrf(self, bridge: str, vrf: str) -> None:
        self.validated.append((bridge, vrf))

    def link_exists(self, name: str) -> bool:
        return name in self.links

    def create_veth(self, host_iface: str, sandbox_iface: str, bridge: str) -> None:
        if self.link_exists(host_iface) or self.link_exists(sandbox_iface):
            raise NetworkDriverError("veth already exists")
        self.links[host_iface] = sandbox_iface
        self.links[sandbox_iface] = host_iface

    def delete_link(self, name: str) -> None:
        peer = self.links.pop(name, None)
        if peer:
            self.links.pop(peer, None)


def _pool_request(tenant: str, pool: str, *, v6: bool = False, reserved: str = "") -> dict:
    return {
        "AddressSpace": "dnlab-vrf-local",
        "Pool": pool,
        "V6": v6,
        "Options": {
            TENANT_OPTION: tenant,
            RESERVED_OPTION: reserved,
        },
    }


def _partitioned_pool_request(
    tenant: str,
    pool: str,
    *,
    host_index: int,
    host_count: int,
) -> dict:
    request = _pool_request(tenant, pool, v6=True)
    request["Options"].update({
        HOST_INDEX_OPTION: str(host_index),
        HOST_COUNT_OPTION: str(host_count),
    })
    return request


def _network_request(
    network_id: str,
    *,
    bridge: str = "br-lab-a",
    vrf: str = "vrf-lab-a",
    lab: str = "lab-a",
    subnet: str = "172.20.20.0/29",
    gateway: str = "172.20.20.1",
) -> dict:
    return {
        "NetworkID": network_id,
        "Options": {
            GENERIC_OPTIONS_KEY: {
                BRIDGE_OPTION: bridge,
                VRF_OPTION: vrf,
                LAB_OPTION: lab,
            },
        },
        "IPv4Data": [{"Pool": subnet, "Gateway": gateway}],
        "IPv6Data": [],
    }


def _endpoint_request(network_id: str, endpoint_id: str, address: str) -> dict:
    return {
        "NetworkID": network_id,
        "EndpointID": endpoint_id,
        "Interface": {
            "Address": address,
            "MacAddress": "02:42:ac:14:14:02",
        },
    }


def test_overlapping_pools_are_isolated_by_tenant(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    first = store.request_pool(_pool_request(
        "lab-a", "172.20.20.0/29", reserved="172.20.20.1,172.20.20.6",
    ))
    second = store.request_pool(_pool_request(
        "lab-b", "172.20.20.0/29", reserved="172.20.20.1,172.20.20.6",
    ))

    assert first["PoolID"] != second["PoolID"]
    assert first["Pool"] == second["Pool"] == "172.20.20.0/29"
    assert store.request_address({"PoolID": first["PoolID"], "Address": "172.20.20.1"})["Address"] == "172.20.20.1/29"
    assert store.request_address({"PoolID": second["PoolID"], "Address": "172.20.20.1"})["Address"] == "172.20.20.1/29"
    assert store.request_address({"PoolID": first["PoolID"]})["Address"] == "172.20.20.2/29"


def test_address_allocation_persists_and_releases(tmp_path):
    path = tmp_path / "state.json"
    first_store = PluginStore(path)
    pool = first_store.request_pool(_pool_request("lab", "198.18.0.0/29"))
    address = first_store.request_address({"PoolID": pool["PoolID"]})["Address"]

    second_store = PluginStore(path)
    with pytest.raises(IPAMError, match="already allocated"):
        second_store.request_address({"PoolID": pool["PoolID"], "Address": address})

    second_store.release_address({"PoolID": pool["PoolID"], "Address": address})
    assert second_store.request_address({"PoolID": pool["PoolID"], "Address": address})["Address"] == address
    second_store.release_pool({"PoolID": pool["PoolID"]})
    with pytest.raises(IPAMError, match="unknown pool"):
        second_store.request_address({"PoolID": pool["PoolID"]})


def test_ipv6_pool_and_reserved_addresses(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    pool = store.request_pool(_pool_request(
        "lab-v6",
        "2001:db8:20::/126",
        v6=True,
        reserved="172.20.20.1,2001:db8:20::1",
    ))

    assert store.request_address({"PoolID": pool["PoolID"]})["Address"] == "2001:db8:20::2/126"


def test_dynamic_ipv6_partitions_are_disjoint_between_hosts(tmp_path):
    first = PluginStore(tmp_path / "host-a.json")
    second = PluginStore(tmp_path / "host-b.json")
    request = ("lab", "2001:db8:20::/120")
    first_pool = first.request_pool(_partitioned_pool_request(*request, host_index=0, host_count=2))
    second_pool = second.request_pool(_partitioned_pool_request(*request, host_index=1, host_count=2))

    first_address = first.request_address({"PoolID": first_pool["PoolID"]})["Address"]
    second_address = second.request_address({"PoolID": second_pool["PoolID"]})["Address"]

    assert first_address == "2001:db8:20::1/120"
    assert second_address == "2001:db8:20::80/120"


def test_invalid_host_partition_is_rejected(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    with pytest.raises(IPAMError, match="host partition"):
        store.request_pool(_partitioned_pool_request(
            "lab", "2001:db8:20::/120", host_index=2, host_count=2,
        ))


def test_invalid_or_duplicate_static_addresses_are_rejected(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    pool = store.request_pool(_pool_request("lab", "198.18.1.0/29"))

    with pytest.raises(IPAMError, match="network address"):
        store.request_address({"PoolID": pool["PoolID"], "Address": "198.18.1.0"})
    with pytest.raises(IPAMError, match="outside pool"):
        store.request_address({"PoolID": pool["PoolID"], "Address": "198.18.2.1"})

    store.request_address({"PoolID": pool["PoolID"], "Address": "198.18.1.2"})
    with pytest.raises(IPAMError, match="already allocated"):
        store.request_address({"PoolID": pool["PoolID"], "Address": "198.18.1.2"})


def test_network_endpoint_join_leave_persists_host_veth(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    ops = FakeNetworkOps()
    store.create_network(_network_request("network-a"), ops)
    store.create_endpoint(_endpoint_request("network-a", "endpoint-a", "172.20.20.2/29"))

    joined = store.join({"NetworkID": "network-a", "EndpointID": "endpoint-a"}, ops)
    host_iface, sandbox_iface = _endpoint_interface_names("network-a", "endpoint-a")

    assert ops.validated == [("br-lab-a", "vrf-lab-a")]
    assert joined == {
        "InterfaceName": {"SrcName": sandbox_iface, "DstPrefix": "eth"},
        "Gateway": "172.20.20.1",
    }
    assert ops.links[host_iface] == sandbox_iface
    persisted = json.loads((tmp_path / "state.json").read_text())
    assert persisted["endpoints"]["endpoint-a"]["host_iface"] == host_iface
    assert len(host_iface) <= 15
    assert len(sandbox_iface) <= 15

    store.leave({"NetworkID": "network-a", "EndpointID": "endpoint-a"}, ops)
    assert host_iface not in ops.links
    persisted = json.loads((tmp_path / "state.json").read_text())
    assert persisted["endpoints"]["endpoint-a"]["host_iface"] == ""


def test_same_subnet_networks_keep_endpoint_state_separate(tmp_path):
    store = PluginStore(tmp_path / "state.json")
    ops = FakeNetworkOps()
    store.create_network(_network_request("network-a"), ops)
    store.create_network(_network_request(
        "network-b", bridge="br-lab-b", vrf="vrf-lab-b", lab="lab-b",
    ), ops)
    store.create_endpoint(_endpoint_request("network-a", "endpoint-a", "172.20.20.2/29"))
    store.create_endpoint(_endpoint_request("network-b", "endpoint-b", "172.20.20.2/29"))

    store.join({"NetworkID": "network-a", "EndpointID": "endpoint-a"}, ops)
    store.join({"NetworkID": "network-b", "EndpointID": "endpoint-b"}, ops)
    ops.links["foreign0"] = "foreign1"
    ops.links["foreign1"] = "foreign0"

    first_host, _ = _endpoint_interface_names("network-a", "endpoint-a")
    second_host, _ = _endpoint_interface_names("network-b", "endpoint-b")
    assert first_host != second_host
    assert first_host in ops.links
    assert second_host in ops.links

    store.delete_network({"NetworkID": "network-a"}, ops)
    assert first_host not in ops.links
    assert second_host in ops.links
    assert "foreign0" in ops.links
    persisted = json.loads((tmp_path / "state.json").read_text())
    assert "network-a" not in persisted["networks"]
    assert "endpoint-a" not in persisted["endpoints"]


def test_network_config_requires_existing_bridge_vrf_contract(tmp_path):
    class RejectingOps(FakeNetworkOps):
        def validate_bridge_vrf(self, bridge: str, vrf: str) -> None:
            raise NetworkDriverError(f"bridge {bridge} is not enslaved to VRF {vrf}")

    store = PluginStore(tmp_path / "state.json")
    with pytest.raises(NetworkDriverError, match="not enslaved"):
        store.create_network(_network_request("network-a"), RejectingOps())


def test_docker_plugin_dispatches_network_and_ipam_apis(tmp_path):
    handler = object.__new__(VRFRequestHandler)
    handler.server = SimpleNamespace(
        store=PluginStore(tmp_path / "state.json"),
        ops=FakeNetworkOps(),
    )

    handler.path = "/Plugin.Activate"
    assert handler._dispatch({}) == {"Implements": ["NetworkDriver", "IpamDriver"]}

    handler.path = "/IpamDriver.RequestPool"
    pool = handler._dispatch(_pool_request("lab", "198.18.2.0/29", reserved="198.18.2.1"))
    assert pool["Pool"] == "198.18.2.0/29"

    handler.path = "/IpamDriver.RequestAddress"
    address = handler._dispatch({"PoolID": pool["PoolID"]})
    assert address["Address"] == "198.18.2.2/29"

    handler.path = "/NetworkDriver.CreateNetwork"
    assert handler._dispatch(_network_request("network-a")) == {}
    handler.path = "/NetworkDriver.CreateEndpoint"
    assert handler._dispatch(_endpoint_request("network-a", "endpoint-a", "172.20.20.2/29")) == {}
    handler.path = "/NetworkDriver.Join"
    joined = handler._dispatch({"NetworkID": "network-a", "EndpointID": "endpoint-a"})
    assert joined["InterfaceName"]["DstPrefix"] == "eth"
