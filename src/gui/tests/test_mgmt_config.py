import pytest
import yaml

from app.controllers.topology_controller import (
    TopologyController, TopologyValidationError,
)
from app.models.topology import Topology


def test_mgmt_gateways_are_derived_from_subnets(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(path, Topology(name="lab"))

    ctrl.set_mgmt_config_by_path(
        path,
        "lab",
        {
            "ipv4-subnet": "172.20.20.0/24",
            "ipv4-gw": "172.20.20.1",
            "ipv6-subnet": "2001:db8:20::/120",
            "ipv6-gw": "2001:db8:20::1",
            "dhcp": True,
        },
    )

    mgmt = yaml.safe_load(path.read_text())["mgmt"]
    assert mgmt["ipv4-gw"] == "172.20.20.254"
    assert mgmt["ipv6-gw"] == "2001:db8:20::ff"
    assert mgmt["dhcp"] is True


def test_mgmt_ipv6_defaults_from_ipv4_when_empty(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(path, Topology(name="lab"))

    ctrl.set_mgmt_config_by_path(
        path,
        "lab",
        {"ipv4-subnet": "172.20.30.0/24", "ipv6-subnet": ""},
    )

    mgmt = yaml.safe_load(path.read_text())["mgmt"]
    assert mgmt["ipv6-subnet"] == "3fff:172:20:30::/64"
    assert mgmt["ipv6-gw"] == "3fff:172:20:30:ffff:ffff:ffff:ffff"


def test_mgmt_ipv4_mapped_ipv6_is_normalized(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(path, Topology(name="lab"))

    ctrl.set_mgmt_config_by_path(
        path,
        "lab",
        {
            "ipv4-subnet": "172.20.21.0/24",
            "ipv6-subnet": "::ffff:172.20.21.0/120",
        },
    )

    mgmt = yaml.safe_load(path.read_text())["mgmt"]
    assert mgmt["ipv6-subnet"] == "3fff:172:20:21::/64"
    assert mgmt["ipv6-gw"] == "3fff:172:20:21:ffff:ffff:ffff:ffff"


def test_too_small_mgmt_ipv4_subnet_is_rejected(tmp_path):
    path = tmp_path / "lab.yml"
    ctrl = TopologyController()
    ctrl._clab.save_topology_to(path, Topology(name="lab"))

    with pytest.raises(TopologyValidationError):
        ctrl.set_mgmt_config_by_path(
            path,
            "lab",
            {"ipv4-subnet": "172.20.30.0/30"},
        )
