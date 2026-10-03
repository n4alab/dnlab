"""Tests for hosts.yml parsing — focused on the jumphost_net SSH fields."""

from pathlib import Path

import pytest
import yaml

from dnlab_multinode.services.hosts_config import (
    HostsConfigError, _parse_hosts_dict,
)


def _base_raw(**jh_net_overrides) -> dict:
    """Minimal hosts.yml dict with optional jumphost_net overrides."""
    return {
        "infrastructure": {
            "master": {"host": "10.0.0.1", "ssh_user": "root"},
            "workers": {},
            "underlay_iface": "eth0",
            "jumphost_net": {
                "network": "dnlab-jh",
                "bridge": "br-jh",
                "ipv4_subnet": "192.168.100.0/24",
                "ipv4_gw": "192.168.100.1",
                **jh_net_overrides,
            },
        },
    }


def test_ssh_port_range_and_bind_ip_defaults():
    cfg = _parse_hosts_dict(_base_raw())
    assert cfg.jumphost_net.ssh_port_range == "2200-2299"
    assert cfg.jumphost_net.ssh_bind_ip == "0.0.0.0"


def test_ssh_port_range_custom():
    cfg = _parse_hosts_dict(_base_raw(ssh_port_range="3000-3099"))
    assert cfg.jumphost_net.ssh_port_range == "3000-3099"


def test_ssh_bind_ip_custom():
    cfg = _parse_hosts_dict(_base_raw(ssh_bind_ip="10.20.30.40"))
    assert cfg.jumphost_net.ssh_bind_ip == "10.20.30.40"


def test_persistence_defaults_to_local_sticky():
    cfg = _parse_hosts_dict(_base_raw())
    assert cfg.persistence.backend == "local-sticky"
    assert cfg.persistence.root == "/var/lib/docker/dnlab-backups"
    assert cfg.persistence.allow_migration_fallback is True
    assert cfg.persistence.cephfs.mountpoint == "/var/lib/docker/dnlab-backups"


def test_persistence_cephfs_config():
    raw = _base_raw()
    raw["infrastructure"]["persistence"] = {
        "backend": "cephfs",
        "root": "/mnt/dnlab-persist",
        "allow_migration_fallback": False,
        "cephfs": {
            "mountpoint": "/mnt/dnlab-persist",
            "expected_fstype": "ceph,fuseblk",
            "marker": ".shared",
        },
    }
    cfg = _parse_hosts_dict(raw)
    assert cfg.persistence.backend == "cephfs"
    assert cfg.persistence.root == "/mnt/dnlab-persist"
    assert cfg.persistence.allow_migration_fallback is False
    assert cfg.persistence.cephfs.mountpoint == "/mnt/dnlab-persist"
    assert cfg.persistence.cephfs.expected_fstype == "ceph,fuseblk"
    assert cfg.persistence.cephfs.marker == ".shared"


def test_persistence_backend_invalid():
    raw = _base_raw()
    raw["infrastructure"]["persistence"] = {"backend": "nfs"}
    with pytest.raises(HostsConfigError, match="persistence.backend"):
        _parse_hosts_dict(raw)


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", ""])
def test_ssh_bind_ip_invalid(bad):
    with pytest.raises(HostsConfigError, match="ssh_bind_ip"):
        _parse_hosts_dict(_base_raw(ssh_bind_ip=bad))


@pytest.mark.parametrize("bad", ["2200", "abc-def", "-2299", "2200-"])
def test_ssh_port_range_malformed(bad):
    with pytest.raises(HostsConfigError, match="ssh_port_range"):
        _parse_hosts_dict(_base_raw(ssh_port_range=bad))


@pytest.mark.parametrize("bad", ["0-100", "100-70000", "3000-2000"])
def test_ssh_port_range_out_of_bounds(bad):
    with pytest.raises(HostsConfigError, match="ssh_port_range"):
        _parse_hosts_dict(_base_raw(ssh_port_range=bad))


def test_rejects_ignored_per_host_interface():
    raw = _base_raw()
    raw["infrastructure"]["master"]["interface"] = "fabric0"
    with pytest.raises(HostsConfigError, match="underlay_iface"):
        _parse_hosts_dict(raw)


def test_rejects_unknown_nested_key():
    raw = _base_raw()
    raw["infrastructure"]["jumphost_net"]["typo"] = "value"
    with pytest.raises(HostsConfigError, match="unknown key 'typo'"):
        _parse_hosts_dict(raw)


def test_rejects_string_boolean_and_integer_values():
    raw = _base_raw()
    raw["image_sync"] = {"enabled": "false"}
    with pytest.raises(HostsConfigError, match="image_sync.enabled must be a boolean"):
        _parse_hosts_dict(raw)
    raw["image_sync"] = {"enabled": True, "interval_seconds": "300"}
    with pytest.raises(HostsConfigError, match="image_sync.interval_seconds must be an integer"):
        _parse_hosts_dict(raw)


def test_complete_canonical_inventory_is_accepted():
    raw = _base_raw()
    raw["infrastructure"].update({
        "underlay_iface": "infra",
        "webui_ports": {"port_range": "9000-9099", "bind_ip": "127.0.0.1"},
        "realnet": {"wan_iface": "eth1", "rr_as": 64512},
        "persistence": {"backend": "local-sticky"},
    })
    raw.update({
        "defaults": {"mgmt": {"ipv4_subnet": "172.31.0.0/24", "ipv4_gw": "172.31.0.1"}},
        "image_sync": {"enabled": True, "include": ["*"], "exclude": [], "interval_seconds": 300},
        "lab_cleanup": {"enabled": True, "interval_seconds": 300, "grace_seconds": 0, "dry_run": False},
        "follow_the_rabbit": {"max_sessions": 2},
    })
    cfg = _parse_hosts_dict(raw)
    assert cfg.underlay_iface == "infra"
    assert cfg.webui_ports.port_range == "9000-9099"
    assert cfg.follow_the_rabbit.max_sessions == 2


def test_canonical_examples_are_accepted_and_match():
    source_example = Path(__file__).parents[1] / "examples" / "hosts.yml.example"
    root_example = Path(__file__).parents[3] / "hosts.yml.example"
    assert source_example.read_text() == root_example.read_text()
    cfg = _parse_hosts_dict(yaml.safe_load(root_example.read_text()))
    assert cfg.underlay_iface == "eth0"
    assert cfg.jumphost_net.ssh_port_range == "2200-2299"
    assert cfg.image_sync.include == ["*"]
