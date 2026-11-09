"""Tests for jumphost port allocation and range parsing."""

from unittest.mock import MagicMock
from pathlib import Path
import subprocess

import pytest

from dnlab_multinode.services.jumphost import (
    allocate_jumphost_ssh_port,
    deploy_jumphost,
    parse_port_range,
    refresh_jumphost_inventory,
    render_dhcp_config,
)


def test_global_dhcp_renders_dual_stack_reservations_for_every_node(topo_factory):
    from dnlab_multinode.models.topology import VDNode

    nodes = {
        "static": VDNode(name="static", kind="linux", image="alpine", mgmt_ipv4="172.20.0.11", mgmt_ipv6="2001:db8::11", mgmt_mac="02:00:00:00:00:11", mgmt_duid="0001000111111111"),
        "dhcp": VDNode(name="dhcp", kind="linux", image="alpine", mgmt_ipv4="172.20.0.12", mgmt_ipv6="2001:db8::12", mgmt_mac="02:00:00:00:00:12", mgmt_duid="0001000122222222"),
    }
    topo = topo_factory(nodes=nodes, links=[], num_workers=0)
    topo.mgmt.ipv6_subnet = "2001:db8::/64"
    assert render_dhcp_config(topo, "172.20.0.53") == ""

    topo.mgmt.dhcp = True
    config = render_dhcp_config(topo, "172.20.0.53")

    assert "enable-ra" in config
    assert "ra-param=eth1,60,1800" in config
    assert "dhcp-range=set:mgmt,172.20.0.0,static,12h" in config
    assert "dhcp-range=set:mgmt,2001:db8::,static,64,12h" in config
    assert "dhcp-host=02:00:00:00:00:11,172.20.0.11" in config
    assert "dhcp-host=02:00:00:00:00:12,172.20.0.12" in config
    assert "dhcp-host=id:0001000111111111,[2001:db8::11]" in config
    assert "dhcp-host=id:0001000122222222,[2001:db8::12]" in config


def test_ipv4_only_dhcp_configuration_is_preserved(topo_factory):
    from dnlab_multinode.models.topology import VDNode

    topo = topo_factory(nodes={'vd': VDNode(name='vd',kind='linux',image='fixture',
        mgmt_ipv4='172.20.0.11',mgmt_mac='02:00:00:00:00:11')},links=[],num_workers=0)
    topo.mgmt.dhcp = True
    assert render_dhcp_config(topo,'172.20.0.53') == (
        'interface=eth1\nbind-dynamic\ndhcp-authoritative\npid-file=/run/dnlab-dnsmasq.pid\n'
        'dhcp-range=set:mgmt,172.20.0.0,static,12h\n'
        'dhcp-option=tag:mgmt,option:router,172.20.0.1\n'
        'dhcp-option=tag:mgmt,option:dns-server,172.20.0.53\n'
        'dhcp-host=02:00:00:00:00:11,172.20.0.11\n')


def test_parse_port_range_ok():
    assert parse_port_range("2200-2299") == (2200, 2299)
    assert parse_port_range("22-22") == (22, 22)


def test_refresh_jumphost_inventory_updates_maps_without_restart(monkeypatch):
    calls = []
    def guard(*args):
        calls.append(args)
        return {"phase":"active", "container_id":"a"*64, "config":{"generation":"b"*32}}
    monkeypatch.setattr("dnlab_multinode.services.jumphost._guard", guard)
    client = MagicMock()
    refresh_jumphost_inventory("demo", client, {"R1":"runtime1", "R2":"runtime2"}, {
        "runtime1":{"host":"10.0.0.10", "port":23001, "api_key":"secret"},
        "runtime2":{"host":"10.0.0.11", "port":23001, "api_key":"secret"}})
    assert calls[1][2] == "inventory-refresh"
    request = calls[1][3]
    assert request["container_id"] == "a"*64 and request["generation"] == "b"*32
    assert request["vds"] == "R1=runtime1\nR2=runtime2\n"
    assert request["relays"] == "runtime1=10.0.0.10:23001:secret\nruntime2=10.0.0.11:23001:secret\n"
    client.run.assert_not_called()
    client.run_no_check.assert_not_called()


@pytest.mark.parametrize("bad", ["", "2200", "2200-", "-2299", "abc-def", "2300-2200"])
def test_parse_port_range_invalid(bad):
    with pytest.raises(ValueError):
        parse_port_range(bad)


@pytest.mark.parametrize("bad", ["0-100", "100-70000"])
def test_parse_port_range_out_of_bounds(bad):
    with pytest.raises(ValueError):
        parse_port_range(bad)


def _fake_client(ps_output: str):
    """Build a MagicMock SSHClient whose run_no_check returns ps_output."""
    client = MagicMock()
    client.run_no_check.return_value = (0, ps_output, "")
    return client


def test_allocate_port_empty_network():
    """No existing jumphosts → first port in range wins."""
    client = _fake_client("")
    port = allocate_jumphost_ssh_port(client, "0.0.0.0", "2200-2299")
    assert port == 2200


def test_allocate_port_skips_used_on_same_bind_ip():
    """Existing lab jumphost on 2200 → next allocation gets 2201."""
    ps = "dnlab-lab-a-jumphost\t0.0.0.0:2200->22/tcp, :::2200->22/tcp\n"
    client = _fake_client(ps)
    port = allocate_jumphost_ssh_port(client, "0.0.0.0", "2200-2299")
    assert port == 2201


def test_allocate_port_ignores_different_bind_ip():
    """A port claimed on another bind IP does not collide with ours."""
    ps = "dnlab-lab-a-jumphost\t127.0.0.1:2200->22/tcp\n"
    client = _fake_client(ps)
    port = allocate_jumphost_ssh_port(client, "0.0.0.0", "2200-2299")
    assert port == 2200


def test_allocate_port_ignores_non_jumphost_containers():
    """Only `dnlab-*-jumphost` containers count toward the used set."""
    ps = (
        "some-other-container\t0.0.0.0:2200->22/tcp\n"
        "dnlab-lab-b-dns\t0.0.0.0:2201->22/tcp\n"
    )
    client = _fake_client(ps)
    port = allocate_jumphost_ssh_port(client, "0.0.0.0", "2200-2299")
    assert port == 2200


def test_allocate_port_exhausted():
    """Range fully used → RuntimeError with actionable message."""
    # Generate 2200..2204 all taken.
    used_chunks = [
        f"dnlab-lab-{i}-jumphost\t0.0.0.0:{2200+i}->22/tcp"
        for i in range(5)
    ]
    client = _fake_client("\n".join(used_chunks) + "\n")
    with pytest.raises(RuntimeError, match="exhausted"):
        allocate_jumphost_ssh_port(client, "0.0.0.0", "2200-2204")


@pytest.fixture
def guard_deploy(monkeypatch):
    calls = []
    def guard(client, lab, action, config=None):
        calls.append((action, config))
        if action == "read": return {"phase": "absent"}
        assert action == "ensure"
        return {"phase": "active", "container_id": "a"*64, "config": config}
    monkeypatch.setattr("dnlab_multinode.services.jumphost._guard", guard)
    monkeypatch.setattr("dnlab_multinode.services.jumphost.ensure_jumphost_network", lambda *a: None)
    monkeypatch.setattr("dnlab_multinode.services.jumphost.allocate_jumphost_ip", lambda *a: "10.100.0.2/24")
    monkeypatch.setattr("dnlab_multinode.services.jumphost.time.sleep", lambda _: None)
    return calls


def _deploy_client(port_output="0.0.0.0:2200\n"):
    client = MagicMock()
    def check(cmd, *a, **kw):
        if cmd.startswith("docker ps"): return 0, "", ""
        if cmd.startswith("docker port"): return (0, port_output, "") if port_output else (1, "", "missing")
        if "State.Running" in cmd: return 0, "true", ""
        return 0, "", ""
    client.run_no_check.side_effect = check
    return client


def test_deploy_jumphost_with_runtime_relay_attaches_mgmt_network(topo_factory, guard_deploy):
    topo = topo_factory(name="lab"); client = _deploy_client()
    result = deploy_jumphost(topo, client, "172.20.0.254", resolver_ip="10.100.0.2",
        relay_map={"vd": {"host": "10.0.0.11", "port": 23001, "api_key": "secret"}})
    cfg = guard_deploy[-1][1]
    assert cfg["attachment"]["network"] == topo.mgmt.network
    assert cfg["attachment"]["ipv4"] == "172.20.0.254/24"
    assert cfg["dns"] == ["10.100.0.2"]
    assert cfg["env"]["JUMPHOST_RELAY_MAP"] == "vd=10.0.0.11:23001:secret"
    assert result[0] == "dnlab-lab-jumphost"
    client.run.assert_not_called()


def test_deploy_jumphost_verifies_ssh_publish_after_mgmt_attach(topo_factory, guard_deploy):
    client = _deploy_client("127.0.0.1:2200\n")
    deploy_jumphost(topo_factory(), client, "172.20.0.254", ssh_bind_ip="127.0.0.1")
    assert any(call.args[0] == "docker port " + "a"*64 + " 22" for call in client.run_no_check.call_args_list)


def test_deploy_jumphost_retains_journal_when_ssh_publish_disappears(topo_factory, guard_deploy):
    client = _deploy_client("")
    with pytest.raises(RuntimeError, match="did not restore SSH port publishing"):
        deploy_jumphost(topo_factory(), client, "172.20.0.254")
    assert [action for action, cfg in guard_deploy] == ["read", "ensure"]
    client.run.assert_not_called()


def test_deploy_jumphost_retries_transient_ssh_publish_after_mgmt_attach(topo_factory, guard_deploy):
    client = _deploy_client(); original = client.run_no_check.side_effect; checks = []
    def check(cmd, *args, **kwargs):
        if cmd.startswith("docker port"):
            checks.append(cmd)
            if len(checks) == 1: return 1, "", "missing"
        return original(cmd, *args, **kwargs)
    client.run_no_check.side_effect = check
    deploy_jumphost(topo_factory(), client, "172.20.0.254")
    assert len(checks) == 2


def test_vd_log_requires_runtime_relay_for_logical_name():
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    result = subprocess.run(
        [str(script), "log", "R1"],
        env={
            "JUMPHOST_VD_MAP": "R1=clab-dnlab-lab-R1-R1",
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 42
    assert "no runtime relay is configured for 'R1'" in result.stderr
    assert "/var/log/dnlab" not in result.stderr


def test_vd_log_requires_runtime_relay_from_persisted_map(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    vd_file = tmp_path / "dnlab-vds"
    vd_file.write_text("R1=clab-dnlab-lab-R1-R1\n")

    result = subprocess.run(
        [str(script), "log", "R1"],
        env={
            "VD_LIST_FILE": str(vd_file),
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 42
    assert "clab-dnlab-lab-R1-R1" in result.stderr


def test_vd_list_prints_logical_names_from_persisted_map(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    vd_file = tmp_path / "dnlab-vds"
    vd_file.write_text("R1=clab-dnlab-lab-R1-R1\nR2=clab-dnlab-lab-R2-R2\n")

    result = subprocess.run(
        [str(script), "list"],
        env={
            "VD_LIST_FILE": str(vd_file),
            "JUMPHOST_VD_LIST": "R1",
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == ["R1", "R2"]


def test_vd_log_legacy_vd_list_file_format_still_requires_relay(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    vd_file = tmp_path / "dnlab-vds"
    vd_file.write_text("R1\n")

    result = subprocess.run(
        [str(script), "log", "R1"],
        env={
            "VD_LIST_FILE": str(vd_file),
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 42
    assert "no runtime relay is configured for 'R1' (R1)" in result.stderr


def test_vd_completion_prints_short_names_from_persisted_map(tmp_path):
    completion = Path(__file__).resolve().parents[1] / "jumphost" / "vd-completion.bash"
    vd_file = tmp_path / "dnlab-vds"
    vd_file.write_text("R1=clab-dnlab-lab-R1-R1\nR2=clab-dnlab-lab-R2-R2\n")
    script = f"""
        set -e
        source {completion}
        _vd_names
    """

    result = subprocess.run(
        ["bash", "-lc", script],
        env={"VD_LIST_FILE": str(vd_file), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == ["R1", "R2"]


def _fake_vd_relay_client_bin(tmp_path, *, response: str = ""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "relay-request"

    client = bin_dir / "vd-relay-client"
    client.write_text(
        f"""#!/bin/sh
echo "$@" > {marker}
printf '%s' "{response}"
exit 0
"""
    )
    client.chmod(0o755)

    return {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
    }, marker


def test_vd_connect_without_relay_does_not_try_legacy_telnet(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "telnet-called"
    telnet = bin_dir / "telnet"
    telnet.write_text(f"#!/bin/sh\necho called > {marker}\nexit 0\n")
    telnet.chmod(0o755)

    result = subprocess.run(
        [str(script), "connect", "n9kv1"],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 42
    assert result.stdout == ""
    assert "no runtime relay is configured" in result.stderr
    assert not marker.exists()


def test_vd_connect_uses_runtime_relay(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    fake_env, marker = _fake_vd_relay_client_bin(
        tmp_path, response="console ready\n",
    )
    relay_file = tmp_path / "dnlab-relays"
    relay_file.write_text("clab-dnlab-lab-n9kv1-n9kv1=10.0.0.11:23001:secret\n")
    fake_env["JUMPHOST_VD_MAP"] = "n9kv1=clab-dnlab-lab-n9kv1-n9kv1"
    fake_env["VD_RELAY_FILE"] = str(relay_file)

    result = subprocess.run(
        [str(script), "connect", "n9kv1"],
        env=fake_env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "console ready\n"
    assert marker.read_text().strip() == (
        "connect 10.0.0.11 23001 secret clab-dnlab-lab-n9kv1-n9kv1"
    )


def test_vd_log_uses_runtime_relay(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    fake_env, marker = _fake_vd_relay_client_bin(
        tmp_path, response="OK\nlog line\n",
    )
    relay_file = tmp_path / "dnlab-relays"
    relay_file.write_text("clab-dnlab-lab-R1-R1=10.0.0.11:23001:secret\n")
    fake_env["JUMPHOST_VD_MAP"] = "R1=clab-dnlab-lab-R1-R1"
    fake_env["VD_RELAY_FILE"] = str(relay_file)

    result = subprocess.run(
        [str(script), "log", "-f", "R1"],
        env=fake_env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "OK\nlog line\n"
    assert marker.read_text().strip() == (
        "log 10.0.0.11 23001 secret clab-dnlab-lab-R1-R1 200 1"
    )


def test_vd_log_history_uses_runtime_relay_all_tail(tmp_path):
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    fake_env, marker = _fake_vd_relay_client_bin(
        tmp_path, response="OK\nhistory\n",
    )
    relay_file = tmp_path / "dnlab-relays"
    relay_file.write_text("clab-dnlab-lab-R1-R1=10.0.0.11:23001:secret\n")
    fake_env["VD_RELAY_FILE"] = str(relay_file)

    result = subprocess.run(
        [str(script), "log", "clab-dnlab-lab-R1-R1"],
        env=fake_env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "OK\nhistory\n"
    assert marker.read_text().strip() == (
        "log 10.0.0.11 23001 secret clab-dnlab-lab-R1-R1 all 0"
    )


def test_vd_does_not_reference_nc_sed_or_legacy_logs():
    script = Path(__file__).resolve().parents[1] / "jumphost" / "vd"
    body = script.read_text()

    assert " nc " not in body
    assert "sed" not in body
    assert "/var/log/dnlab" not in body
    assert "vd-relay-client" in body


def test_jumphost_image_keeps_telnet_and_python_client():
    dockerfile = Path(__file__).resolve().parents[1] / "jumphost" / "Dockerfile"
    body = dockerfile.read_text()

    assert "telnet" in body
    assert "python3" in body
    assert "COPY vd-relay-client /usr/local/bin/vd-relay-client" in body
