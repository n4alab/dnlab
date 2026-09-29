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
    assert "dhcp-host=02:00:00:00:00:11,172.20.0.11" in config
    assert "dhcp-host=02:00:00:00:00:12,172.20.0.12" in config
    assert "dhcp-host=id:0001000111111111,[2001:db8::11]" in config
    assert "dhcp-host=id:0001000122222222,[2001:db8::12]" in config


def test_parse_port_range_ok():
    assert parse_port_range("2200-2299") == (2200, 2299)
    assert parse_port_range("22-22") == (22, 22)


def test_refresh_jumphost_inventory_updates_maps_without_restart():
    client = MagicMock()
    client.run_no_check.return_value = (0, "true", "")

    refresh_jumphost_inventory(
        "demo", client,
        {"R1": "clab-dnlab-demo-R1-R1", "R2": "clab-dnlab-demo-R2-R2"},
        {
            "clab-dnlab-demo-R1-R1": {
                "host": "10.0.0.10", "port": 23001, "api_key": "secret",
            },
            "clab-dnlab-demo-R2-R2": {
                "host": "10.0.0.11", "port": 23001, "api_key": "secret",
            },
        },
    )

    command = client.run.call_args.args[0]
    assert command.startswith("docker exec dnlab-demo-jumphost sh -c ")
    assert "clab-dnlab-demo-R2-R2" in command
    assert "10.0.0.11:23001:secret" in command
    assert "mv /etc/dnlab-vds.new /etc/dnlab-vds" in command
    assert "docker rm" not in command


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


def test_deploy_jumphost_with_runtime_relay_attaches_mgmt_network(topo_factory):
    topo = topo_factory(name="lab")
    client = MagicMock()

    def run_no_check(cmd, *_, **__):
        if cmd.startswith("docker ps"):
            return 0, "", ""
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker network inspect -f" in cmd and topo.jumphost_net.network in cmd:
            if ".IPAM.Config" in cmd:
                return 0, topo.jumphost_net.ipv4_subnet, ""
            if ".Containers" in cmd:
                return 0, "", ""
        if "docker inspect -f" in cmd:
            return 0, "true", ""
        if cmd.startswith("docker port dnlab-lab-jumphost 22"):
            return 0, "0.0.0.0:2200\n", ""
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    client.run.return_value = ""

    deploy_jumphost(
        topo,
        client,
        "172.20.0.254",
        resolver_ip="10.100.0.2",
        relay_map={"clab-dnlab-lab-R1-R1": {"host": "10.0.0.11", "port": 23001, "api_key": "secret"}},
    )

    commands = "\n".join(call.args[0] for call in client.run.call_args_list if call.args)
    assert f"--network {topo.jumphost_net.network}" in commands
    assert "ip link add jh-lab type veth peer name jhc-lab" in commands
    assert "nsenter -t \"$pid\" -n ip addr add 172.20.0.254/24 dev eth1" in commands
    assert "docker network connect --ip 172.20.0.254" not in commands


def test_deploy_jumphost_verifies_ssh_publish_after_mgmt_attach(topo_factory):
    topo = topo_factory(name="lab")
    client = MagicMock()

    def run_no_check(cmd, *_, **__):
        if cmd.startswith("docker ps"):
            return 0, "", ""
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker network inspect -f" in cmd and topo.jumphost_net.network in cmd:
            if ".IPAM.Config" in cmd:
                return 0, topo.jumphost_net.ipv4_subnet, ""
            if ".Containers" in cmd:
                return 0, "", ""
        if "docker inspect -f" in cmd:
            return 0, "true", ""
        if cmd.startswith("docker port dnlab-lab-jumphost 22"):
            return 0, "127.0.0.1:2200\n", ""
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    client.run.return_value = ""

    deploy_jumphost(
        topo,
        client,
        "172.20.0.254",
        ssh_bind_ip="127.0.0.1",
    )

    assert any(
        call.args[0] == "docker port dnlab-lab-jumphost 22"
        for call in client.run_no_check.call_args_list
        if call.args
    )


def test_deploy_jumphost_cleans_up_when_ssh_publish_disappears(topo_factory, monkeypatch):
    topo = topo_factory(name="lab")
    client = MagicMock()
    monkeypatch.setattr("dnlab_multinode.services.jumphost.time.sleep", lambda _: None)

    def run_no_check(cmd, *_, **__):
        if cmd.startswith("docker ps"):
            return 0, "", ""
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker network inspect -f" in cmd and topo.jumphost_net.network in cmd:
            if ".IPAM.Config" in cmd:
                return 0, topo.jumphost_net.ipv4_subnet, ""
            if ".Containers" in cmd:
                return 0, "", ""
        if "docker inspect -f" in cmd:
            return 0, "true", ""
        if cmd.startswith("docker port dnlab-lab-jumphost 22"):
            return 1, "", "no public port '22' published"
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    client.run.return_value = ""

    with pytest.raises(RuntimeError, match="did not restore SSH port publishing"):
        deploy_jumphost(topo, client, "172.20.0.254")

    cleanup_cmd = "docker rm -f dnlab-lab-jumphost 2>/dev/null"
    commands = [call.args[0] for call in client.run.call_args_list if call.args]
    assert commands.count(cleanup_cmd) == 2


def test_deploy_jumphost_retries_transient_ssh_publish_after_mgmt_attach(topo_factory, monkeypatch):
    topo = topo_factory(name="lab")
    client = MagicMock()
    monkeypatch.setattr("dnlab_multinode.services.jumphost.time.sleep", lambda _: None)
    port_checks = 0

    def run_no_check(cmd, *_, **__):
        nonlocal port_checks
        if cmd.startswith("docker ps"):
            return 0, "", ""
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker network inspect -f" in cmd and topo.jumphost_net.network in cmd:
            if ".IPAM.Config" in cmd:
                return 0, topo.jumphost_net.ipv4_subnet, ""
            if ".Containers" in cmd:
                return 0, "", ""
        if cmd.startswith("docker port dnlab-lab-jumphost 22"):
            port_checks += 1
            if port_checks == 1:
                return 1, "", "no public port '22' published"
            return 0, "0.0.0.0:2200\n", ""
        if "docker inspect -f" in cmd:
            return 0, "true", ""
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    client.run.return_value = ""

    deploy_jumphost(topo, client, "172.20.0.254")

    assert port_checks == 2


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
