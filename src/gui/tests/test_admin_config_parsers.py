from pathlib import Path

import pytest

from app.services.admin_config.base import ConfigParseError
from app.services.admin_config.devices_parser import parse_devices_config, serialize_devices_config
from app.services.admin_config.hosts_parser import parse_hosts_config, serialize_hosts_config
from app.services.admin_config.paths_parser import parse_paths_config, serialize_paths_config


def test_devices_roundtrip_preserves_metadata_and_webui():
    content = """{
      "_comment": "keep me",
      "defaults": {"type": "router"},
      "vendors": {"linux": {"title": "Linux", "color": "#4A4A4A"}},
      "icons": {"router": "img/devices/router.svg"},
      "kinds": {
        "linux": {
          "label": "Linux",
          "vendor": "linux",
          "type": "router",
          "mgmt_iface": "eth0",
          "webui": [{"scheme": "http", "port": 80, "path": "/", "label": "LuCI"}]
        }
      }
    }"""
    model = parse_devices_config(content, Path("devices.json"), True)
    dumped = serialize_devices_config(model)
    reparsed = parse_devices_config(dumped, Path("devices.json"), True)

    assert reparsed.data.metadata["_comment"] == "keep me"
    assert reparsed.data.kinds[0].webui[0].port == 80


def test_devices_roundtrip_preserves_deploy_kind_and_image_patterns():
    content = """{
      "vendors": {"juniper": {"title": "Juniper", "color": "#84B135"}},
      "icons": {"server": "img/devices/server.svg"},
      "kinds": {
        "juniper_apstra": {
          "label": "Apstra",
          "vendor": "juniper",
          "type": "server",
          "deploy_kind": "generic_vm",
          "image_patterns": ["juniper_apstra"],
          "mgmt_iface": "eth0"
        }
      }
    }"""
    model = parse_devices_config(content, Path("devices.json"), True)
    dumped = serialize_devices_config(model)
    reparsed = parse_devices_config(dumped, Path("devices.json"), True)
    kind = reparsed.data.kinds[0]

    assert kind.kind == "juniper_apstra"
    assert kind.deploy_kind == "generic_vm"
    assert kind.image_patterns == ["juniper_apstra"]


def test_devices_roundtrip_preserves_resource_env_and_mgmt_passthrough():
    content = """{
      "vendors": {"cisco": {"title": "Cisco", "color": "#049fd9"}},
      "icons": {"switch": "img/devices/switch.svg"},
      "kinds": {
        "cisco_c9800cl": {
          "label": "C9800-CL",
          "vendor": "cisco",
          "type": "switch",
          "env": {
            "VCPU": "4",
            "RAM": "18432",
            "CLAB_MGMT_PASSTHROUGH": "true"
          }
        }
      }
    }"""
    model = parse_devices_config(content, Path("devices.json"), True)
    dumped = serialize_devices_config(model)
    reparsed = parse_devices_config(dumped, Path("devices.json"), True)
    env = reparsed.data.kinds[0].extra["env"]

    assert env["VCPU"] == "4"
    assert env["RAM"] == "18432"
    assert env["CLAB_MGMT_PASSTHROUGH"] == "true"


def test_devices_rejects_unknown_vendor():
    content = """{
      "vendors": {"linux": {"title": "Linux", "color": "#4A4A4A"}},
      "icons": {"router": "img/devices/router.svg"},
      "kinds": {"bad": {"label": "Bad", "vendor": "missing", "type": "router"}}
    }"""
    with pytest.raises(ConfigParseError):
        parse_devices_config(content, Path("devices.json"), True)


def test_paths_rejects_relative_known_path():
    model = parse_paths_config("topologies_dir: labs\n", Path("paths.yml"), True)
    with pytest.raises(ConfigParseError):
        serialize_paths_config(model)


def test_paths_parser_knows_dockerization_paths():
    content = """
containerlab_bin: /usr/bin/containerlab
docker_socket: unix:///var/run/docker.sock
topologies_dir: /root/dnlab-topologies
gui_dir: /opt/dnlab-gui
multinode_dir: /opt/dnlab-multinode
image_build_dir: /opt/dnlab-image-build
vrnetlab_dir: /opt/vrnetlab
image_build_workspace: /var/lib/dnlab-image-build
hosts_file: /etc/dnlab/hosts.yml
persist_root: /var/lib/docker/dnlab-backups
ssh_key: /root/.ssh/id_ed25519
gui_ssh_key: /root/.ssh/dnlab-gui.key
image_sync_state: /var/lib/dnlab-image-sync/state.json
lab_cleanup_state: /var/lib/dnlab-lab-cleanup/state.json
log_root: /var/log/dnlab
tmp_dir: /tmp
syslog_mount: /var/log/dnlab
"""
    model = parse_paths_config(content, Path("paths.yml"), True)
    entries = {entry.key: entry for entry in model.data.entries}

    assert entries["gui_dir"].known is True
    assert entries["multinode_dir"].known is True
    assert entries["image_build_dir"].known is True
    assert entries["vrnetlab_dir"].known is True
    assert entries["image_build_workspace"].known is True
    assert entries["lab_cleanup_state"].known is True
    assert entries["log_root"].known is True
    assert entries["tmp_dir"].known is True
    assert entries["syslog_mount"].known is False

    dumped = serialize_paths_config(model)
    assert "image_build_dir: /opt/dnlab-image-build" in dumped
    assert "lab_cleanup_state: /var/lib/dnlab-lab-cleanup/state.json" in dumped
    assert "log_root: /var/log/dnlab" in dumped


def test_paths_parser_marks_backend_paths_as_managed_in_docker_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("DNLAB_MULTINODE_API_URL", "http://dnlab-multinode:8081")
    monkeypatch.setenv("DNLAB_IMAGE_BUILD_API_URL", "http://dnlab-image-build:8082")
    content = f"""
containerlab_bin: {tmp_path}/missing-containerlab
docker_socket: unix://{tmp_path}/missing-docker.sock
multinode_dir: {tmp_path}/missing-multinode
log_root: {tmp_path}/missing-dnlab-log-root
image_build_dir: {tmp_path}/missing-image-build
vrnetlab_dir: {tmp_path}/missing-vrnetlab
image_build_workspace: {tmp_path}/missing-image-build-workspace
image_sync_state: {tmp_path}/missing-image-sync/state.json
lab_cleanup_state: {tmp_path}/missing-lab-cleanup/state.json
"""
    model = parse_paths_config(content, Path("paths.yml"), True)
    entries = {entry.key: entry for entry in model.data.entries}

    assert model.warnings == []
    assert entries["containerlab_bin"].exists is False
    assert entries["containerlab_bin"].scope == "dnlab-multinode"
    assert entries["containerlab_bin"].warning is None
    assert entries["containerlab_bin"].status_label == "managed by dnlab-multinode"
    assert entries["docker_socket"].status_label == "managed by dnlab-multinode"
    assert entries["image_build_workspace"].status_label == "managed by dnlab-image-build"
    assert entries["image_sync_state"].status_label == "state generated by daemon"
    assert entries["lab_cleanup_state"].status_label == "state generated by daemon"
    assert entries["log_root"].scope == "dnlab-stack"
    assert entries["log_root"].status_label == "managed by dNLab stack"


def test_paths_parser_warns_for_missing_paths_in_standalone_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("DNLAB_MULTINODE_API_URL", raising=False)
    monkeypatch.delenv("DNLAB_IMAGE_BUILD_API_URL", raising=False)
    content = f"""
containerlab_bin: {tmp_path}/missing-containerlab
image_build_workspace: {tmp_path}/missing-image-build-workspace
hosts_file: {tmp_path}/missing-hosts.yml
topologies_dir: {tmp_path}/missing-topologies
gui_ssh_key: {tmp_path}/missing-gui.key
"""
    model = parse_paths_config(content, Path("paths.yml"), True)
    entries = {entry.key: entry for entry in model.data.entries}

    assert entries["containerlab_bin"].warning == "path does not exist yet"
    assert entries["image_build_workspace"].warning == "path does not exist yet"
    assert entries["hosts_file"].warning == "path does not exist yet"
    assert entries["topologies_dir"].warning == "path does not exist yet"
    assert entries["gui_ssh_key"].warning == "path does not exist yet"
    assert entries["containerlab_bin"].status_label == "path does not exist yet"


def test_hosts_structured_parse_and_serialize_without_orchestrator_validation():
    content = """
plus:
  follow_the_rabbit:
    max_sessions: 2
infrastructure:
  master:
    host: localhost
    ssh_user: root
  workers:
    worker1:
      host: 10.0.0.11
      ssh_user: dnlab
"""
    model = parse_hosts_config(content, Path("hosts.yml"), True)
    dumped = serialize_hosts_config(model, validate_with_orchestrator=False)

    assert "worker1:" in dumped
    assert "host: 10.0.0.11" in dumped
    assert "follow_the_rabbit:" in dumped
    assert "max_sessions: 2" in dumped


def test_hosts_serializer_normalizes_legacy_aliases():
    content = """
plus:
  follow_the_rabbit:
    max_sessions: 2
infrastructure:
  master: {host: 10.0.0.1}
  workers: {}
  realnet:
    bgp_as: 64512
    lab_as_pool: 64513-64520
"""
    model = parse_hosts_config(content, Path("hosts.yml"), True)
    dumped = serialize_hosts_config(model, validate_with_orchestrator=False)
    assert "rr_as: 64512" in dumped
    assert "router_as_pool: 64513-64520" in dumped
    assert "bgp_as:" not in dumped
    assert "lab_as_pool:" not in dumped
    assert "plus:" not in dumped
    assert "follow_the_rabbit:" in dumped
