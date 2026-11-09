from contextlib import nullcontext
import importlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
diagnostics = importlib.import_module('nos_move_diagnostics')


def test_driver_specific_bridge_does_not_fall_back_to_docker_bridge_name():
    network = {'Driver': 'dnlab-vrf', 'Id': 'a'*64, 'Options': {'dnlab.bridge': 'drspbabc'}}
    assert diagnostics.network_bridge(network) == 'drspbabc'
    del network['Options']['dnlab.bridge']
    with pytest.raises(RuntimeError, match='explicit owned bridge'):
        diagnostics.network_bridge(network)
    network['Driver'] = 'bridge'
    assert diagnostics.network_bridge(network) == 'br-' + 'a'*12


def test_passive_capture_follows_resolved_uplink_after_move(tmp_path, monkeypatch):
    observed = []
    class Capture:
        def __init__(self, label, interface, namespace=None):
            observed.append(interface)
    monkeypatch.setattr(diagnostics, 'Headers', Capture)
    network = {'Name': 'red', 'Id': 'network', 'Driver': 'dnlab-vrf', 'Options': {'dnlab.bridge': 'drspbabc'}}
    container = {'NetworkSettings': {'Networks': {'red': {'IPAddress': '192.0.2.30', 'IPPrefixLen': 24, 'Gateway': '192.0.2.1'}}}}
    connections = []
    def uplink(connection):
        connections.append(connection)
        return {'name': 'dnmu0'}
    port = SimpleNamespace(container=lambda:container, uplink=uplink)
    backend = SimpleNamespace(namespace=lambda *args:nullcontext('ns'), linux=SimpleNamespace(link=lambda *args:True))
    helper = diagnostics.Diagnostics(tmp_path, backend, {}, {}, port, [network])
    helper.start_capture('target', network)
    assert observed == ['dnmu0', 'dnlab-mgmt', 'dmu0', 'mgmt0', 'tap0', 'drspbabc']
    assert connections == [{'network_id':'network','network_name':'red','cidr':'192.0.2.30/24','gateway':'192.0.2.1'}]
