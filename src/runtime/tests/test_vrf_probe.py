import importlib
from pathlib import Path

import pytest

from dnlab_runtime.manifest import Conflict


@pytest.fixture
def probe(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools'))
    return importlib.import_module('management_vrf_smoke')


@pytest.mark.parametrize('foreign', [None, 'alias', 'type'])
def test_probe_refuses_foreign_or_unproven_host_links(probe, foreign):
    link = {'ifalias': 'owned', 'linkinfo': {'info_kind': 'bridge'}}
    if foreign is None:
        link = None
    elif foreign == 'alias':
        link['ifalias'] = 'another-lab'
    else:
        link['linkinfo']['info_kind'] = 'veth'
    with pytest.raises(Conflict):
        probe.require_link_owner(link, 'owned', 'bridge')


def test_probe_preflight_rejects_plugin_source_drift_before_host_commands(probe, monkeypatch, tmp_path):
    installed, checkout = tmp_path / 'installed.py', tmp_path / 'checkout.py'
    installed.write_text('old plugin')
    checkout.write_text('current plugin')
    monkeypatch.setattr(probe, 'PLUGIN_SOURCE', installed)
    monkeypatch.setattr(probe, 'CHECKOUT_SOURCE', checkout)
    monkeypatch.setattr(probe.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(probe, 'command', lambda *args: pytest.fail('must not mutate or restart service'))
    with pytest.raises(Conflict, match='differs'):
        probe.preflight(None)


@pytest.mark.parametrize('bad', ['mac', 'alias', 'table', 'index'])
def test_creation_gap_recovery_never_adopts_another_host_link(probe, bad):
    intent = {'kind': 'vrf', 'owner': 'owned', 'mac': '02:00:00:00:00:01', 'table': 40000, 'ifindex': 10}
    link = {'address': intent['mac'], 'ifindex': 10, 'linkinfo': {'info_kind': 'vrf', 'info_data': {'table': 40000}}}
    probe.require_creation_identity(link, intent)  # Alias has not been set yet.
    if bad == 'mac':
        link['address'] = '02:00:00:00:00:02'
    elif bad == 'alias':
        link['ifalias'] = 'foreign'
    elif bad == 'table':
        link['linkinfo']['info_data']['table'] = 40001
    else:
        link['ifindex'] = 11
    with pytest.raises(Conflict):
        probe.require_creation_identity(link, intent)
