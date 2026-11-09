import importlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
probe = importlib.import_module('vios_port_mapping')


class QueryConsole:
    def __init__(self, fail=None, wrong=False):
        self.commands = []
        self.fail, self.wrong = fail, wrong

    def send(self, command, timeout):
        self.commands.append((command, timeout))
        index = len(self.commands) - 1
        self.last_command = command
        self.last_response = 'partial CLI output'
        if index == self.fail:
            raise RuntimeError('console prompt timed out')
        slot = index + 1 if self.wrong else index
        return f'GigabitEthernet0/{slot} is down\n Hardware is iGbE, address is 0200.0000.{slot:04x}\nRouter#'


def test_individual_queries_checkpoint_every_port_with_finite_timeout(tmp_path):
    console = QueryConsole()
    result = probe.collect_interface_macs(console, tmp_path, 15)
    assert console.commands == [(f'show interfaces GigabitEthernet0/{i}', 20) for i in range(16)]
    assert len(result) == 16
    path = tmp_path / 'interface-mac-queries.json'
    assert all(row['status'] == 'passed' for row in json.loads(path.read_text()))
    assert path.stat().st_mode & 0o777 == 0o600


def test_timeout_saves_partial_response_and_previous_success_without_retry(tmp_path):
    console = QueryConsole(fail=1)
    with pytest.raises(RuntimeError, match='timed out'):
        probe.collect_interface_macs(console, tmp_path, 15)
    records = json.loads((tmp_path / 'interface-mac-queries.json').read_text())
    assert len(console.commands) == len(records) == 2
    assert records[0]['status'] == 'passed'
    assert records[1]['status'] == 'failed'
    assert records[1]['response'] == 'partial CLI output'
    assert records[1]['error_type'] == 'RuntimeError'


def test_query_rejects_response_for_another_interface(tmp_path):
    with pytest.raises(RuntimeError, match='unexpected interface'):
        probe.collect_interface_macs(QueryConsole(wrong=True), tmp_path, 15)
    records = json.loads((tmp_path / 'interface-mac-queries.json').read_text())
    assert len(records) == 1 and records[0]['status'] == 'failed'
    assert 'GigabitEthernet0/1' in records[0]['response']


def test_guest_hardware_mac_uses_active_address_instead_of_bia():
    output = '''GigabitEthernet0/4 is administratively down, line protocol is down
  Hardware is iGbE, address is 0200.0000.0004 (bia 0200.0000.0099)
  Internet address is 192.0.2.4/24
GigabitEthernet0/8 is administratively down, line protocol is down
  Hardware is iGbE, address is 02:00:00:00:00:08 (bia 0200.0000.0008)
'''
    assert probe.interface_macs(output) == {'GigabitEthernet0/4': '02:00:00:00:00:04', 'GigabitEthernet0/8': '02:00:00:00:00:08'}


@pytest.mark.parametrize('output', ['', 'GigabitEthernet0/4 is down\n Hardware is iGbE, address is 0000.0004', 'GigabitEthernet0/4 is down\n Hardware is iGbE, address is 0200.0000.0004\nGigabitEthernet0/8 is down\n Hardware is iGbE, address is 0200.0000.0004'])
def test_mac_inventory_refuses_absent_invalid_or_duplicated_addresses(output):
    with pytest.raises(RuntimeError):
        probe.interface_macs(output)


def fixture():
    macs = {f'GigabitEthernet0/{index}': f'02:00:00:00:00:{index:02x}' for index in range(16)}
    guest = [{'nics': [f'e1000,netdev=p{index:02d},mac={macs[f"GigabitEthernet0/{index}"]}' for index in range(16)]}]
    return guest, macs


def test_guest_names_correlate_to_every_slot_including_first_middle_last():
    guest, macs = fixture()
    rows = probe.match_slots(guest, macs, 15)
    assert [(rows[index]['linux_iface'], rows[index]['guest_iface'], rows[index]['qemu_backend']) for index in (1, 4, 8, 15)] == [('eth1','GigabitEthernet0/1','p01'),('eth4','GigabitEthernet0/4','p04'),('eth8','GigabitEthernet0/8','p08'),('eth15','GigabitEthernet0/15','p15')]


@pytest.mark.parametrize('bad', ['guest-name','guest-mac','missing-slot','duplicate-slot','missing-mac'])
def test_mismatch_or_ambiguous_inventory_blocks_port_qualification(bad):
    guest, macs = fixture()
    if bad == 'guest-name': macs['GigabitEthernet1/0'] = macs.pop('GigabitEthernet0/4')
    if bad == 'guest-mac': macs['GigabitEthernet0/4'] = '02:00:00:00:00:99'
    if bad == 'missing-slot': guest[0]['nics'].pop()
    if bad == 'duplicate-slot': guest[0]['nics'][4] = guest[0]['nics'][3]
    if bad == 'missing-mac': guest[0]['nics'][4] = 'e1000,netdev=p04'
    with pytest.raises(RuntimeError):
        probe.match_slots(guest, macs, 15)


@pytest.mark.parametrize('slot',[0,1,8,15])
def test_selected_management_mapping_has_one_stable_port(slot):
    guest,macs=fixture()
    rows=probe.match_slots(guest,macs,15,management_slot=slot)
    assert [r['guest_iface'] for r in rows if r['linux_iface']=='mgmt0']==[f'GigabitEthernet0/{slot}']
    assert all(r['linux_iface']==f'eth{i}' for i,r in enumerate(rows) if i!=slot)
