"""New boot activation lineage, using only synthetic services and journal."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import SessionActivation
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_activation import activation
from test_libvirt_install import request_profile


def successor(driver, installed, boot='next-boot'):
    current = deepcopy(installed)
    current['context'] = dict(boot_id=boot)
    old = installed.get('postboot', {})
    current['postboot'] = dict(kind='postboot-session-view-v1',
        source_sha256=old.get('source_sha256', fingerprint(installed)),
        qualification_id='qualification-'+boot, recovery_id='recovery-'+boot)
    return current


def complete_old(activation):
    driver, adapter, value, installed = activation
    previous = driver.apply(value['id'])
    adapter.rows.clear()
    return driver, adapter, previous, successor(driver, installed)


def test_successor_records_fresh_commands_preserving_completed_predecessor(activation):
    driver, adapter, previous, current = complete_old(activation)
    value = driver.prepare_successor('next', current, predecessor_id=previous['id'])
    assert value['predecessor'] == dict(id=previous['id'], sha256=fingerprint(previous))
    assert {i['nonce'] for i in previous['items']}.isdisjoint(i['nonce'] for i in value['items'])
    result = driver.apply('next')
    assert result['phase'] == 'ready_empty'
    assert driver.read(previous['id']) == previous
    assert len(adapter.calls) == 8
    reopened = SessionActivation(driver.journal, adapter)
    assert reopened.prepare_successor('next', current, predecessor_id=previous['id']) == result
    assert reopened.apply('next') == result and len(adapter.calls) == 8


@pytest.mark.parametrize('change', ['same-boot', 'pending', 'root', 'persistent', 'profile', 'missing-lineage'])
def test_unqualified_successor_refused_without_actions_or_new_record(activation, change):
    driver, adapter, previous, current = complete_old(activation)
    if change == 'same-boot':current['context'] = deepcopy(previous['installation']['context'])
    elif change == 'pending':
        # A different, still prepared predecessor cannot be skipped.
        current0 = deepcopy(current)
        driver.prepare_successor('pending', current0, predecessor_id=previous['id'])
        previous = driver.read('pending')
        current = successor(driver, current0, 'third-boot')
    elif change == 'root':current['postboot']['source_sha256'] = '0'*64
    elif change == 'persistent':current['items'][0]['proof'] = {'foreign':True}
    elif change == 'profile':current['profile']['service_order'].reverse()
    else:current.pop('postboot')
    before = driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.prepare_successor('refused', current, predecessor_id=previous['id'])
    assert driver.journal.db.total_changes == before and len(adapter.calls) == 4
    with pytest.raises(Conflict, match='missing'):driver.read('refused')


def test_fork_and_same_boot_second_activation_are_refused(activation):
    driver, adapter, previous, current = complete_old(activation)
    driver.prepare_successor('next', current, predecessor_id=previous['id'])
    before = driver.journal.db.total_changes
    for source in (current, successor(driver, current, 'different-boot')):
        with pytest.raises(Conflict, match='reserved'):
            driver.prepare_successor('fork', source, predecessor_id=previous['id'])
    assert driver.journal.db.total_changes == before and len(adapter.calls) == 4


def test_conflict_on_last_target_prevents_successor_metadata(activation):
    driver, adapter, previous, current = complete_old(activation)
    adapter.rows[current['profile']['service_order'][-1]] = {'foreign':'preserve'}
    before = driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.prepare_successor('next', current, predecessor_id=previous['id'])
    assert driver.journal.db.total_changes == before and len(adapter.calls) == 4


def test_lost_response_recovers_only_original_successor_action(activation):
    driver, adapter, previous, current = complete_old(activation)
    value = driver.prepare_successor('next', current, predecessor_id=previous['id'])
    adapter.lost = value['items'][1]['spec']['key']
    with pytest.raises(OSError):driver.apply('next')
    assert driver.read('next')['items'][1]['phase'] == 'requested'
    assert driver.read(previous['id']) == previous
    assert driver.apply('next')['phase'] == 'ready_empty' and len(adapter.calls) == 8


def test_third_boot_extends_exact_completed_lineage(activation):
    driver, adapter, previous, current = complete_old(activation)
    driver.prepare_successor('next', current, predecessor_id=previous['id'])
    second = driver.apply('next')
    adapter.rows.clear()
    third = successor(driver, current, 'third-boot')
    driver.prepare_successor('third', third, predecessor_id='next')
    assert driver.apply('third')['phase'] == 'ready_empty'
    assert driver.read('next') == second and driver.read(previous['id']) == previous
    assert len(adapter.calls) == 12
