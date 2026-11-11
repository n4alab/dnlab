"""Recover unused monitors without repeating the completed reload."""

from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation_prestart import retire_unused_monitors
from dnlab_runtime.manifest import Conflict
from test_libvirt_activation_bus_controller import bus_controller, controller, service, install, request_profile


def test_reload_completion_survives_new_prestart_subscription(bus_controller):
    driver, reference, state, data, _ = bus_controller
    state['lost'] = 'manager-reload'
    with pytest.raises(OSError):
        driver.apply_original(reference)
    assert state['calls'] == ['manager-reload']
    retire_unused_monitors(driver, reference)
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_activation_retired_monitors').fetchone()[0] == 1
    bindings = {}
    for index, item in enumerate(reference['items'][1:]):
        unit = item['spec']['unit']
        entry = data['subscriptions'][unit]
        entry['reference']['token'] = format(index + 20, '032x')
        bindings[unit] = driver.monitor.register(entry['request'], entry['reference'])
    driver.bind_monitors(bindings, after_reload=True)
    driver.recover_original(reference)
    state['lost'] = None
    assert driver.apply_original(reference)['phase'] == 'ready_empty'
    assert state['calls'] == ['manager-reload'] + driver.source['profile']['service_order']


def test_prestart_recovery_refuses_any_start_intent(bus_controller):
    driver, reference, state, data, _ = bus_controller
    data['lost'] = driver.source['profile']['service_order'][0]
    with pytest.raises(OSError):
        driver.apply_original(reference)
    original = list(state['calls'])
    with pytest.raises(Conflict, match='start already tracked'):
        retire_unused_monitors(driver, reference)
    assert state['calls'] == original
    assert driver.journal.db.execute('SELECT count(*) FROM libvirt_activation_monitor_bindings').fetchone()[0] == 1


def test_prestart_recovery_requires_original_reload_exit(bus_controller):
    driver, reference, state, _, _ = bus_controller
    with pytest.raises(Conflict, match='completed reload'):
        retire_unused_monitors(driver, reference)
    assert state['calls'] == []
