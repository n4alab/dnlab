"""Boot, exit and retirement composition; all host/SDK effects are inert."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition_retirement import StoppedDefinitionRetirement
from dnlab_runtime.vm_shutdown import stopped_proof
from test_vm_shutdown import shutdown, boot, pipeline, event_boot, creation, process, observer, definition, template, instance


@pytest.fixture
def stopped(shutdown):
    e = shutdown
    with e.process.exit_witness(e.running['birth']) as witness:
        e.control['witness'] = witness
        e.driver.prepare(e.operation,e.p.events.operation,witness)
        e.driver.apply(e.operation,witness)
    definitions = e.driver.definitions
    domain = e.p.events.state['domains'][e.running['birth']['uuid']]
    domain.autostart = lambda:0
    domain.hasManagedSaveImage = lambda flags:0
    domain.snapshotNum = lambda flags:0
    domain.checkpointCount = lambda:0
    e.control['undefines'] = 0
    def undefine(flags):
        assert flags == 0
        e.control['undefines'] += 1
        e.p.events.state['domains'].pop(e.running['birth']['uuid'])
        if e.control.get('lost_undefine'):raise OSError('lost undefine reply')
        return 0
    domain.undefineFlags = undefine
    def preflight(current):
        return dict(definition_sha256=current.get('retirement',{}).get('definition_sha256',fingerprint(current)),
            session_sha256=current['session_sha256'],never_started=False,
            shutdown_sha256=fingerprint(e.driver.read(e.operation)),writers_absent=True,resources_unchanged=True)
    e.retire = StoppedDefinitionRetirement(definitions,preflight=preflight)
    return e


def test_stopped_retirement_preserves_boot_exit_and_resources(stopped):
    e = stopped;definitions = e.driver.definitions
    reservations = [tuple(row) for row in definitions.journal.db.execute('SELECT * FROM resources ORDER BY key')]
    receipt = deepcopy(e.driver.read(e.operation))
    e.retire.prepare('retire-stopped',e.p.events.operation)
    result = e.retire.apply('retire-stopped')
    assert result['phase'] == 'retired' and result['proof']['never_started'] is False
    assert result['definition'] == e.running and result['shutdown'] == receipt
    current = definitions.read(e.p.events.operation)
    assert current['boot'] == e.running['boot']
    assert stopped_proof(definitions,current) == receipt['proof']
    assert e.storage.observe(e.p.events.operation)['phase'] == 'ready'
    assert e.taps.observe(e.p.events.operation)['phase'] == 'retained'
    assert e.retire.apply('retire-stopped') == result
    assert e.retire.prepare('retire-stopped',e.p.events.operation) == result
    assert e.control['undefines'] == 1 and e.control['calls'] == 1
    assert [tuple(row) for row in definitions.journal.db.execute('SELECT * FROM resources ORDER BY key')] == reservations


def test_lost_undefine_reply_uses_original_exit_without_resend(stopped):
    e = stopped;e.control['lost_undefine'] = True
    e.retire.prepare('retire-stopped',e.p.events.operation)
    with pytest.raises(OSError,match='lost undefine'):e.retire.apply('retire-stopped')
    assert e.retire.read('retire-stopped')['phase'] == 'undefine_requested'
    result = e.retire.apply('retire-stopped')
    assert result['phase'] == 'retired' and result['call_ack'] is None
    assert e.control['undefines'] == 1


def test_absence_before_undefine_intent_is_not_adopted(stopped):
    e = stopped
    e.retire.prepare('retire-stopped',e.p.events.operation)
    e.p.events.state['domains'].clear()
    with pytest.raises(RuntimeErrorBase):e.retire.apply('retire-stopped')
    assert e.retire.read('retire-stopped')['phase'] == 'prepared'
    assert e.control['undefines'] == 0


def test_reappearing_retired_domain_blocks_writer_absence(stopped):
    e = stopped;domains = e.p.events.state['domains'];uuid = e.running['birth']['uuid']
    domain = domains[uuid]
    e.retire.prepare('retire-stopped',e.p.events.operation)
    e.retire.apply('retire-stopped');domains[uuid] = domain
    with pytest.raises(RuntimeErrorBase,match='reappeared'):
        stopped_proof(e.driver.definitions,e.driver.definitions.read(e.p.events.operation))
    assert e.control['undefines'] == 1


@pytest.mark.parametrize('fault',['writer','overlay','shutdown','boot'])
def test_changed_original_resources_or_history_prevents_undefine(stopped,fault):
    e = stopped;definitions = e.driver.definitions
    e.retire.prepare('retire-stopped',e.p.events.operation)
    if fault == 'writer':e.control['extra'] = [dict(pid=60000,uids=[1001]*4,gids=[1001]*4,groups=[])]
    elif fault == 'overlay':next(iter(e.files['files'].values()))['identity']['inode'] += 1
    elif fault == 'shutdown':
        value = e.driver.read(e.operation);value['error_type'] = 'changed'
        with definitions.journal.transaction():e.driver._write(value)
    else:
        value = definitions.read(e.p.events.operation);value['boot']['source_id'] = 'other'
        with definitions.journal.transaction():definitions._save(e.p.events.operation,value)
    with pytest.raises(RuntimeErrorBase):e.retire.apply('retire-stopped')
    assert e.control['undefines'] == 0
