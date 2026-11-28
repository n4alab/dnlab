"""Separate post-boot retirement of VM/TAP metadata never dispatched.

Historical process proofs remain historical. A trusted current observer must
qualify absence in the new boot; no old PID, libvirt connection or worker is
adopted. Native service restoration is a separate, durably tracked operation.
"""
from copy import deepcopy
import json

from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import require
from vm_prepared_cancellation import prepared_tap_state, closure

TABLE = 'vm_postboot_retirements'


def proof(request, original):
    require(set(request) == {'id', 'nonce', 'original_sha256', 'checkpoint_sha256',
                             'current_context', 'restoration_id'}
            and all(type(request[k]) is str and len(request[k]) == 32
                    and all(c in '0123456789abcdef' for c in request[k])
                    for k in ('id', 'nonce', 'restoration_id'))
            and request['original_sha256'] == fingerprint(original)
            and type(request['checkpoint_sha256']) is str
            and len(request['checkpoint_sha256']) == 64
            and all(c in '0123456789abcdef' for c in request['checkpoint_sha256']),
            'explicit immutable post-boot retirement request required')
    epoch = original['epoch'];current = request['current_context']
    require(type(current) is dict and set(current) == {'boot_id', 'host_id', 'namespaces'}
            and current['host_id'] == epoch['profile']['host_id']
            and type(current['boot_id']) is str and len(current['boot_id']) == 36
            and current['boot_id'] != epoch['snapshot']['record']['boot_id']
            and 'prepared_taps' in original,
            'separate new-boot context and original prepared TAP metadata required')
    require(type(current['namespaces']) is dict
            and set(current['namespaces']) == {'mnt', 'net', 'pid', 'user'}
            and all(type(row) is dict and set(row) == {'device', 'inode'}
                    and all(type(row[k]) is int and row[k] > 0 for k in ('device', 'inode'))
                    for row in current['namespaces'].values()),
            'complete current namespace identities required')
    return dict(request_sha256=fingerprint(request), original_sha256=fingerprint(original),
                checkpoint_sha256=request['checkpoint_sha256'], current_context=deepcopy(current),
                original_boot_ended=True, execution_lock_held=True, checkpoint_verified=True,
                domains_absent=True, directory_absent=True, taps_absent=True,
                original_service_stopped=True, original_service_config_verified=True,
                window_active=True)


def _observe(request, original, observe):
    wanted = proof(request, original);actual = observe()
    require(type(actual) is dict and canonical(actual) == canonical(wanted),
            'qualified post-boot absence/context observation differs')


def _receipt(request, original):
    return dict(retirement_id=request['id'], operation=original['operation'],
                original_sha256=fingerprint(original), history_preserved=True,
                vm_never_created=True, guest_shutdown_claimed=False,
                prepared_tap_count=len(original['prepared_taps']['ifindices']),
                vm_claims_released=True, infrastructure_claim_preserved=True,
                original_process_reused=False)


def _archive(db, request, original):
    row = db.execute('SELECT * FROM '+TABLE+' WHERE id=?', (request['id'],)).fetchone()
    require(row is not None, 'original post-boot retirement archive missing')
    value = json.loads(row['payload'])
    require(set(value) == {'request', 'original', 'receipt', 'phase', 'restoration'}
            and row['operation_id'] == original['operation']
            and row['fingerprint'] == fingerprint(value)
            and value['request'] == request and value['original'] == original
            and value['receipt'] == _receipt(request, original)
            and value['phase'] in ('vm_retired', 'completed')
            and (value['restoration'] is None) == (value['phase'] == 'vm_retired'),
            'original post-boot retirement archive differs')
    return value


def completed_vm(db, request, original):
    proof(request, original);value = _archive(db, request, original)
    definition = json.loads(original['definition']['payload'])
    closed = db.execute('SELECT payload FROM lab_closures WHERE lab=?',
                        (definition['birth']['lab_id'],)).fetchone()
    require(closed is not None and json.loads(closed[0]) == closure(request, original),
            'original post-boot lab closure differs')
    for table in ('vm_definition_intents', 'vm_initial_starts', 'vm_tap_intents'):
        require(db.execute('SELECT 1 FROM '+table+' WHERE id=?',
                           (original['operation'],)).fetchone() is None,
                'retired original VM metadata reappeared')
    require(db.execute('SELECT 1 FROM vm_tap_ifindices WHERE operation_id=?',
                       (original['operation'],)).fetchone() is None,
            'retired original TAP ifindex claim reappeared')
    for claim in original['vm_claims']:
        require(db.execute('SELECT 1 FROM resources WHERE key=?', (claim['key'],)).fetchone() is None,
                'retired original VM resource claim reappeared')
    return deepcopy(value['receipt'])


def retire_vm(db, request, original, *, observe):
    proof(request, original)
    require(callable(observe) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0] == 2,
            'durable original database and current observer required')
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (TABLE,)).fetchone()
    if exists and db.execute('SELECT 1 FROM '+TABLE+' LIMIT 1').fetchone():
        result = completed_vm(db, request, original);_observe(request, original, observe);return result
    db.execute('BEGIN IMMEDIATE')
    try:
        require(prepared_tap_state(db, operation=original['operation'],
                    hold_id=original['infrastructure_claim']['operation_id'], epoch=original['epoch'],
                    session_profile=original['prepared_taps']['session_profile']) == original,
                'original prepared metadata changed before post-boot retirement')
        _observe(request, original, observe)
        db.execute('CREATE TABLE IF NOT EXISTS '+TABLE+' (id TEXT PRIMARY KEY,'
                   'operation_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        archive = dict(request=deepcopy(request), original=deepcopy(original),
                       receipt=_receipt(request, original), phase='vm_retired', restoration=None)
        db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?)',
                   (request['id'], original['operation'], canonical(archive), fingerprint(archive)))
        definition = json.loads(original['definition']['payload'])
        db.execute('INSERT INTO lab_closures VALUES(?,?)',
                   (definition['birth']['lab_id'], canonical(closure(request, original))))
        _observe(request, original, observe)
        for table, key in (('vm_tap_intents', 'intent'), ('vm_initial_starts', 'initial'),
                           ('vm_definition_intents', 'definition')):
            row = original['prepared_taps'][key] if key == 'intent' else original[key]
            deleted = db.execute('DELETE FROM '+table+' WHERE id=? AND fingerprint=?',
                                 (original['operation'], row['fingerprint']))
            require(deleted.rowcount == 1, 'original metadata deletion differs')
        for row in original['prepared_taps']['ifindices']:
            deleted = db.execute('DELETE FROM vm_tap_ifindices WHERE ifindex=? AND operation_id=? AND interface_name=?',
                                 (row['ifindex'], row['operation_id'], row['interface_name']))
            require(deleted.rowcount == 1, 'original TAP ifindex deletion differs')
        for claim in original['vm_claims']:
            deleted = db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                                 tuple(claim[k] for k in ('key', 'lab', 'node', 'operation_id')))
            require(deleted.rowcount == 1, 'original VM claim deletion differs')
        require([dict(r) for r in db.execute('SELECT * FROM resources')] == [original['infrastructure_claim']],
                'original infrastructure claim must remain held')
        _observe(request, original, observe);result = completed_vm(db, request, original)
        db.execute('COMMIT');return result
    except BaseException:
        db.execute('ROLLBACK');raise


def release_hold(db, request, original, restoration, *, observe_restored):
    """Release only after a separate qualified restoration; preserve old hold rows."""
    proof(request, original)
    require(not db.in_transaction and db.execute('PRAGMA synchronous').fetchone()[0] == 2
            and callable(observe_restored), 'durable original DB and restoration observer required')
    wanted = dict(restoration_id=request['restoration_id'], retirement_id=request['id'],
                  current_context=deepcopy(request['current_context']),
                  container_id=json.loads(original['hold']['payload'])['actor']['container_id'],
                  running_healthy=True, original_policy_restored=True,
                  original_config_verified=True, generation_verified=True)
    require(type(restoration) is dict and canonical(restoration) == canonical(wanted),
            'qualified separate service restoration receipt required')
    db.execute('BEGIN IMMEDIATE')
    try:
        completed_vm(db, request, original);value = _archive(db, request, original)
        require(canonical(observe_restored()) == canonical(wanted), 'restored service observation differs')
        for table, rows in (('image_build_holds', [original['hold']]),
                            ('image_build_control_commands', original['commands'])):
            actual = sorted([dict(r) for r in db.execute('SELECT * FROM '+table)], key=lambda r:r['id'])
            require(actual == sorted(rows, key=lambda r:r['id']), 'original hold/command history changed')
        if value['phase'] == 'completed':
            require(value['restoration'] == restoration
                    and db.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 0,
                    'completed original hold retirement differs')
        else:
            require([dict(r) for r in db.execute('SELECT * FROM resources')] == [original['infrastructure_claim']],
                    'original exclusive infrastructure claim differs')
            claim = original['infrastructure_claim']
            removed = db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                                 tuple(claim[k] for k in ('key', 'lab', 'node', 'operation_id')))
            require(removed.rowcount == 1, 'original infrastructure claim release differs')
            value.update(phase='completed', restoration=deepcopy(restoration))
            db.execute('UPDATE '+TABLE+' SET payload=?,fingerprint=? WHERE id=?',
                       (canonical(value), fingerprint(value), request['id']))
        require(canonical(observe_restored()) == canonical(wanted), 'restored service changed before release')
        db.execute('COMMIT');return deepcopy(value)
    except BaseException:
        db.execute('ROLLBACK');raise
