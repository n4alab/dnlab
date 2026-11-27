"""Restore policy and retire a never-dispatched stop; preserve original history.

The producer must be fenced and exited before the one policy update. No stop,
start or VM operation is exposed. The original generation remains authoritative.
"""
from copy import deepcopy
import json

from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import require
from image_build_admin_original import _Holds, _Commands
from image_build_admin_recovery import AdministrativeRecovery
from image_build_unreleased_retirement import RETAINED
from image_build_admin_fence import OriginalGateFence
from image_build_unreleased_execution import _writer, CheckpointedRetirementFence


def stop_observation(request, *, owner_alive):
    return dict(original_sha256=request['original_sha256'], owner_sha256=request['owner_sha256'],
                service_sha256=request['service_sha256'], owner_alive=owner_alive,
                restart_policy=deepcopy(request['restart_policy']), execution_lock_held=True,
                no_native_dispatch=True, vm_resources_absent=True, window_active=True)


def stop_state(db, *, hold_id, command_id, epoch, claim_present=True):
    """SELECT only: completed policy suspension and a never-dispatched stop."""
    holds = _Holds(db)
    commands = _Commands(db, holds)
    hold = holds.read(hold_id)
    require(hold['phase'] == 'policy_disabled'
            and set(hold['actions']) == {'disable_restart', 'stop'},
            'only a suspended policy with an unreleased stop permits retirement')
    rows = []
    for action, phase in (('disable_restart', 'completed'), ('stop', 'armed')):
        item = hold['actions'][action]
        value = commands._read(item['reference'], historical=True)
        require(item['phase'] == value['phase'] == phase
                and value['command'] == item['command']
                and value['outcome'] == item['outcome']
                and value['epoch_id'] == epoch['id']
                and value['epoch_sha256'] == fingerprint(epoch)
                and value['reference']['process_record'] == epoch['snapshot']['record'],
                'original stop/policy lineage differs')
        rows.append(value)
    disabled, stop = rows
    require(disabled.get('native_dispatch_started') is True
            and disabled.get('policy_ack') == dict(container_id=hold['actor']['container_id'],
                restart_policy=dict(Name='no', MaximumRetryCount=0), status=200, warnings_empty=True)
            and stop['id'] == command_id and stop['outcome'] is None and stop['details'] is None
            and set(stop) == {'id', 'command', 'reference', 'epoch_id', 'epoch_sha256',
                             'phase', 'outcome', 'details'},
            'completed policy ACK and original never-dispatched stop required')
    saved = db.execute('SELECT payload,fingerprint FROM vm_runtime_epochs WHERE id=?',
                       (epoch['id'],)).fetchone()
    require(saved is not None and json.loads(saved['payload']) == epoch
            and saved['fingerprint'] == fingerprint(epoch), 'original producer epoch differs')
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, count in (('image_build_holds', 1), ('image_build_control_commands', 2),
                         ('vm_runtime_epochs', 1), ('journal_identity', 1)):
        require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] == count,
                'unexpected original stop journal records')
    allowed = {'image_build_holds', 'image_build_control_commands', 'vm_runtime_epochs',
               'journal_identity', 'resources', 'image_build_administrative_retirements', *RETAINED}
    for table in tables - allowed:
        require(db.execute('SELECT COUNT(*) FROM "'+table.replace('"', '""')+'"').fetchone()[0] == 0,
                'workload, worker or unqualified records remain: '+table)
    retained = {}
    for table in RETAINED:
        if table in tables:
            retained[table] = [dict(row) for row in db.execute('SELECT * FROM '+table+' LIMIT 2')]
            require(len(retained[table]) <= 1, 'unexpected retained SDK state')
    claim = dict(key=holds._key(hold), lab=hold['scope']['lab_id'],
                 node='image-build', operation_id=hold_id)
    require([dict(row) for row in db.execute('SELECT * FROM resources')]
            == ([claim] if claim_present else []), 'original exclusive stop claim differs')
    identity = db.execute('SELECT singleton,identity FROM journal_identity').fetchone()
    require(identity['singleton'] == 1, 'original journal identity differs')
    return dict(journal_identity=identity['identity'], hold=hold, commands=rows,
                epoch=deepcopy(epoch), claim=claim, retained=retained)


def stop_receipt(request):
    return dict(original_sha256=request['original_sha256'], recovery_id=request['id'],
                claim_released=True, stop_never_dispatched=True,
                policy_restored=True, service_stop_start_performed=0)


def retire_stop(db, request, owner_exit, *, hold_id, command_id, epoch, check):
    """Atomic tombstone after original pidfd exit and fresh policy observation."""
    AdministrativeRecovery._request(request)
    AdministrativeRecovery._exit(request, owner_exit)
    require(callable(check) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0] == 2,
            'original durable database and mandatory qualified observer required')
    receipt = stop_receipt(request)
    payload = dict(kind='unreleased-stop-policy-restoration-v1', request=deepcopy(request),
                   owner_exit=deepcopy(owner_exit), receipt=receipt)
    db.execute('BEGIN IMMEDIATE')
    try:
        table = db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone()
        existing = db.execute('SELECT * FROM image_build_administrative_retirements').fetchall() if table else []
        require(len(existing) <= 1 and (not existing or existing[0]['hold_id'] == hold_id),
                'foreign administrative retirement exists')
        original = stop_state(db, hold_id=hold_id, command_id=command_id,
                                epoch=epoch, claim_present=not existing)
        require(fingerprint(original) == request['original_sha256']
                and fingerprint(epoch['snapshot']) == request['owner_sha256']
                and original['hold']['policy'] == request['restart_policy'],
                'original policy retirement binding differs')
        check()
        if existing:
            row = existing[0]
            require(row['id'] == request['id'] and row['command_id'] == command_id
                    and json.loads(row['payload']) == payload
                    and row['fingerprint'] == fingerprint(payload),
                    'original policy retirement cannot be replaced')
        else:
            check()
            require(stop_state(db, hold_id=hold_id, command_id=command_id, epoch=epoch) == original,
                    'original policy history changed before retirement')
            db.execute('CREATE TABLE IF NOT EXISTS image_build_administrative_retirements '
                       '(id TEXT PRIMARY KEY,hold_id TEXT UNIQUE NOT NULL,command_id TEXT UNIQUE NOT NULL,'
                       'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            claim = original['claim']
            removed = db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                                 tuple(claim[key] for key in ('key', 'lab', 'node', 'operation_id')))
            require(removed.rowcount == 1, 'original policy claim release differs')
            db.execute('INSERT INTO image_build_administrative_retirements VALUES(?,?,?,?,?)',
                       (request['id'], hold_id, command_id, canonical(payload), fingerprint(payload)))
        check()
        require(stop_state(db, hold_id=hold_id, command_id=command_id,
                             epoch=epoch, claim_present=False) == original,
                'original policy history changed during retirement')
        db.execute('COMMIT')
        return deepcopy(receipt)
    except BaseException:
        db.execute('ROLLBACK')
        raise


def execute_stop_retirement(fence, request, original, owner_exit, *, arguments, observe, persist):
    """Use an already copied, fenced WAL; acknowledge binding before mode=rw."""
    require(type(fence) in (OriginalGateFence, CheckpointedRetirementFence) and fence.database is not None
            and fence.baseline is not None and callable(observe) and callable(persist),
            'original fenced readonly snapshot and explicit providers required')
    wanted = stop_observation(request, owner_alive=False)
    def check():
        require(canonical(observe()) == canonical(wanted), 'qualified final policy observation differs')
        fence.check()
    def save(name, value):
        require(persist(name, deepcopy(value)) == fingerprint(value),
                'durable policy retirement report not acknowledged')
    copied = fence.database
    table = copied.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone()
    row = copied.execute('SELECT * FROM image_build_administrative_retirements WHERE hold_id=?',
                         (arguments['hold_id'],)).fetchone() if table else None
    if row is not None:
        require(stop_state(copied, **arguments, claim_present=False) == original,
                'original committed policy history differs')
        expected = dict(kind='unreleased-stop-policy-restoration-v1', request=request,
                        owner_exit=owner_exit, receipt=stop_receipt(request))
        require(row['id'] == request['id'] and row['command_id'] == arguments['command_id']
                and json.loads(row['payload']) == expected and row['fingerprint'] == fingerprint(expected),
                'original committed policy retirement differs')
        check()
        fence.verify_raw()
        save('retirement.json', dict(receipt=expected['receipt'], already_committed=True))
        return deepcopy(expected['receipt'])
    require(type(fence) is OriginalGateFence,
            'WAL absent without committed policy retirement; no new writer')
    require(stop_state(copied, **arguments) == original, 'original policy write history differs')
    check()
    save('write-binding.json', dict(request=request, original_sha256=fingerprint(original),
         physical=fence.binding, raw=fence.baseline, journal_identity=original['journal_identity']))
    check()
    fence.verify_raw()
    db = _writer(fence)
    try:
        require(stop_state(db, **arguments) == original, 'writable original policy history differs')
        receipt = retire_stop(db, request, owner_exit, **arguments, check=check)
        require(stop_state(db, **arguments, claim_present=False) == original,
                'original policy retirement commit differs')
        fence.check()
        save('retirement.json', dict(receipt=receipt, already_committed=False))
        return receipt
    finally:
        db.close()


class UnreleasedStopRecovery(AdministrativeRecovery):
    """Fence the idle producer, restore policy once, then retire its claim."""
    @staticmethod
    def _retirement(request, receipt):
        require(receipt == stop_receipt(request)
                and receipt['stop_never_dispatched'] is True
                and receipt['service_stop_start_performed'] == 0,
                'separate never-dispatched-stop retirement receipt required')
