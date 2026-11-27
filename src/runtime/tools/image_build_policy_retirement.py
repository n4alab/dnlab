"""Retire a policy-only uncertain outcome without replaying service actions.

The original stop/start must already have durable successful outcomes. A caller
pins the idle producer, owns its execution fence, and qualifies the exact
generation from the original start checkpoint before and after retiring it.
Original commands, responses, epochs and SDK records are never rewritten.
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


def policy_observation(request, *, owner_alive):
    return dict(original_sha256=request['original_sha256'], owner_sha256=request['owner_sha256'],
                service_sha256=request['service_sha256'], owner_alive=owner_alive,
                restart_policy=deepcopy(request['restart_policy']), execution_lock_held=True,
                no_native_dispatch=True, vm_resources_absent=True, window_active=True)


def policy_state(db, *, hold_id, command_id, epoch, claim_present=True):
    """SELECT only; require the one uncertain final policy of a known start."""
    holds = _Holds(db)
    commands = _Commands(db, holds)
    hold = holds.read(hold_id)
    actions = ('disable_restart', 'stop', 'start', 'restore_restart')
    require(hold['phase'] == 'restarted' and set(hold['actions']) == set(actions),
            'only the final policy of an already restarted hold is eligible')
    rows = []
    for action in actions:
        item = hold['actions'][action]
        value = commands._read(item['reference'], historical=True)
        expected = 'release_requested' if action == 'restore_restart' else 'completed'
        require(item['phase'] == value['phase'] == expected
                and value['command'] == item['command']
                and value['outcome'] == item['outcome']
                and value['epoch_id'] == epoch['id']
                and value['epoch_sha256'] == fingerprint(epoch)
                and value['reference']['process_record'] == epoch['snapshot']['record']
                and value.get('native_dispatch_started') is True,
                'original policy command lineage or completion differs')
        rows.append(value)
    pending = rows[-1]
    start = rows[2]
    require(pending['id'] == command_id and pending['outcome'] is None
            and pending['details'] is None and 'policy_ack' not in pending
            and 'start_ack' in start and 'start_progress' in start,
            'original pending policy and acknowledged first start required')
    require(start['start_progress']['actor'] == start['outcome']['evidence']['actor']
            == pending['command']['actor'], 'policy must target the original qualified start')
    saved = db.execute('SELECT payload,fingerprint FROM vm_runtime_epochs WHERE id=?',
                       (epoch['id'],)).fetchone()
    require(saved is not None and json.loads(saved['payload']) == epoch
            and saved['fingerprint'] == fingerprint(epoch), 'original producer epoch differs')
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table, count in (('image_build_holds', 1), ('image_build_control_commands', 4),
                         ('vm_runtime_epochs', 1), ('journal_identity', 1)):
        require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] == count,
                'unexpected original policy journal records')
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
            == ([claim] if claim_present else []), 'original exclusive policy claim differs')
    identity = db.execute('SELECT singleton,identity FROM journal_identity').fetchone()
    require(identity['singleton'] == 1, 'original journal identity differs')
    return dict(journal_identity=identity['identity'], hold=hold, commands=rows,
                epoch=deepcopy(epoch), claim=claim, retained=retained)


def policy_receipt(request):
    return dict(original_sha256=request['original_sha256'], recovery_id=request['id'],
                claim_released=True, old_policy_response_uncertain=True,
                original_stop_start_preserved=True, service_actions_performed=0)


def retire_policy(db, request, owner_exit, *, hold_id, command_id, epoch, check):
    """Atomic tombstone after original pidfd exit and fresh policy observation."""
    AdministrativeRecovery._request(request)
    AdministrativeRecovery._exit(request, owner_exit)
    require(callable(check) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0] == 2,
            'original durable database and mandatory qualified observer required')
    receipt = policy_receipt(request)
    payload = dict(kind='observed-final-policy-retirement-v1', request=deepcopy(request),
                   owner_exit=deepcopy(owner_exit), receipt=receipt)
    db.execute('BEGIN IMMEDIATE')
    try:
        table = db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements'").fetchone()
        existing = db.execute('SELECT * FROM image_build_administrative_retirements').fetchall() if table else []
        require(len(existing) <= 1 and (not existing or existing[0]['hold_id'] == hold_id),
                'foreign administrative retirement exists')
        original = policy_state(db, hold_id=hold_id, command_id=command_id,
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
            require(policy_state(db, hold_id=hold_id, command_id=command_id, epoch=epoch) == original,
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
        require(policy_state(db, hold_id=hold_id, command_id=command_id,
                             epoch=epoch, claim_present=False) == original,
                'original policy history changed during retirement')
        db.execute('COMMIT')
        return deepcopy(receipt)
    except BaseException:
        db.execute('ROLLBACK')
        raise


def execute_policy_retirement(fence, request, original, owner_exit, *, arguments, observe, persist):
    """Use an already copied, fenced WAL; acknowledge binding before mode=rw."""
    require(type(fence) in (OriginalGateFence, CheckpointedRetirementFence) and fence.database is not None
            and fence.baseline is not None and callable(observe) and callable(persist),
            'original fenced readonly snapshot and explicit providers required')
    wanted = policy_observation(request, owner_alive=False)
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
        require(policy_state(copied, **arguments, claim_present=False) == original,
                'original committed policy history differs')
        expected = dict(kind='observed-final-policy-retirement-v1', request=request,
                        owner_exit=owner_exit, receipt=policy_receipt(request))
        require(row['id'] == request['id'] and row['command_id'] == arguments['command_id']
                and json.loads(row['payload']) == expected and row['fingerprint'] == fingerprint(expected),
                'original committed policy retirement differs')
        check()
        fence.verify_raw()
        save('retirement.json', dict(receipt=expected['receipt'], already_committed=True))
        return deepcopy(expected['receipt'])
    require(type(fence) is OriginalGateFence,
            'WAL absent without committed policy retirement; no new writer')
    require(policy_state(copied, **arguments) == original, 'original policy write history differs')
    check()
    save('write-binding.json', dict(request=request, original_sha256=fingerprint(original),
         physical=fence.binding, raw=fence.baseline, journal_identity=original['journal_identity']))
    check()
    fence.verify_raw()
    db = _writer(fence)
    try:
        require(policy_state(db, **arguments) == original, 'writable original policy history differs')
        receipt = retire_policy(db, request, owner_exit, **arguments, check=check)
        require(policy_state(db, **arguments, claim_present=False) == original,
                'original policy retirement commit differs')
        fence.check()
        save('retirement.json', dict(receipt=receipt, already_committed=False))
        return receipt
    finally:
        db.close()


class ObservedPolicyRecovery(AdministrativeRecovery):
    """Same durable owner-exit protocol, with no service update capability."""
    def __init__(self, journal, *, preflight, terminate_owner, retire_claim):
        def forbidden(_):
            raise RuntimeError('observed policy recovery cannot update the service')
        super().__init__(journal, preflight=preflight, terminate_owner=terminate_owner,
                         update_policy=forbidden, retire_claim=retire_claim)

    @staticmethod
    def _retirement(request, receipt):
        require(receipt == policy_receipt(request)
                and all(receipt[key] is True for key in
                        ('claim_released', 'old_policy_response_uncertain', 'original_stop_start_preserved'))
                and type(receipt['service_actions_performed']) is int,
                'separate observed-policy receipt required')

    def read(self, operation):
        value = super().read(operation)
        require(value['phase'] != 'policy_requested', 'observational recovery cannot request a policy action')
        return value

    def prepare(self, request):
        with self.journal.execution_lock:
            self._request(request)
            row = self.journal.db.execute('SELECT id FROM image_build_admin_recoveries WHERE id=?',
                                          (request['id'],)).fetchone()
            if row:
                value = self.read(request['id'])
                require(value['request'] == request, 'observed policy intent cannot be replaced')
                return value
            self._pre(request, owner_alive=True, restart=request['restart_policy'])
            self._save(dict(request=deepcopy(request), phase='prepared', owner_exit=None, retirement=None), insert=True)
            return self.read(request['id'])

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation)
            request = value['request']
            require(value['phase'] != 'owner_term_requested', 'owner TERM uncertain; no resend or inferred exit')
            if value['phase'] == 'completed':
                return value
            def check(alive):
                self._pre(request, owner_alive=alive, restart=request['restart_policy'])
            if value['phase'] == 'prepared':
                check(True)
                value['phase'] = 'owner_term_requested'
                self._save(value)
                check(True)
                proof = self.terminate_owner(deepcopy(request), check=lambda: check(True))
                self._exit(request, proof)
                value.update(phase='owner_exited', owner_exit=deepcopy(proof))
                self._save(value)
            if value['phase'] == 'owner_exited':
                check(False)
                value['phase'] = 'policy_verified'
                self._save(value)
            if value['phase'] == 'policy_verified':
                check(False)
                receipt = self.retire_claim(deepcopy(request), deepcopy(value['owner_exit']))
                self._retirement(request, receipt)
                value.update(phase='completed', retirement=deepcopy(receipt))
                self._save(value)
            return self.read(operation)
