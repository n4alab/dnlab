"""Retire only never-dispatched VM metadata under the original execution fence.

Original rows are archived verbatim. A durable closed-lab fence prevents the
old producer from preparing them again, including producers running old code.
The infrastructure hold is preserved for ordinary restoration by that owner.
No native resource or service operation is available in this module.
"""
from contextlib import nullcontext
from copy import deepcopy
import json
from types import SimpleNamespace

from dnlab_runtime.backend_reservations import tap_keys, storage_keys
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_initial_start import VMInitialStart
from dnlab_runtime.vm_template import fields, require, template_digest
from image_build_admin_original import _Holds, _Commands

TABLE = 'vm_prepared_cancellations'
RETAINED = ('metadata', 'libvirt_loop_sdk_imports', 'libvirt_qemu_sdk_imports',
            'vm_libvirt_event_loops', 'vm_libvirt_feeds')


def prepared_state(db, *, operation, hold_id, epoch):
    """SELECT only; absence providers must separately qualify physical state."""
    return _prepared_state(db, operation=operation, hold_id=hold_id, epoch=epoch)


def prepared_tap_state(db, *, operation, hold_id, epoch, session_profile):
    """Separate administrative reader for TAP intents never released to a worker.

    This does not expand the live-owner cancellation or its proof contract.
    Post-boot callers must separately qualify the current absence of resources.
    """
    return _prepared_state(db, operation=operation, hold_id=hold_id, epoch=epoch,
                           session_profile=session_profile)


def _prepared_state(db, *, operation, hold_id, epoch, session_profile=None):
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    holders = _Holds(db)
    hold = holders.read(hold_id)
    require(hold['phase'] == 'held' and set(hold['actions']) == {'disable_restart', 'stop'},
            'original completed held infrastructure required')
    commands = _Commands(db, holders)
    command_rows = []
    for name in ('disable_restart', 'stop'):
        item = hold['actions'][name]
        value = commands._read(item['reference'], historical=True)
        require(value['phase'] == item['phase'] == 'completed'
                and value['outcome'] == item['outcome'] and value['command'] == item['command']
                and value.get('native_dispatch_started') is True
                and value['epoch_id'] == epoch['id'] and value['epoch_sha256'] == fingerprint(epoch)
                and value['reference']['process_record'] == epoch['snapshot']['record'],
                'original infrastructure command lineage differs')
        command_rows.append(dict(db.execute('SELECT * FROM image_build_control_commands WHERE id=?',
                                           (value['id'],)).fetchone()))
    saved_epoch = db.execute('SELECT payload,fingerprint FROM vm_runtime_epochs WHERE id=?',
                            (epoch['id'],)).fetchone()
    require(saved_epoch is not None and json.loads(saved_epoch['payload']) == epoch
            and saved_epoch['fingerprint'] == fingerprint(epoch), 'original producer epoch differs')
    view = SimpleNamespace(db=db, lock=nullcontext())
    definitions = object.__new__(VMDefinitionDriver)
    definitions.journal = view
    definition = definitions.read(operation)
    initial_reader = object.__new__(VMInitialStart)
    initial_reader.journal = view
    initial = initial_reader.read(operation)
    birth = definition['birth']
    require(set(definition) == {'request_id', 'birth', 'xml', 'session_sha256', 'lab_generation',
                                'request_fingerprint', 'phase', 'creation_ack', 'ack', 'error_type'}
            and definition['phase'] == 'prepared' and definition['creation_ack'] is None
            and definition['ack'] is None and definition['error_type'] == ''
            and initial['phase'] == 'pending'
            and initial['last_step'] in (('directory',) if session_profile is not None
                                         else ('prepared', 'preflight'))
            and initial['receipt'] is None and initial['birth'] == birth
            and initial['definition_sha256'] == definition['request_fingerprint']
            and template_digest(initial['template']) == birth['template_sha256']
            and birth['lab_id'] == hold['scope']['lab_id']
            and birth['host_id'] == hold['scope']['host_id'] == epoch['profile']['host_id'],
            'only original VM metadata before any allocation/define may retire')
    require(db.execute('SELECT 1 FROM lab_closures WHERE lab=?', (birth['lab_id'],)).fetchone() is None,
            'existing lab closure requires a separate recovery')
    expected = [dict(key=key, lab=birth['lab_id'], node=birth['node_id'], operation_id=operation)
                for key in sorted(tap_keys(definition['xml']) | storage_keys(definition['xml']))]
    claim = dict(key=holders._key(hold), lab=hold['scope']['lab_id'], node='image-build', operation_id=hold_id)
    require([dict(r) for r in db.execute('SELECT * FROM resources ORDER BY key')]
            == sorted([claim, *expected], key=lambda r:r['key']),
            'original VM and infrastructure claims differ')
    counts = dict(journal_identity=1, vm_runtime_epochs=1, vm_definition_intents=1,
                  vm_initial_starts=1, image_build_holds=1, image_build_control_commands=2)
    tap_metadata = None
    if session_profile is not None:
        from dnlab_runtime.vm_taps import VMTaps
        definitions.session = SimpleNamespace(profile=deepcopy(session_profile))
        reader = object.__new__(VMTaps)
        reader.journal, reader.definitions = view, definitions
        taps = reader.read(operation)
        require(taps['phase'] == 'prepared' and taps['items']
                and all(item['phase'] == 'prepared' and item['proof'] is None
                        for item in taps['items'])
                and taps['context'] == dict(boot_id=epoch['snapshot']['record']['boot_id'],
                                            **epoch['snapshot']['namespaces']['net']),
                'only original TAP metadata without worker dispatch may retire')
        indices = [dict(r) for r in db.execute('SELECT * FROM vm_tap_ifindices ORDER BY ifindex')]
        expected_indices = sorted([dict(ifindex=item['spec']['tap']['ifindex'],
                                        operation_id=operation,
                                        interface_name=item['spec']['tap']['name'])
                                   for item in taps['items']], key=lambda r:r['ifindex'])
        require(indices == expected_indices, 'original TAP ifindex claims differ')
        counts.update(vm_tap_intents=1, vm_tap_ifindices=len(indices))
        tap_metadata = dict(intent=dict(db.execute('SELECT * FROM vm_tap_intents WHERE id=?',
                                                   (operation,)).fetchone()),
                            ifindices=indices, session_profile=deepcopy(session_profile))
    for table, count in counts.items():
        require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] == count,
                'unexpected original records: '+table)
    allowed = {*counts, 'resources', *RETAINED}
    retained = {}
    for table in tables:
        if table in RETAINED:
            rows = [dict(r) for r in db.execute('SELECT * FROM '+table)]
            require(len(rows) <= 1, 'unexpected retained SDK metadata')
            retained[table] = rows
        elif table not in allowed:
            require(db.execute('SELECT COUNT(*) FROM "'+table.replace('"', '""')+'"').fetchone()[0] == 0,
                    'unqualified resource/worker records remain: '+table)
    identity = db.execute('SELECT singleton,identity FROM journal_identity').fetchone()
    require(identity['singleton'] == 1, 'original journal identity differs')
    result = dict(journal_identity=identity['identity'], operation=operation, epoch=deepcopy(epoch),
                definition=dict(db.execute('SELECT * FROM vm_definition_intents WHERE id=?', (operation,)).fetchone()),
                initial=dict(db.execute('SELECT * FROM vm_initial_starts WHERE id=?', (operation,)).fetchone()),
                vm_claims=expected, infrastructure_claim=claim,
                hold=dict(db.execute('SELECT * FROM image_build_holds WHERE id=?', (hold_id,)).fetchone()),
                commands=command_rows, retained=retained)
    if tap_metadata is not None:
        result['prepared_taps'] = tap_metadata
    return result


def request_proof(request, original):
    fields(request, ('id', 'nonce', 'original_sha256', 'owner_sha256', 'absence_sha256'),
           'prepared VM cancellation request')
    require(all(type(request[k]) is str and len(request[k]) == 32
                and all(c in '0123456789abcdef' for c in request[k]) for k in ('id', 'nonce'))
            and all(type(request[k]) is str and len(request[k]) == 64
                    and all(c in '0123456789abcdef' for c in request[k])
                    for k in ('original_sha256', 'owner_sha256', 'absence_sha256'))
            and request['original_sha256'] == fingerprint(original)
            and request['owner_sha256'] == fingerprint(original['epoch']['snapshot']),
            'immutable original cancellation bindings required')
    definition = json.loads(original['definition']['payload'])
    return dict(original_sha256=request['original_sha256'], owner_sha256=request['owner_sha256'],
                absence_sha256=request['absence_sha256'], session_sha256=definition['session_sha256'],
                original_owner_alive=True, execution_fence_held=True, domains_absent=True,
                directory_absent=True, taps_absent=True, infrastructure_held=True, window_active=True)


def closure(request, original):
    definition = json.loads(original['definition']['payload'])
    return dict(closure_id=request['id'], generation=definition['lab_generation'], phase='closed',
                stops={}, cancellation_id=request['id'], vm_never_created=True)


def receipt(request, original):
    return dict(cancellation_id=request['id'], operation=original['operation'],
                original_sha256=request['original_sha256'], lab_closed=True,
                history_preserved=True, vm_never_created=True, guest_shutdown_claimed=False,
                vm_claims_released=True, infrastructure_claim_preserved=True)


def completed(db, request, original):
    request_proof(request, original)
    row = db.execute('SELECT * FROM '+TABLE+' WHERE id=?', (request['id'],)).fetchone()
    expected = dict(request=request, original=original, receipt=receipt(request, original))
    require(row is not None and row['operation_id'] == original['operation']
            and json.loads(row['payload']) == expected and row['fingerprint'] == fingerprint(expected),
            'original cancellation archive differs')
    definition = json.loads(original['definition']['payload'])
    saved = db.execute('SELECT payload FROM lab_closures WHERE lab=?', (definition['birth']['lab_id'],)).fetchone()
    require(saved is not None and json.loads(saved[0]) == closure(request, original),
            'original cancellation fence differs')
    for table in ('vm_definition_intents', 'vm_initial_starts'):
        require(db.execute('SELECT 1 FROM '+table+' WHERE id=?', (original['operation'],)).fetchone() is None,
                'cancelled original VM metadata reappeared')
    for claim in original['vm_claims']:
        require(db.execute('SELECT 1 FROM resources WHERE key=?', (claim['key'],)).fetchone() is None,
                'cancelled original resource claim reappeared')
    return deepcopy(expected['receipt'])


def cancel_prepared(db, request, original, *, observe):
    """Archive + close + release atomically; never issue a host command."""
    wanted = request_proof(request, original)
    require(callable(observe) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0] == 2,
            'original durable DB and qualified observer required')
    def check():
        observed = observe()
        require(type(observed) is dict and observed == wanted
                and all(observed[key] is True for key in (
                    'original_owner_alive', 'execution_fence_held', 'domains_absent',
                    'directory_absent', 'taps_absent', 'infrastructure_held', 'window_active')),
                'qualified original absence/owner observation differs')
    table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if table and db.execute('SELECT 1 FROM '+TABLE+' LIMIT 1').fetchone():
        result = completed(db, request, original);check();return result
    db.execute('BEGIN IMMEDIATE')
    try:
        hold_id = original['infrastructure_claim']['operation_id']
        require(prepared_state(db, operation=original['operation'], hold_id=hold_id,
                               epoch=original['epoch']) == original, 'original VM metadata changed before cancellation')
        check()
        db.execute('CREATE TABLE IF NOT EXISTS '+TABLE+' (id TEXT PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,'
                   'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        archive = dict(request=deepcopy(request), original=deepcopy(original), receipt=receipt(request, original))
        db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?)',
                   (request['id'], original['operation'], canonical(archive), fingerprint(archive)))
        definition = json.loads(original['definition']['payload'])
        db.execute('INSERT INTO lab_closures VALUES(?,?)',
                   (definition['birth']['lab_id'], canonical(closure(request, original))))
        check()
        for name in ('vm_initial_starts', 'vm_definition_intents'):
            deleted = db.execute('DELETE FROM '+name+' WHERE id=? AND fingerprint=?',
                                 (original['operation'], original['initial' if name == 'vm_initial_starts' else 'definition']['fingerprint']))
            require(deleted.rowcount == 1, 'original prepared metadata removal differs')
        for claim in original['vm_claims']:
            deleted = db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                                 tuple(claim[k] for k in ('key', 'lab', 'node', 'operation_id')))
            require(deleted.rowcount == 1, 'original prepared claim removal differs')
        require(dict(db.execute('SELECT * FROM resources WHERE key=?',
                                (original['infrastructure_claim']['key'],)).fetchone()) == original['infrastructure_claim'],
                'infrastructure claim changed during cancellation')
        check();result = completed(db, request, original)
        db.execute('COMMIT');return result
    except BaseException:
        db.execute('ROLLBACK');raise


def execute_cancellation(fence, request, original, *, observe, persist):
    """Bind the existing WAL and durable evidence before any writable open."""
    from image_build_admin_fence import OriginalGateFence
    from image_build_unreleased_execution import _writer
    require(type(fence) is OriginalGateFence and fence.database is not None
            and fence.baseline is not None and callable(observe) and callable(persist),
            'original live journal fence and explicit evidence providers required')
    request_proof(request, original)
    copied = fence.database
    exists = copied.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if exists and copied.execute('SELECT 1 FROM '+TABLE+' LIMIT 1').fetchone():
        result = completed(copied, request, original)
        require(observe() == request_proof(request, original), 'committed cancellation observation differs')
        fence.verify_raw()
        require(persist('cancellation.json', dict(receipt=result, already_committed=True)) ==
                fingerprint(dict(receipt=result, already_committed=True)), 'durable cancellation report required')
        return result
    require(prepared_state(copied, operation=original['operation'],
                           hold_id=original['infrastructure_claim']['operation_id'],
                           epoch=original['epoch']) == original, 'original copied VM metadata differs')
    binding = dict(request=request, journal_identity=original['journal_identity'],
                   physical=fence.binding, raw=fence.baseline, original_sha256=fingerprint(original))
    require(persist('write-binding.json', deepcopy(binding)) == fingerprint(binding),
            'durable original write binding required before writable open')
    require(observe() == request_proof(request, original), 'original cancellation observation differs')
    fence.verify_raw()
    db = _writer(fence)
    try:
        result = cancel_prepared(db, request, original, observe=observe)
        fence.check()
        value = dict(receipt=result, already_committed=False)
        require(persist('cancellation.json', value) == fingerprint(value),
                'durable cancellation report required')
        return result
    finally:
        db.close()
