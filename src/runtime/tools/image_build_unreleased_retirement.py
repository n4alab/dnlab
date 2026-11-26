"""Administrative metadata retirement of one first arm, never released.

No operational providers or defaults: the caller must hold the original gate
lock, pin the existing database and re-observe producer absence, original
sources/context and unchanged service. Absence is not a shutdown receipt.
This module never constructs a Journal, changes policy, or releases a command.
"""
from copy import deepcopy
import json
import re

from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import digest, fields, require
from image_build_admin_original import _Commands, _Holds

KIND='unreleased-image-build-retirement-v1'
OBSERVATION='qualified-unreleased-image-build-retirement-v1'
RETAINED=('metadata','libvirt_loop_sdk_imports','libvirt_qemu_sdk_imports','vm_libvirt_event_loops')


def unreleased_state(db, *, hold_id, command_id, epoch, claim_present=True):
    """SELECT only. Reject even a release intent without a native ACK."""
    holds=_Holds(db);commands=_Commands(db,holds);hold=holds.read(hold_id)
    require(hold['phase']=='prepared' and set(hold['actions'])=={'disable_restart'},
            'only the first unreleased image-build arm permits metadata retirement')
    item=hold['actions']['disable_restart']
    require(item['phase']=='armed' and item['reference'] is not None
            and item['reference']['token']==command_id and item['outcome'] is None,
            'original arm must never have requested release')
    command=commands._read(item['reference'],historical=True)
    require(set(command)=={'id','command','reference','epoch_id','epoch_sha256','phase','outcome','details'}
            and command['id']==command_id and command['phase']=='armed'
            and command['command']==item['command'] and command['outcome'] is command['details'] is None
            and command['epoch_id']==epoch['id'] and command['epoch_sha256']==fingerprint(epoch)
            and command['reference']['process_record']==epoch['snapshot']['record'],
            'original lower arm or producer lineage differs; no release/progress allowed')
    row=db.execute('SELECT payload,fingerprint FROM vm_runtime_epochs WHERE id=?',(epoch['id'],)).fetchone()
    require(row is not None and json.loads(row['payload'])==epoch and row['fingerprint']==fingerprint(epoch),
            'original producer epoch differs')
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ('image_build_holds','image_build_control_commands','vm_runtime_epochs','journal_identity'):
        require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==1, 'unexpected original gate records')
    allowed={'image_build_holds','image_build_control_commands','vm_runtime_epochs','journal_identity',
             'resources','image_build_administrative_retirements',*RETAINED}
    for table in tables-allowed:
        require(db.execute('SELECT COUNT(*) FROM "'+table.replace('"','""')+'"').fetchone()[0]==0,
                'workload, worker or unqualified journal records remain: '+table)
    retained={}
    for table in RETAINED:
        if table not in tables:continue
        rows=[dict(row) for row in db.execute('SELECT * FROM '+table+' LIMIT 2')]
        require(len(rows)<=1, 'unexpected retained SDK/event-loop records')
        retained[table]=rows
    claim=dict(key=holds._key(hold),lab=hold['scope']['lab_id'],node='image-build',operation_id=hold_id)
    require([dict(row) for row in db.execute('SELECT * FROM resources')]==([claim] if claim_present else []),
            'original exclusive gate claim differs')
    identity=db.execute('SELECT singleton,identity FROM journal_identity').fetchone()
    require(identity['singleton']==1, 'original journal identity differs')
    return dict(journal_identity=identity['identity'],hold=hold,command=command,epoch=deepcopy(epoch),
                claim=claim,retained=retained)


def _observation(request, original):
    fields(request,('kind','id','nonce','original_sha256','owner_sha256','context_sha256',
                    'sources_sha256','service_sha256'),'unreleased administrative request')
    require(request['kind']==KIND and all(type(request[key]) is str and re.fullmatch('[0-9a-f]{32}',request[key])
            for key in ('id','nonce')) and all(digest(request[key]) for key in request if key.endswith('_sha256')),
            'explicit immutable unreleased retirement request required')
    epoch=original['epoch'];hold=original['hold']
    service={key:deepcopy(hold[key]) for key in ('actor','policy','binding_sha256','jobs_sha256')}
    require(request['original_sha256']==fingerprint(original)
            and request['owner_sha256']==fingerprint(epoch['snapshot'])
            and request['context_sha256']==fingerprint(ImageBuildCommands._context(epoch))
            and request['sources_sha256']==epoch['profile']['sources_sha256']
            and request['service_sha256']==fingerprint(service), 'original administrative bindings differ')
    return dict(kind=OBSERVATION,journal_identity=original['journal_identity'],
        owner_sha256=request['owner_sha256'],context_sha256=request['context_sha256'],
        sources_sha256=request['sources_sha256'],service_sha256=request['service_sha256'],
        owner_absent=True,execution_lock_held=True)


def _payload(request, original):
    wanted=_observation(request,original)
    receipt=dict(kind=KIND,recovery_id=request['id'],original_sha256=request['original_sha256'],
        claim_released=True,command_never_released=True,owner_absence_verified=True,
        shutdown_claimed=False,start_claimed=False,service_actions_performed=0)
    return dict(request=deepcopy(request),observation=wanted,receipt=receipt)


def completed_unreleased(db, request, *, hold_id, command_id, epoch):
    """SELECT only: prove an already committed retirement, never infer one."""
    original=unreleased_state(db,hold_id=hold_id,command_id=command_id,epoch=epoch,claim_present=False)
    expected=_payload(request,original)
    table=db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements' AND type='table'").fetchone()
    require(table is not None, 'original committed retirement missing')
    rows=db.execute('SELECT * FROM image_build_administrative_retirements LIMIT 2').fetchall()
    require(len(rows)==1 and rows[0]['hold_id']==hold_id and rows[0]['command_id']==command_id
            and rows[0]['id']==request['id'] and json.loads(rows[0]['payload'])==expected
            and rows[0]['fingerprint']==fingerprint(expected), 'original committed retirement differs')
    return deepcopy(expected['receipt'])


def retire_unreleased(db, request, *, hold_id, command_id, epoch, observe):
    """Atomic tombstone/claim release; mandatory observations may only read.

    The external provider owns qualified procfs/source/service reads and the
    existing lock. Missing or changed evidence aborts; no inferred process exit,
    automatic native command, policy restoration or rollback is provided here.
    """
    require(callable(observe) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0]==2,
            'original durable database and qualified readonly observer required')
    request=deepcopy(request);epoch=deepcopy(epoch)
    db.execute('BEGIN IMMEDIATE')
    try:
        table=db.execute("SELECT 1 FROM sqlite_master WHERE name='image_build_administrative_retirements' AND type='table'").fetchone()
        existing=db.execute('SELECT * FROM image_build_administrative_retirements').fetchall() if table else []
        require(len(existing)<=1 and (not existing or existing[0]['hold_id']==hold_id),
                'foreign administrative retirement exists')
        original=unreleased_state(db,hold_id=hold_id,command_id=command_id,epoch=epoch,claim_present=not existing)
        payload=_payload(request,original);wanted=payload['observation'];receipt=payload['receipt']
        def check():
            proof=observe()
            require(type(proof) is dict and canonical(proof)==canonical(wanted),
                    'qualified producer absence, lock, sources or unchanged service unavailable')
        check()
        if existing:
            row=existing[0]
            require(row['id']==request['id'] and row['command_id']==command_id
                    and json.loads(row['payload'])==payload and row['fingerprint']==fingerprint(payload),
                    'original unreleased retirement cannot be replaced')
        else:
            check()
            require(unreleased_state(db,hold_id=hold_id,command_id=command_id,epoch=epoch)==original,
                    'original arm changed before retirement')
            db.execute('CREATE TABLE IF NOT EXISTS image_build_administrative_retirements '
                '(id TEXT PRIMARY KEY,hold_id TEXT UNIQUE NOT NULL,command_id TEXT UNIQUE NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            claim=original['claim']
            removed=db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                tuple(claim[key] for key in ('key','lab','node','operation_id')))
            require(removed.rowcount==1, 'original gate claim release differs')
            db.execute('INSERT INTO image_build_administrative_retirements VALUES(?,?,?,?,?)',
                (request['id'],hold_id,command_id,canonical(payload),fingerprint(payload)))
        check()
        require(unreleased_state(db,hold_id=hold_id,command_id=command_id,epoch=epoch,claim_present=False)==original,
                'original gate history changed during retirement')
        db.execute('COMMIT')
        return deepcopy(receipt)
    except BaseException:
        db.execute('ROLLBACK');raise
