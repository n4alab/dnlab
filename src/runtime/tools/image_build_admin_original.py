"""Validate and retire an original gate claim without rewriting its history.

The caller pins the original database and holds its kernel execution lock.
Reads may use a coherent byte-identical copy under that lock. Writes require
the original producer's verified exit and the restored service policy first.
No Journal constructor is run against the original database.
"""
from copy import deepcopy
import json
from types import SimpleNamespace

from dnlab_runtime.image_build_commands import ImageBuildCommands
from dnlab_runtime.image_build_hold import ImageBuildHold
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import require
from image_build_admin_recovery import AdministrativeRecovery


class _Holds(ImageBuildHold):
    def __init__(self, db):
        # Read-only access to the existing validators, without table setup.
        self.journal=SimpleNamespace(db=db)


class _Commands(ImageBuildCommands):
    def __init__(self, db, holds):
        self.journal=SimpleNamespace(db=db);self.read_hold=holds.read


EMPTY_TABLES=('operations','nodes','workload_generations','vm_runtime_references',
    'vm_definition_intents','vm_initial_starts','vm_directory_intents','vm_tap_intents',
    'vm_storage_intents','libvirt_account_processes','image_build_arm_retirements')


def original_state(db, *, hold_id, start_id, epoch, claim_present=True):
    """SELECT only; qualify the exact hold, producer and unknown start."""
    holds=_Holds(db);commands=_Commands(db,holds);hold=holds.read(hold_id)
    require(hold['phase']=='cleanup_verified' and set(hold['actions'])=={'disable_restart','stop','start'}
            and hold['actions']['start']['phase']=='release_requested'
            and hold['actions']['start']['reference']['token']==start_id,
            'original unknown-start hold required')
    rows=[]
    for action in ('disable_restart','stop','start'):
        item=hold['actions'][action]
        value=commands._read(item['reference'],historical=True)
        require(value['command']==item['command'] and value['phase']==item['phase']
                and value['epoch_id']==epoch['id'] and value['epoch_sha256']==fingerprint(epoch)
                and value['reference']['process_record']==epoch['snapshot']['record']
                and value['outcome']==item['outcome'], 'original control lineage differs')
        rows.append(value)
    start=rows[-1]
    require(start['id']==start_id and start.get('native_dispatch_started') is True
            and start['outcome'] is None and start['details'] is None
            and all(key not in start for key in ('start_ack','start_progress','exit_progress')),
            'only original start without durable acknowledgement permits administrative retirement')
    original_epoch=db.execute('SELECT payload,fingerprint FROM vm_runtime_epochs WHERE id=?',(epoch['id'],)).fetchone()
    require(original_epoch is not None and json.loads(original_epoch['payload'])==epoch
            and original_epoch['fingerprint']==fingerprint(epoch), 'original producer epoch differs')
    for table,count in (('image_build_holds',1),('image_build_control_commands',3),('vm_runtime_epochs',1)):
        require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==count, 'unexpected original gate records')
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in EMPTY_TABLES:
        require(table not in tables or db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0,
                'original workload or native worker intent remains: '+table)
    claim=dict(key=holds._key(hold),lab=hold['scope']['lab_id'],node='image-build',operation_id=hold_id)
    claims=[dict(row) for row in db.execute('SELECT * FROM resources')]
    require(claims==([claim] if claim_present else []), 'original exclusive gate claim differs')
    identities=db.execute('SELECT singleton,identity FROM journal_identity').fetchall()
    require(len(identities)==1 and identities[0]['singleton']==1, 'original journal identity differs')
    return dict(journal_identity=identities[0]['identity'],hold=hold,commands=rows,epoch=deepcopy(epoch),claim=claim)


def retire_original(db, request, owner_exit, *, hold_id, start_id, epoch, check):
    """One atomic tombstone/claim removal after qualified producer exit/policy."""
    AdministrativeRecovery._request(request);AdministrativeRecovery._exit(request,owner_exit)
    require(callable(check) and not db.in_transaction
            and db.execute('PRAGMA synchronous').fetchone()[0]==2,
            'original durable database and administrative preflight required')
    receipt=dict(original_sha256=request['original_sha256'],recovery_id=request['id'],
                 claim_released=True,old_start_uncertain=True)
    payload=dict(request=deepcopy(request),owner_exit=deepcopy(owner_exit),receipt=receipt)
    db.execute('BEGIN IMMEDIATE')
    try:
        check()
        table=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='image_build_administrative_retirements'").fetchone()
        existing=(db.execute('SELECT * FROM image_build_administrative_retirements WHERE hold_id=?',(hold_id,)).fetchone()
                  if table else None)
        original=original_state(db,hold_id=hold_id,start_id=start_id,epoch=epoch,claim_present=existing is None)
        require(fingerprint(original)==request['original_sha256']
                and fingerprint(epoch['snapshot'])==request['owner_sha256'], 'original administrative journal binding differs')
        if existing is not None:
            require(existing['id']==request['id'] and existing['command_id']==start_id
                    and json.loads(existing['payload'])==payload and existing['fingerprint']==fingerprint(payload),
                    'original administrative retirement cannot be replaced')
        else:
            db.execute('CREATE TABLE IF NOT EXISTS image_build_administrative_retirements '
                '(id TEXT PRIMARY KEY,hold_id TEXT UNIQUE NOT NULL,command_id TEXT UNIQUE NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            check()
            require(original_state(db,hold_id=hold_id,start_id=start_id,epoch=epoch)==original,
                    'original gate changed before retirement commit')
            claim=original['claim']
            removed=db.execute('DELETE FROM resources WHERE key=? AND lab=? AND node=? AND operation_id=?',
                tuple(claim[key] for key in ('key','lab','node','operation_id')))
            require(removed.rowcount==1, 'original gate claim release differs')
            db.execute('INSERT INTO image_build_administrative_retirements VALUES(?,?,?,?,?)',
                (request['id'],hold_id,start_id,canonical(payload),fingerprint(payload)))
        check()
        require(original_state(db,hold_id=hold_id,start_id=start_id,epoch=epoch,claim_present=False)==original,
                'original gate history changed during retirement')
        db.execute('COMMIT')
        return deepcopy(receipt)
    except BaseException:
        db.execute('ROLLBACK');raise
