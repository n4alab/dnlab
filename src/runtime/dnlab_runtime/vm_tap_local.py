"""Original-process TAP provider; launching/supervising that worker is external.

No descriptor is reopened, reconstructed or closed implicitly on uncertainty.
The caller must retain this provider in the qualified creator worker. A new
provider without its live descriptors cannot adopt even matching resources.
Bridge configuration, QEMU handoff and full workload teardown are separate.
"""
from copy import deepcopy
import json
import os

from .libvirt_account_commands import reference_proof
from .manifest import Conflict, canonical, fingerprint
from .vm_tap_retention import RetainedTapDevice, TapRetention
from .vm_template import fields, require


def worker_command(value):
    return dict(action='vm-tap-lease',operation_id=value['id'],birth=deepcopy(value['birth']),
        definition_sha256=value['definition_sha256'],context=deepcopy(value['context']),
        specs=[deepcopy(item['spec']) for item in value['items']])


class LocalTapEndpoints:
    def __init__(self, journal, *, read_context, inventory, verify_worker,
                 device_factory=None, process_id=os.getpid):
        require(all(callable(fn) for fn in (read_context,inventory,verify_worker,process_id)),
            'qualified original TAP worker providers required')
        self.journal,self.read_context,self.inventory = journal,read_context,inventory
        self.verify_worker,self.process_id = verify_worker,process_id
        self.device_factory=self._device if device_factory is None else device_factory
        require(callable(self.device_factory), 'original TAP device factory required')
        self.sets=None;self.live={}
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_actors '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_creators '
                '(id TEXT PRIMARY KEY,operation_id TEXT NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _device(self, spec, context, record):
        return RetainedTapDevice(spec,context,read_context=self.read_context,inventory=self.inventory,record=record)

    def attach(self, sets):
        require(self.sets is None and sets.journal is self.journal and sets.endpoints is self,
            'original VM TAP coordinator required')
        self.sets=sets

    def _set(self, operation):
        require(self.sets is not None, 'original VM TAP coordinator not attached')
        return self.sets.read(operation)

    def _worker(self, value, reference):
        command=worker_command(value);reference_proof(reference,command)
        require(reference['process_record']['pid']==self.process_id()
            and reference['process_record']['boot_id']==value['context']['boot_id']
            and self.read_context()==value['context'], 'original TAP worker process/context differs')
        if self.verify_worker(deepcopy(reference),deepcopy(command)) is not True:
            raise Conflict('original TAP worker liveness/provenance not verified')

    def _actor(self, operation):
        value=self._set(operation)
        row=self.journal.db.execute('SELECT * FROM vm_tap_actors WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original TAP worker binding missing')
        actor=json.loads(row['payload'])
        fields(actor,('id','birth','command','reference'),'original TAP actor')
        if (fingerprint(actor)!=row['fingerprint'] or actor['id']!=operation
                or actor['birth']!=value['birth'] or row['domain_uuid']!=value['birth']['uuid']
                or actor['command']!=worker_command(value)):
            raise Conflict('original TAP worker binding changed')
        self._worker(value,actor['reference'])
        return actor

    def bind(self, operation, reference):
        with self.journal.execution_lock:
            value=self._set(operation);self._worker(value,reference)
            if self.journal.db.execute('SELECT 1 FROM vm_tap_actors WHERE id=?',(operation,)).fetchone():
                actor=self._actor(operation)
                if actor['reference']!=reference:raise Conflict('original TAP actor cannot be replaced')
                return actor
            require(value['phase']=='prepared' and all(item['phase']=='prepared' for item in value['items']),
                'original worker must be bound before TAP allocation')
            actor=dict(id=operation,birth=deepcopy(value['birth']),command=worker_command(value),reference=deepcopy(reference))
            with self.journal.transaction():
                self.sets._check(value,mutate=True);self._worker(value,reference)
                self.journal.db.execute('INSERT INTO vm_tap_actors VALUES(?,?,?,?)',
                    (operation,value['birth']['uuid'],canonical(actor),fingerprint(actor)))
            return self._actor(operation)

    def _read(self, nonce):
        row=self.journal.db.execute('SELECT * FROM vm_tap_creators WHERE id=?',(nonce,)).fetchone()
        if row is None:return None
        value=json.loads(row['payload'])
        fields(value,('id','operation_id','birth','spec','worker_reference_sha256','lease_token','phase','records','proof'),
            'original TAP creator')
        if (fingerprint(value)!=row['fingerprint'] or value['id']!=nonce
                or value['operation_id']!=row['operation_id'] or value['spec']['tap']['nonce']!=nonce):
            raise Conflict('original TAP creator journal changed')
        phases=('opened','create_requested','created')
        records=value['records'];phase=value['phase']
        if (phase not in ('opening',*phases,'retained') or type(records) is not list or len(records)>3
                or [record['phase'] for record in records]!=list(phases[:len(records)])
                or len(records)!={'opening':0,'opened':1,'create_requested':2,'created':3,'retained':3}[phase]
                or (phase=='retained')!=(value['proof'] is not None)):
            raise Conflict('original TAP creation chronology differs')
        for record in records:
            fields(record,('phase','request','request_sha256','context','proof'),'original TAP creation record')
            if (record['request']!=value['spec']['tap'] or record['request_sha256']!=fingerprint(record['request'])
                    or record['context']!=value['spec']['context']):raise Conflict('original TAP creation record differs')
        return value

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_tap_creators SET payload=?,fingerprint=? WHERE id=?',
            (canonical(value),fingerprint(value),value['id']))

    def _source(self, item, operation):
        actor=self._actor(operation);value=self._set(operation)
        matches=[saved for saved in value['items'] if saved['spec']==item['spec']]
        require(len(matches)==1, 'original TAP item not in VM set')
        nonce=item['spec']['tap']['nonce'];original=self._read(nonce)
        if original is not None:
            if (original['operation_id']!=operation or original['birth']!=value['birth']
                    or original['spec']!=item['spec'] or original['worker_reference_sha256']!=fingerprint(actor['reference'])):
                raise Conflict('original TAP creator lineage changed')
            entry=self.live.get(nonce)
            if (entry is None or entry['device']._lease_token!=original['lease_token']
                    or entry['device'].spec!=item['spec']['tap'] or entry['device'].context!=item['spec']['context']):
                raise Conflict('original TAP creator lease unavailable; no adoption')
        return original

    def _host(self, item, operation):
        self._source(item,operation)
        self.sets._check(self._set(operation),mutate=True)
        self._source(item,operation)

    def _record(self, nonce, record):
        value=self._read(nonce)
        if value is None:raise Conflict('original TAP creator intent missing before open')
        item=dict(spec=deepcopy(value['spec']),phase='create_requested',proof=None);operation=value['operation_id']
        self._host(item,operation)
        fields(record,('phase','request','request_sha256','context','proof'),'TAP birth callback')
        require(record['request']==value['spec']['tap'] and record['context']==value['spec']['context']
            and record['request_sha256']==fingerprint(value['spec']['tap']), 'original TAP callback request differs')
        expected={'opening':'opened','opened':'create_requested','create_requested':'created'}.get(value['phase'])
        require(expected is not None and record['phase']==expected, 'TAP birth cannot be overwritten or replayed')
        if expected=='created':
            if self.live[nonce]['device'].capture()!=record['proof']:raise Conflict('original TAP birth reply differs')
        else:
            require(record['proof']==dict(device=self.live[nonce]['device']._identity),
                'original TAP open/request device differs')
        with self.journal.transaction():
            self._host(item,operation)
            if self._read(nonce)!=value:raise Conflict('original TAP creation step changed')
            value['records'].append(deepcopy(record));value['phase']=expected;self._save(value)
        self._read(nonce);self._host(item,operation)

    def _retainer(self, item, operation):
        nonce=item['spec']['tap']['nonce'];entry=self.live[nonce]
        if entry['retainer'] is None:
            def check(value):
                self._host(item,operation);original=self._read(nonce)
                if value['birth']!=original['records'][-1]['proof']:raise Conflict('original TAP birth changed')
                return dict(request_sha256=value['request_sha256'],lease_token=value['lease_token'],
                    original_birth_sha256=fingerprint(value['birth']),resources_verified=True,guest_writers_absent=True)
            entry['retainer']=TapRetention(self.journal,entry['device'],preflight=check)
        return entry['retainer']

    def observe(self, item, operation):
        nonce=item['spec']['tap']['nonce'];original=self._read(nonce)
        if original is None:
            if self.read_context()!=item['spec']['context']:raise Conflict('original TAP observation namespace changed')
            links=self.inventory()
            require(type(links) is list and all(type(link) is dict and type(link.get('ifindex')) is int
                and isinstance(link.get('ifname'),str) for link in links), 'complete original TAP inventory required')
            if self.read_context()!=item['spec']['context']:raise Conflict('TAP namespace changed during observation')
            matches=[link for link in links if link['ifname']==item['spec']['tap']['name']
                or link['ifindex']==item['spec']['tap']['ifindex']]
            return deepcopy(matches) if matches else None
        self._source(item,operation)
        if original['phase']!='retained':raise Conflict('original TAP worker completion requires recovery')
        entry=self.live[nonce];proof=original['proof'];retainer=entry['retainer']
        if (retainer is None or retainer.read(nonce)!=proof['retention']
                or entry['device']._birth_proof!=original['records'][-1]['proof']
                or entry['device'].capture()!=proof['retention']['retained_proof']):
            raise Conflict('original retained TAP descriptor or receipt changed')
        self._source(item,operation)
        if self._read(nonce)!=original or entry['device'].capture()!=proof['retention']['retained_proof']:
            raise Conflict('original retained TAP changed during observation')
        return deepcopy(proof)

    def _finish(self, item, operation):
        self._host(item,operation);nonce=item['spec']['tap']['nonce'];original=self._read(nonce)
        if original['phase']=='retained':return self.observe(item,operation)
        require(original['phase']=='created', 'uncertain TAP creation has no original birth; no resend')
        device=self.live[nonce]['device'];birth=original['records'][-1]['proof']
        if device._birth_proof is None:
            # Only a durably saved ORIGINAL reply on this original still-open
            # FD can complete a lost recorder response, never a name lookup.
            if device.capture()!=birth:raise Conflict('original TAP birth no longer matches creator FD')
            device._birth_proof=deepcopy(birth)
        if device._birth_proof!=birth:raise Conflict('original TAP birth acknowledgement differs')
        retainer=self._retainer(item,operation)
        retainer.prepare(nonce,birth=birth,uid=item['spec']['uid'],gid=item['spec']['gid'])
        retention=retainer.apply(nonce)
        proof=dict(operation_id=operation,spec_sha256=fingerprint(item['spec']),
            worker_reference_sha256=original['worker_reference_sha256'],retention=retention)
        self.sets._proof(self._set(operation),item,proof)
        with self.journal.transaction():
            self._host(item,operation)
            if self._read(nonce)!=original:raise Conflict('original TAP creator changed before retention receipt')
            original.update(phase='retained',proof=proof);self._save(original)
        return self.observe(item,operation)

    def create(self, item, operation):
        with self.journal.execution_lock:
            self._host(item,operation);value=self._set(operation)
            require(any(saved['spec']==item['spec'] and saved['phase']=='create_requested' for saved in value['items']),
                'original VM TAP create checkpoint required')
            nonce=item['spec']['tap']['nonce']
            if self._read(nonce) is not None or nonce in self.live:raise Conflict('TAP create cannot be repeated')
            record=lambda value:self._record(nonce,value)
            device=self.device_factory(deepcopy(item['spec']['tap']),deepcopy(item['spec']['context']),record)
            require(isinstance(device,RetainedTapDevice) and device.spec==item['spec']['tap']
                and device.context==item['spec']['context'] and device.record is record
                and device._fd is None and not device._entered, 'new unopened original TAP device required')
            original=dict(id=nonce,operation_id=operation,birth=deepcopy(value['birth']),spec=deepcopy(item['spec']),
                worker_reference_sha256=fingerprint(self._actor(operation)['reference']),lease_token=device._lease_token,
                phase='opening',records=[],proof=None)
            with self.journal.transaction():
                self._host(item,operation)
                self.journal.db.execute('INSERT INTO vm_tap_creators VALUES(?,?,?,?)',
                    (nonce,operation,canonical(original),fingerprint(original)))
            self.live[nonce]=dict(device=device,retainer=None)
            self._host(item,operation);device.__enter__();device.create()
            return self._finish(item,operation)

    def recover(self, item, operation):
        with self.journal.execution_lock:
            self._host(item,operation)
            if self._read(item['spec']['tap']['nonce']) is None:
                raise Conflict('original TAP creator intent missing; no create on recovery')
            return self._finish(item,operation)
