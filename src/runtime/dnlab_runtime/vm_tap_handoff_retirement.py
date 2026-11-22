"""Whole-set retirement for TAPs acquired by the original, now stopped QEMU.

Uses the existing retirement journal and remaining-resource checks. Each new
cleanup handle records its own intent/acks under its child, never overwriting
the creator or handoff receipts. Lost live handles cannot be reopened by name.
"""
from copy import deepcopy

from .manifest import canonical, fingerprint, identifier
from .vm_definition_retirement import StoppedDefinitionRetirement
from .vm_tap_cleanup_handle import TapCleanupHandle
from .vm_tap_handoff import VMTapHandoff
from .vm_tap_retirement import VMTapRetirement
from .vm_template import fields, require

RECORDS = ('cleanup_acquire_requested','opened','cleanup_acquired','cleanup_unpersist_requested',
           'cleanup_unpersisted','cleanup_close_requested','cleanup_closed')


class _CleanupLease:
    def __init__(self, owner, operation, nonce, handle):
        self.owner,self.operation,self.nonce,self.handle = owner,operation,nonce,handle

    @property
    def device(self):return self

    @property
    def _fd(self):return self.handle.device._fd

    def release(self, nonce):
        require(nonce == self.nonce, 'original cleanup child required')
        if not self.handle.requested:self.handle.acquire()
        require(self.handle.acquisition is not None, 'original cleanup attachment uncertain; no reopen')
        self.handle.observe()
        self.owner._record(self.operation,self.nonce,dict(phase='cleanup_acquired',receipt=deepcopy(self.handle.acquisition)))
        if not self.handle.unpersist_requested:self.handle.unpersist()
        else:self.handle.recover_unpersist()

    def close(self):self.handle.close()

    def confirm_absent(self, nonce):
        require(nonce == self.nonce and self.handle.close_ack is not None, 'original cleanup close required')
        self.owner._record(self.operation,self.nonce,dict(phase='cleanup_closed',receipt=deepcopy(self.handle.close_ack)))
        return self.handle.confirm_absent()


class VMTapHandoffRetirement(VMTapRetirement):
    def __init__(self, handoff, retirement, *, preflight):
        require(isinstance(handoff,VMTapHandoff) and isinstance(retirement,StoppedDefinitionRetirement)
                and handoff.definitions is retirement.definitions, 'original handoff and stopped retirement required')
        self.handoff,self.handles,self.current = handoff,{},{}
        super().__init__(handoff.taps,retirement,preflight=preflight)

    def read(self, operation):
        value = super().read(operation)
        for child in value['items']:
            creator = child['creator']
            fields(creator,('original','handoff','cleanup'),'transferred TAP retirement child')
            fields(creator['cleanup'],('lease_token','records'),'original cleanup handle history')
            history = creator['cleanup']['records'];phases = [r.get('phase') for r in history]
            require(phases == list(RECORDS[:len(phases)]) and len(phases) <= len(RECORDS)
                    and (creator['cleanup']['lease_token'] is None) == (not history)
                    and creator['handoff']['phase'] == 'acquired'
                    and creator['handoff']['tap_set'] == value['tap_set']
                    and creator['original']['spec']['tap']['nonce'] == child['nonce'],
                    'original transferred TAP cleanup lineage changed')
            allowed = dict(prepared=(0,),releasing=range(6),close_requested=range(5,8),absent=(7,))
            require(len(history) in allowed[child['phase']], 'cleanup history does not prove its retirement stage')
            if history:
                token = creator['cleanup']['lease_token']
                require(type(token) is str and len(token) == 32 and all(c in '0123456789abcdef' for c in token)
                        and history[0]['lease_token'] == token,
                        'original cleanup handle token changed')
                for record in history:
                    if 'receipt' in record:
                        require(record['receipt']['lease_token'] == creator['cleanup']['lease_token'],
                                'original cleanup acknowledgement token differs')
            if child['phase'] == 'absent':
                require(history[-1]['receipt'] == child['proof']['close'],
                        'completed TAP absence requires original durable cleanup close')
        return value

    def _source(self, value, *, held=True):
        super()._source(value,held=held)
        require(self.handoff.taps is self.taps and self.handoff.endpoints is self.endpoints,
                'original transferred TAP controllers changed')
        handoff = self.handoff.read(value['tap_set']['id'])
        self.handoff._source(handoff)
        require(handoff['phase'] == 'acquired' and all(i['phase'] == 'released' for i in handoff['items']),
                'complete original QEMU TAP acquisition required for stopped retirement')
        for item,child in zip(value['tap_set']['items'],value['items']):
            require(child['creator']['handoff'] == handoff
                    and self.endpoints._source(item,value['tap_set']['id']) == child['creator']['original'],
                    'original TAP creator or handoff receipt changed')

    def _check(self, value, *, held=True):
        self.current[value['id']] = value
        super()._check(value,held=held)

    def _record(self, operation, nonce, record):
        value = self.current[operation]
        self._check(value)
        child = next(i for i in value['items'] if i['nonce'] == nonce)
        cleanup = child['creator']['cleanup'];history = cleanup['records']
        existing = next((r for r in history if r['phase'] == record['phase']),None)
        if existing is not None:
            require(existing == record, 'original cleanup acknowledgement cannot change')
            return
        require(len(history) < len(RECORDS) and record['phase'] == RECORDS[len(history)],
                'original cleanup acknowledgement order differs')
        with self.journal.transaction():
            self._check(value)
            if not history:cleanup['lease_token'] = record['lease_token']
            history.append(deepcopy(record));self._write(value);self._check(value)

    def _lease(self, value, item, child):
        key = (value['id'],child['nonce'])
        if key not in self.handles:
            require(not child['creator']['cleanup']['records'], 'original live cleanup handle lost; no reopen')
            link_birth = next(i['link_birth'] for i in child['creator']['handoff']['items'] if i['nonce'] == child['nonce'])
            def record(receipt):self._record(key[0],key[1],receipt)
            def preflight():
                current = self.current[key[0]];self._check(current)
                return dict(retirement_sha256=fingerprint(current['retirement']),tap_birth_sha256=fingerprint(link_birth),
                            writers_absent=True,remaining_resources_verified=True)
            device = self.endpoints.device_factory(deepcopy(item['spec']['tap']),deepcopy(item['spec']['context']),record)
            handle = TapCleanupHandle(device,self.handoff.monitor,link_birth,item['proof']['retention']['retained_proof'],
                retirement_sha256=fingerprint(value['retirement']),preflight=preflight,record=record)
            self.handles[key] = _CleanupLease(self,value['id'],child['nonce'],handle)
        return self.handles[key]

    def _layout(self, value):
        pump = not self.journal.db.in_transaction
        for item,child in zip(value['tap_set']['items'],value['items']):
            creator = child['creator']
            link_birth = next(i['link_birth'] for i in creator['handoff']['items'] if i['nonce'] == child['nonce'])
            if child['phase'] == 'absent':
                removal = self.handoff.monitor.verify_removed(link_birth,pump=pump)
                original_device = self.endpoints.live[child['nonce']]['device']
                require(not original_device._links() and child['proof'] == dict(
                    tap_birth_sha256=fingerprint(link_birth),retirement_sha256=fingerprint(value['retirement']),
                    close=dict(lease_token=creator['cleanup']['lease_token'],original_cleanup_fd_closed=True),
                    removal=removal,absence_verified=True), 'original transferred TAP absence receipt changed')
                continue
            lease = self._lease(value,item,child);handle = lease.handle
            if handle.close_ack is not None:
                require(child['phase'] == 'close_requested', 'unexpected transferred TAP closure')
                handle.absence(pump=pump)
            elif handle.acquisition is not None:
                require(child['phase'] in ('releasing','close_requested'), 'unexpected cleanup handle acquisition')
                handle.observe(pump=pump)
                require(creator['cleanup']['lease_token'] == handle.device._lease_token,
                        'original live cleanup handle replaced')
            else:
                require(child['phase'] in ('prepared','releasing'), 'original cleanup handle acknowledgement missing')
                source = next(i for i in creator['handoff']['items'] if i['nonce'] == child['nonce'])
                self.handoff._link(creator['handoff'],source,item)

    def prepare(self, operation, definition_id, retirement_id):
        identifier(operation,'TAP retirement operation_id')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_tap_retirements WHERE id=? OR definition_id=?',
                                          (operation,definition_id)).fetchone()
            if row is not None:
                value = self.read(row['id'])
                require(value['id'] == operation and value['tap_set']['id'] == definition_id
                        and value['retirement']['id'] == retirement_id, 'original transferred retirement request differs')
                self._check(value);return value
            taps = self.taps.read(definition_id);handoff = self.handoff.read(definition_id)
            value = dict(id=operation,birth=deepcopy(taps['birth']),definition=self.definitions.read(definition_id),
                tap_set=taps,retirement=self.retirement.read(retirement_id),actor=self.endpoints._actor(definition_id),
                items=[dict(nonce=i['spec']['tap']['nonce'],creator=dict(original=self.endpoints._source(i,definition_id),
                    handoff=deepcopy(handoff),cleanup=dict(lease_token=None,records=[])),phase='prepared',proof=None)
                    for i in taps['items']],phase='prepared',proof=None)
            self._check(value,held=False)
            with self.journal.transaction():
                self._check(value,held=False)
                self.journal.db.execute('INSERT INTO vm_tap_retirements VALUES(?,?,?,?)',
                    (operation,definition_id,canonical(value),fingerprint(value)))
            return self.read(operation)
