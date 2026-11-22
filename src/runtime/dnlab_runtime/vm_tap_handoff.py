"""Explicit original-actor TAP handoff; historical retention receipts stay intact.

Only this adapter accepts the creator FD's recorded closure. The old endpoint
provider and retirement protocol remain unchanged. A lost live actor, monitor or
close acknowledgement cannot be reconstructed from a matching interface name.
"""
from copy import deepcopy
import json
import os

from .manifest import Conflict, canonical, fingerprint
from .qemu_process import PinnedQEMUProcess
from .qemu_tap_descriptors import QEMUTapDescriptors
from .vm_tap_link_events import TapLinkEvents
from .vm_tap_local import LocalTapEndpoints
from .vm_template import fields, require


class HandoffTapEndpoints(LocalTapEndpoints):
    def __init__(self, journal, *, monitor, **providers):
        require(isinstance(monitor, TapLinkEvents) and monitor.runtime.journal is journal
                and monitor.socket is not None, 'original pre-creation TAP subscription required')
        self.monitor, self.handoff = monitor, None
        monitor._check()
        super().__init__(journal, **providers)
        require(self.read_context() == monitor.context, 'original TAP monitor namespace differs')

    def create(self, item, operation):
        self.monitor.drain()
        return super().create(item, operation)

    def observe(self, item, operation):
        self.monitor._check()
        if self.handoff is not None and self.handoff.exists(operation):
            return self.handoff.observe_item(item, operation)
        if self.sets is not None:
            stage = self.sets.definitions.read(operation).get('boot',{}).get('phase')
            require(stage in (None,'prepared','arming_requested','armed'),
                    'explicit TAP handoff required before original VM start')
        return super().observe(item, operation)

    def retirement_lease(self, item, operation, *, preflight):
        require(self.handoff is None or not self.handoff.exists(operation),
                'handed-off TAP requires its separate qualified retirement')
        return super().retirement_lease(item, operation, preflight=preflight)


class VMTapHandoff:
    def __init__(self, taps, *, process_factory=PinnedQEMUProcess, descriptors_factory=QEMUTapDescriptors):
        require(isinstance(taps.endpoints, HandoffTapEndpoints) and taps.endpoints.sets is taps
                and taps.endpoints.handoff is None and callable(process_factory) and callable(descriptors_factory),
                'original explicit handoff endpoint/controller capability required')
        self.taps, self.endpoints = taps, taps.endpoints
        self.definitions, self.journal, self.monitor = taps.definitions, taps.journal, taps.endpoints.monitor
        self.process_factory, self.descriptors_factory = process_factory, descriptors_factory
        self.closed, self.processes = {}, {}
        self.monitor._check()
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_tap_handoffs '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
        self.endpoints.handoff = self

    def exists(self, operation):
        return self.journal.db.execute('SELECT 1 FROM vm_tap_handoffs WHERE id=?', (operation,)).fetchone() is not None

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_tap_handoffs WHERE id=?', (operation,)).fetchone()
        if row is None:raise Conflict('original TAP handoff intent missing')
        value = json.loads(row['payload'])
        fields(value, ('id','birth','definition_sha256','tap_set','actor_sha256','monitor','phase','items','acquisition'),
               'original TAP handoff')
        require(value['id'] == operation == value['birth']['creator_operation_id']
                and row['domain_uuid'] == value['birth']['uuid'] and fingerprint(value) == row['fingerprint']
                and value['phase'] in ('prepared','releasing','released','acquired')
                and value['tap_set'] == self.taps.read(operation), 'original TAP handoff lineage changed')
        require(len(value['items']) == len(value['tap_set']['items']), 'complete TAP handoff set required')
        phases = []
        for item, source in zip(value['items'], value['tap_set']['items']):
            fields(item, ('nonce','link_birth','lease_token','fd','phase','close_proof'), 'original TAP close intent')
            link = item['link_birth'];tap = source['spec']['tap']
            fields(link, ('monitor_id','epoch','context','name','ifindex','sequence'), 'original monitored TAP birth')
            require(item['nonce'] == source['spec']['tap']['nonce'] and type(item['fd']) is int and item['fd'] >= 0
                    and item['lease_token'] == source['proof']['retention']['lease_token']
                    and link['name'] == tap['name'] and link['ifindex'] == tap['ifindex']
                    and link['context'] == value['tap_set']['context']
                    and link['monitor_id'] == value['monitor']['id'] and link['epoch'] == value['monitor']['epoch']
                    and type(link['sequence']) is int and link['sequence'] > 0
                    and item['phase'] in ('held','close_requested','released'), 'original TAP close owner changed')
            if item['phase'] == 'released':
                require(item['close_proof'] == self._closed_proof(value, item), 'original TAP close receipt changed')
            else:require(item['close_proof'] is None, 'unexpected early TAP close receipt')
            phases.append(item['phase'])
        rest = [phase for phase in phases if phase != 'released']
        require(phases == ['released'] * (len(phases) - len(rest)) + rest
                and rest in (['held'] * len(rest), ['close_requested'] + ['held'] * (len(rest) - 1))
                and (value['phase'] not in ('released','acquired') or not rest)
                and (value['phase'] != 'prepared' or phases == ['held'] * len(phases))
                and (value['phase'] == 'acquired') == (value['acquisition'] is not None),
                'original TAP handoff order or acquisition changed')
        return value

    def _closed_proof(self, value, item):
        return dict(monitor_id=value['monitor']['id'], lease_token=item['lease_token'], fd=item['fd'],
                    actor_sha256=value['actor_sha256'], original_fd_closed=True)

    def _save(self, value):
        self.journal.db.execute('UPDATE vm_tap_handoffs SET payload=?,fingerprint=? WHERE id=?',
                                (canonical(value),fingerprint(value),value['id']))

    def _source(self, value):
        definition = self.definitions.read(value['id'])
        self.definitions._fence(definition);self.definitions._session(definition)
        self.monitor._check()
        require(self.endpoints.handoff is self and self.taps.endpoints is self.endpoints
                and definition['birth'] == value['birth']
                and self.taps.read(value['id']) == value['tap_set']
                and definition['request_fingerprint'] == value['definition_sha256']
                and self.monitor.id == value['monitor']['id'] and self.monitor.epoch == value['monitor']['epoch']
                and self.monitor.identity == value['monitor']['socket']
                and self.monitor.context == value['tap_set']['context']
                and fingerprint(self.endpoints._actor(value['id'])) == value['actor_sha256'],
                'original TAP handoff actor, monitor or definition changed')
        return definition

    def _verify_links(self, operation, names, scope):
        value = self.read(operation)
        self._source(value)
        require(sorted(source['spec']['tap']['name'] for source in value['tap_set']['items']) == names
                and scope == value['tap_set']['context'], 'original complete TAP descriptor request differs')
        for item, source in zip(value['items'], value['tap_set']['items']):
            self._link(value, item, source)
        return dict(names=names, context_sha256=fingerprint(scope), continuity_verified=True)

    def _link(self, value, item, source):
        self.monitor.verify(item['link_birth'], pump=not self.journal.db.in_transaction)
        original = self.endpoints._source(source, value['id'])
        require(original is not None and original['proof'] == source['proof'], 'original retained TAP birth differs')
        device = self.endpoints.live[item['nonce']]['device']
        expected = source['proof']['retention']['retained_proof']['link']
        require(device._links() == [expected], 'original handed-off TAP kernel configuration changed')
        return device

    def _descriptors(self, value, definition):
        record = definition.get('boot', {}).get('process_record')
        require(record is not None and record['birth'] == value['birth'], 'original durable QEMU process required')
        key = value['id']
        if key not in self.processes:
            self.processes[key] = self.descriptors_factory(self.process_factory(deepcopy(record)),
                verify_links=lambda names, scope:self._verify_links(key,names,scope))
        observer = self.processes[key]
        require(observer.process.record == record, 'original QEMU descriptor observer cannot be replaced')
        names = sorted(source['spec']['tap']['name'] for source in value['tap_set']['items'])
        return observer.observe(names, value['tap_set']['context'])

    def observe_item(self, source, operation):
        value = self.read(operation);definition = self._source(value)
        matches = [(item, original) for item, original in zip(value['items'],value['tap_set']['items'])
                   if original == source]
        require(len(matches) == 1, 'original TAP handoff item required')
        item, source = matches[0]
        device = self._link(value,item,source)
        if device._fd is not None:
            require(item['phase'] in ('held','close_requested') and device._fd == item['fd']
                    and item['nonce'] not in self.closed
                    and definition.get('boot',{}).get('phase') in (None,'prepared','arming_requested','armed'),
                    'original creator FD differs or was not released before boot')
            return LocalTapEndpoints.observe(self.endpoints, source, operation)
        require(item['phase'] in ('close_requested','released')
                and self.closed.get(item['nonce']) == self._closed_proof(value,item),
                'original TAP close acknowledgement lost; no descriptor adoption')
        if definition.get('boot', {}).get('process_record') is not None:
            writers = self.taps._writers(value['tap_set'],definition)
            if writers:
                proof = self._descriptors(value,definition)
                if value['phase'] == 'acquired':
                    require(value['acquisition'] == proof, 'original QEMU TAP acquisition changed')
            else:
                from .vm_shutdown import stopped_proof
                stopped_proof(self.definitions,definition)
                require(value['phase'] == 'acquired'
                        and value['acquisition']['process_record_sha256'] ==
                            fingerprint(definition['boot']['process_record'])
                        and value['acquisition']['context_sha256'] == fingerprint(value['tap_set']['context']),
                        'original stopped TAP acquisition receipt required')
            require(definition['boot']['phase'] not in ('resume_requested','running') or value['phase'] == 'acquired',
                    'QEMU TAP acquisition must be durable before guest resume')
        # This is the immutable retention BIRTH, not a claim that its creator
        # descriptor remains open. Current ownership was checked separately.
        return deepcopy(source['proof'])

    def drain_for_exit(self, operation):
        """Consume and record original events before shutdown's SQL publication.

        This does not assert writer absence or complete shutdown. The existing
        shutdown transaction must still qualify the original pidfd exit and
        recheck all resources with the candidate completion receipt visible.
        """
        value = self.read(operation);self._source(value)
        for item, source in zip(value['items'],value['tap_set']['items']):
            self._link(value,item,source)

    def _full(self, value):
        definition = self._source(value)
        self.definitions._resources(definition)
        return definition

    def _release_ready(self, value):
        definition = self._full(value)
        require(definition.get('boot',{}).get('phase') == 'armed',
                'original armed VM required before TAP release')
        domain = self.definitions.connection.lookupByUUIDString(value['birth']['uuid'])
        require(self.definitions._ack(definition,domain) == definition['ack'],
                'original inactive definition changed before TAP release')
        return definition

    def prepare(self, operation):
        with self.journal.execution_lock:
            require(callable(self.taps.writers), 'qualified writer census required before TAP handoff')
            if self.exists(operation):
                value = self.read(operation);self._full(value)
                return value
            definition = self.definitions.read(operation)
            require(definition['phase'] == 'defined' and definition.get('boot') is None,
                    'new TAP handoff intent must precede boot')
            tap_set = self.taps.observe(operation)
            require(tap_set['phase'] == 'retained', 'complete retained TAP set required')
            self.definitions._resources(definition)
            items = []
            for source in tap_set['items']:
                nonce = source['spec']['tap']['nonce'];device = self.endpoints.live[nonce]['device']
                link_birth = self.monitor.birth(source['spec']['tap']['name'],source['spec']['tap']['ifindex'])
                require(device._fd is not None, 'original creator FD required before handoff intent')
                items.append(dict(nonce=nonce, link_birth=link_birth, lease_token=device._lease_token,
                                  fd=device._fd, phase='held', close_proof=None))
            value = dict(id=operation,birth=deepcopy(definition['birth']),
                definition_sha256=definition['request_fingerprint'],tap_set=deepcopy(tap_set),
                actor_sha256=fingerprint(self.endpoints._actor(operation)),
                monitor=dict(id=self.monitor.id,epoch=self.monitor.epoch,socket=deepcopy(self.monitor.identity)),
                phase='prepared',items=items,acquisition=None)
            with self.journal.transaction():
                self._full(value)
                self.journal.db.execute('INSERT INTO vm_tap_handoffs VALUES(?,?,?,?)',
                    (operation,value['birth']['uuid'],canonical(value),fingerprint(value)))
            return self.read(operation)

    def release(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);definition = self._full(value)
            if value['phase'] in ('released','acquired'):return value
            self._release_ready(value)
            for index in range(len(value['items'])):
                self._release_ready(value);item = value['items'][index]
                if item['phase'] == 'released':continue
                if item['phase'] == 'held':
                    with self.journal.transaction():
                        self._release_ready(value)
                        value['phase']='releasing';item['phase']='close_requested';self._save(value)
                    self._release_ready(value)
                    device = self.endpoints.live[item['nonce']]['device']
                    require(device._fd == item['fd'] and device.capture() ==
                            value['tap_set']['items'][index]['proof']['retention']['retained_proof'],
                            'original creator descriptor changed before close')
                    self._link(value,item,value['tap_set']['items'][index])
                    # Invalidate the local handle before close. An ambiguous
                    # syscall cannot cause a retry/finalizer to close a reused FD.
                    device._fd = None
                    os.close(item['fd'])
                    self.closed[item['nonce']] = self._closed_proof(value,item)
                require(self.closed.get(item['nonce']) == self._closed_proof(value,item),
                        'uncertain original TAP close; no repeated close')
                self._release_ready(value)
                with self.journal.transaction():
                    self._release_ready(value)
                    item.update(phase='released',close_proof=deepcopy(self.closed[item['nonce']]))
                    self._save(value)
            with self.journal.transaction():
                self._release_ready(value);value['phase']='released';self._save(value)
            return self.read(operation)

    def acquire(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);definition = self._full(value)
            require(value['phase'] in ('released','acquired'), 'complete original TAP release required')
            proof = self._descriptors(value,definition)
            if value['phase'] == 'acquired':
                require(value['acquisition'] == proof, 'original QEMU TAP acquisition changed')
                return value
            require(definition['boot']['phase'] == 'monitored_paused'
                    and self.definitions.connection.lookupByUUIDString(value['birth']['uuid']).state(0)[0] == 3,
                    'original monitored paused QEMU required before acquisition commit')
            with self.journal.transaction():
                self._full(value)
                require(self._descriptors(value,self.definitions.read(operation)) == proof,
                        'original QEMU TAP set changed before acquisition commit')
                require(self.definitions.connection.lookupByUUIDString(value['birth']['uuid']).state(0)[0] == 3,
                        'original QEMU must remain paused before acquisition commit')
                value.update(phase='acquired',acquisition=proof);self._save(value)
            return self.read(operation)
