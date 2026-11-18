"""Persistent consumer of one original SDK feed for paused VM boot.

Registration is supplied by the original live feed; this object never opens a
connection, starts an event loop, discovers a QEMU PID or mutates a domain.
Raw events are committed before queue acknowledgement. Reopening a journal
cannot recreate collector continuity. Unknown UUID events are retained as data,
never used to adopt a domain. QEMU birth remains a separate mandatory provider.
"""
from copy import deepcopy
import json
import time
import uuid

from .manifest import Conflict, canonical, fingerprint
from .vm_events import VMEventTracker, validate_birth
from .vm_template import digest, fields, require
from .workload_identity import WorkloadReference


class LibvirtBootEvents:
    def __init__(self, definitions, feed, *, runtime, observer, clock=time.monotonic,
                 pause=time.sleep, timeout=5):
        require(feed.connection is definitions.connection and callable(observer)
                and callable(getattr(runtime, 'check', None)) and callable(clock) and callable(pause)
                and type(timeout) in (int,float) and 0 < timeout <= 10,
                'original connection/feed, runtime and bounded boot event providers required')
        self.definitions, self.journal, self.feed = definitions, definitions.journal, feed
        self.runtime, self.observer = runtime, observer
        self.clock, self.pause, self.timeout = clock, pause, timeout
        self.id, self.epoch = uuid.uuid4().hex, fingerprint(runtime.check())
        self.tracker = VMEventTracker(self.journal, self._observe_birth)
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_libvirt_feeds '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_libvirt_raw_events '
                '(feed_id TEXT NOT NULL,sequence INTEGER NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,'
                'PRIMARY KEY(feed_id,sequence))')
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_libvirt_boot_sources '
                '(id TEXT PRIMARY KEY,domain_uuid TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')
            require(self.journal.db.execute('SELECT 1 FROM vm_libvirt_feeds WHERE id=?',(feed.id,)).fetchone() is None,
                    'original feed collector cannot be reconstructed or adopted')
            feed.read(0)
            value=dict(id=feed.id,collector_id=self.id,loop_sha256=feed.loop_sha256,epoch_sha256=self.epoch,cursor=0)
            self.journal.db.execute('INSERT INTO vm_libvirt_feeds VALUES(?,?,?)',
                                    (feed.id,canonical(value),fingerprint(value)))

    def _feed(self):
        require(fingerprint(self.runtime.check()) == self.epoch, 'original boot collector runtime epoch differs')
        row=self.journal.db.execute('SELECT * FROM vm_libvirt_feeds WHERE id=?',(self.feed.id,)).fetchone()
        require(row is not None, 'original feed journal missing')
        value=json.loads(row['payload'])
        fields(value,('id','collector_id','loop_sha256','epoch_sha256','cursor'),'original feed cursor')
        require(fingerprint(value)==row['fingerprint'] and value['id']==self.feed.id
                and value['collector_id']==self.id and value['loop_sha256']==self.feed.loop_sha256
                and value['epoch_sha256']==self.epoch and type(value['cursor']) is int and value['cursor']>=0,
                'original feed journal or collector differs')
        return value

    def pump(self):
        with self.journal.execution_lock:
            value=self._feed();batch=self.feed.read(value['cursor'])
            fields(batch,('feed_id','loop_sha256','events'),'original feed batch')
            require(batch['feed_id']==value['id'] and batch['loop_sha256']==value['loop_sha256']
                    and type(batch['events']) is list and len(batch['events'])<=4096, 'original feed batch differs')
            events=deepcopy(batch['events']);cursor=value['cursor']
            for event in events:
                fields(event,('sequence','uuid','kind','event','detail'),'raw libvirt event')
                WorkloadReference('libvirt','vm',event['uuid'])
                require(type(event['sequence']) is int and event['sequence']==cursor+1
                        and ((event['kind']=='reboot' and event['event'] is None and event['detail'] is None)
                             or (event['kind']=='lifecycle' and type(event['event']) is int and event['event']>=0
                                 and type(event['detail']) is int and event['detail']>=0)), 'event history gap or malformed callback')
                cursor=event['sequence']
            if events:
                with self.journal.transaction():
                    require(self._feed()==value, 'original feed cursor changed before commit')
                    for event in events:
                        self.journal.db.execute('INSERT INTO vm_libvirt_raw_events VALUES(?,?,?,?)',
                            (self.feed.id,event['sequence'],canonical(event),fingerprint(event)))
                    value['cursor']=cursor
                    self.journal.db.execute('UPDATE vm_libvirt_feeds SET payload=?,fingerprint=? WHERE id=?',
                        (canonical(value),fingerprint(value),value['id']))
            # A lost ack never causes the committed raw events to be inserted twice.
            self.feed.acknowledge(cursor)
            return cursor

    def read(self, source_id):
        row=self.journal.db.execute('SELECT * FROM vm_libvirt_boot_sources WHERE id=?',(source_id,)).fetchone()
        require(row is not None, 'original boot event source missing')
        value=json.loads(row['payload'])
        fields(value,('id','collector_id','feed_id','epoch_sha256','birth','request_fingerprint','phase','cursor',
                      'initial','reference_sha256','process_record_sha256','tracker_sequence','reason'),'boot event source')
        validate_birth(value['birth'])
        fields(value['initial'],('started','paused','resumed'),'original boot lifecycle sequence')
        require(value['id']==source_id and fingerprint(value)==row['fingerprint']
                and row['domain_uuid']==value['birth']['uuid'] and value['collector_id']==self.id
                and value['feed_id']==self.feed.id and value['epoch_sha256']==self.epoch
                and value['phase'] in ('armed','active','recovery_required') and digest(value['request_fingerprint'])
                and type(value['cursor']) is int and value['cursor']>=0
                and type(value['tracker_sequence']) is int and value['tracker_sequence']>=0
                and all(v is None or (type(v) is int and 0<v<=value['cursor']) for v in value['initial'].values()),
                'original boot source collector differs')
        require((value['reference_sha256'] is None and value['process_record_sha256'] is None)
                or (digest(value['reference_sha256']) and digest(value['process_record_sha256'])),
                'complete original event activation reference required')
        require(value['phase']!='active' or value['reference_sha256'] is not None,
                'active event source requires original paused process receipt')
        return value

    def _save(self, value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE vm_libvirt_boot_sources SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def _definition(self, source):
        value=self.definitions.read(source['birth']['creator_operation_id'])
        require(value['birth']==source['birth'] and value['request_fingerprint']==source['request_fingerprint']
                and value['boot']['source_id']==source['id'], 'original boot definition lineage differs')
        self.definitions._fence(value)
        return value

    def _observe_birth(self, birth):
        row=self.journal.db.execute('SELECT id FROM vm_libvirt_boot_sources WHERE domain_uuid=?',(birth['uuid'],)).fetchone()
        require(row is not None, 'original tracked boot source missing')
        source=self.read(row['id']);value=self._definition(source);boot=value['boot']
        require(source['birth']==birth and source['reference_sha256']==fingerprint(boot['reference'])
                and source['process_record_sha256']==fingerprint(boot['process_record']), 'original paused process receipt differs')
        return self.observer(deepcopy(boot['reference']),deepcopy(boot['process_record']))(deepcopy(birth))

    def _drain(self, source_id):
        cursor=self.pump();source=self.read(source_id)
        require(source['phase']!='recovery_required', 'boot event source requires qualified recovery: '+source['reason'])
        rows=self.journal.db.execute('SELECT * FROM vm_libvirt_raw_events WHERE feed_id=? AND sequence>? AND sequence<=? ORDER BY sequence',
                                    (self.feed.id,source['cursor'],cursor)).fetchall()
        for row in rows:
            event=json.loads(row['payload'])
            require(fingerprint(event)==row['fingerprint'] and event['sequence']==row['sequence']==source['cursor']+1,
                    'persisted raw event differs or history incomplete')
            if event['uuid']==source['birth']['uuid']:
                self._reduce(source,event)
            source['cursor']=event['sequence'];self._save(source)
            require(source['phase']!='recovery_required', 'boot event source requires qualified recovery: '+source['reason'])
        require(source['cursor']==cursor, 'persisted raw event history incomplete')
        return source

    def _reduce(self, source, event):
        value=self._definition(source);stage=value['boot']['phase']
        early=stage in ('start_requested','paused','activation_requested','monitored_paused')
        code=(event['event'],event['detail'])
        if event['kind']=='lifecycle' and code in ((2,0),(3,0),(4,0)):
            slot={(2,0):'started',(3,0):'paused',(4,0):'resumed'}[code]
            allowed=early if slot!='resumed' else source['phase']=='active' and stage in ('resume_requested','running')
            if source['initial'][slot] is not None or not allowed or (slot!='started' and source['initial']['started'] is None):
                source.update(phase='recovery_required',reason='unexpected or repeated boot lifecycle event')
            else:
                if source['phase']=='active':self._observe_birth(source['birth'])
                source['initial'][slot]=event['sequence']
            return
        if source['phase']!='active':
            source.update(phase='recovery_required',reason='lifecycle changed before paused process activation')
            return
        kind='reboot' if event['kind']=='reboot' else {2:'started',5:'stopped',8:'crash'}.get(event['event'])
        if kind is None:
            source.update(phase='recovery_required',reason='unexpected lifecycle event requires a qualified operation')
            return
        result=self.tracker.record(source['id'],source['tracker_sequence']+1,kind)
        source['tracker_sequence']+=1
        if result['state']['phase']!='active':source.update(phase='recovery_required',reason=result['state']['reason'])

    def _armed_ack(self, source):
        return dict(source_id=source['id'],collector_id=self.id,request_fingerprint=source['request_fingerprint'],
                    birth_sha256=fingerprint(source['birth']),ready=True)

    def _active_ack(self, source):
        return dict(source_id=source['id'],collector_id=self.id,reference_sha256=source['reference_sha256'],
                    process_record_sha256=source['process_record_sha256'],active=True)

    def arm(self, value):
        with self.journal.execution_lock:
            boot=value['boot'];require(boot['phase']=='arming_requested', 'original boot arming checkpoint required')
            require(self.definitions.read(value['birth']['creator_operation_id'])==value, 'original boot intent differs')
            self.definitions._fence(value)
            domain=self.definitions.connection.lookupByUUIDString(value['birth']['uuid'])
            require(self.definitions._ack(value,domain)==value['ack'], 'original inactive definition required before event arming')
            cursor=self.pump()
            history=self.journal.db.execute('SELECT payload FROM vm_libvirt_raw_events WHERE feed_id=? AND sequence<=?',
                                           (self.feed.id,cursor)).fetchall()
            for row in history:
                event=json.loads(row['payload'])
                if event['uuid']==value['birth']['uuid']:
                    require(event['kind']=='lifecycle' and event['event']==0,
                            'unexpected domain lifecycle before original event arm')
            require(self.definitions._ack(value,domain)==value['ack'], 'original inactive definition changed during event arming')
            source=dict(id=boot['source_id'],collector_id=self.id,feed_id=self.feed.id,epoch_sha256=self.epoch,
                birth=deepcopy(value['birth']),request_fingerprint=value['request_fingerprint'],phase='armed',cursor=cursor,
                initial=dict(started=None,paused=None,resumed=None),reference_sha256=None,process_record_sha256=None,
                tracker_sequence=0,reason='')
            with self.journal.transaction():
                require(self.journal.db.execute('SELECT 1 FROM vm_libvirt_boot_sources WHERE id=? OR domain_uuid=?',
                        (source['id'],source['birth']['uuid'])).fetchone() is None, 'original event arming cannot be repeated')
                self.journal.db.execute('INSERT INTO vm_libvirt_boot_sources VALUES(?,?,?,?)',
                    (source['id'],source['birth']['uuid'],canonical(source),fingerprint(source)))
            return self._armed_ack(source)

    def activate(self, value):
        with self.journal.execution_lock:
            require(value['boot']['phase']=='activation_requested', 'original activation checkpoint required')
            source=self._drain(value['boot']['source_id']);deadline=self.clock()+self.timeout
            while source['initial']['started'] is None:
                if self.clock()>=deadline:raise Conflict('original boot event not observed before activation deadline')
                self.pause(min(0.01,max(0,deadline-self.clock())))
                source=self._drain(source['id'])
            current=self._definition(source)
            require(current==value and self.definitions.connection.lookupByUUIDString(source['birth']['uuid']).state(0)[0]==3,
                    'original paused VM activation differs')
            reference=fingerprint(value['boot']['reference']);record=fingerprint(value['boot']['process_record'])
            if source['phase']=='armed':
                source.update(reference_sha256=reference,process_record_sha256=record)
                self._observe_candidate(source,value)
                self._save(source)
                self.tracker.begin(source['id'],source['birth'])
                source['phase']='active';self._save(source)
            require(source['phase']=='active' and source['reference_sha256']==reference
                    and source['process_record_sha256']==record, 'original event activation cannot be replaced')
            self._observe_birth(source['birth'])
            return self._active_ack(source)

    def _observe_candidate(self, source, value):
        require(source['birth']==value['birth'], 'original paused event owner differs')
        return self.observer(deepcopy(value['boot']['reference']),deepcopy(value['boot']['process_record']))(deepcopy(source['birth']))

    def verify(self, ack):
        with self.journal.execution_lock:
            source=self._drain(ack['source_id'])
            require(ack in (self._armed_ack(source),self._active_ack(source)), 'original event acknowledgement differs')
            self._definition(source)
            if source['phase']=='active':
                self._observe_birth(source['birth'])
                tracked=self.tracker.read(source['id'])
                require(tracked['monitor_id']==self.tracker.monitor_id and tracked['phase']=='active',
                        'original VM tracker continuity differs')
            else:require(ack==self._armed_ack(source), 'inactive source cannot verify activation')
            return True

    def recover_arm(self, value):
        """Read an existing original arm receipt; never register another one."""
        with self.journal.execution_lock:
            require(value['boot']['phase']=='arming_requested', 'original uncertain arming checkpoint required')
            source=self._drain(value['boot']['source_id'])
            require(source['phase']=='armed' and self._definition(source)==value,
                    'original armed source receipt missing or changed')
            domain=self.definitions.connection.lookupByUUIDString(source['birth']['uuid'])
            require(self.definitions._ack(value,domain)==value['ack'], 'original inactive definition differs')
            ack=self._armed_ack(source);self.verify(ack)
            return ack

    def recover_activation(self, value):
        """Only the saved active receipt can resolve an uncertain activation."""
        with self.journal.execution_lock:
            require(value['boot']['phase']=='activation_requested', 'original uncertain activation checkpoint required')
            source=self._drain(value['boot']['source_id'])
            require(source['phase']=='active' and self._definition(source)==value,
                    'original active source receipt missing or changed')
            domain=self.definitions.connection.lookupByUUIDString(source['birth']['uuid'])
            require(domain.state(0)[0]==3, 'original VM must remain paused during event recovery')
            ack=self._active_ack(source);self.verify(ack)
            return ack
