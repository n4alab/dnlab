"""One supervised default libvirt event loop for an original runtime process.

Register before opening SDK connections. The tracked daemon thread has process
lifetime: it is not stopped when a connection closes, since libvirt can retain
callbacks after close. Retirement invalidates its witness without stopping SDK
dispatch. There is no replacement, forced thread termination or reconnect.
Native SDK failures remain pending for explicit runtime recovery.
"""
from copy import deepcopy
import json
import os
import threading
import time
import uuid

from .manifest import Conflict, canonical, fingerprint
from .vm_template import fields, require


class EventLoopRegistry:
    """Process-wide reservation; a failed registration is never retried."""
    def __init__(self):
        self.lock, self.owner = threading.Lock(), None

    def claim(self, owner):
        with self.lock:
            require(self.owner is None, 'libvirt event implementation already reserved in this process')
            self.owner = owner


_REGISTRY = EventLoopRegistry()


class LibvirtEventLoop:
    def __init__(self, runtime, sdk, *, thread_factory=threading.Thread, clock=time.monotonic,
                 process_id=os.getpid, native_id=threading.get_native_id, registry=None,
                 interval_ms=100, freshness=2.0, startup_timeout=2.0):
        require(all(callable(getattr(sdk,name,None)) for name in
                    ('virEventRegisterDefaultImpl','virEventAddTimeout','virEventRunDefaultImpl'))
                and all(callable(fn) for fn in (thread_factory,clock,process_id,native_id))
                and type(interval_ms) is int and 1<=interval_ms<=1000
                and type(freshness) in (int,float) and interval_ms/1000*3<=freshness<=10
                and type(startup_timeout) in (int,float) and 0<startup_timeout<=10,
                'qualified SDK and bounded event-loop supervision required')
        self.runtime, self.journal, self.sdk = runtime, runtime.journal, sdk
        self.thread_factory, self.clock = thread_factory, clock
        self.process_id, self.native_id = process_id, native_id
        self.registry = _REGISTRY if registry is None else registry
        self.interval_ms, self.freshness, self.startup_timeout = interval_ms, freshness, startup_timeout
        self.lock, self.ready = threading.RLock(), threading.Event()
        self.id, self.epoch, self.thread, self.receipt = uuid.uuid4().hex, None, None, None
        self.timer, self.thread_id, self.last_tick = None, None, None
        self.ticks, self.iterations, self.failure, self.attempted = 0, 0, '', False
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_libvirt_event_loops '
                '(id TEXT PRIMARY KEY,epoch_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _save(self, value, *, insert=False):
        with self.journal.transaction():
            if insert:
                self.journal.db.execute('INSERT INTO vm_libvirt_event_loops VALUES(?,?,?,?)',
                    (self.id,self.epoch['id'],canonical(value),fingerprint(value)))
            else:
                self.journal.db.execute('UPDATE vm_libvirt_event_loops SET payload=?,fingerprint=? WHERE id=?',
                    (canonical(value),fingerprint(value),self.id))

    def _configuration(self):
        return dict(interval_ms=self.interval_ms,freshness=self.freshness,startup_timeout=self.startup_timeout)

    def _fail(self, reason):
        with self.lock:
            if not self.failure:self.failure=reason

    def _thread_context(self):
        require(self.epoch is not None and self.process_id()==self.epoch['snapshot']['record']['pid']
                and self.runtime.thread_namespaces()==self.epoch['snapshot']['namespaces'],
                'original event-loop process or thread namespaces differ')

    def _heartbeat(self, timer, opaque):
        try:
            self._thread_context()
            with self.lock:
                require(opaque is self and timer==self.timer and type(timer) is int
                        and self.native_id()==self.thread_id, 'original event-loop timer/thread differs')
                self.last_tick=self.clock();self.ticks+=1
        except Exception as error:self._fail(type(error).__name__+': '+str(error))

    def _begin_thread(self):
        self._thread_context()
        with self.lock:
            require(self.thread_id is None, 'event-loop thread cannot be replaced')
            self.thread_id=self.native_id()
            require(type(self.thread_id) is int and self.thread_id>0, 'original event-loop native TID required')

    def _iterate(self):
        self._thread_context()
        require(self.native_id()==self.thread_id, 'event-loop dispatch moved to another thread')
        require(self.sdk.virEventRunDefaultImpl()==0, 'original SDK event iteration failed')
        self._thread_context()
        with self.lock:
            self.iterations+=1
            if self.ticks and not self.failure:self.ready.set()

    def _run(self):
        try:
            self._begin_thread()
            while True:self._iterate()
        except BaseException as error:
            self._fail(type(error).__name__+': '+str(error));self.ready.set()

    def start(self):
        with self.journal.execution_lock:
            require(not self.attempted, 'original event loop start cannot be repeated')
            self.attempted=True;self.epoch=deepcopy(self.runtime.check())
            require(self.process_id()==self.epoch['snapshot']['record']['pid'], 'original runtime process required for event loop')
            self.registry.claim(self.id)
            value=dict(id=self.id,epoch_id=self.epoch['id'],epoch_sha256=fingerprint(self.epoch),
                       configuration_sha256=fingerprint(self._configuration()),
                       phase='registration_requested',timer=None,thread_id=None)
            self._save(value,insert=True)
            try:
                require(self.sdk.virEventRegisterDefaultImpl()==0, 'default SDK event implementation registration failed')
                timer=self.sdk.virEventAddTimeout(self.interval_ms,self._heartbeat,self)
                require(type(timer) is int and timer>=0, 'original heartbeat timer receipt required')
                self.timer=timer;value.update(phase='thread_requested',timer=timer);self._save(value)
                require(self.runtime.check()==self.epoch, 'original runtime changed before event thread start')
                self.thread=self.thread_factory(target=self._run,name='dnlab-libvirt-events-'+self.id[:8],daemon=True)
                self.thread.start()
                if not self.ready.wait(self.startup_timeout):
                    raise Conflict('original event loop did not become ready before deadline: '+self.failure)
                self._live()
                require(self.runtime.check()==self.epoch, 'original runtime changed during event-loop startup')
                value.update(phase='running',thread_id=self.thread_id);self._save(value)
                self.receipt=deepcopy(value)
                return self.check()
            except BaseException as error:
                self._fail(type(error).__name__+': '+str(error))
                # Keep the uncertain native registration/thread and original
                # intent. Do not retry registration or remove SDK resources.
                raise

    def _live(self):
        with self.lock:
            require(not self.failure and self.thread is not None and self.thread.is_alive()
                    and self.thread.native_id==self.thread_id and self.thread_id is not None
                    and self.last_tick is not None and self.ticks>0 and self.iterations>0,
                    'original live event-loop thread unavailable: '+self.failure)
            age=self.clock()-self.last_tick
            if not 0<=age<=self.freshness:
                self._fail('event-loop heartbeat stale or clock reversed')
                raise Conflict('event-loop heartbeat stale or clock reversed')

    def check(self):
        require(self.receipt is not None, 'original running event-loop epoch required')
        try:return self._check()
        except Exception as error:
            self._fail(type(error).__name__+': '+str(error))
            raise

    def _check(self):
        require(self.runtime.check()==self.epoch, 'original running event-loop epoch required')
        self._live()
        with self.journal.lock:
            row=self.journal.db.execute('SELECT payload,fingerprint FROM vm_libvirt_event_loops WHERE id=?',(self.id,)).fetchone()
        require(row is not None, 'original event-loop receipt missing')
        value=json.loads(row['payload'])
        fields(value,('id','epoch_id','epoch_sha256','configuration_sha256','phase','timer','thread_id'),'event-loop receipt')
        require(value==self.receipt and fingerprint(value)==row['fingerprint'] and value['phase']=='running'
                and value['configuration_sha256']==fingerprint(self._configuration()),
                'original event-loop journal differs')
        self._live()
        return fingerprint(value)

    def retire(self):
        """Seal admission; dispatch continues until this runtime process exits."""
        with self.journal.execution_lock:
            self.check()
            value=deepcopy(self.receipt);value['phase']='retired';self._save(value)
            self._fail('event-loop witness explicitly retired; dispatch continues until process exit')
            return value
