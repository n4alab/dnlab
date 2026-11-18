"""Bounded SDK event transport for one original libvirt connection.

The caller supplies a supervised, already registered event loop witness. Its
check must return the same qualified SHA256 while that original loop is live.
This transport neither runs a loop nor opens/reconnects a connection. Callbacks
copy only UUID and scalar event data; SDK domain handles never escape them.
Events are not ownership, process-birth, readiness or ordinary-exit proofs.
The consumer must persist events before acknowledging their sequence.
"""
from collections import deque
from copy import deepcopy
from threading import RLock
import uuid

from .manifest import Conflict
from .vm_template import digest, require
from .workload_identity import WorkloadReference


class LibvirtEventFeed:
    def __init__(self, connection, check_loop, *, limit=4096):
        require(callable(check_loop) and type(limit) is int and 1 <= limit <= 4096,
                'qualified event loop and bounded event queue required')
        self.connection, self.check_loop, self.limit = connection, check_loop, limit
        self.loop_sha256 = check_loop()
        require(digest(self.loop_sha256), 'original running event loop receipt required')
        self.id = uuid.uuid4().hex
        self.lock = RLock()
        self.queue, self.callbacks = deque(), []
        self.sequence, self.acknowledged = 0, 0
        self.failure, self.closed, self.registered = '', False, False
        self.close_registered = False

    def _healthy(self):
        with self.lock:
            require(not self.closed and not self.failure, 'original libvirt event feed unavailable: ' + self.failure)
        # Do not hold the callback queue lock while consulting a supervisor.
        if self.check_loop() != self.loop_sha256:
            self._fail('original event loop changed or stopped')
            raise Conflict('original event loop changed or stopped')
        with self.lock:
            require(not self.closed and not self.failure, 'original libvirt event feed unavailable: ' + self.failure)

    def _fail(self, reason):
        with self.lock:
            if not self.failure:self.failure = reason

    def _append(self, raw, domain, opaque, kind, event=None, detail=None):
        # Exceptions must be latched: SDK dispatch may otherwise swallow them.
        try:
            require(raw is self.connection._raw and opaque is self, 'foreign event connection or subscription')
            domain_uuid = domain.UUIDString()
            WorkloadReference('libvirt', 'vm', domain_uuid)
            require(kind == 'reboot' or (type(event) is int and event >= 0
                    and type(detail) is int and detail >= 0), 'malformed lifecycle event')
            with self.lock:
                require(not self.closed and not self.failure, 'original event feed is not accepting events')
                require(len(self.queue) < self.limit, 'event queue overflow; history incomplete')
                self.sequence += 1
                self.queue.append(dict(sequence=self.sequence, uuid=domain_uuid, kind=kind,
                                       event=event, detail=detail))
        except Exception as error:
            self._fail(type(error).__name__ + ': ' + str(error))

    def _lifecycle(self, raw, domain, event, detail, opaque):
        self._append(raw, domain, opaque, 'lifecycle', event, detail)

    def _reboot(self, raw, domain, opaque):
        self._append(raw, domain, opaque, 'reboot')

    def _disconnected(self, raw, reason, opaque):
        self._fail('hypervisor connection closed; event history incomplete')

    def start(self):
        require(not self.registered and not self.callbacks and not self.close_registered,
                'event registration cannot be repeated')
        try:
            self.connection._check()
            raw = self.connection._raw
            require(raw.registerCloseCallback(self._disconnected, self) == 0,
                    'connection-close subscription was not acknowledged')
            self.close_registered = True
            for event_id, callback in ((0, self._lifecycle), (1, self._reboot)):
                self.connection._check()
                token = raw.domainEventRegisterAny(None, event_id, callback, self)
                require(type(token) is int and token >= 0 and token not in self.callbacks,
                        'unique original event callback receipt required')
                self.callbacks.append(token)
                self.connection._check()
            self.connection._check()
            self.registered = True
            return self
        except BaseException:
            self._fail('event registration incomplete; cannot renew subscription')
            raise

    def read(self, after_sequence):
        self.connection._check()
        self._healthy()
        with self.lock:
            require(self.registered and not self.closed and not self.failure and type(after_sequence) is int
                    and self.acknowledged <= after_sequence <= self.sequence,
                    'original retained event cursor required')
            return dict(feed_id=self.id, loop_sha256=self.loop_sha256,
                        events=deepcopy([event for event in self.queue if event['sequence'] > after_sequence]))

    def acknowledge(self, sequence):
        """Release memory only after the caller has durably consumed events."""
        self.connection._check()
        with self.lock:
            require(self.registered and not self.closed and not self.failure and type(sequence) is int
                    and self.acknowledged <= sequence <= self.sequence, 'invalid event acknowledgement')
            while self.queue and self.queue[0]['sequence'] <= sequence:self.queue.popleft()
            self.acknowledged = sequence

    def close(self):
        with self.lock:
            if self.closed:return
            self.closed = True
        raw = self.connection._raw
        errors = []
        if raw is not None:
            for token in self.callbacks:
                try:raw.domainEventDeregisterAny(token)
                except Exception as error:errors.append(error)
            if self.close_registered:
                try:raw.unregisterCloseCallback()
                except Exception as error:errors.append(error)
        if errors:
            first = errors[0]
            for error in errors[1:]:first.add_note('event deregistration also failed: ' + str(error))
            raise first
