"""New cleanup descriptor for a continuously monitored, already retired TAP.

This is NOT a replacement creator lease. The original retention and handoff
history must remain unchanged. The owning coordinator supplies durable records
and complete retired-domain/writer/resource checks before every mutation.
No reopen, ioctl or close is automatically repeated after uncertainty.
"""
from copy import deepcopy

from .manifest import fingerprint
from .vm_tap_device import IFREQ, TUNSETIFF
from .vm_tap_link_events import TapLinkEvents
from .vm_tap_retention import RetainedTapDevice, TUNSETPERSIST, PERSIST, ownership, signature
from .vm_template import digest, require


class TapCleanupHandle:
    def __init__(self, device, monitor, birth, retained, *, retirement_sha256, preflight, record):
        require(isinstance(device,RetainedTapDevice) and not device._entered and device._fd is None
                and isinstance(monitor,TapLinkEvents) and device.context == monitor.context
                and birth['name'] == device.spec['name'] and birth['ifindex'] == device.spec['ifindex']
                and digest(retirement_sha256) and callable(preflight) and callable(record)
                and device.record is record
                and retained['flags'] & PERSIST and retained['context'] == device.context,
                'new cleanup handle, original TAP continuity and retired-owner observers required')
        self.device,self.monitor,self.birth = device,monitor,deepcopy(birth)
        self.retained,self.retirement = deepcopy(retained),retirement_sha256
        self.preflight,self.record = preflight,record
        self.requested,self.unpersist_requested,self.unpersisted,self.close_requested = False,False,False,False
        self.acquisition,self.close_ack = None,None

    def _source(self):
        self.monitor.verify(self.birth)
        expected = dict(retirement_sha256=self.retirement, tap_birth_sha256=fingerprint(self.birth),
                        writers_absent=True, remaining_resources_verified=True)
        require(self.preflight() == expected, 'qualified retired domain, writer absence and remaining resources required')

    def _capture(self, *, allow_unpersisted=False, pump=True):
        self.monitor.verify(self.birth,pump=pump)
        proof = self.device.capture()
        wanted = ownership(self.retained)
        actual = ownership(proof)
        require(signature(proof) == signature(self.retained) and actual[:2] == wanted[:2]
                and actual[2] in ((0,1) if allow_unpersisted else (1,)),
                'original cleanup TAP descriptor/configuration differs')
        return proof

    def acquire(self):
        require(not self.requested, 'cleanup attachment cannot be repeated')
        self.requested = True
        self._source()
        require(self.device._links() == [self.retained['link']], 'original retired TAP missing or changed')
        self.record(dict(phase='cleanup_acquire_requested',lease_token=self.device._lease_token,
                         tap_birth_sha256=fingerprint(self.birth),retirement_sha256=self.retirement))
        self._source()
        self.device.__enter__()
        self._source()
        require(self.device._links() == [self.retained['link']], 'original retired TAP changed before cleanup attachment')
        self.device.ioctl(self.device._fd,TUNSETIFF,IFREQ.pack(
            self.device.spec['name'].encode('ascii'),self.retained['flags'] & ~PERSIST))
        proof = self._capture()
        self._source()
        self.acquisition = dict(lease_token=self.device._lease_token,fd=self.device._fd,
                                tap_birth_sha256=fingerprint(self.birth),proof_sha256=fingerprint(proof))
        self.record(dict(phase='cleanup_acquired',receipt=deepcopy(self.acquisition)))
        return deepcopy(self.acquisition)

    def observe(self, *, pump=True):
        require(self.acquisition is not None and self.device._fd == self.acquisition['fd']
                and self.device._lease_token == self.acquisition['lease_token'],
                'original cleanup descriptor acknowledgement lost')
        proof = self._capture(allow_unpersisted=self.unpersist_requested,pump=pump)
        if not self.unpersist_requested:
            require(fingerprint(proof) == self.acquisition['proof_sha256'], 'original cleanup attachment changed')
        return proof

    def unpersist(self):
        require(not self.unpersist_requested, 'cleanup unpersist cannot be repeated')
        self._source();self.observe()
        self.unpersist_requested = True
        self.record(dict(phase='cleanup_unpersist_requested',receipt=deepcopy(self.acquisition)))
        self._source();self.observe()
        self.device.ioctl(self.device._fd,TUNSETPERSIST,0)
        return self.recover_unpersist()

    def recover_unpersist(self):
        require(self.unpersist_requested, 'original cleanup unpersist intent required')
        self._source()
        proof = self.observe()
        require(ownership(proof)[2] == 0, 'uncertain cleanup unpersist; no repeated ioctl')
        self.unpersisted = True
        self.record(dict(phase='cleanup_unpersisted',proof_sha256=fingerprint(proof)))
        return proof

    def close(self):
        require(self.unpersisted and not self.close_requested, 'qualified single cleanup close required')
        self._source();proof = self.observe()
        require(ownership(proof)[2] == 0, 'cleanup TAP persistence returned before close')
        self.close_requested = True
        self.record(dict(phase='cleanup_close_requested',receipt=deepcopy(self.acquisition)))
        self._source();self.observe()
        self.device.close()
        self.close_ack = dict(lease_token=self.device._lease_token,original_cleanup_fd_closed=True)
        self.record(dict(phase='cleanup_closed',receipt=deepcopy(self.close_ack)))

    def absence(self, *, pump=True):
        require(self.close_requested and self.close_ack is not None and self.device._fd is None,
                'original cleanup close acknowledgement required')
        proof = self.monitor.verify_removed(self.birth,pump=pump)
        require(not self.device._links(), 'original cleanup TAP name or ifindex reoccupied')
        return dict(tap_birth_sha256=fingerprint(self.birth),retirement_sha256=self.retirement,
                    close=deepcopy(self.close_ack),removal=proof,absence_verified=True)

    def confirm_absent(self):
        proof = self.absence()
        # This observer must be independent of live TAP presence after close.
        expected = dict(retirement_sha256=self.retirement,tap_birth_sha256=fingerprint(self.birth),
                        writers_absent=True,remaining_resources_verified=True)
        require(self.preflight() == expected, 'remaining resources changed after TAP cleanup')
        require(self.absence() == proof, 'original TAP absence changed during cleanup confirmation')
        return proof
