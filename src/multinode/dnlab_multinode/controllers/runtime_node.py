"""Opt-in native coordinator; manifests and complete placement remain caller inputs.

Only single-host stops are qualified. Distributed cleanup needs its own tracked
barrier before finalization. Existing deployment backends are not enabled here.
"""
from dnlab_multinode.services.runtime_operations import OperationDriver, RuntimeOperationError


class RuntimeNodeController:
    def __init__(self, store, client_factory):
        self.store = store
        self.driver = OperationDriver(store, client_factory)

    def prepare_local_stop(self, request, target, *, participating_hosts):
        if (request.get('action') != 'stop' or request.get('stop_mode') != 'coordinated'
                or not isinstance(participating_hosts, (list, tuple))
                or list(participating_hosts) != [target.get('host')]):
            raise RuntimeOperationError('complete single-host coordinated stop footprint required')
        return self.driver.prepare(request, target)

    def advance_local_stop(self, lab, key, *, participating_hosts):
        current = self.store.get(lab, key, private=True)
        if (current['request'].get('action') != 'stop'
                or current['request'].get('stop_mode') != 'coordinated'
                or not isinstance(participating_hosts, (list, tuple))
                or list(participating_hosts) != [current['target']['host']]):
            raise RuntimeOperationError('complete single-host coordinated stop footprint required')
        # Re-observe before deciding: a stale parked receipt cannot authorize
        # cleanup if the runtime now requires explicit recovery.
        current = self.driver.advance(lab, key)
        if current['cancel_requested']:
            return current
        stages = {'awaiting_link_cleanup': ('exit_verified', 'cleanup'),
                  'awaiting_finalization': ('links_cleaned', 'finalize')}
        if current['phase'] not in stages:
            return current
        expected, stage = stages[current['phase']]
        receipt = current['receipt']
        if receipt.get('stop_stage') != expected or receipt.get('shutdown_verified') is not True:
            raise RuntimeOperationError('coordinated stop receipt does not verify the requested stage')
        # Durable intent before sending; the existing driver owns ACK recovery.
        self.store.request_stop_stage(lab, key, stage)
        return self.driver.advance(lab, key)
