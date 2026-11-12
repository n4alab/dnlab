"""Repeatable operation execution and compensation across daemon restarts."""

from __future__ import annotations

from .backend import LABEL
from .journal import TERMINAL
from .manifest import Conflict, NotFound, RuntimeErrorBase, capabilities, validate_request, fingerprint


class Cancelled(Exception):
    pass


class Engine:
    def __init__(self, journal, backend, *, vm_tap_tasks=None):
        self.journal = journal
        self.backend = backend
        self.execution_lock = journal.execution_lock
        if vm_tap_tasks is not None:
            from .vm_tap_tasks import TapTasks
            if not isinstance(vm_tap_tasks,TapTasks) or vm_tap_tasks.journal is not journal:
                raise Conflict('VM TAP tasks must use the original runtime journal')
        self.vm_tap_tasks = vm_tap_tasks
        from .management_authority import bind_backend
        bind_backend(backend,journal)
        from .link_engine import LinkEngine
        self.links = LinkEngine(self)
        from .stop_protocol import StopProtocol
        self.stops = StopProtocol(self)

    def plan(self, raw: dict):
        request = validate_request(raw)
        from .inspection import snapshot
        def node_snapshot():
            return {k:v for k,v in snapshot(self,request['lab_id'],request['node_id']).items() if k!='cleanup_inventory'}
        before=node_snapshot()
        from .lab_closure import check
        check(self.journal,request)
        from .management_authority import available
        available(self.journal,request['lab_id'],request['node_id'])
        if request["action"] == "stop" and request.get('stop_mode') != 'coordinated':
            self.links.node_free(request["lab_id"], request["node_id"])
        current = before['node']
        from .manifest import check_management_identity
        check_management_identity(request,current)
        revision = current["revision"] if current else 0
        if revision != request["expected_revision"]:
            raise Conflict(f"stale revision; current revision is {revision}")
        if request["action"] == "stop" and not current:
            raise NotFound("node has no committed spec")
        self.journal.available_resources(request,request.get('spec') or current['spec'])
        container=None
        if current is not None or request['action']=='start':
            container=self.backend.inspect(request,request.get('spec') or current['spec'])
        result = {
            "schema_version": 1, "mutations_performed": False,
            "expected_revision": revision, "affected_nodes": [request["node_id"]],
            "steps": ["create_container", "start_container", "ensure_endpoints", "verify", "commit"] if request["action"] == "start" else ["signal_process", "verify_exit", "delete_endpoints", "remove_container", "commit"],
            "capabilities": capabilities(),
        }
        if request['action']=='start':
            from .endpoint_preflight import observe
            endpoints=observe(self.backend,request,request['spec'])
            if endpoints is not None:result['endpoint_preflight']=endpoints
            from .management_network import preflight
            proof=preflight(self.backend,request,request['spec'])
            if proof is not None:result['management_preflight']=proof
        if request.get('stop_mode') == 'coordinated':
            result.update(self.stops.plan(request))
        if node_snapshot()!=before:raise Conflict('node changed during read-only planning; retry required')
        result['node_preflight']={'journal_id':self.journal.identity,'lab_id':request['lab_id'],'node_id':request['node_id'],
            'request_fingerprint':fingerprint({k:v for k,v in request.items() if k!='management_preflight'}),
            'revision':revision,'committed_state':current['state'] if current else 'absent',
            'container_state':'absent' if container is None else 'running' if container['State']['Running'] else 'stopped',
            'container_id':container['Id'] if container else None,
            'pending_operation_id':before['operation']['id'] if before['operation'] else None,
            'workload_phase':before['birth']['phase'] if before['birth'] else None}
        return result

    def check_cancel(self, operation_id: str):
        if self.journal.get(operation_id)["cancel_requested"]:
            raise Cancelled()

    def execute(self, operation_id: str):
        with self.execution_lock:
            operation = self.journal.get(operation_id, private=True)
            if operation["phase"] in TERMINAL:
                return self.journal.get(operation_id)
            request = operation["payload"]
            from .lab_closure import check
            check(self.journal,request)
            if request.get('stop_mode') == 'coordinated':
                return self.stops.execute(operation_id)
            current = self.journal.node(request["lab_id"], request["node_id"])
            spec = request.get("spec") or current["spec"]
            try:
                self.check_cancel(operation_id)
                self.journal.phase(operation_id, "validating")
                self.plan(request)
                if request['action']=='start':
                    from .management_network import preflight
                    preflight(self.backend,request,spec,required=True)
                self.check_cancel(operation_id)
                self.journal.phase(operation_id, "applying")
                if request["action"] == "start":
                    existing = self.backend.inspect(request, spec)
                    if existing and existing.get("Config", {}).get("Labels", {}).get(LABEL + ".creator") != operation_id and (not current or current["state"] != "running"):
                        raise Conflict("cannot adopt workload without a committed running node")
                    from .endpoint_preflight import checkpoint
                    checkpoint(self.backend,request,spec,operation_id)
                    self.backend.create(request, spec, operation_id)
                    self.check_cancel(operation_id)
                    self.backend.start(request, spec)
                    from .management_authority import rebind
                    rebind(self.journal,request,spec,self.backend.inspect(request,spec),operation_id)
                    self.check_cancel(operation_id)
                    for endpoint in spec.get("endpoints", []):
                        self.backend.ensure_endpoint(request, spec, endpoint)
                        self.check_cancel(operation_id)
                    self.journal.phase(operation_id, "verifying")
                    self.backend.verify(request, spec)
                    self.check_cancel(operation_id)
                    self.journal.finish(operation_id, spec, "running")
                else:
                    from .management_authority import stop_allowed
                    stop_allowed(self.journal,request,spec,self.backend.inspect(request,spec))
                    self.backend.stop(request, spec, force=request.get("force", False) or operation["recovery_force"])
                    self.backend.delete_endpoints(request, spec)
                    self.backend.remove(request, spec)
                    self.journal.phase(operation_id, "verifying")
                    # A stop cancellation does not recreate an already stopped workload.
                    # Commit the observed stopped state even if cancellation raced with exit.
                    self.journal.finish(operation_id, spec, "stopped", stop_finished=True)
            except BaseException as exc:
                # Process death is handled by journal replay, not in-process compensation.
                if not isinstance(exc, Exception):
                    raise
                cancelled = isinstance(exc, Cancelled) or self.journal.get(operation_id)["cancel_requested"]
                error = "cancellation requested" if cancelled else self._error(exc)
                from .workload_generation import GenerationConflict
                from .management_network import NetworkIdentityConflict
                from .endpoint_preflight import EndpointConflict
                from .backend_reservations import BackendOwnershipConflict
                if isinstance(exc,(GenerationConflict,NetworkIdentityConflict,EndpointConflict,BackendOwnershipConflict)):
                    self.journal.phase(operation_id,'recovery_required',error)
                elif request["action"] == "start":
                    self._compensate_start(operation_id, request, spec, cancelled, error)
                else:
                    self.journal.phase(operation_id, "cancelled" if isinstance(exc, Cancelled) else "recovery_required", error)
            return self.journal.get(operation_id)

    @staticmethod
    def _error(exc: Exception) -> str:
        # Only our errors are safe for external status; unexpected errors may include env.
        return str(exc) if isinstance(exc, RuntimeErrorBase) else f"operation failed ({type(exc).__name__})"

    def _compensate_start(self, operation_id, request, spec, cancelled, error):
        self.journal.phase(operation_id, "cancelling" if cancelled else "compensating", error)
        try:
            container = self.backend.inspect(request, spec)
            if container and container.get("Config", {}).get("Labels", {}).get(LABEL + ".creator") != operation_id:
                # Repeated start of a committed node must never destroy the existing VD.
                current = self.journal.node(request["lab_id"], request["node_id"])
                if not current or current["state"] != "running":
                    raise Conflict("container was created by a different operation")
                self.backend.verify(request, spec)
            else:
                self.backend.stop(request, spec, force=self.journal.get(operation_id)["recovery_force"])
                self.backend.delete_endpoints(request, spec)
                self.backend.remove(request, spec)
            self.journal.rollback_finished(operation_id, "cancelled" if cancelled else "failed", error)
        except Exception as cleanup_error:
            self.journal.phase(operation_id, "recovery_required", error + "; cleanup: " + self._error(cleanup_error))

    def recover(self):
        return [self.execute(operation_id) for operation_id in self.journal.pending()]

    def reconcile(self, operation_id: str, *, force: bool = False):
        self.journal.queue_recovery(operation_id, force=force)
        return self.execute(operation_id)

    def inspect(self, lab: str, node: str):
        from .inspection import inspect
        return inspect(self,lab,node)
