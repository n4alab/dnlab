"""Wire the original activation journal to one live native supervisor."""

from contextlib import ExitStack, contextmanager, suppress
from copy import deepcopy

from dnlab_runtime.libvirt_activation_bus import BusStartPlan
from dnlab_runtime.libvirt_activation_controller import ActivationController
from dnlab_runtime.libvirt_activation_events import ActivationEventMonitor
from dnlab_runtime.libvirt_activation_runner import ActivationProcessRunner, ActivationWorkerObserver
from dnlab_runtime.manifest import Conflict, fingerprint
from tools.libvirt_bus_worker_runner import BusStartProcessRunner, BusWorkerObserver, NativeActivationRunner
from tools.libvirt_empty_session import EmptySessionInventory
from tools.libvirt_initial_state import InitialSessionState
from tools.libvirt_service_generation import NativeServiceObserver, ServiceSocketReader
from tools.libvirt_service_units import ServiceUnitReader, observe_service_files
from tools.libvirt_systemd_events import open_activation_stream


class OriginalMonitor:
    """Bind the live monitor after the journal assigns the original step nonces."""

    def __init__(self):
        self.monitor = None

    def verify(self, reference, request):
        return self.monitor is not None and self.monitor.verify(reference, request)

    def read_original(self, reference, request):
        if self.monitor is None:
            raise Conflict('original native activation monitor unavailable')
        return self.monitor.read_original(reference, request)


def close_worker_pipes(runner):
    for live in runner.live.values():
        process = live['process']
        for stream in (process.stdin, process.stdout, process.stderr):
            with suppress(OSError):
                stream.close()


@contextmanager
def open_native_activation(journal, installation, *, root, operation, window, binary,
                           reload_profile, start_profile, sources_sha256, bus_inventory,
                           read_context, source_reader, resources, inventory, virsh, files, unit_query,
                           prestart_reference=None, predecessor_id=None, state_admission=None):
    """Prepare and bind an activation, leaving all command releases to the caller."""
    installation = deepcopy(installation)
    bus_inventory = deepcopy(bus_inventory)
    context = installation['context']
    if context != bus_inventory['context'] or read_context() != context:
        raise Conflict('original native activation context differs')
    planner = BusStartPlan(dict(kind='dbus-start-v1', worker_sha256=start_profile['worker']['sha256'],
                                library_sha256=bus_inventory['proof']['library']['object']['sha256']))
    monitor = OriginalMonitor()
    with ExitStack() as lifetime:
        reload_observer = ActivationWorkerObserver(journal)
        lifetime.callback(reload_observer.close)
        start_observer = BusWorkerObserver(journal)
        lifetime.callback(start_observer.close)

        def verify_connection(reference, connection):
            return monitor.monitor is not None and stream.signals.verify_worker_connection(reference, connection)

        reload_runner = ActivationProcessRunner(journal, profile=reload_profile, observer=reload_observer)
        start_runner = BusStartProcessRunner(journal, profile=start_profile, observer=start_observer,
                                            inventory=bus_inventory, sources_sha256=sources_sha256,
                                            verify_connection=verify_connection)
        lifetime.callback(close_worker_pipes, reload_runner)
        lifetime.callback(close_worker_pipes, start_runner)
        runner = NativeActivationRunner(reload_runner, start_runner)
        socket_reader = ServiceSocketReader(root, installation)
        initial_state = None

        def read_generation(value, item, receipt):
            return controller._generation_observer(value, item, receipt)

        empty = EmptySessionInventory(installation, binary=virsh, sockets=socket_reader,
                                      read_generation=read_generation)

        def check_resources(value, receipts):
            proof = resources(value, receipts)
            initial_state(receipts)
            return proof

        controller = ActivationController(
            journal, installation, operation=operation, window=window, binary=binary,
            runner=runner, source_reader=source_reader, monitor=monitor, resources=check_resources,
            inventory=inventory, empty=empty, command_builder=planner)
        if predecessor_id is None:
            if state_admission is not None:raise Conflict('postboot state requires explicit predecessor')
            initial_state = InitialSessionState(root, installation)
        else:
            from tools.libvirt_postboot_state import PostBootEmptyState
            initial_state = PostBootEmptyState(root, installation, controller.driver.read(predecessor_id),
                                               approved=state_admission)
            if state_admission is None:raise Conflict('approved postboot state required before native preparation')
        unit_reader = ServiceUnitReader(installation, query=unit_query,
                                        files=lambda: observe_service_files(files, installation))

        def correlate(request, subscription, event):
            value = controller.driver.read(operation)
            matches = [item for item in value['items'] if controller.monitor_request(value, item) == request]
            if len(matches) != 1:
                raise Conflict('original native start step differs')
            command = planner(installation, matches[0], operation, binary)
            return start_runner.jobs.correlate(command, subscription, event)

        with journal.execution_lock:
            reference = (controller.prepare() if predecessor_id is None
                         else controller.prepare_successor(predecessor_id,state_admission=state_admission))
            if prestart_reference is not None:
                from dnlab_runtime.libvirt_activation_prestart import retire_unused_monitors
                retire_unused_monitors(controller, prestart_reference)
            with journal.lock:
                already_bound = journal.db.execute(
                    'SELECT 1 FROM libvirt_activation_monitor_bindings WHERE activation_id=?',
                    (operation,)).fetchone()
                event_table = journal.db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='libvirt_activation_event_monitors'"
                ).fetchone()
                already_registered = event_table and journal.db.execute(
                    'SELECT 1 FROM libvirt_activation_event_monitors WHERE activation_id=?',
                    (operation,)).fetchone()
            if (already_bound or already_registered or
                    prestart_reference is None and any(item['phase'] != 'prepared' for item in reference['items'])):
                raise Conflict('original native activation supervisor cannot be replaced')
            requests = [controller.monitor_request(reference, item) for item in reference['items']
                        if item['spec']['kind'] == 'start']
            stream, processes = lifetime.enter_context(
                open_activation_stream(root, bus_inventory, requests, read_context=read_context))
            event_monitor = ActivationEventMonitor(
                journal, binary=binary, activation_reader=controller.driver.read,
                command_intent=controller.commands.inspect_intent,
                command_reader=controller.commands.inspect_completion,
                stream=stream, processes=processes, correlate=correlate,
                observe=NativeServiceObserver(installation, unit_reader=unit_reader,
                                              processes=processes, socket_reader=socket_reader),
                command_builder=planner)
            monitor.monitor = event_monitor
            lifetime.callback(setattr, monitor, 'monitor', None)
            references = {request['spec']['unit']: event_monitor.register(
                request, stream.subscription(request['spec']['unit'])) for request in requests}
            controller.bind_monitors(references, after_reload=prestart_reference is not None)
            if prestart_reference is not None:
                reference=deepcopy(prestart_reference)
                controller.recover_original(reference)
        yield controller, reference
