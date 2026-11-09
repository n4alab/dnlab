"""Publish an original initial batch into existing public lifecycle state.

This does not schedule, start workloads, attach links or finalize deployment.
The caller persists the returned candidate through its existing state store.
"""
from copy import deepcopy

from ..models.state import NodeRuntimeState
from ..services.runtime_operations import RuntimeOperationError, encoded, digest
from ..services.runtime_lab_closure import check


def candidate(batch, lab, key, state):
    """Observe every original generation before constructing any public update."""
    if state.lab_name != lab or state.runtime_mode != 'custom' or state.teardown_requested:
        raise RuntimeOperationError('original custom deployment state required for publication')
    value = batch.get(lab, key, private=True)
    if value['phase'] != 'completed' or value['cancel_requested']:
        raise RuntimeOperationError('completed uncancelled initial batch required for publication')
    batch.management_usage.verify(lab,key)
    payload = value['payload']
    compilation = payload.get('compilation')
    if (not isinstance(compilation, dict)
            or compilation.get('fingerprint') != digest({k: v for k, v in compilation.items() if k != 'fingerprint'})
            or encoded(compilation.get('members')) != encoded(payload['original'])):
        raise RuntimeOperationError('original compiled topology required for publication')
    if 'management_plan' in compilation and compilation['management_plan'] != state.management_plan:
        raise RuntimeOperationError('public management ledger differs from initial compilation')
    members = batch.members(lab, key)
    nodes = {member['node'] for member in members}
    if state.retired_native_nodes or set(state.node_runtime) - nodes:
        raise RuntimeOperationError('initial publication cannot replace existing or retired workloads')
    for member in members:
        check(batch.store, member['request'])
        host = member['target']['host']
        scheduled = state.scheduling.get(host)
        if scheduled is None or member['node'] not in scheduled.vd:
            raise RuntimeOperationError('public placement differs from original initial batch')
    placements = [(host, node) for host, assignment in state.scheduling.items() for node in assignment.vd]
    if sorted(placements) != sorted((m['target']['host'], m['node']) for m in members):
        raise RuntimeOperationError('complete original public placement required for publication')
    # bindings() re-observes each original workload with the generation guard.
    # Nothing is assigned to the caller's state, even if the last one fails.
    bindings = batch.bindings(lab, key)
    result = deepcopy(state)
    for member in members:
        node = member['node']; spec = member['request']['spec']
        published = NodeRuntimeState(
            node=node, host=member['target']['host'], container=spec['container_name'],
            kind=spec['kind'], image=spec['image'],
            mgmt_ipv4=spec.get('management', {}).get('ipv4', ''),
            runtime_binding=bindings[node], state='running',
        )
        prior = state.node_runtime.get(node)
        if prior is not None:
            fields = ('node', 'host', 'container', 'kind', 'image', 'mgmt_ipv4', 'runtime_binding')
            if any(getattr(prior, field) != getattr(published, field) for field in fields):
                raise RuntimeOperationError('public workload differs from original initial generation')
            # Preserve already-published access/status metadata on replay.
            published = deepcopy(prior)
        result.node_runtime[node] = published
    return result


def publish(batch, lab, key, state, load_current, checkpoint):
    """Persist one candidate under the same lock as public lifecycle changes.

    A failed or uncertain checkpoint propagates. Retrying re-observes the saved
    batch; it never creates another generation or mutates the caller's snapshot.
    """
    state = deepcopy(state)
    with batch.store.executing(lab, 'management-barrier'):
        with batch.store.executing(lab, 'public-lifecycle'):
            with batch.store.executing(lab, 'initial-deployment:all'):
                batch.store.sync_directory()
                result = candidate(batch, lab, key, state)
                # Serialize closure/admission checkpoints too. Re-read the
                # existing public store so stale caller snapshots cannot erase
                # teardown or another persisted lifecycle update.
                with batch.store.transaction():
                    for member in batch.members(lab, key):
                        check(batch.store, member['request'])
                    current = load_current()
                    if current is None or encoded(current.to_dict()) != encoded(state.to_dict()):
                        raise RuntimeOperationError('public deployment changed before initial publication')
                    checkpoint(result)
                return result
