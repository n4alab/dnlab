"""Read-only cleanup admission; ordinary callers remain blocked.

An explicit attestation needs trusted qualification and observation providers.
Labels or a JSON document claiming qualification cannot enable a gate. The
live runners do not yet supply these providers. Admission is not authorization
to execute a gate or to delete any resource.
"""
from copy import deepcopy
import math
import re
import time


class CleanupCompatibilityError(RuntimeError):
    def __init__(self, reason, evidence):
        self.evidence = evidence
        super().__init__('live gate blocked: ' + reason)


def require_qualified_cleanup(api, *, attestation=None):
    """Observe local daemon candidates, then refuse an unqualified live gate.

    Absence from the local Engine does not prove cleanup safety. Explicit
    admission covers only the local host and coordinator in the attestation.
    """
    evidence = {'schema_version': 1, 'scope': 'local-engine-only',
                'qualified': False, 'candidates': []}
    try:
        containers = api.request('GET', '/containers/json?all=1')
        if not isinstance(containers, list):
            raise ValueError('container inventory is not a list')
        seen = set()
        for item in containers:
            if not isinstance(item, dict):
                raise ValueError('invalid inventory entry')
            cid = item.get('Id')
            if (not isinstance(cid, str) or not re.fullmatch(r'[0-9a-f]{64}', cid)
                    or cid in seen):
                raise ValueError('invalid or duplicate container identity')
            seen.add(cid)
            labels, names = item.get('Labels'), item.get('Names')
            if not isinstance(labels, dict) or not isinstance(names, list):
                raise ValueError('incomplete container inventory')
            if not all(isinstance(name, str) for name in names):
                raise ValueError('invalid container names')
            command = item.get('Command', '')
            if not isinstance(command, str):
                raise ValueError('invalid command observation')
            candidate = (labels.get('com.docker.compose.service') == 'lab-cleanup'
                         or labels.get('com.docker.compose.service') == 'multinode'
                         or any('lab-cleanup' in name or 'lab_cleanup' in name
                                for name in names)
                         or 'lab-cleanup' in command or 'lab_cleanup' in command
                         or 'dnlab-multinode' in command or 'cleanup-labs' in command)
            if candidate:
                # Do not retain command, environment or arbitrary labels.
                evidence['candidates'].append({'container_id': cid,
                                               'names': names})
        evidence['inventory_count'] = len(containers)
    except Exception as error:
        if type(attestation) is CleanupAttestation:
            attestation.invalidate()
        raise CleanupCompatibilityError('cleanup inventory unavailable or incomplete',
                                        evidence) from error
    if attestation is not None:
        if type(attestation) is not CleanupAttestation:
            raise CleanupCompatibilityError('explicit verified attestation required', evidence)
        return attestation._check(evidence)
    raise CleanupCompatibilityError(
        'deployed cleanup protection is not qualified; no live resources created',
        evidence)


ENTRYPOINTS = {
    'daemon': {'daemon-start'},
    'multinode': {'api-cleanup', 'cli-cleanup', 'cli-sync'},
    'native': {'cli-cleanup', 'cli-sync'},
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


class CleanupAttestation:
    """One local gate/window, with pinned qualification and current identities.

    ``verify_execution(role, profile)`` must authenticate a prior execution
    receipt against its pinned digest, artifact and entrypoints. ``observe``
    must freshly qualify the local context, actor artifacts/generations, held
    image-build and the agreed exclusion of native CLI use. These are trusted
    IO providers, not booleans supplied by a gate request. Neither provider is
    implemented or operationally qualified by this in-memory comparison.

    Artifact digests cover execution assets/import configuration; generation
    digests cover current process/starttime/namespace/configuration, or the
    native installation identity while native CLI use is excluded. A failure
    invalidates this instance. Cleanup remains with the original resource
    guards; an expired attestation never authorizes generic cleanup or recovery.
    """

    def __init__(self, context, actors, *, verify_execution, observe,
                 lifetime=300, clock=time.monotonic):
        _require(isinstance(context, dict) and set(context) == {
            'gate_id', 'lab_id', 'host_id', 'coordinator_id', 'boot_id',
            'window_id', 'image_build_hold_sha256'}, 'complete local gate context required')
        _require(all(isinstance(v, str) and v and len(v) <= 256 for v in context.values()),
                 'nonempty gate context required')
        _require(_sha(context['image_build_hold_sha256']), 'qualified image-build hold required')
        _require(isinstance(actors, dict) and set(actors) == set(ENTRYPOINTS),
                 'all three cleanup ingress families required')
        for role, actor in actors.items():
            _require(isinstance(actor, dict) and set(actor) == {
                'container_id', 'artifact_sha256', 'generation_sha256', 'qualification_sha256'},
                'complete actor provenance required')
            _require(all(_sha(actor[key]) for key in (
                'artifact_sha256', 'generation_sha256', 'qualification_sha256')),
                'pinned actor and qualification digests required')
            _require(actor['container_id'] is None if role == 'native' else _sha(actor['container_id']),
                     'actor container identity differs')
        ids = [actors[role]['container_id'] for role in ('daemon', 'multinode')]
        _require(len(set(ids)) == 2, 'distinct cleanup container identities required')
        _require(callable(verify_execution) and callable(observe) and callable(clock),
                 'trusted qualification, observation and clock providers required')
        _require(type(lifetime) in (int, float) and math.isfinite(lifetime)
                 and 0 < lifetime <= 3600, 'bounded gate window required')
        self._context, self._actors = deepcopy(context), deepcopy(actors)
        self._verify, self._observe, self._clock = verify_execution, observe, clock
        self._last = clock()
        _require(type(self._last) in (int, float) and math.isfinite(self._last),
                 'monotonic clock observation required')
        self._deadline = self._last + lifetime
        self._invalid = False

    def invalidate(self):
        self._invalid = True

    def recheck(self, api):
        """Re-observe before allocations and at recovery/phase boundaries."""
        return require_qualified_cleanup(api, attestation=self)

    def _check(self, inventory):
        try:
            _require(not self._invalid, 'attestation invalidated; fresh qualification required')
            now = self._clock()
            _require(type(now) in (int, float) and math.isfinite(now)
                     and self._last <= now < self._deadline, 'attestation window expired or clock changed')
            self._last = now
            expected_ids = {v['container_id'] for v in self._actors.values() if v['container_id']}
            observed_ids = {v['container_id'] for v in inventory['candidates']}
            _require(observed_ids == expected_ids, 'cleanup container inventory differs')
            for role, actor in self._actors.items():
                receipt = self._verify(role, deepcopy(actor))
                _require(isinstance(receipt, dict) and set(receipt) == {
                    'receipt_sha256', 'artifact_sha256', 'executed_entrypoints', 'scope'},
                    'authenticated execution receipt required')
                entrypoints = receipt['executed_entrypoints']
                _require(isinstance(entrypoints, list) and all(isinstance(e, str) for e in entrypoints)
                         and len(entrypoints) == len(set(entrypoints))
                         and set(entrypoints) == ENTRYPOINTS[role], 'cleanup entrypoint qualification incomplete')
                _require(receipt['receipt_sha256'] == actor['qualification_sha256']
                         and receipt['artifact_sha256'] == actor['artifact_sha256']
                         and receipt['scope'] == 'custom-protection-synthetic-v1',
                         'execution qualification does not match actor artifact')
            current = self._observe()
            _require(isinstance(current, dict) and set(current) == {
                'context', 'actors', 'window_active', 'native_cli_excluded',
                'image_build_held', 'unexpected_actors'}, 'complete current observation required')
            _require(current['context'] == self._context, 'gate context or image-build hold changed')
            _require(all(current[k] is True for k in (
                'window_active', 'native_cli_excluded', 'image_build_held')),
                'agreed gate window or image-build hold unavailable')
            _require(current['unexpected_actors'] == [], 'unexpected cleanup actor observed')
            expected = {role: {k: v for k, v in actor.items() if k != 'qualification_sha256'}
                        for role, actor in self._actors.items()}
            _require(current['actors'] == expected, 'actor provenance or generation changed')
            # Providers may take time; expiry during observation must not admit.
            now = self._clock()
            _require(type(now) in (int, float) and math.isfinite(now)
                     and self._last <= now < self._deadline, 'attestation expired during observation')
            self._last = now
        except Exception as error:
            self.invalidate()
            raise CleanupCompatibilityError('cleanup attestation recheck failed', inventory) from error
        return {**deepcopy(inventory), 'scope': 'qualified-local-coordinator',
                'qualified': True, 'gate_context': deepcopy(self._context)}
