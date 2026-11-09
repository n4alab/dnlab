"""Compose trusted current observers for local cleanup admission.

This module supplies no window, census or image-build stop implementation.
Those providers must observe their qualified original journals and resources;
request payloads and saved provenance reports are not observation providers.
"""
from copy import deepcopy

from cleanup_container_observer import observe_container
from cleanup_execution import canonical_digest, require, sha


class CleanupObservation:
    """Reconstruct all three artifacts and bracket them with gate conditions.

    ``native(descriptor)`` freshly checks the qualified native installation and
    returns the same identity/digest/evidence shape as ``observe_container``.
    ``environment()`` freshly observes context, census, agreed window and held
    image-build, returning CleanupAttestation's observation without ``actors``.
    IO providers are trusted local code, never selected by a gate request.
    """

    def __init__(self, api, receipts, profiles, *, native, environment,
                 container=observe_container):
        require(type(profiles) is dict and set(profiles) == {'daemon', 'multinode'},
                'both original container profiles required')
        require(all(callable(provider) for provider in (native, environment, container)),
                'current native, environment and container observers required')
        self._api, self._receipts = api, receipts
        self._profiles = deepcopy(profiles)
        self._native, self._environment, self._container = native, environment, container

    def _conditions(self):
        current = deepcopy(self._environment())
        require(type(current) is dict and set(current) == {
            'context', 'window_active', 'native_cli_excluded',
            'image_build_held', 'unexpected_actors'}, 'complete gate conditions required')
        require(all(current[key] is True for key in (
            'window_active', 'native_cli_excluded', 'image_build_held')),
            'current window, native exclusion and image-build hold required')
        require(current['unexpected_actors'] == [], 'cleanup census has unexpected actors')
        return current

    def __call__(self):
        before = self._conditions()
        actors = {}
        for role in ('daemon', 'multinode', 'native'):
            descriptor = self._receipts.describe(role)
            if role == 'native':
                observed = self._native(deepcopy(descriptor))
                identity = None
            else:
                profile = deepcopy(self._profiles[role])
                identity = profile['container_id']
                observed = self._container(self._api, role, profile, deepcopy(descriptor))
            require(type(observed) is dict and set(observed) == {
                'container_id', 'artifact_sha256', 'generation_sha256', 'evidence'},
                'complete current actor provenance required')
            require(observed['container_id'] == identity
                    and (identity is None if role == 'native' else sha(identity)),
                    'original actor identity differs')
            require(observed['artifact_sha256'] == canonical_digest(descriptor),
                    'current artifact differs from executed qualification')
            require(type(observed['evidence']) is dict
                    and sha(observed['generation_sha256'])
                    and observed['generation_sha256'] == canonical_digest(observed['evidence']),
                    'current generation evidence differs')
            actors[role] = {key: observed[key] for key in (
                'container_id', 'artifact_sha256', 'generation_sha256')}
        after = self._conditions()
        require(after == before, 'gate conditions changed during actor observation')
        return {**after, 'actors': actors}
