"""Acquire a new gate baseline in its own original process before effects.

Only past timestamp changes of the transient parent can differ from the
historical qualification. Files, entries, permissions and identities must still
match. The returned baseline retains current timestamps; later admission uses
the ordinary exact comparison and qualified scope transitions.
"""
from copy import deepcopy
import os
import stat

from cleanup_execution import canonical_digest, require, sha
from cleanup_scope_sources import ROOT, indexed


def capture(previous, *, context, read_sources, verify_actors, read_owner, persist):
    """All IO providers are trusted local code, never selected by a request.

    verify_actors freshly qualifies the original artifacts/generations and
    agreed window, returning their digest. persist must durably save the whole
    receipt. A failure, including after persistence, never returns a grant.
    """
    require(all(callable(fn) for fn in (read_sources, verify_actors, read_owner, persist)),
            'explicit original baseline providers required')
    historical = deepcopy(previous)
    before = indexed(historical)
    require(ROOT in before and before[ROOT].get('kind') == 'directory',
            'qualified historical transient parent required')

    def owner():
        value = deepcopy(read_owner())
        require(type(value) is dict and set(value) == {
            'pid', 'start_ticks', 'boot_id', 'namespace_sha256',
            'executable_sha256', 'cmdline_sha256'}, 'complete original baseline owner required')
        require(value['pid'] == os.getpid() and type(value['pid']) is int
                and type(value['start_ticks']) is str and value['start_ticks'].isdecimal()
                and int(value['start_ticks']) > 0 and value['boot_id'] == context['boot_id']
                and value['namespace_sha256'] == canonical_digest(context['namespaces'])
                and all(sha(value[key]) for key in ('executable_sha256', 'cmdline_sha256')),
                'original gate process/context differs')
        return value

    original = owner()
    actors = verify_actors()
    require(sha(actors), 'fresh original actor qualification required')
    first, second = deepcopy(read_sources()), deepcopy(read_sources())
    require(first == second, 'scheduled sources changed during baseline capture')
    current = indexed(first)
    require(current.keys() == before.keys(), 'historical scheduled source paths changed')
    require(all(current[key] == before[key] for key in before if key != ROOT),
            'qualified scheduled file or definition changed')
    old, new = before[ROOT], current[ROOT]
    require(set(old) == set(new) == {'source_id', 'kind', 'metadata', 'names'}
            and new['kind'] == 'directory' and new['names'] == old['names'],
            'transient directory entries changed')
    for row in (old, new):
        require(type(row['metadata']) is list and len(row['metadata']) == 8
                and all(type(v) is int and v >= 0 for v in row['metadata'])
                and stat.S_ISDIR(row['metadata'][2]), 'complete transient directory metadata required')
    require(new['metadata'][:6] == old['metadata'][:6],
            'transient parent identity, permissions or size changed')
    require(owner() == original and verify_actors() == actors,
            'original gate owner or actor proof changed during capture')
    receipt = dict(kind='same-session-scheduled-baseline-v1', baseline=first,
                   historical_sha256=canonical_digest(historical),
                   current_sha256=canonical_digest(first), context_sha256=canonical_digest(context),
                   owner=original, actor_proof_sha256=actors)
    persist(deepcopy(receipt))
    require(owner() == original and verify_actors() == actors and read_sources() == first,
            'gate baseline changed after persistence')
    return deepcopy(receipt)
