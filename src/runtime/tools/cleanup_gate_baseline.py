"""Acquire a new gate baseline in its own original process before effects.

Past parent timestamps may differ. An explicitly supplied trusted SSH verifier
may also qualify added session scopes before effects. Existing sources remain
immutable. Later admission uses the ordinary exact comparison; this function
does not grant an exception during execution of the gate.
"""
from copy import deepcopy
import os
import re
import stat

from cleanup_execution import canonical_digest, require, sha
from cleanup_scope_sources import ROOT, indexed


class BaselineComparisonError(ValueError):
    """Bounded evidence from the rejected read, without authorization."""
    def __init__(self, message, before, current):
        added, removed = set(current)-set(before), set(before)-set(current)
        changed = {key for key in set(before) & set(current) if before[key] != current[key]}
        self.diagnostic = dict(kind='scheduled-baseline-comparison-v1',
            expected_sha256=canonical_digest(before), observed_sha256=canonical_digest(current))
        for name, values in dict(added=added, removed=removed, changed=changed).items():
            self.diagnostic[name] = sorted(values)[:128]
            self.diagnostic[name+'_count'] = len(values)
        super().__init__(message)


def capture(previous, *, context, read_sources, verify_actors, read_owner, persist,
            qualify_ssh=None):
    """All IO providers are trusted local code, never selected by a request.

    verify_actors freshly qualifies the original artifacts/generations and
    agreed window, returning their digest. persist must durably save the whole
    receipt. A failure, including after persistence, never returns a grant.
    qualify_ssh is trusted local code, not a request field. It must freshly
    verify the exact SSH unit definition, root session/leader, pidfd, process
    starttime, namespace and source identity. Its proof is checked again before
    return. No removed scope, drop-in or changed existing file is accepted.
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
    def compare(condition, message):
        if not condition:
            raise BaselineComparisonError(message, before, current)

    added = set(current)-set(before)
    compare(not (set(before)-set(current)) and (not added or callable(qualify_ssh)),
            'historical scheduled source paths changed')
    compare(all(current[key] == before[key] for key in before if key != ROOT),
            'qualified scheduled file or definition changed')
    proofs = {}
    for path in sorted(added):
        match = re.fullmatch(re.escape(ROOT) + r'/session-(c[0-9]+)\.scope', path)
        compare(match is not None, 'only qualified added SSH session scopes allowed')
        row = current[path]
        require(set(row) == {'source_id', 'kind', 'metadata', 'sha256'}
                and row['kind'] == 'file' and sha(row['sha256'])
                and type(row['metadata']) is list and len(row['metadata']) == 8
                and all(type(v) is int and v >= 0 for v in row['metadata'])
                and row['metadata'][2] == stat.S_IFREG | 0o644
                and row['metadata'][3:5] == [0, 0], 'root-owned regular SSH scope required')
        proof = deepcopy(qualify_ssh(match[1], deepcopy(row)))
        require(type(proof) is dict and set(proof) == {
                    'session_id', 'context_sha256', 'source_sha256', 'qualification_sha256'}
                and proof['session_id'] == match[1]
                and proof['context_sha256'] == canonical_digest(context)
                and proof['source_sha256'] == canonical_digest(row)
                and sha(proof['qualification_sha256']), 'complete current SSH qualification required')
        proofs[path] = proof
    old, new = before[ROOT], current[ROOT]
    require(set(old) == set(new) == {'source_id', 'kind', 'metadata', 'names'}
            and new['kind'] == 'directory' and type(old['names']) is list
            and type(new['names']) is list
            and len(set(new['names'])) == len(new['names'])
            and set(new['names']) == set(old['names']) | {path[len(ROOT)+1:] for path in added},
            'transient directory entries changed')
    for row in (old, new):
        require(type(row['metadata']) is list and len(row['metadata']) == 8
                and all(type(v) is int and v >= 0 for v in row['metadata'])
                and stat.S_ISDIR(row['metadata'][2]), 'complete transient directory metadata required')
    require(new['metadata'][:5 if added else 6] == old['metadata'][:5 if added else 6],
            'transient parent identity, permissions or size changed')
    require(owner() == original and verify_actors() == actors,
            'original gate owner or actor proof changed during capture')
    receipt = dict(kind='same-session-scheduled-baseline-v1', baseline=first,
                   historical_sha256=canonical_digest(historical),
                   current_sha256=canonical_digest(first), context_sha256=canonical_digest(context),
                   owner=original, actor_proof_sha256=actors)
    if proofs:
        receipt['prebaseline_ssh'] = proofs
    persist(deepcopy(receipt))
    require(owner() == original and verify_actors() == actors,
            'gate baseline changed after persistence')
    observed = indexed(read_sources())
    if observed != current:
        raise BaselineComparisonError('gate baseline changed after persistence', current, observed)
    require(all(qualify_ssh(proof['session_id'], deepcopy(current[path])) == proof
                for path, proof in proofs.items()), 'SSH qualification changed after persistence')
    return deepcopy(receipt)
