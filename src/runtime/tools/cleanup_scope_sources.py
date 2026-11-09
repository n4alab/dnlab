"""Qualify only expected Docker scope changes of one original gate.

No IO or operational proof provider is supplied here. Trusted callers must
authenticate births/journals and freshly qualify Docker identities and scope
definitions. Gate requests or a matching scope filename are not such proofs.
"""
from copy import deepcopy

from cleanup_execution import absolute, canonical_digest, require, sha

ROOT = '/run/systemd/transient'
CONTEXT = {'gate_id', 'lab_id', 'host_id', 'coordinator_id', 'boot_id',
           'window_id', 'image_build_hold_sha256'}


def indexed(value):
    require(type(value) is dict and set(value) == {'complete', 'candidates'}
            and value['complete'] is True and type(value['candidates']) is list,
            'complete scheduled source descriptor required')
    result = {}
    for row in value['candidates']:
        require(type(row) is dict and absolute(row.get('source_id'))
                and row['source_id'] not in result, 'unique canonical source paths required')
        result[row['source_id']] = deepcopy(row)
    return result


def belongs(path, scope):
    return path == scope or path == scope + '.d' or path.startswith(scope + '.d/')


class QualifiedScopeSources:
    """Project authenticated gate scope changes onto an immutable baseline.

    ``transitions()`` reads original durable gate intents, without allocating.
    ``verify(intent, observed_rows)`` independently authenticates the same birth
    nonce/journal and definition profile against current Docker and kernel state.
    For removal it must prove original cleanup and absence; for creation it must
    qualify the original running generation. It must reject unknown directives,
    changed ownership and incomplete evidence. A receipt from this trusted local
    provider is required on every call, never learned from observed filenames.
    """

    def __init__(self, baseline, *, context, definition_profile_sha256,
                 transitions, verify):
        require(type(context) is dict and set(context) == CONTEXT
                and all(type(v) is str and v for v in context.values())
                and sha(context['image_build_hold_sha256']), 'complete original gate context required')
        require(sha(definition_profile_sha256) and callable(transitions) and callable(verify),
                'qualified scope profile and trusted providers required')
        self._baseline = indexed(baseline)
        require(ROOT in self._baseline and self._baseline[ROOT].get('kind') == 'directory',
                'original transient directory proof required')
        self._context, self._profile = deepcopy(context), definition_profile_sha256
        self._transitions, self._verify = transitions, verify

    def __call__(self, observed):
        current = indexed(observed)
        normalized = deepcopy(current)
        intents = deepcopy(self._transitions())
        require(type(intents) is list and len(intents) <= 128, 'bounded original scope intents required')
        seen, added, removed, completed = set(), set(), set(), set()
        for intent in intents:
            require(type(intent) is dict and set(intent) == {
                'action', 'container_id', 'nonce', 'journal_sha256', 'birth_sha256', 'rows'},
                'complete original scope transition required')
            cid, action = intent['container_id'], intent['action']
            require(sha(cid) and cid not in seen and action in ('created', 'removed')
                    and type(intent['nonce']) is str and len(intent['nonce']) == 32
                    and all(c in '0123456789abcdef' for c in intent['nonce'])
                    and sha(intent['journal_sha256']) and sha(intent['birth_sha256']),
                    'distinct qualified scope birth and journal required')
            seen.add(cid)
            scope = ROOT + '/docker-' + cid + '.scope'
            before = {path: row for path, row in self._baseline.items() if belongs(path, scope)}
            after = {path: row for path, row in current.items() if belongs(path, scope)}
            expected = indexed({'complete': True, 'candidates': intent['rows']})
            require(scope in expected and expected[scope].get('kind') == 'file'
                    and all(belongs(path, scope) for path in expected),
                    'only original scope and its qualified drop-ins allowed')
            require(all(row.get('kind') in ('file', 'directory') for row in expected.values()),
                    'scope symlinks or unsupported resources refused')
            if action == 'created':
                require(not before and after == expected, 'created scope differs or existed in baseline')
            else:
                # A gate birth may have appeared and completed entirely after
                # the immutable baseline. Its original durable birth and
                # qualified cleanup/absence still require the verifier below.
                require((not before or before == expected) and not after,
                        'removed scope differs or remains present')
            receipt = self._verify(deepcopy(intent), deepcopy(after))
            wanted = {'context': self._context, 'action': action, 'container_id': cid,
                      'nonce': intent['nonce'], 'journal_sha256': intent['journal_sha256'],
                      'birth_sha256': intent['birth_sha256'],
                      'definition_profile_sha256': self._profile,
                      'rows_sha256': canonical_digest(intent['rows'])}
            require(type(receipt) is dict and receipt == wanted,
                    'authenticated current scope proof differs from original gate')
            for path in after:
                normalized.pop(path)
            normalized.update(before)
            names = {path[len(ROOT) + 1:].split('/')[0] for path in expected}
            if action == 'created':
                added.update(names)
            elif before:
                removed.update(names)
            else:
                completed.update(names)
        require(ROOT in current, 'transient directory missing')
        if intents:
            before, after = self._baseline[ROOT], current[ROOT]
            require(set(before) == set(after) == {'source_id', 'kind', 'metadata', 'names'}
                    and before['kind'] == after['kind'] == 'directory', 'directory descriptor differs')
            for row in (before, after):
                require(type(row['metadata']) is list and len(row['metadata']) == 8
                        and all(type(v) is int and v >= 0 for v in row['metadata'])
                        and type(row['names']) is list
                        and all(type(v) is str for v in row['names'])
                        and len(row['names']) == len(set(row['names'])),
                        'complete transient directory identity required')
            require(after['metadata'][:5] == before['metadata'][:5],
                    'transient directory identity or permissions changed')
            require(not (added & set(before['names'])) and removed <= set(before['names'])
                    and not (completed & set(before['names']))
                    and set(after['names']) == (set(before['names']) - removed) | added,
                    'unrelated transient directory entries changed')
            # Only entry-dependent size/mtime/ctime may differ, after all
            # changed entries have authenticated original gate proofs.
            normalized[ROOT] = deepcopy(before)
        require(normalized == self._baseline, 'unqualified scheduled source change')
        return {'complete': True, 'candidates': sorted(normalized.values(), key=lambda row: row['source_id'])}
