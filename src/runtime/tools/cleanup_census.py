"""Scoped cleanup entrypoint census, with trusted readonly IO providers.

Recognized invocations cover the declared single coordinator. Opaque commands
and arbitrary external automation are outside that declared scope; this is not
a universal proof of absence. No command is executed by this module.
"""
from copy import deepcopy
import hashlib
from pathlib import PurePosixPath
import re

from cleanup_execution import canonical_digest, require, sha


def classify(argv):
    """Recognize service and CLI entrypoints, including non-cleanup CLI use.

    The agreed window excludes all native CLI invocations. For Python, inspect
    only the executable/module position; command arguments are never searched
    for strings that might merely be payload data.
    """
    require(type(argv) is list and argv and all(type(word) is str
            and '\0' not in word for word in argv) and bool(argv[0]),
            'complete process argv required')
    entry, arguments = argv[0], list(argv[1:])
    if re.fullmatch(r'python(?:[23](?:\.\d+)*)?', PurePosixPath(entry).name):
        while arguments and arguments[0] in ('-B', '-I', '-S', '-s', '-u', '-E'):
            arguments.pop(0)
        if not arguments:
            return None
        if arguments[0] == '-m':
            require(len(arguments) >= 2 and bool(arguments[1]), 'incomplete Python module invocation')
            entry = arguments[1]
        elif arguments[0].startswith('-'):
            return None
        else:
            entry = arguments[0]
    if entry == '/opt/dnlab-image-build/api.py':
        return 'image_build'
    if entry in {
        'dnlab_multinode.cli', 'dnlab_multinode.api',
        'dnlab_multinode.lab_cleanup_cli', 'dnlab_multinode.services.lab_cleanup',
    } or PurePosixPath(entry).name in {
        'dnlab-multinode', 'dnlab-multinode-api', 'dnlab-lab-cleanup',
    }:
        return 'cleanup'
    if re.fullmatch(
        r'(?:/opt/dnlab-multinode|/root/dnlab-multinode|'
        r'/usr/local/lib/python[0-9]+\.[0-9]+/site-packages)'
        r'/dnlab_multinode/(?:api|cli|lab_cleanup_cli|services/lab_cleanup)\.py', entry):
        return 'cleanup'
    if PurePosixPath(entry).name in {'api.py', 'cli.py', 'lab_cleanup_cli.py', 'lab_cleanup.py'}:
        return 'unqualified_script'
    return None


def candidate(argv):
    """Retain cleanup, image-build and ambiguous scripts for separate checks."""
    return classify(argv) is not None


def process_groups(rows):
    require(type(rows) is list, 'complete process inventory required')
    groups, seen = {'cleanup': [], 'image_build': [], 'unqualified_script': []}, set()
    for row in rows:
        require(type(row) is dict and set(row) == {'pid', 'start_ticks', 'argv'},
                'complete process census row required')
        pid, ticks = row['pid'], row['start_ticks']
        require(type(pid) is int and pid > 0 and pid not in seen
                and type(ticks) is str and ticks.isdecimal() and int(ticks) > 0,
                'unique process generation required')
        seen.add(pid)
        role = classify(row['argv'])
        if role is not None:
            raw = b'\0'.join(word.encode() for word in row['argv']) + b'\0'
            groups[role].append({'pid': pid, 'start_ticks': ticks,
                                 'cmdline_sha256': hashlib.sha256(raw).hexdigest()})
    return {role: sorted(rows, key=lambda row: row['pid']) for role, rows in groups.items()}


def processes(rows):
    """All recognized candidates, retaining the original flat census format."""
    return sorted((row for group in process_groups(rows).values() for row in group),
                  key=lambda row: row['pid'])


class CleanupCensus:
    """Reobserve explicit scheduled sources and recognizable local processes.

    ``sources()`` returns the complete, qualified scheduled-source descriptor;
    its digest is pinned after review, never learned during admission. Native
    installation files are checked by the separate provenance observer.
    ``process_inventory()`` must provide a complete bounded scan, with each
    candidate's identity and command checked before/after reading. The two
    expected generations come from current qualified container provenance.
    """

    def __init__(self, *, context, expected_processes, scheduled_sha256,
                 read_context, process_inventory, sources, qualify_sources=None):
        require(type(context) is dict and context, 'declared coordinator context required')
        require(type(expected_processes) is list and len(expected_processes) == 2,
                'two qualified cleanup process generations required')
        seen = set()
        for row in expected_processes:
            require(type(row) is dict and set(row) == {'pid', 'start_ticks', 'cmdline_sha256'}
                    and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in seen
                    and type(row['start_ticks']) is str and row['start_ticks'].isdecimal()
                    and int(row['start_ticks']) > 0 and sha(row['cmdline_sha256']),
                    'qualified original process identity required')
            seen.add(row['pid'])
        require(sha(scheduled_sha256) and all(callable(reader) for reader in (
            read_context, process_inventory, sources)), 'pinned sources and trusted census readers required')
        self._context = deepcopy(context)
        self._expected = sorted(deepcopy(expected_processes), key=lambda row: row['pid'])
        self._scheduled = scheduled_sha256
        self._read_context, self._processes, self._sources = read_context, process_inventory, sources
        require(qualify_sources is None or callable(qualify_sources), 'trusted scope qualifier required')
        self._qualify_sources = qualify_sources

    def __call__(self):
        require(self._read_context() == self._context, 'coordinator census context differs')
        snapshots = []
        for _ in range(2):
            groups = process_groups(self._processes())
            require(not groups['unqualified_script'], 'unqualified script entrypoint observed')
            require(not groups['image_build'], 'image-build is running; qualified hold required')
            observed = groups['cleanup']
            require(observed == self._expected, 'cleanup process set differs or native CLI is active')
            sources = deepcopy(self._sources())
            require(type(sources) is dict and set(sources) == {'complete', 'candidates'}
                    and sources['complete'] is True and type(sources['candidates']) is list,
                    'complete scheduled source inventory required')
            qualified = sources if self._qualify_sources is None else self._qualify_sources(deepcopy(sources))
            require(canonical_digest(qualified) == self._scheduled,
                    'scheduled source descriptor differs from qualification')
            snapshots.append({'processes': observed, 'scheduled_sha256': canonical_digest(qualified),
                              'observed_scheduled_sha256': canonical_digest(sources)})
        require(snapshots[0] == snapshots[1] and self._read_context() == self._context,
                'coordinator census changed during observation')
        return {'context': deepcopy(self._context), **snapshots[1], 'unexpected_actors': [],
                'scope': 'declared-single-coordinator-recognized-entrypoints',
                'gate_allowed': False}
