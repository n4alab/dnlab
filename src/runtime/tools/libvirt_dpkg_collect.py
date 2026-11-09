"""Prepared single readonly dpkg diagnostic; host execution needs explicit consent.

Only fixed status/status-old paths and current boot/namespaces are observed.
No package commands, logs, services, original journal or automatic retry.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

RUNTIME = Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT = Path('/var/lib/dnlab-runtime-spikes')
PATHS = ('var/lib/dpkg/status', 'var/lib/dpkg/status-old')
LIMIT = 32 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def collect(request, *, read, context, persist):
    from tools.libvirt_dpkg_diagnosis import diagnose

    expected = request['context']
    snapshots = []
    for index in range(2):
        if context() != expected:
            raise ValueError('expected collection context differs')
        snapshot = {}
        for path in PATHS:
            value = read(path)
            if value is None:
                if path == PATHS[0]:
                    raise ValueError('current status absent')
                snapshot[path] = None
                continue
            raw = value['raw']
            if not isinstance(raw, bytes) or not raw or len(raw) > LIMIT:
                raise ValueError('bounded status bytes required')
            persist(f'pass{index + 1}-{Path(path).name}.raw', raw)
            snapshot[path] = dict(value)
        snapshots.append(snapshot)
        # Capture proof even if the subsequent context or digest check refuses.
        persist(f'pass{index + 1}-proof.json', json.dumps({path: None if value is None else
            dict(sha256=sha(value['raw']), metadata=value['metadata'], bytes=len(value['raw']))
            for path, value in snapshot.items()}, sort_keys=True).encode())
        if context() != expected:
            raise ValueError('collection context changed')
    if snapshots[0] != snapshots[1]:
        raise ValueError('dpkg inputs changed between passes')
    current = snapshots[0][PATHS[0]]['raw']
    candidate = snapshots[0][PATHS[1]]
    baseline = candidate['raw'] if candidate is not None and sha(candidate['raw']) == request['expected_sha256'] else None
    result = diagnose(expected_sha256=request['expected_sha256'],
        observed_sha256=request['observed_sha256'], observed_raw=current,
        expected_packages=request['expected_packages'], baseline_raw=baseline)
    result.update(status='collected', context=expected, passes=2,
        candidate=None if candidate is None else dict(path=PATHS[1], sha256=sha(candidate['raw']),
            matches_historical_digest=baseline is not None))
    return result


def verify_recipe(folder):
    # Input paths are fixed and inventoried, never supplied by a host artifact.
    receipt = json.loads((folder / 'receipt.json').read_text())
    sources = {str(path.relative_to(RUNTIME)): sha(path.read_bytes())
        for name in ('tools', 'dnlab_runtime') for path in (RUNTIME / name).glob('*.py')}
    raw = (folder / 'request.json').read_bytes()
    if (receipt.get('schema_version') != 1 or receipt.get('runtime_root') != str(RUNTIME)
            or receipt.get('source_sha256') != sources or not sources
            or receipt.get('request_sha256') != sha(raw)):
        raise ValueError('frozen dpkg diagnostic recipe differs')
    return raw, json.loads(raw)


def run(folder):
    raw, request = verify_recipe(folder)
    if not re.fullmatch(r'[0-9a-f]{32}', request.get('nonce', '')):
        raise ValueError('explicit collection nonce required')
    sys.path.insert(0, str(RUNTIME))
    from dnlab_runtime.vm_bundle import metadata, pinned_file
    from tools.libvirt_configuration_prepare import context

    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    output = OUTPUT_PARENT / ('libvirt-dpkg-readonly-' + request['nonce'][:12])
    parent = output_fd = None
    try:
        parent = os.open(OUTPUT_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(parent)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('private report parent is not root controlled')
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)

        def persist(name, data):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=output_fd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.fsync(output_fd)

        def read(path):
            if path not in PATHS:
                raise ValueError('unexpected diagnostic path')
            try:
                with pinned_file(root, path) as (fd, info):
                    if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > LIMIT:
                        raise ValueError('status metadata differs')
                    data = bytearray()
                    while len(data) <= LIMIT:
                        part = os.read(fd, min(65536, LIMIT + 1 - len(data)))
                        if not part:
                            break
                        data.extend(part)
                    if len(data) > LIMIT:
                        raise ValueError('status grew beyond bound')
                    return dict(raw=bytes(data), metadata=list(metadata(info)))
            except FileNotFoundError:
                if path != PATHS[1]:
                    raise
                return None

        persist('intent.json', raw)
        try:
            result = collect(request, read=read, context=lambda: context(request), persist=persist)
            if verify_recipe(folder)[0] != raw:
                raise ValueError('recipe changed during collection')
        except Exception as error:
            result = dict(status='failed', qualified=False, error_type=type(error).__name__, error=str(error))
        persist('result.json', json.dumps(result, indent=2, sort_keys=True).encode())
        print(json.dumps(dict(output=str(output), **result), sort_keys=True))
        return 0 if result['status'] == 'collected' else 1
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if parent is not None:
            os.close(parent)
        os.close(root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect-host', action='store_true')
    parser.add_argument('--recipe', type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.collect_host:
        parser.error('native diagnostic requires --collect-host')
    return run(args.recipe)


if __name__ == '__main__':
    raise SystemExit(main())
