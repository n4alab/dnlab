"""Collect only the current /run identity and virsh file proof."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

RUNTIME = Path('/opt/dnlab/src/runtime')
SCOPE = 'libvirt-activation-inputs-readonly-v1'
VIRSH = '/usr/bin/virsh'
MAX_BINARY_BYTES = 16 * 1024 * 1024


def validate(request):
    from dnlab_runtime.libvirt_postboot import context

    if (not isinstance(request, dict) or set(request) != {'scope', 'nonce', 'context'}
            or request['scope'] != SCOPE or not isinstance(request['nonce'], str)
            or re.fullmatch('[0-9a-f]{32}', request['nonce']) is None):
        raise ValueError('fixed activation input collection required')
    context(request['context'])


def snapshot(root):
    from dnlab_runtime.manifest import Conflict
    from dnlab_runtime.vm_bundle import metadata, pinned_file
    from tools.libvirt_install_parents import identity

    run = os.open('run', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
    try:
        parent = identity(os.fstat(run))
        with pinned_file(root, VIRSH.lstrip('/')) as (fd, info):
            if (info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111
                    or not 4 <= info.st_size <= MAX_BINARY_BYTES):
                raise Conflict('bounded root-controlled virsh executable required')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(info.st_size + 1)
            if len(raw) != info.st_size or not raw.startswith(b'\x7fELF'):
                raise Conflict('bounded virsh ELF content required')
            virsh = dict(path=VIRSH, sha256=hashlib.sha256(raw).hexdigest(), metadata=list(metadata(info)))
        if identity(os.fstat(run)) != parent or identity(os.stat('run', dir_fd=root, follow_symlinks=False)) != parent:
            raise Conflict('original /run changed during activation input collection')
        return dict(run_parent=parent, virsh=virsh)
    finally:
        os.close(run)


def run(recipe, *, root, read_context, output_parent):
    from tools.libvirt_bus_inventory_host import private_report, verify_recipe

    request = verify_recipe(recipe, validate_request=validate)
    expected = request['context']
    with private_report(output_parent, 'libvirt-activation-inputs-' + request['nonce'][:12]) as (write, output):
        def save(name, value):
            write(name + '.json', json.dumps(value, sort_keys=True).encode() + b'\n')

        def check(name):
            observed = read_context(expected['host_id'])
            save(name, dict(expected=expected, observed=observed))
            if observed != expected:
                raise ValueError('activation input context differs')

        save('intent', request)
        try:
            observations = []
            for index in (1, 2):
                check(f'pass{index}-context-before')
                proof = snapshot(root)
                save(f'pass{index}-proof', proof)
                check(f'pass{index}-context-after')
                observations.append(proof)
            if observations[0] != observations[1] or verify_recipe(recipe, validate_request=validate) != request:
                raise ValueError('activation input collection changed')
            result = dict(status='collected', context=expected, passes=2, **observations[0])
        except Exception as error:
            result = dict(status='failed', error_type=type(error).__name__, error=str(error))
        save('result', result)
        return result, output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', required=True, type=Path)
    parser.add_argument('--collect-host', required=True, action='store_true')
    args = parser.parse_args(argv)
    if not sys.dont_write_bytecode or not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0:
        parser.error('root and python -B -I -S required')
    sys.path.insert(0, str(RUNTIME))
    from tools.libvirt_bus_inventory_host import OUTPUT_PARENT, host_context, verify_recipe

    verify_recipe(args.recipe, validate_request=validate)
    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result, output = run(args.recipe, root=root, read_context=host_context, output_parent=OUTPUT_PARENT)
    finally:
        os.close(root)
    print(json.dumps(dict(status=result['status'], output=str(output)), sort_keys=True))
    return 0 if result['status'] == 'collected' else 1


if __name__ == '__main__':
    raise SystemExit(main())
