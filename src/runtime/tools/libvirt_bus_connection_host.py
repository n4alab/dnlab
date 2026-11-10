"""One-shot readonly D-Bus connection probe over a recorded inventory."""

import argparse
import json
import os
from pathlib import Path
import re
import sys

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.libvirt_bus_inventory_host import (
    OUTPUT_PARENT, host_context, prepare_recipe, private_report, sha, verify_recipe,
)

SCOPE = 'bus-connection-readonly-v1'


def validate(request):
    if (not isinstance(request, dict) or set(request) != {'nonce', 'host_id', 'scope', 'inventory_sha256'}
            or request['scope'] != SCOPE
            or not isinstance(request['host_id'], str)
            or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', request['host_id']) is None
            or not isinstance(request['nonce'], str) or re.fullmatch('[0-9a-f]{32}', request['nonce']) is None
            or not isinstance(request['inventory_sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', request['inventory_sha256']) is None):
        raise ValueError('fixed bus connection request required')


def freeze(folder, request):
    return prepare_recipe(folder, request, validate_request=validate)


def run(recipe, inventory_raw, *, root_fd, read_context, output_parent, opener=None):
    request = verify_recipe(recipe, validate_request=validate)
    if len(inventory_raw) > 65536 or sha(inventory_raw) != request['inventory_sha256']:
        raise ValueError('recorded bus inventory digest differs')
    inventory = json.loads(inventory_raw)
    if (inventory['status'] != 'collected' or inventory['passes'] != 2
            or not inventory['library_present'] or inventory['context']['host_id'] != request['host_id']):
        raise ValueError('complete two-pass library and socket inventory required')
    if opener is None:
        from tools.libvirt_bus_connection import open_proven_bus
        opener = open_proven_bus
    name = 'libvirt-bus-connection-' + request['nonce'][:12]
    with private_report(output_parent, name) as (persist, output):
        persist('intent.json', json.dumps(request, sort_keys=True).encode())
        try:
            context = read_context()
            persist('context.json', json.dumps(dict(observed=context, expected=inventory['context']),
                                                sort_keys=True).encode())
            if context != inventory['context']:
                raise ValueError('recorded bus inventory context differs')
            with opener(root_fd, inventory, read_context=read_context) as (_, _, identity):
                persist('connection.json', json.dumps(identity, sort_keys=True).encode())
            if verify_recipe(recipe, validate_request=validate) != request:
                raise ValueError('bus connection recipe changed during the probe')
            result = dict(status='verified', scope=SCOPE, connection=identity)
        except Exception as error:
            result = dict(status='failed', scope=SCOPE, error_type=type(error).__name__, error=str(error))
        persist('result.json', json.dumps(result, sort_keys=True).encode())
    return result, output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', required=True, type=Path)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--connect-readonly', action='store_true')
    args = parser.parse_args(argv)
    if not args.connect_readonly:
        parser.error('explicit --connect-readonly required')
    if not sys.dont_write_bytecode:
        parser.error('python -B required')
    request = verify_recipe(args.recipe, validate_request=validate)
    with args.inventory.open('rb') as stream:
        raw = stream.read(65537)
    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result, output = run(args.recipe, raw, root_fd=root, output_parent=OUTPUT_PARENT,
                             read_context=lambda: host_context(request['host_id']))
    finally:
        os.close(root)
    print(json.dumps(dict(result=result, output=str(output)), sort_keys=True))
    return 0 if result['status'] == 'verified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
