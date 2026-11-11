"""Inherited-source worker for one gated systemd StartUnit call."""

import hashlib
import json
import os
from pathlib import Path
import sys


def source_inventory(runtime):
    sources = {}
    for directory in ('dnlab_runtime', 'tools'):
        for path in (runtime / directory).glob('*.py'):
            if path.is_symlink():
                raise ValueError('worker source symlink refused')
            sources[str(path.relative_to(runtime))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not sources:
        raise ValueError('worker source inventory missing')
    raw = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def main():
    raw = sys.stdin.buffer.readline(16385)
    if not raw.endswith(b'\n') or len(raw) > 16384:
        raise ValueError('bounded D-Bus bootstrap frame required')
    bootstrap = json.loads(raw)
    if set(bootstrap) != {'token', 'command', 'inventory', 'sources_sha256'}:
        raise ValueError('original D-Bus bootstrap fields required')
    source = Path(__file__).resolve()
    runtime = source.parents[1]
    expected = bootstrap['sources_sha256']
    if source_inventory(runtime) != expected:
        raise ValueError('original D-Bus worker sources differ')
    sys.path.insert(0, str(runtime))

    from dnlab_runtime.libvirt_activation_bus import hex_value, serve_request, validate
    from dnlab_runtime.manifest import fingerprint
    from tools.libvirt_bus_connection import open_proven_bus
    from tools.libvirt_bus_inventory_host import host_context
    from tools.libvirt_systemd_bus import SystemdStartBus

    command = validate(bootstrap['command'])
    inventory = bootstrap['inventory']
    token = bootstrap['token']
    transport = command['transport']
    if (not hex_value(token, 32) or os.geteuid() != 0
            or hashlib.sha256(source.read_bytes()).hexdigest() != transport['worker_sha256']
            or inventory['proof']['library']['object']['sha256'] != transport['library_sha256']):
        raise ValueError('original privileged D-Bus worker and library required')

    def context():
        return host_context(inventory['context']['host_id'])

    root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with open_proven_bus(root, inventory, read_context=context) as (abi, handle, identity):
            connection = dict(token=token, context_sha256=fingerprint(inventory['context']),
                              manager_owner=identity['manager_owner'], unique_name=identity['unique_name'])

            def qualify(original, requested):
                return (original == connection and requested == command
                        and context() == inventory['context'] and source_inventory(runtime) == expected)

            bus = SystemdStartBus(abi, handle, connection, transport=transport, qualify=qualify)
            serve_request(sys.stdin, sys.stdout, dict(token=token, command=command, connection=connection),
                          bus=bus, announce_connection=True)
    finally:
        os.close(root)


if __name__ == '__main__':
    main()
