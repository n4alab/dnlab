"""Isolated native handoff plus original RTNL monitor; no VM or production lease.

Run explicitly with --execute. Own namespace, no bridges, addresses, guest or
background process. Runtime identity here is a diagnostic current-process
witness, not a substitute for the production RuntimeProcess capability.
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sys
import uuid

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_tap_link_events import TapLinkEvents, NEWLINK, DELLINK
from vm_tap_handoff_probe import KernelTap, ProbeError, handoff, namespace


def monitored_handoff(tap, monitor, save):
    original = None
    monitor.open()
    try:
        monitor.drain()
        def checkpoint(phase, **proof):
            nonlocal original
            if phase == 'created':
                birth = proof['birth']
                original = monitor.birth(birth['name'], birth['ifindex'])
                save('monitor_birth', birth=deepcopy(original))
            elif phase in ('release_requested', 'creator_released', 'acquire_requested',
                           'acquired', 'unpersist_requested'):
                save('monitor_continuity', boundary=phase, proof=monitor.verify(original))
            elif phase == 'completed':
                events = monitor.drain()
                relevant = [e for e in events[original['sequence'] - 1:]
                            if e['name'] == original['name'] or e['ifindex'] == original['ifindex']]
                if (not relevant or relevant[-1]['kind'] != DELLINK
                        or any(e['name'] != original['name'] or e['ifindex'] != original['ifindex']
                               or e['kind'] != NEWLINK for e in relevant[:-1])):
                    raise ProbeError('expected original final deletion event missing or ambiguous')
                try:
                    monitor.verify(original)
                except RuntimeErrorBase:
                    if monitor.poisoned:
                        raise ProbeError('event feed lost during final deletion check')
                else:
                    raise ProbeError('deleted TAP unexpectedly accepted as continuous')
                save('monitor_deletion_observed', birth=deepcopy(original), cursor=len(events))
            save(phase, **proof)
        handoff(tap, checkpoint)
    finally:
        monitor.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if not args.execute:
        parser.error('native diagnostic requires --execute')
    output = Path(args.output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    token = uuid.uuid4().hex
    values = dict(token=token, host_namespace=namespace(), events=[])

    def save(phase, **proof):
        values['events'].append(dict(phase=phase, **proof))
        path = output / ('%03d-%s.json' % (len(values['events']), phase))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(values, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    tap = None
    try:
        save('namespace_requested')
        os.unshare(os.CLONE_NEWNET)
        if namespace() == values['host_namespace'] or socket.if_nameindex() != [(1, 'lo')]:
            raise ProbeError('fresh isolated namespace required')
        save('isolated', namespace=namespace())
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        def scope():
            device, inode = namespace()
            return dict(boot_id=boot, device=device, inode=inode)
        class ProbeEpoch:
            def check(self):
                # Only the live caller: no lookup/discovery of another worker.
                raw = Path('/proc/thread-self/stat').read_text()
                return dict(pid=os.getpid(), start_ticks=int(raw[raw.rfind(')') + 2:].split()[19]),
                            namespace=namespace(), uid=os.geteuid(), gid=os.getegid())
        monitor = TapLinkEvents(scope(), runtime=ProbeEpoch(), read_context=scope,
                                record=lambda event: save('monitor', record=event))
        tap = KernelTap('dhm' + token[:11])
        monitored_handoff(tap, monitor, save)
        print(json.dumps(dict(status='completed', output=str(output), production_qualified=False)))
    except BaseException as error:
        save('failed', error=dict(type=type(error).__name__, message=str(error)),
             namespace_destruction_required=True)
        raise
    finally:
        if tap is not None:
            tap.finish()


if __name__ == '__main__':
    main()
