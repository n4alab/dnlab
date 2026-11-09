"""Bounded console I/O for an already-owned CLI process, without input EOF.

The caller owns process birth, durable execution tracking and error recovery.
This pump neither spawns a process nor retries or signals one on uncertainty.
"""
import math
import os
import select
import time


def exchange(process, command, marker, *, timeout=15, limit=131072, observe=lambda row: None):
    if (not isinstance(command, bytes) or not command or len(command) > 4096
            or not isinstance(marker, bytes) or not marker or marker in command
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
            or type(limit) is not int or limit < len(marker)
            or any(getattr(process, name, None) is None for name in ('stdin', 'stdout', 'stderr'))):
        raise ValueError('bounded console command, distinct output marker and process pipes required')
    output, error = bytearray(), bytearray()
    readers = {process.stdout.fileno(): output, process.stderr.fileno(): error}
    deadline = time.monotonic() + timeout
    input_closed = False
    marker_seen = False

    def snapshot():
        observe({'stdout_hex': output.hex(), 'stderr_hex': error.hex(),
                 'marker_seen': marker_seen, 'input_closed': input_closed,
                 'exit_code': process.poll()})

    try:
        snapshot()
        process.stdin.write(command)
        process.stdin.flush()
        while True:
            if not marker_seen and marker in output:
                marker_seen = True
                # The peer's existing EOF semantics disconnect the console.
                # Close only after the required response is already observed.
                snapshot()
                process.stdin.close()
                input_closed = True
                snapshot()
            status = process.poll()
            if status is not None and not readers:
                snapshot()
                if status or error or output.startswith(b'ERR ') or not marker_seen:
                    raise RuntimeError('console exited without qualified response')
                return {'output': bytes(output), 'exit_code': status,
                        'marker_seen_before_input_close': True, 'exit_verified': True}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                snapshot()
                raise RuntimeError('console response or process exit remains uncertain')
            ready, _, _ = select.select(list(readers), [], [], min(remaining, .1))
            for fd in ready:
                data = os.read(fd, min(4096, limit - len(output) - len(error) + 1))
                if not data:
                    del readers[fd]
                    continue
                readers[fd].extend(data)
                snapshot()
                if len(output) + len(error) > limit:
                    raise RuntimeError('console evidence exceeded bound')
    finally:
        if not input_closed:
            process.stdin.close()
