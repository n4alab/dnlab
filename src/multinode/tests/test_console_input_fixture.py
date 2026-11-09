"""Owned local child processes only: no Docker or lab networking."""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from console_input_fixture import exchange


def run_child(code, **options):
    return subprocess.Popen([sys.executable, '-u', '-c', code], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)


def finish(process):
    # This is our unreaped direct child; no process discovery or name lookup.
    if process.poll() is None:
        process.kill()
    process.wait(timeout=3)
    process.stdout.close()
    process.stderr.close()


def test_input_stays_open_until_output_and_exit_is_verified():
    process = run_child("import sys;sys.stdin.buffer.readline();print('unique-response',flush=True);assert sys.stdin.buffer.read()==b''")
    observations = []
    try:
        result = exchange(process, b'first-command\n', b'unique-response', timeout=3,
                          observe=observations.append)
        assert result['exit_verified'] and result['exit_code'] == 0
        seen = next(i for i, r in enumerate(observations) if r['marker_seen'])
        closed = next(i for i, r in enumerate(observations) if r['input_closed'])
        assert seen < closed and not observations[seen]['input_closed']
    finally:
        finish(process)


@pytest.mark.parametrize('code', [
    "import sys;print(sys.stdin.buffer.readline().decode(),flush=True)",
    "import sys;sys.stdin.buffer.readline();print('ERR refused',flush=True)",
    "import sys;sys.stdin.buffer.readline();print('unique-response',flush=True);sys.exit(1)",
    "import sys;sys.stdin.buffer.readline();print('unique-response',flush=True);print('unexpected error',file=sys.stderr,flush=True)",
])
def test_echo_error_or_failed_exit_cannot_qualify_console(code):
    process = run_child(code)
    try:
        with pytest.raises(RuntimeError, match='without qualified response'):
            exchange(process, b'first-command\n', b'unique-response', timeout=3)
    finally:
        finish(process)


def test_timeout_closes_input_and_does_not_claim_process_exit():
    process = run_child('import time;time.sleep(60)')
    try:
        with pytest.raises(RuntimeError, match='remains uncertain'):
            exchange(process, b'first-command\n', b'unique-response', timeout=.1)
        assert process.stdin.closed and process.poll() is None
    finally:
        finish(process)


def test_output_bound_is_enforced():
    process = run_child("import sys;sys.stdin.buffer.readline();print('x'*1000,flush=True)")
    try:
        with pytest.raises(RuntimeError, match='exceeded bound'):
            exchange(process, b'first-command\n', b'unique-response', timeout=3, limit=32)
    finally:
        finish(process)


def test_marker_in_command_is_rejected_before_any_input_write():
    with pytest.raises(ValueError):
        exchange(None, b'unique-response\n', b'unique-response')
