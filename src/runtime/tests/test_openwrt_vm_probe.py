"""Serial bytes only; no socket, subprocess, VM or host files are opened."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from openwrt_vm_probe import observe_shell
from dnlab_runtime.vm_template import TemplateError

NONCE = 'a' * 32
BOOT = '12345678-1234-4234-8234-123456789abc'


class Serial:
    def __init__(self, blocks, *, short=False):
        self.blocks, self.sent, self.short = list(blocks), [], short

    def send(self, value):
        self.sent.append(value)
        return len(value) - 1 if self.short and len(value) > 1 else len(value)

    def recv(self, size):
        assert size == 65536
        value = self.blocks.pop(0) if self.blocks else b''
        if isinstance(value, BaseException):
            raise value
        return value


def test_shell_output_proves_nonce_kernel_and_boot_id_across_chunks():
    serial = Serial([b'OpenWrt\r\nroot@OpenWrt:/# ',
        b'__DNLAB_VM_' + NONCE.encode(),
        ('__\r\n6.12.1\r\n' + BOOT + '\r\nroot@OpenWrt:/# ').encode()])
    records = []
    proof = observe_shell(serial, NONCE, record=records.append)
    assert proof['guest_shell_verified'] and proof['guest_boot_id'] == BOOT
    assert proof['guest_shutdown_verified'] is False
    assert len(serial.sent) == 2 and serial.sent[0] == b'\n'
    assert ('__DNLAB_VM_' + NONCE + '__').encode() not in serial.sent[1]
    assert [row['phase'] for row in records] == ['prepared', 'command_requested', 'observed']


def test_terminal_echo_alone_cannot_certify_the_guest():
    command = ("printf '%s%s\\n' '__DNLAB_VM_' '" + NONCE
               + "__'; uname -r; cat /proc/sys/kernel/random/boot_id\n").encode()
    serial = Serial([b'root@OpenWrt:/# ', command])
    records = []
    with pytest.raises(TemplateError, match='console closed'):
        observe_shell(serial, NONCE, record=records.append)
    assert len(serial.sent) == 2 and records[-1]['phase'] == 'failed'


def test_partial_boot_id_waits_for_the_rest_of_the_same_response():
    serial = Serial([b'root@OpenWrt:/# ',
        ('__DNLAB_VM_' + NONCE + '__\n6.12.1\n' + BOOT[:16]).encode(),
        (BOOT[16:] + '\n').encode()])
    assert observe_shell(serial, NONCE, record=lambda row: None)['guest_boot_id'] == BOOT
    assert len(serial.sent) == 2


def test_short_command_delivery_is_never_retried():
    serial = Serial([b'root@OpenWrt:/# '], short=True)
    with pytest.raises(TemplateError, match='uncertain; no resend'):
        observe_shell(serial, NONCE, record=lambda row: None)
    assert len(serial.sent) == 2


def test_expired_deadline_stops_before_guest_command():
    serial = Serial([b'root@OpenWrt:/# '])
    times = iter([0, 2])
    with pytest.raises(TemplateError, match='deadline'):
        observe_shell(serial, NONCE, record=lambda row: None, timeout=1, clock=lambda: next(times))
    assert serial.sent == [b'\n']


def test_console_timeout_does_not_reuse_the_invalidated_stream():
    serial = Serial([TimeoutError('synthetic console timeout'), b'root@OpenWrt:/# '])
    records = []
    with pytest.raises(TimeoutError):
        observe_shell(serial, NONCE, record=records.append)
    assert serial.sent == [b'\n'] and len(serial.blocks) == 1
    assert records[-1]['phase'] == 'failed'


@pytest.mark.parametrize('response', ['6.12.1\nnot-a-boot-id\n', 'not-a-kernel\n' + BOOT + '\n'])
def test_malformed_guest_response_is_rejected(response):
    serial = Serial([b'root@OpenWrt:/# ', ('__DNLAB_VM_' + NONCE + '__\n' + response).encode()])
    with pytest.raises((TemplateError, ValueError)):
        observe_shell(serial, NONCE, record=lambda row: None)
    assert len(serial.sent) == 2
