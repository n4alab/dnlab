"""Bounded first-boot shell observation over an already qualified VM console.

The caller owns the original QEMU/console capability. No connection, guest
login, retry of uncertain input, VM lifecycle or host operation is performed.
This probe is specific to an OpenWrt root serial shell, not generic readiness.
"""
import re
import time
import uuid

from dnlab_runtime.vm_template import require


def observe_shell(stream, nonce, *, record, timeout=120, clock=time.monotonic):
    require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce)
            and callable(record) and callable(clock)
            and type(timeout) in (int, float) and 0 < timeout <= 120,
            'explicit OpenWrt probe nonce, recorder and bounded deadline required')
    marker = '__DNLAB_VM_' + nonce + '__'
    # Neither this command nor its terminal echo contains the complete marker.
    command = ("printf '%s%s\\n' '__DNLAB_VM_' '" + nonce
               + "__'; uname -r; cat /proc/sys/kernel/random/boot_id\n").encode()
    output = bytearray()
    started = clock()
    deadline = started + timeout
    last = started
    sent = False
    response_start = None
    record(dict(phase='prepared', nonce=nonce, command=command.decode(), timeout=timeout))
    try:
        require(stream.send(b'\n') == 1, 'initial console input delivery uncertain; no resend')
        while True:
            now = clock()
            require(last <= now < deadline, 'OpenWrt shell probe deadline exceeded or clock changed')
            last = now
            # VMConsole invalidates its stream after any I/O error, including
            # timeout. The caller selects its bounded timeout before connect;
            # this probe never reuses an invalidated console or reconnects.
            block = stream.recv(65536)
            require(type(block) is bytes and block, 'original OpenWrt console closed')
            output.extend(block)
            require(len(output) <= 1024 * 1024, 'OpenWrt console output exceeds bound')
            text = output.decode('utf-8', errors='replace').replace('\r', '')
            if not sent and re.search(r'root@[^\s:]+:[^\r\n]*#\s*$', text):
                record(dict(phase='command_requested', nonce=nonce))
                response_start = len(output)
                # A short send is an uncertain result, never a replay request.
                require(stream.send(command) == len(command), 'guest command delivery uncertain; no resend')
                sent = True
            if sent:
                # A partial final line is not a malformed guest response.
                response = output[response_start:].decode('utf-8', errors='replace').replace('\r', '')
                lines = response.split('\n')[:-1]
                matches = [index for index, line in enumerate(lines) if line == marker]
                require(len(matches) <= 1, 'ambiguous OpenWrt probe response')
                if matches and len(lines) > matches[0] + 2:
                    kernel, boot = lines[matches[0]+1:matches[0]+3]
                    require(re.fullmatch(r'[0-9]+\.[0-9]+[^\s\x00]*', kernel)
                            and str(uuid.UUID(boot)) == boot, 'OpenWrt kernel/boot response differs')
                    require(last <= clock() < deadline, 'OpenWrt probe expired during response')
                    result = dict(nonce=nonce, kernel_release=kernel, guest_boot_id=boot,
                                  guest_shell_verified=True, guest_shutdown_verified=False)
                    record(dict(phase='observed', result=result, console=text))
                    return result
    except BaseException as error:
        try:
            record(dict(phase='failed', nonce=nonce, command_sent=sent,
                        error_type=type(error).__name__, error=str(error),
                        console=bytes(output).decode('utf-8', errors='replace')))
        except BaseException as recording_error:
            error.add_note('console diagnostic persistence failed: ' + str(recording_error))
        raise
