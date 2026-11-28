"""Readonly qualification of an added root SSH scope before gate effects.

This is not an execution-time exemption. Query binaries are pinned by the
local gate assembler; no commands, paths or profile are supplied by a guest.
"""
import hashlib
import os
from pathlib import Path
import re
import select
import subprocess
from copy import deepcopy

from cleanup_census_readers import read_regular
from cleanup_execution import canonical_digest, require
from cleanup_scope_sources import ROOT


def definition(sid):
    require(type(sid) is str and re.fullmatch(r'c[0-9]+', sid), 'canonical SSH session ID required')
    return ('\n'.join([
        '# This is a transient unit file, created programmatically via the systemd API. Do not edit.',
        '[Scope]', 'Slice=user-0.slice', '', '[Unit]',
        'Description=Session '+sid+' of User root',
        'Requires=user-runtime-dir@0.service', 'After=user-runtime-dir@0.service',
        'Wants=user@0.service', 'After=user@0.service', 'After=systemd-logind.service',
        'After=systemd-user-sessions.service', 'RequiresMountsFor=/root', '', '[Scope]',
        'SendSIGHUP=yes', 'OOMPolicy=continue', 'TasksMax=infinity'])+'\n').encode()


def query(binary, args, expected_sha256):
    def check():
        raw, _ = read_regular(binary, 64*1024*1024)
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'SSH query binary changed')
    check()
    result = subprocess.run([binary, *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    check()
    require(result.returncode == 0 and not result.stderr and len(result.stdout) < 65536,
            'readonly SSH session query failed')
    rows = {}
    for line in result.stdout.decode().splitlines():
        key, sep, value = line.partition('=')
        require(sep and key not in rows, 'ambiguous SSH query properties')
        rows[key] = value
    return rows


def qualify(sid, row, *, context, systemctl_sha256, loginctl_sha256, retain=None):
    expected_bytes = definition(sid)
    scope = 'session-'+sid+'.scope'
    path = ROOT+'/'+scope
    require(row['source_id'] == path and row['sha256'] == hashlib.sha256(expected_bytes).hexdigest(),
            'SSH scope definition hash differs')

    def observe():
        props = ['Id', 'Name', 'User', 'Service', 'Remote', 'Class', 'Type', 'State',
                 'Leader', 'Scope', 'TimestampMonotonic']
        session = query('/usr/bin/loginctl', ['show-session', sid,
            *['--property='+key for key in props]], loginctl_sha256)
        require(all(session.get(key) == value for key, value in dict(
            Id=sid, Name='root', User='0', Service='sshd', Remote='yes', Class='user',
            Type='tty', State='active', Scope=scope).items()), 'SSH session profile differs')
        require(session.get('Leader', '').isdecimal() and int(session['Leader']) > 0
                and session.get('TimestampMonotonic', '').isdecimal()
                and int(session['TimestampMonotonic']) > 0, 'SSH session identity unavailable')
        props = ['Id', 'LoadState', 'ActiveState', 'SubState', 'FragmentPath',
                 'ControlGroup', 'InvocationID', 'Transient', 'Slice']
        unit = query('/usr/bin/systemctl', ['show', scope,
            *['--property='+key for key in props]], systemctl_sha256)
        require(all(unit.get(key) == value for key, value in dict(
            Id=scope, LoadState='loaded', ActiveState='active', SubState='running',
            FragmentPath=path, ControlGroup='/user.slice/user-0.slice/'+scope,
            Transient='yes', Slice='user-0.slice').items())
            and re.fullmatch('[0-9a-f]{32}', unit.get('InvocationID', '')),
            'SSH unit profile differs')
        return session, unit

    session, unit = observe()
    pid = int(session['Leader'])
    proc = Path('/proc')/str(pid)

    def leader():
        raw, _ = read_regular(proc/'stat', 16384)
        head, tail = raw.rsplit(b')', 1)
        require(int(head.split(b'(', 1)[0]) == pid, 'SSH leader PID differs')
        ticks = tail.split()[19].decode()
        require(ticks.isdecimal() and int(ticks) > 0, 'SSH leader starttime unavailable')
        status, _ = read_regular(proc/'status', 65536)
        uids = [line.split()[1:] for line in status.splitlines() if line.startswith(b'Uid:')]
        cgroup, _ = read_regular(proc/'cgroup', 16384)
        require(uids == [[b'0']*4] and cgroup == ('0::'+unit['ControlGroup']+'\n').encode(),
                'SSH leader credentials/cgroup differ')
        namespaces = {}
        for name in context['namespaces']:
            info = (proc/'ns'/name).stat()
            namespaces[name] = dict(device=info.st_dev, inode=info.st_ino)
        require(namespaces == context['namespaces'], 'SSH leader namespaces differ')
        cmdline, _ = read_regular(proc/'cmdline', 65536)
        return dict(pid=pid, start_ticks=ticks, namespaces=namespaces,
                    cmdline_sha256=hashlib.sha256(cmdline).hexdigest())

    fd = os.pidfd_open(pid, 0)
    try:
        poll = select.poll()
        poll.register(fd, select.POLLIN)
        require(not poll.poll(0), 'SSH leader exited or pidfd unavailable')
        original = leader()
        raw, metadata = read_regular(path, 65536)
        require(raw == expected_bytes and metadata == row['metadata']
                and os.lstat(path).st_nlink == 1, 'SSH scope bytes/identity changed')
        require(observe() == (session, unit) and leader() == original and not poll.poll(0),
                'SSH session changed during qualification')
        proof = dict(session=session, unit=unit, leader=original, source=row)
        receipt = dict(session_id=sid, context_sha256=canonical_digest(context),
            source_sha256=canonical_digest(row), qualification_sha256=canonical_digest(proof))
        if retain is not None:
            retain(fd, deepcopy(receipt))
        return receipt
    finally:
        os.close(fd)


class SessionWitnesses:
    """Keep original pidfds until the definitive baseline has been acquired."""
    def __init__(self, *, context, read_context, systemctl_sha256, loginctl_sha256, record):
        self.context, self.read_context = deepcopy(context), read_context
        self.systemctl, self.loginctl, self.record = systemctl_sha256, loginctl_sha256, record
        self.originals, self.exits = {}, {}
        self.closed = False

    def _check(self):
        require(not self.closed and self.read_context() == self.context,
                'original SSH witness context unavailable')

    def qualify(self, sid, row):
        self._check()
        require(sid not in self.exits, 'retired SSH identity cannot be reused')
        previous = self.originals.get(sid)

        def retain(fd, proof):
            if previous is not None:
                require(previous['row'] == row and previous['proof'] == proof,
                        'original SSH generation changed')
                poll = select.poll()
                poll.register(previous['fd'], select.POLLIN)
                require(not poll.poll(0), 'original SSH witness exited or unavailable')
            else:
                self.originals[sid] = dict(fd=os.dup(fd), row=deepcopy(row), proof=proof)

        return qualify(sid, row, context=self.context, systemctl_sha256=self.systemctl,
                       loginctl_sha256=self.loginctl, retain=retain)

    def removed(self, sid, row):
        self._check()
        require(sid in self.originals, 'SSH removal requires original live witness')
        original = self.originals[sid]
        require(original['row'] == row, 'removed SSH source differs from original witness')
        poll = select.poll()
        poll.register(original['fd'], select.POLLIN)
        require(poll.poll(0) == [(original['fd'], select.POLLIN)],
                'original SSH process exit not verified')
        scope = 'session-'+sid+'.scope'
        require(not os.path.lexists(ROOT+'/'+scope) and not os.path.lexists(ROOT+'/'+scope+'.d'),
                'original SSH scope or drop-ins remain')
        expected = dict(Id=scope, LoadState='not-found', ActiveState='inactive',
                        SubState='dead', InvocationID='')
        observed = query('/usr/bin/systemctl', ['show', scope,
            *['--property='+key for key in expected]], self.systemctl)
        require(observed == expected, 'original SSH unit absence not verified')
        self._check()
        proof = dict(original['proof'], exit_sha256=canonical_digest(dict(
            original=original['proof'], unit=observed, pidfd_exit=True)))
        if sid not in self.exits:
            self.record(dict(kind='qualified-prebaseline-ssh-exit', proof=deepcopy(proof)))
            self.exits[sid] = deepcopy(proof)
        require(self.exits[sid] == proof, 'original SSH exit receipt differs')
        return proof

    def check_exits(self, sources):
        """Also prove sessions born and gone entirely between acquisitions."""
        self._check()
        paths = {row['source_id'] for row in sources['candidates']}
        for sid, original in list(self.originals.items()):
            if original['row']['source_id'] not in paths:
                self.removed(sid, original['row'])
        return sources

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            for original in self.originals.values():
                try:
                    os.close(original.pop('fd'))
                except OSError:
                    # Continue closing the other owned descriptors.
                    pass
        finally:
            self.originals.clear()
