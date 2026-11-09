"""Standalone root-local jumphost birth and management attachment journal.

Only explicit recovery may bind a create response lost before the ID was saved.
No operation adopts a legacy container or deletes an interface by name.
"""
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager, ExitStack
from collections import Counter


class JumphostError(RuntimeError):
    pass


class DockerExecError(JumphostError):
    def __init__(self, status):
        self.status = status
        super().__init__('Docker exec HTTP ' + str(status))


class DockerExecHTTP:
    """Local structured exec transport; no command/environment in errors."""
    def __init__(self, path='/var/run/docker.sock'):
        if not isinstance(path, str) or not os.path.isabs(path):
            raise JumphostError('absolute Docker Unix socket required')
        self.path = path

    def call(self, method, path, payload=None, *, missing=False):
        connection = http.client.HTTPConnection('localhost', timeout=15)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(15)
        try:
            connection.sock.connect(self.path)
            connection.request(method, path, None if payload is None else canonical(payload),
                               {'Content-Type':'application/json'})
            response = connection.getresponse(); raw = response.read()
            if response.status == 404 and missing:
                try: value = json.loads(raw)
                except (ValueError, UnicodeDecodeError): raise JumphostError('invalid Docker exec absence response') from None
                if not isinstance(value, dict) or not isinstance(value.get('message'), str):
                    raise JumphostError('invalid Docker exec absence response')
                return None
            if not 200 <= response.status < 300:
                raise DockerExecError(response.status)
            if not raw:
                return {}
            try: return json.loads(raw)
            except (ValueError, UnicodeDecodeError): raise JumphostError('invalid Docker exec JSON response') from None
        except (OSError, http.client.HTTPException):
            raise JumphostError('Docker exec transport failed; operation remains uncertain') from None
        finally:
            connection.close()


class JournaledDHCPStop:
    """Persist stop intent before TERM; requalify exit after a lost receipt.

    Caller owns its operation lock/offline fence. ``probe`` is read-only and
    must verify the original container, attachments, files and process identity.
    A stopped retry never sends another signal or trusts only a cached receipt.
    """
    def __init__(self, intent, save, probe, stop):
        self.intent, self.save, self.probe, self.stop = intent, save, probe, stop
        try:
            expected = {'service':intent['service'],'exit_verified':True}
            if (not re.fullmatch('[0-9a-f]{32}', intent['id'])
                    or not re.fullmatch('[0-9a-f]{64}', intent['service']['container']['id'])
                    or intent['phase'] not in ('intent','stopping','stopped')
                    or type(intent['attempted']) is not bool
                    or intent['phase'] == 'intent' and intent['attempted']
                    or intent['phase'] == 'stopping' and not intent['attempted']
                    or intent['phase'] == 'stopped' and intent['receipt'] != expected
                    or intent['phase'] != 'stopped' and intent['receipt'] is not None):
                raise ValueError()
        except (KeyError,TypeError,ValueError):
            raise JumphostError('complete original DHCP stop intent required') from None

    def state(self):
        value = self.probe(self.intent['service'])
        expected = {'state':'running','service':self.intent['service']}
        stopped = dict(expected, state='stopped', exit_verified=True)
        if value not in (expected, stopped):
            raise JumphostError('DHCP stop observation differs from original generation')
        return value['state']

    def run(self):
        intent = self.intent
        state = self.state()
        expected = {'service':intent['service'],'exit_verified':True}
        if state == 'running':
            if intent['phase'] == 'stopped':
                raise JumphostError('committed DHCP shutdown no longer verified')
            intent['phase'] = 'stopping'; intent['attempted'] = True; self.save()
            if self.stop(intent['service']) != expected:
                raise JumphostError('DHCP shutdown receipt differs')
            if self.state() != 'stopped':
                raise JumphostError('DHCP shutdown remains unverified')
        if intent['phase'] != 'stopped':
            intent['receipt'] = expected; intent['phase'] = 'stopped'; self.save()
        return expected


class JournaledDHCPMain:
    """Write the individually bind-mounted main file without replacing its inode.

    The caller holds its operation lock and offline fence. ``preflight`` must
    verify the original container, all attachments, mount and service absence,
    returning the same container proof and verified shutdown receipt. The intent
    is write-ahead: a crash permits only the recorded chunk's possible prefixes.
    No launcher, signal, path replacement or service restart is performed here.
    """
    LIMIT = 1024 * 1024
    CHUNK = 4096

    @staticmethod
    def identity(info, *, directory=False):
        kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        mode = 0o755 if directory else 0o644
        if (not kind or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode
                or not directory and info.st_nlink != 1):
            raise JumphostError('DHCP main asset ownership differs')
        return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'gid':info.st_gid,'mode':mode,'directory':directory,'nlink':info.st_nlink}

    def __init__(self, directory, intent, save, preflight):
        self.directory = Path(directory)
        self.intent, self.save, self.preflight = intent, save, preflight
        self.filename = intent.get('filename', 'main')
        try:
            self.old, self.new = intent['old'].encode(), intent['new'].encode()
            receipt = intent['service_exit']
            offset, pending = intent['offset'], intent['pending_end']
            if (self.filename not in ('main','hosts','options') or not self.directory.is_absolute()
                    or not re.fullmatch('[0-9a-f]{32}', intent['nonce'])
                    or not re.fullmatch('[0-9a-f]{64}', intent['container']['id'])
                    or receipt['exit_verified'] is not True
                    or receipt['service']['container'] != intent['container']
                    or not self.new and self.filename == 'main'
                    or max(len(self.old), len(self.new)) > self.LIMIT
                    or b'\0' in self.old or b'\0' in self.new
                    or intent['phase'] not in ('intent','writing','truncating','ready')
                    or type(offset) is not int or not 0 <= offset <= len(self.new)
                    or pending is not None and (type(pending) is not int
                        or not offset < pending <= min(offset + self.CHUNK, len(self.new)))
                    or intent['phase'] != 'writing' and pending is not None
                    or intent['phase'] == 'intent' and offset != 0
                    or intent['phase'] in ('truncating','ready') and offset != len(self.new)
                    or not isinstance(intent['directory'], dict) or not isinstance(intent['file'], dict)):
                raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError):
            raise JumphostError('complete original DHCP main write intent required') from None

    def prefix(self, offset):
        return self.new[:offset] + self.old[offset:]

    def original(self, directory, asset):
        expected = {'container':self.intent['container'],'service_exit':self.intent['service_exit']}
        if self.preflight() != expected:
            raise JumphostError('DHCP main container/shutdown preflight differs')
        self.identities(directory, asset)

    def identities(self, directory, asset):
        if (self.identity(os.fstat(directory), directory=True) != self.intent['directory']
                or self.identity(self.directory.lstat(), directory=True) != self.intent['directory']
                or self.identity(os.fstat(asset)) != self.intent['file']
                or self.identity(os.stat(self.filename, dir_fd=directory, follow_symlinks=False)) != self.intent['file']):
            raise JumphostError('DHCP main directory/file generation differs')

    def contents(self, asset):
        return os.pread(asset, self.LIMIT + 1, 0)

    def verify(self):
        """Qualify a recorded partial write without saving or authorizing writes."""
        with ExitStack() as stack:
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, directory)
            asset = os.open(self.filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            stack.callback(os.close, asset)
            self.identities(directory, asset); actual = self.contents(asset)
            phase = self.intent['phase']; offset = self.intent['offset']; end = self.intent['pending_end']
            if phase == 'intent': valid = actual == self.old
            elif phase == 'ready': valid = actual == self.new
            elif phase == 'truncating': valid = actual in (self.prefix(len(self.new)), self.new)
            else:
                valid = (actual == self.prefix(offset) if end is None else
                         any(actual == self.prefix(i) for i in range(end, offset - 1, -1)))
            if not valid: raise JumphostError('DHCP main journal content differs')
            return {'identity':{key:self.intent['file'][key] for key in ('device','inode')},
                    'phase':phase,'sha256':hashlib.sha256(actual).hexdigest(),'size':len(actual)}

    def run(self):
        intent = self.intent
        with ExitStack() as stack:
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, directory)
            flags = os.O_RDONLY if intent['phase'] == 'ready' else os.O_RDWR
            asset = os.open(self.filename, flags | os.O_NOFOLLOW, dir_fd=directory)
            stack.callback(os.close, asset)
            self.original(directory, asset)
            if intent['phase'] == 'intent':
                if self.contents(asset) != self.old:
                    raise JumphostError('DHCP original main content differs')
                intent['phase'] = 'writing'; self.save()
            while intent['phase'] == 'writing':
                self.original(directory, asset)
                offset, end = intent['offset'], intent['pending_end']
                actual = self.contents(asset)
                if end is not None:
                    # pwrite can be short or its acknowledgement can be lost.
                    # Every byte outside the persisted chunk must still match.
                    matched = next((i for i in range(end, offset - 1, -1)
                                    if actual == self.prefix(i)), None)
                    if matched is None:
                        raise JumphostError('DHCP main pending chunk content differs')
                    os.fsync(asset)
                    intent['offset'] = matched; intent['pending_end'] = None; self.save()
                    continue
                if actual != self.prefix(offset):
                    raise JumphostError('DHCP main confirmed content differs')
                if offset == len(self.new):
                    intent['phase'] = 'truncating'; self.save(); break
                end = min(offset + self.CHUNK, len(self.new))
                intent['pending_end'] = end; self.save()
                self.original(directory, asset)
                if self.contents(asset) != self.prefix(offset):
                    raise JumphostError('DHCP main changed before chunk write')
                count = os.pwrite(asset, self.new[offset:end], offset)
                if not 0 < count <= end - offset:
                    raise JumphostError('DHCP main write made no valid progress')
                os.fsync(asset)
                intent['offset'] += count; intent['pending_end'] = None; self.save()
            if intent['phase'] == 'truncating':
                self.original(directory, asset)
                if self.contents(asset) not in (self.prefix(len(self.new)), self.new):
                    raise JumphostError('DHCP main truncate content differs')
                os.ftruncate(asset, len(self.new)); os.fsync(asset); os.fsync(directory)
                intent['phase'] = 'ready'; self.save()
            self.original(directory, asset)
            if self.contents(asset) != self.new:
                raise JumphostError('committed DHCP main content differs')
            return {'identity':{key:intent['file'][key] for key in ('device','inode')},
                    'content':intent['new']}


class JournaledDHCPAssets:
    """Update all structural assets after shutdown, keeping every inode.

    This is a private writing sub-operation. Caller holds the same lock/fence as
    stopping/starting and persists the complete intent. A read-only verifier
    qualifies only the exact partial chunks authorized by that original intent.
    """
    NAMES = ('main','hosts','options')

    @staticmethod
    def binding(intent):
        fields = ('nonce','filename','container','service_exit','directory','file','old','new')
        return digest({key:intent[key] for key in ('id','container','service_exit','directory')} |
            {'files':{name:{key:intent['files'][name][key] for key in fields} for name in JournaledDHCPAssets.NAMES}})

    @classmethod
    def prepare(cls, directory, previous, desired, container, service_exit, operation_id):
        directory = Path(directory)
        if set(previous) != set(cls.NAMES) or set(desired) != set(cls.NAMES):
            raise JumphostError('complete original and target DHCP files required')
        with ExitStack() as stack:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            identity = JournaledDHCPMain.identity(os.fstat(fd), directory=True)
            if JournaledDHCPMain.identity(directory.lstat(), directory=True) != identity:
                raise JumphostError('DHCP asset directory changed during planning')
            if set(os.listdir(fd)) != set(cls.NAMES):
                raise JumphostError('DHCP asset directory has unqualified entries')
            result = {'id':operation_id,'container':container,'service_exit':service_exit,
                      'directory':identity,'phase':'prepared','files':{}}
            for name in cls.NAMES:
                asset = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd); stack.callback(os.close, asset)
                proof = JournaledDHCPMain.identity(os.fstat(asset))
                if ({key:proof[key] for key in ('device','inode')} != previous[name]['identity']
                        or os.pread(asset, JournaledDHCPMain.LIMIT + 1, 0) != previous[name]['content'].encode()
                        or JournaledDHCPMain.identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) != proof):
                    raise JumphostError('DHCP original asset identity/content differs')
                result['files'][name] = {'nonce':digest([operation_id,name])[:32],'filename':name,
                    'container':container,'service_exit':service_exit,'directory':identity,'file':proof,
                    'old':previous[name]['content'],'new':desired[name],'phase':'intent','offset':0,'pending_end':None}
            result['fingerprint'] = cls.binding(result)
            cls(directory,result,lambda:None,lambda:None)  # Validate every target before exposing a plan.
            return result

    def __init__(self, directory, intent, save, preflight):
        self.directory, self.intent = Path(directory), intent
        self.save, self.preflight = save, preflight
        try:
            if (not re.fullmatch('[0-9a-f]{32}',intent['id'])
                    or intent['phase'] not in ('prepared','writing','ready')
                    or set(intent['files']) != set(self.NAMES)):
                raise ValueError()
            self.fingerprint = self.binding(intent)
            if intent['fingerprint'] != self.fingerprint: raise ValueError()
            for name, child in intent['files'].items():
                if (child['filename'] != name or child['nonce'] != digest([intent['id'],name])[:32]
                        or any(child[key] != intent[key] for key in ('container','service_exit','directory'))
                        or intent['phase'] == 'prepared' and child['phase'] != 'intent'
                        or intent['phase'] == 'ready' and child['phase'] != 'ready'):
                    raise ValueError()
                JournaledDHCPMain(self.directory,child,self.save,self.original)
        except (KeyError,TypeError,ValueError,AttributeError):
            raise JumphostError('complete original structural DHCP asset intent required') from None

    def verify(self):
        phase = self.intent['phase']
        if (phase not in ('prepared','writing','ready')
                or phase == 'prepared' and any(v['phase'] != 'intent' for v in self.intent['files'].values())
                or phase == 'ready' and any(v['phase'] != 'ready' for v in self.intent['files'].values())):
            raise JumphostError('structural DHCP asset progress differs')
        if self.intent['fingerprint'] != self.fingerprint or self.binding(self.intent) != self.fingerprint:
            raise JumphostError('structural DHCP asset intent changed')
        directory = os.open(self.directory,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if (JournaledDHCPMain.identity(os.fstat(directory),directory=True) != self.intent['directory']
                    or set(os.listdir(directory)) != set(self.NAMES)):
                raise JumphostError('structural DHCP directory identity/contents differ')
        finally: os.close(directory)
        return {name:JournaledDHCPMain(self.directory,self.intent['files'][name],self.save,self.original).verify()
                for name in self.NAMES}

    def original(self):
        expected = {'container':self.intent['container'],'service_exit':self.intent['service_exit']}
        if self.preflight() != expected:
            raise JumphostError('structural DHCP container/shutdown preflight differs')
        self.verify()
        return expected

    def run(self):
        self.original()
        if self.intent['phase'] != 'ready':
            self.intent['phase'] = 'writing'; self.save()
            for name in self.NAMES:
                JournaledDHCPMain(self.directory,self.intent['files'][name],self.save,self.original).run()
            self.original(); self.intent['phase'] = 'ready'; self.save()
        self.original()
        return {name:{'identity':{key:self.intent['files'][name]['file'][key] for key in ('device','inode')},
                      'content':self.intent['files'][name]['new']} for name in self.NAMES}


class JournaledDHCPExec:
    """A launch sub-operation; caller owns the journal lock and offline fence.

    ``preflight`` requalifies the original container, attachments and mounted
    files and returns its container proof plus its current ``exec_ids``.
    ``observe`` returns a fully qualified nonce-bound service, or verified
    absence. It must raise for a foreign/ambiguous process, never return None
    for an inspection error. The enclosing structural operation persists the
    initial intent before calling this runner and retains it on any exception.
    """
    def __init__(self, intent, save, preflight, observe, *, docker=None):
        self.intent, self.save, self.preflight, self.observe = intent, save, preflight, observe
        self.docker = docker or DockerExecHTTP()
        nonce = intent.get('nonce')
        if (not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce)
                or not isinstance(intent.get('container'), dict)
                or not re.fullmatch('[0-9a-f]{64}', intent['container'].get('id', ''))
                or intent.get('phase') not in ('intent','created','starting','verifying','ready')
                or type(intent.get('create_attempts')) is not int or intent['create_attempts'] < 0
                or type(intent.get('start_attempted')) is not bool
                or not isinstance(intent.get('observed_exec_ids'), list)
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in intent['observed_exec_ids'])
                or len(set(intent['observed_exec_ids'])) != len(intent['observed_exec_ids'])
                or intent.get('exec_id') is not None and (not isinstance(intent['exec_id'], str)
                    or not re.fullmatch('[0-9a-f]{64}', intent['exec_id']))):
            raise JumphostError('complete original DHCP exec intent required')
        identity = intent['exec_id']
        if (identity is None and (intent['phase'] != 'intent' or intent['start_attempted'])
                or identity is not None and identity not in intent['observed_exec_ids']
                or intent['phase'] in ('starting','verifying','ready') and not intent['start_attempted']
                or intent['phase'] == 'ready' and not isinstance(intent.get('service'), dict)):
            raise JumphostError('DHCP exec journal phase/proof inconsistent')
        self.marker = 'DNLAB_DHCP_OPERATION_NONCE=' + nonce
        self.command = ['env', self.marker, 'dnsmasq', '--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf']
        self.config = {'Cmd':self.command, 'User':'0', 'AttachStdin':False,
            'AttachStdout':False, 'AttachStderr':False, 'Tty':False, 'Privileged':False}

    def original(self):
        value = self.preflight()
        if (not isinstance(value, dict) or value.get('container') != self.intent['container']
                or not isinstance(value.get('exec_ids'), list)
                or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in value['exec_ids'])):
            raise JumphostError('DHCP exec original container/files preflight differs')
        return value

    def inspect(self, identity, *, missing=False):
        value = self.docker.call('GET', '/exec/' + identity + '/json', missing=missing)
        if value is None:
            return None
        expected = {'tty':False, 'entrypoint':self.command[0], 'arguments':self.command[1:],
                    'privileged':False, 'user':'0'}
        if (not isinstance(value, dict) or value.get('ID') != identity
                or value.get('ContainerID') != self.intent['container']['id']
                or value.get('ProcessConfig') != expected
                or any(value.get(key) is not False for key in ('OpenStdin','OpenStdout','OpenStderr'))
                or type(value.get('Running')) is not bool
                or type(value.get('Pid')) is not int or value['Pid'] < 0
                or value.get('ExitCode') is not None and type(value['ExitCode']) is not int):
            raise JumphostError('DHCP exec ownership/configuration differs')
        return value

    def discover(self):
        """Locate inactive creates whose response was lost; never adopt a run."""
        candidates = []
        for identity in self.original()['exec_ids']:
            raw = self.docker.call('GET', '/exec/' + identity + '/json', missing=True)
            if raw is None:
                continue
            config = raw.get('ProcessConfig') if isinstance(raw, dict) else None
            if not isinstance(config, dict) or not isinstance(config.get('arguments'), list):
                raise JumphostError('invalid Docker exec discovery record')
            if self.marker not in config['arguments']:
                continue
            value = self.inspect(identity)
            if value['Running'] or value['ExitCode'] is not None or value['Pid'] != 0:
                raise JumphostError('unbound DHCP exec has already run; refusing adoption')
            candidates.append(identity)
        return sorted(candidates)

    def observed_service(self):
        value = self.observe()
        if value is not None and (not isinstance(value, dict)
                or value.get('container') != self.intent['container']
                or value.get('operation_nonce') != self.intent['nonce']):
            raise JumphostError('DHCP exec service generation differs')
        if self.intent.get('service') is not None and value != self.intent['service']:
            raise JumphostError('committed DHCP exec service replaced or absent')
        return value

    def ready(self, value):
        self.original()
        self.intent['service'] = value; self.intent['phase'] = 'ready'; self.save()
        return value

    def run(self):
        self.original()
        if self.intent['phase'] == 'ready':
            value = self.observed_service()
            if value is None:
                raise JumphostError('committed DHCP service missing')
            return value
        identity = self.intent['exec_id']
        if identity is None:
            if self.observed_service() is not None:
                raise JumphostError('unbound DHCP service already present; refusing another launch')
            candidates = self.discover() if self.intent['create_attempts'] else []
            if candidates:
                # Only the selected ID can ever be started. Other late/inactive
                # creates remain associated with this intent until Docker GC or
                # container cleanup; they do not represent OS processes.
                self.intent['observed_exec_ids'] = sorted(set(self.intent['observed_exec_ids']) | set(candidates))
                identity = candidates[0]
            else:
                self.intent['create_attempts'] += 1; self.save()
                self.original()
                created = self.docker.call('POST', '/containers/' + self.intent['container']['id'] + '/exec', self.config)
                identity = created.get('Id') if isinstance(created, dict) else None
                if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
                    raise JumphostError('invalid DHCP exec creation identity')
                self.intent['observed_exec_ids'].append(identity)
            self.intent['exec_id'] = identity; self.intent['phase'] = 'created'; self.save()
        self.original()
        value = self.inspect(identity, missing=True)
        if value is None:
            service = self.observed_service() if self.intent['start_attempted'] else None
            if service is not None:
                return self.ready(service)
            raise JumphostError('original DHCP exec missing; refusing another launch')
        if not self.intent['start_attempted'] and (value['Running'] or value['ExitCode'] is not None):
            raise JumphostError('DHCP exec ran without its persisted start intent')
        if not value['Running'] and value['ExitCode'] is None:
            if self.observed_service() is not None:
                raise JumphostError('DHCP service already present before inactive exec start')
            self.intent['start_attempted'] = True; self.intent['phase'] = 'starting'; self.save()
            self.original()
            # A save or a renewed container/files preflight can take time.
            # Requalify absence at the last boundary before the start request,
            # including retries of an exec whose ID is already persisted.
            if self.observed_service() is not None:
                raise JumphostError('DHCP service already present before inactive exec start')
            try:
                self.docker.call('POST', '/exec/' + identity + '/start', {'Detach':True,'Tty':False})
            except DockerExecError as error:
                if error.status != 409:
                    raise
                current = self.inspect(identity)
                if not current['Running'] and current['ExitCode'] is None:
                    raise
        deadline = time.monotonic() + 5
        while True:
            self.original()
            value = self.inspect(identity, missing=True)
            if value is None:
                service = self.observed_service()
                if service is not None and self.intent['start_attempted']:
                    return self.ready(service)
                raise JumphostError('DHCP exec vanished before verification')
            if not value['Running'] and value['ExitCode'] is not None:
                if value['ExitCode'] != 0:
                    raise JumphostError('DHCP daemon launcher failed; recovery required')
                self.intent['phase'] = 'verifying'; self.save()
                service = self.observed_service()
                if service is not None:
                    return self.ready(service)
            if time.monotonic() >= deadline:
                raise JumphostError('DHCP daemon launch/readiness unresolved; recovery required')
            time.sleep(.05)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def execute(argv, *, pass_fds=(), input=None):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=45, pass_fds=pass_fds, input=input)
    if result.returncode:
        # argv can contain the login password. Do not log it.
        raise JumphostError(f'jumphost command failed: {argv[0]} rc={result.returncode}: {result.stderr[-1000:]}')
    return result.stdout


def context():
    info = os.stat('/proc/self/ns/net')
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'device': info.st_dev, 'inode': info.st_ino}


def signature(value):
    return {key: value.get(key) for key in ('ifname', 'ifindex', 'address', 'ifalias', 'link_index')} | {
        'kind': value.get('linkinfo', {}).get('info_kind')}


def same_bind_mounts(actual, expected):
    """Docker may reorder binds; preserve exact mappings and unique targets."""
    def qualified(values):
        if not isinstance(values, list): return False
        targets = set()
        for entry in values:
            if not isinstance(entry, str) or '\x00' in entry: return False
            parts = entry.rsplit(':', 2)
            if len(parts) != 3: return False
            source, target, mode = parts
            if not source.startswith('/') or not target.startswith('/') or mode != 'ro': return False
            # Aliases of the same destination are still conflicting mounts.
            target = os.path.normpath('/' + target.lstrip('/'))
            if target in targets: return False
            targets.add(target)
        return True
    return qualified(actual) and qualified(expected) and Counter(actual) == Counter(expected)


def names(lab, segment='default'):
    key = digest(['jumphost-attachment-v1', lab, segment])
    return 'jh' + key[:13]


def validate(value):
    fields = {'lab', 'generation', 'name', 'image', 'network', 'ip', 'bind_ip', 'port', 'env', 'dns', 'binds', 'dhcp', 'attachment'}
    if not isinstance(value, dict) or not fields <= set(value) or set(value) - fields - {'management_intent'}:
        raise JumphostError('complete jumphost configuration required')
    if not re.fullmatch('[0-9a-f]{32}', value.get('generation', '')):
        raise JumphostError('coordinator generation required')
    for key in ('lab', 'name', 'image'):
        if not isinstance(value[key], str) or not value[key] or '\x00' in value[key]:
            raise JumphostError('invalid jumphost ' + key)
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['name']):
        raise JumphostError('invalid jumphost container name')
    if type(value['port']) is not int or not 1 <= value['port'] <= 65535:
        raise JumphostError('invalid SSH port')
    try:
        ipaddress.IPv4Address(value['ip']); ipaddress.ip_address(value['bind_ip'])
    except ValueError:
        raise JumphostError('invalid jumphost address') from None
    if (not isinstance(value['env'], dict) or any(not isinstance(k, str) or not k or '=' in k
            or not isinstance(v, str) or '\x00' in k + v for k, v in value['env'].items())
            or not isinstance(value['dns'], list) or not isinstance(value['binds'], list) or not isinstance(value['dhcp'], str)):
        raise JumphostError('invalid jumphost environment/assets')
    for address in value['dns']: ipaddress.ip_address(address)
    if any(not isinstance(v, str) or not v.startswith('/') or not v.endswith(':ro') for v in value['binds']):
        raise JumphostError('only explicit read-only jumphost binds supported')
    net = value['network']
    if not isinstance(net, dict) or set(net) != {'name', 'bridge', 'subnet', 'gateway'}:
        raise JumphostError('complete external network configuration required')
    subnet = ipaddress.IPv4Network(net['subnet'], strict=True)
    if ipaddress.IPv4Address(value['ip']) not in subnet or ipaddress.IPv4Address(net['gateway']) not in subnet:
        raise JumphostError('external network address differs')
    attachment = value['attachment']
    if not isinstance(attachment, dict) or set(attachment) != {'segment', 'network', 'bridge', 'interface', 'ipv4', 'ipv6'}:
        raise JumphostError('complete attachment configuration required')
    if not isinstance(attachment['segment'], str) or not attachment['segment']:
        raise JumphostError('management segment required')
    for name in (net['bridge'], attachment['bridge'], attachment['interface']):
        if not isinstance(name, str) or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', name):
            raise JumphostError('invalid attachment interface')
    if attachment['interface'] in ('lo', 'eth0'):
        raise JumphostError('management interface is reserved')
    if ipaddress.ip_interface(attachment['ipv4']).version != 4:
        raise JumphostError('IPv4 attachment required')
    if attachment['ipv6'] and ipaddress.ip_interface(attachment['ipv6']).version != 6:
        raise JumphostError('IPv6 attachment differs')
    return json.loads(canonical(value))


DHCP_ROOT = '/etc/dnlab-dhcp'


def dhcp_files(content):
    if not isinstance(content, str) or not content or '\x00' in content:
        raise JumphostError('complete DHCP content required')
    parts = {'main': [], 'hosts': [], 'options': []}
    for line in content.splitlines():
        if line.startswith('dhcp-host='): parts['hosts'].append(line[len('dhcp-host='):])
        elif line.startswith('dhcp-option='): parts['options'].append(line[len('dhcp-option='):])
        elif line.startswith(('dhcp-hostsfile=', 'dhcp-optsfile=', 'log-facility=', 'conf-file=', 'conf-dir=')):
            raise JumphostError('unqualified DHCP include/log directive')
        else: parts['main'].append(line)
    parts['main'] += ['dhcp-hostsfile=' + DHCP_ROOT + '/hosts', 'dhcp-optsfile=' + DHCP_ROOT + '/options',
                      'log-facility=/run/dnlab-dhcp.log', 'log-dhcp']
    return {key: '\n'.join(value) + ('\n' if value else '') for key, value in parts.items()}



def dhcp_listener_requirements(main):
    """Expected DHCP listeners for the renderer's reservation-only profile."""
    interfaces = []; required = set(); ra = False; static = []
    try:
        for line in main.splitlines():
            if line.startswith('interface='):
                name = line.split('=',1)[1]
                if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',name) or name in interfaces or name in ('lo','eth0'):
                    raise ValueError()
                interfaces.append(name)
            elif line == 'enable-ra': ra = True
            elif line.startswith('no-dhcp-interface='):
                static.append(line.split('=',1)[1])
            elif line.startswith(('dhcp-alternate-port','except-interface=')):
                raise ValueError()
            elif line.startswith('dhcp-range='):
                parts = line.split('=',1)[1].split(',')
                while parts and parts[0].startswith(('set:','tag:')): parts.pop(0)
                address = ipaddress.ip_address(parts[0])
                if parts[1] != 'static' or len(parts) != (4 if address.version == 6 else 3): raise ValueError()
                if address.version == 6 and not 0 <= int(parts[2]) <= 128: raise ValueError()
                required.add(('udp6',547) if address.version == 6 else ('udp',67))
        if (not interfaces or ra and ('udp6',547) not in required
                or len(static)!=len(set(static)) or not set(static)<=set(interfaces)
                or static and not dns_listener_bindings(main)
                or not required and (set(static)!=set(interfaces) or not dns_listener_bindings(main))):raise ValueError()
        if ra: required.add(('raw6',58))
        return sorted(interfaces), sorted(required)
    except (ValueError,IndexError,TypeError,AttributeError):
        raise JumphostError('qualified reservation-only DHCP listener profile required') from None



def dns_listener_bindings(main):
    """Explicit proxy profile; legacy DHCP profiles retain their old checks."""
    lines=main.splitlines()
    if 'port=53' not in lines:return []
    addresses=[line.split('=',1)[1] for line in lines if line.startswith('listen-address=')]
    upstream=[line.split('=',1)[1] for line in lines if line.startswith('server=')]
    if (not addresses or len(addresses)!=len(set(addresses)) or len(upstream)!=1
            or 'no-resolv' not in lines):raise JumphostError('qualified DNS proxy profile required')
    try:
        ipaddress.IPv4Address(upstream[0]);result=[]
        for value in addresses:
            address=ipaddress.ip_address(value)
            if address.is_unspecified or address.is_multicast or address.is_loopback:raise ValueError()
            encoded=''.join(address.packed[i:i+4][::-1].hex() for i in range(0,len(address.packed),4))
            for protocol in ('udp','tcp'):result.append((protocol+('6' if address.version==6 else ''),53,encoded))
        return sorted(result)
    except ValueError:raise JumphostError('qualified DNS proxy address required') from None


def file_identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'regular': stat.S_ISREG(info.st_mode)}


def hash_descriptor(fd):
    value = hashlib.sha256(); offset = 0
    while True:
        chunk = os.pread(fd, 1024 * 1024, offset)
        if not chunk: return value.hexdigest()
        value.update(chunk); offset += len(chunk)


def namespace_identity(fd):
    info = os.fstat(fd)
    return {'device': info.st_dev, 'inode': info.st_ino}


def dhcp_validate_identity(value, expected=None):
    """Validate observed host proofs before they can authorize a service signal."""
    if (value['pid_file']['regular'] is not True or value['pid_file']['mode'] & 0o022
            or value['pid_file']['uid'] != value['profile']['uid']
            or value['uids'] != [value['profile']['uid']] * 4
            or len(set(value['gids'])) != 1
            or value['profile']['gid'] is not None and value['gids'][0] != value['profile']['gid']):
        raise JumphostError('DHCP process/PID file credentials differ')
    if (value['pid_namespace'] != value['container']['pid_namespace']
            or value['net_namespace'] != value['container']['net_namespace']
            or value['mount_namespace'] != value['container']['mount_namespace']):
        raise JumphostError('DHCP process belongs to another container namespace')
    binary = value['binary']
    if (not binary['regular'] or binary['uid'] != 0 or binary['mode'] & 0o022
            or binary != value['mapped_binary'] or value['command'] != ['dnsmasq', '--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf']):
        raise JumphostError('DHCP executable/command identity differs')
    if expected is not None and value != expected:
        raise JumphostError('DHCP service generation differs')
    return value


def dhcp_validate_birth_nonce(environment, expected):
    """Bind a daemon from a pending launch intent; never log its environment."""
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{32}', expected):
        raise JumphostError('DHCP process birth nonce invalid')
    prefix = 'DNLAB_DHCP_OPERATION_NONCE='
    observed = [entry for entry in environment.split('\0') if entry.startswith(prefix)]
    if observed != [prefix + expected]:
        raise JumphostError('DHCP process birth nonce differs')
    return expected


# Qualification is intentionally digest-specific. New helper builds require a
# new on-host service/log qualification before enabling reload for that image.
DHCP_LOG_PROFILES = {
    'sha256:de63a0cd8f1083ecab8d81ffcc3446227271b9677ad8dd2e08547704b57850da': {
        'binary_sha256': 'fdb17a6b5511ce142f3b16bf8e212fe8b05d7abcc2ca2fcdec1aa033691d0196',
        'gid': 0, 'mode': 0o660,
    },
    # Explicit local candidate qualification: same executable hash and observed
    # log ownership/writer profile; no inheritance from its base image.
    'sha256:3683cf53b8ed9440fb7b803da90888b829e36b37f113109f73ec6916d8bd2c98': {
        'binary_sha256': 'fdb17a6b5511ce142f3b16bf8e212fe8b05d7abcc2ca2fcdec1aa033691d0196',
        'gid': 0, 'mode': 0o660,
    },
    # Explicit native-ID candidate: on-host service/log diagnosis 2026-10-26.
    'sha256:5cc5ceac4f13444706496220e9bd88b0777bb65ca0243329d7fec97653acdb17': {
        'binary_sha256': 'fdb17a6b5511ce142f3b16bf8e212fe8b05d7abcc2ca2fcdec1aa033691d0196',
        'gid': 0, 'mode': 0o660,
    },
}


def dhcp_validate_log(value, service, main, expected=None):
    profile = DHCP_LOG_PROFILES.get(service['container']['image'])
    if (profile is None or service['binary_sha256'] != profile['binary_sha256']
            or [line for line in main.splitlines() if line.startswith('log-facility=')]
               != ['log-facility=/run/dnlab-dhcp.log']):
        raise JumphostError('DHCP log image/configuration profile not qualified')
    for directory in value['directories']:
        if not directory['directory'] or directory['uid'] != 0 or directory['mode'] & 0o022:
            raise JumphostError('DHCP log parent directory ownership differs')
    if len(value['directories']) != 2:
        raise JumphostError('DHCP log parent directory proof incomplete')
    info = value['file']
    if (not info['regular'] or info['uid'] != service['profile']['uid']
            or info['gid'] != profile['gid'] or info['mode'] != profile['mode'] or info['nlink'] != 1):
        raise JumphostError('DHCP log ownership differs from qualified profile')
    if (value['writer'] != {'host_pid': service['host_pid'], 'start': service['start']}
            or value['configuration_sha256'] != hashlib.sha256(main.encode()).hexdigest()):
        raise JumphostError('DHCP log writer/configuration differs')
    if expected is not None and value != expected:
        raise JumphostError('DHCP log generation changed')
    return value


class DHCPHostService:
    """Observe and signal a service in the original container from the host.

    Container root/proc descriptors, namespace identity and host pidfd remain
    pinned through inspection. Container-local PID numbers are only locators.
    """
    def __init__(self, worker, record, network_fd):
        self.worker, self.record, self.network_fd = worker, record, network_fd
        self.stack = ExitStack()

    def __enter__(self):
        try:
            self.container = self.worker.container(self.record)
            if not self.container or not self.container['State']['Running']:
                raise JumphostError('original DHCP container unavailable')
            state = self.container['State']; self.init_pid = state['Pid']
            self.init = self.open('/proc/' + str(self.init_pid), directory=True)
            self.root = self.open('root', directory=True, parent=self.init, nofollow=False)
            self.run_dir = self.open('run', directory=True, parent=self.root)
            self.pid_namespace = self.ns(self.init, 'pid')
            self.mount_namespace = self.ns(self.init, 'mnt')
            self.net_namespace = namespace_identity(self.network_fd)
            if self.ns(self.init, 'net') != self.net_namespace:
                raise JumphostError('DHCP container network namespace differs')
            self.container_proof = {'id': self.container['Id'], 'image': self.record['image']['Id'],
                'started_at': state['StartedAt'], 'init_pid': self.init_pid,
                'init_start': self.read('stat', self.init).rsplit(')', 1)[1].split()[19],
                'pid_namespace': self.pid_namespace, 'mount_namespace': self.mount_namespace,
                'net_namespace': self.net_namespace, 'host': self.record['context']}
            self.recheck_container()
            return self
        except BaseException:
            self.stack.close(); raise

    def __exit__(self, *args):
        self.stack.close()

    def open(self, path, *, parent=None, directory=False, nofollow=True):
        flags = os.O_RDONLY | (os.O_DIRECTORY if directory else 0) | (os.O_NOFOLLOW if nofollow else 0)
        fd = os.open(path, flags, dir_fd=parent); self.stack.callback(os.close, fd)
        return fd

    def read(self, path, parent):
        fd = self.open(path, parent=parent)
        return os.read(fd, 1024 * 1024).decode()

    def ns(self, proc, name):
        # proc namespace entries are kernel magic links, intentionally followed.
        fd = self.open('ns/' + name, parent=proc, nofollow=False)
        return namespace_identity(fd)

    def root_directory(self, components):
        fd = self.root
        for part in components: fd = self.open(part, directory=True, parent=fd)
        return fd

    def recheck_container(self):
        value = self.worker.container(self.record)
        if (not value or not value['State']['Running'] or value['Id'] != self.container['Id']
                or value['State']['Pid'] != self.init_pid or value['State']['StartedAt'] != self.container['State']['StartedAt']
                or self.worker.host_context() != self.record['context']):
            raise JumphostError('DHCP original container generation changed')

    def account_file(self, name, etc):
        fd = self.open(name, parent=etc); info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise JumphostError('DHCP image account database ownership differs')
        return os.read(fd, 1024 * 1024).decode()

    def credentials(self):
        profile = {}
        main = self.record['dhcp_assets']['files']['main']['content']
        for line in main.splitlines():
            if line.startswith(('user=', 'group=')):
                key, value = line.split('=', 1)
                if key in profile: raise JumphostError('ambiguous DHCP credentials')
                profile[key] = value
        etc = self.root_directory(['etc'])
        accounts = [line.split(':') for line in self.account_file('passwd', etc).splitlines() if line and not line.startswith('#')]
        name = profile.get('user', 'nobody')
        matches = [row for row in accounts if row[0] == name or name.isdecimal() and row[2] == name]
        if len(matches) != 1: raise JumphostError('DHCP configured user not qualified by container image')
        uid = int(matches[0][2]); gid = None
        if 'group' in profile:
            groups = [line.split(':') for line in self.account_file('group', etc).splitlines() if line and not line.startswith('#')]
            matches = [row for row in groups if row[0] == profile['group'] or profile['group'].isdecimal() and row[2] == profile['group']]
            if len(matches) != 1: raise JumphostError('DHCP configured group not qualified by container image')
            gid = int(matches[0][2])
        # An omitted group is selected by dnsmasq's build. Pin the observed group
        # in the service proof rather than equating it to PID-file GID.
        return {'uid': uid, 'gid': gid, 'user': name, 'group': profile.get('group')}

    def log_identity(self, service, proc):
        log = self.open('dnlab-dhcp.log', parent=self.run_dir)
        info = os.fstat(log)
        current_run = self.open('run', directory=True, parent=self.root)
        if namespace_identity(current_run) != namespace_identity(self.run_dir):
            raise JumphostError('DHCP log parent directory generation changed')
        directories = []
        for fd in (self.root, self.run_dir):
            current = os.fstat(fd)
            directories.append(namespace_identity(fd) | {'uid': current.st_uid, 'gid': current.st_gid,
                'mode': stat.S_IMODE(current.st_mode), 'directory': stat.S_ISDIR(current.st_mode)})
        # A service UID alone does not prove which process writes this inode.
        # Observe the qualified process's actual writable file description.
        descriptors = self.open('fd', directory=True, parent=proc)
        writable = False
        for name in os.listdir(descriptors):
            if not name.isdecimal(): continue
            try:
                target = os.stat(name, dir_fd=descriptors)
                if (target.st_dev, target.st_ino) != (info.st_dev, info.st_ino): continue
                rows = dict(line.split(':', 1) for line in self.read('fdinfo/' + name, proc).splitlines() if ':' in line)
                if int(rows['flags'].strip(), 8) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                    writable = True
            except FileNotFoundError: continue
        if not writable: raise JumphostError('DHCP log has no qualified service writer')
        main = self.record['dhcp_assets']['files']['main']['content']
        value = {'directories': directories, 'file': file_identity(info) | {'nlink': info.st_nlink},
            'writer': {'host_pid': service['host_pid'], 'start': service['start']},
            'configuration_sha256': hashlib.sha256(main.encode()).hexdigest()}
        return dhcp_validate_log(value, service, main)

    def observe(self, expected=None, *, birth_nonce=None):
        self.recheck_container()
        pidfile = self.open('dnlab-dnsmasq.pid', parent=self.run_dir)
        info = os.fstat(pidfile); pid_text = os.read(pidfile, 128).decode().strip()
        if not stat.S_ISREG(info.st_mode) or not pid_text.isdecimal() or int(pid_text) <= 1:
            raise JumphostError('invalid DHCP PID file')
        candidates = []
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal(): continue
            try:
                scope = os.stat(path / 'ns/pid')
                if {'device': scope.st_dev, 'inode': scope.st_ino} != self.pid_namespace: continue
                status = (path / 'status').read_text()
                rows = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
                if rows.get('NSpid', '').split()[-1:] == [pid_text]: candidates.append(int(path.name))
            except (FileNotFoundError, ProcessLookupError, PermissionError): continue
        if len(candidates) != 1: raise JumphostError('DHCP host process mapping missing or ambiguous')
        host_pid = candidates[0]; proc = self.open('/proc/' + str(host_pid), directory=True)
        status = dict(line.split(':', 1) for line in self.read('status', proc).splitlines() if ':' in line)
        if status.get('NSpid', '').split()[-1:] != [pid_text]: raise JumphostError('DHCP process mapping changed')
        executable = self.open('exe', parent=proc, nofollow=False)
        binary_dir = self.root_directory(['usr', 'sbin']); binary = self.open('dnsmasq', parent=binary_dir)
        command = self.read('cmdline', proc).rstrip('\0').split('\0')
        if command and os.path.basename(command[0]) == 'dnsmasq': command[0] = 'dnsmasq'
        value = {'container': self.container_proof, 'host_pid': host_pid, 'pid': int(pid_text),
            'start': self.read('stat', proc).rsplit(')', 1)[1].split()[19], 'command': command,
            'uids': list(map(int, status['Uid'].split())), 'gids': list(map(int, status['Gid'].split())),
            'profile': self.credentials(), 'pid_file': file_identity(info),
            'pid_namespace': self.ns(proc, 'pid'), 'net_namespace': self.ns(proc, 'net'),
            'mount_namespace': self.ns(proc, 'mnt'), 'binary': file_identity(os.fstat(binary)),
            'mapped_binary': file_identity(os.fstat(executable))}
        # The process executable and the original container file must be the
        # same inode; pin content as well across retries/recovery.
        value['binary_sha256'] = hash_descriptor(binary)
        nonce = birth_nonce if birth_nonce is not None else self.record.get('dhcp_service_nonce')
        if nonce is not None:
            value['operation_nonce'] = dhcp_validate_birth_nonce(self.read('environ', proc), nonce)
        dhcp_validate_identity(value)
        value['log'] = self.log_identity(value, proc)
        self.recheck_container()
        return dhcp_validate_identity(value, expected)

    def launch_inventory(self, expected):
        """Complete live-daemon inventory in the original PID namespace.

        An old zombie is permitted only with its original process identity.
        Access errors are conflicts, and an executable renamed by a foreign
        process is still recognized by inode/hash, not just its command name.
        """
        dhcp_validate_identity(expected)
        self.recheck_container()
        if self.container_proof != expected['container']:
            raise JumphostError('DHCP launch original container differs')
        binary = self.open('dnsmasq', parent=self.root_directory(['usr','sbin']))
        if (file_identity(os.fstat(binary)) != expected['binary']
                or hash_descriptor(binary) != expected['binary_sha256']):
            raise JumphostError('DHCP launch image executable differs')
        daemons = []
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal(): continue
            try:
                scope = os.stat(path / 'ns/pid')
                if {'device':scope.st_dev,'inode':scope.st_ino} != self.pid_namespace: continue
                proc = self.open(str(path),directory=True)
                status = dict(line.split(':',1) for line in self.read('status',proc).splitlines() if ':' in line)
                local = status.get('NSpid','').split()[-1:]
                if not local: raise JumphostError('DHCP launch namespace inventory incomplete')
                identity = {'host_pid':int(path.name),'pid':int(local[0]),
                    'start':self.read('stat',proc).rsplit(')',1)[1].split()[19]}
                if (identity['host_pid'] == expected['host_pid'] or identity['pid'] == expected['pid']):
                    if any(identity[k] != expected[k] for k in identity):
                        raise JumphostError('DHCP launch original PID replaced')
                if status['State'].strip().startswith('Z'): continue
                executable = self.open('exe',parent=proc,nofollow=False)
                value = file_identity(os.fstat(executable))
                if (self.read('comm',proc).strip() == 'dnsmasq'
                        or (value['device'],value['inode']) == (expected['binary']['device'],expected['binary']['inode'])
                        or hash_descriptor(executable) == expected['binary_sha256']):
                    daemons.append(identity)
            except (FileNotFoundError,ProcessLookupError):
                try:
                    rows = dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
                    if not rows['State'].strip().startswith('Z'):
                        raise JumphostError('DHCP launch live inventory incomplete')
                except (FileNotFoundError,ProcessLookupError): pass
        self.recheck_container()
        return sorted(daemons,key=lambda v:v['host_pid'])

    def observe_launch(self, expected, nonce):
        self.worker.dhcp_preflight(self.record)
        inventory = self.launch_inventory(expected)
        if not inventory:
            if self.shutdown_status(expected) != {'state':'stopped','service':expected,'exit_verified':True}:
                raise JumphostError('DHCP launch absence is not verified')
            return None
        if len(inventory) != 1:
            raise JumphostError('DHCP launch daemon inventory ambiguous')
        value = self.observe(birth_nonce=nonce)
        if (inventory != [{k:value[k] for k in ('host_pid','pid','start')}]
                or self.launch_inventory(expected) != inventory):
            raise JumphostError('DHCP launch daemon inventory changed')
        return value

    def listener_inventory(self, expected, requirements, *, bindings=None):
        proc = self.open('/proc/' + str(expected['host_pid']),directory=True)
        descriptors = self.open('fd',parent=proc,directory=True)
        def socket_inodes():
            result = set()
            for name in os.listdir(descriptors):
                if not name.isdecimal(): continue
                try: target = os.readlink(name,dir_fd=descriptors)
                except FileNotFoundError: continue
                match = re.fullmatch(r'socket:\[([0-9]+)\]',target)
                if match: result.add(int(match[1]))
            return result
        def tables(owned):
            result = []
            for table in sorted({v[0] for v in requirements}):
                lines = self.read('net/' + table,proc).splitlines()
                header = lines[0].split() if lines else []
                if (len(header) < 4 or header[:2] != ['sl','local_address']
                        or header[2] not in ('rem_address','remote_address') or header[3] != 'st'):
                    raise JumphostError('DHCP listener table schema differs')
                width = 32 if table.endswith('6') else 8
                for line in lines[1:]:
                    row = line.split()
                    if len(row) < 10: raise JumphostError('DHCP listener row incomplete')
                    try:
                        inode,uid = int(row[9]),int(row[7])
                        if inode not in owned: continue
                        local,remote = row[1],row[2]
                        if (not re.fullmatch('[0-9A-Fa-f]{'+str(width)+'}:[0-9A-Fa-f]{4}',local)
                                or not re.fullmatch('[0-9A-Fa-f]{'+str(width)+'}:[0-9A-Fa-f]{4}',remote)):
                            raise ValueError()
                        address,port = local.split(':');port = int(port,16)
                        if (table,port) not in requirements: continue
                        if bindings is not None and (table,port,address.lower()) not in bindings:continue
                        if row[3] != ('0A' if table.startswith('tcp') else '07') or int(remote.replace(':',''),16) != 0 or bindings is None and int(address,16) != 0 or uid < 0:
                            raise ValueError()
                        result.append({'table':table,'port':port,'inode':inode,'uid':uid,'address':address.lower()})
                    except ValueError:
                        raise JumphostError('DHCP listener binding differs: ' + canonical({'table':table,'local':row[1],'remote':row[2],'state':row[3],'uid':row[7],'inode':row[9]})) from None
            if set(requirements) != {(v['table'],v['port']) for v in result}:
                raise JumphostError('DHCP listener missing or not owned by original service: ' + canonical({'required':requirements,'observed':result,'process_socket_inodes':sorted(owned)}))
            if bindings is not None and {(v['table'],v['port'],v['address']) for v in result}!=set(bindings):
                raise JumphostError('DNS proxy listener address missing or not owned by original service')
            return sorted(result,key=lambda v:(v['table'],v['port'],v['inode']))
        before = socket_inodes();result = tables(before)
        if socket_inodes() != before or tables(before) != result:
            raise JumphostError('DHCP listener generation changed')
        return result

    def readiness(self, expected):
        """Read-only process/file/attachment/listener proof; not a packet probe."""
        self.worker.dhcp_preflight(self.record)
        self.observe(expected,birth_nonce=expected.get('operation_nonce'))
        files = self.record['dhcp_assets']['files']
        interfaces,requirements = dhcp_listener_requirements(files['main']['content'])
        attachments = [self.record['config']['attachment']] + [
            row['config']['attachment'] for row in self.worker.extension_rows(self.record).values()]
        selected = {row['interface']:row for row in attachments if row['interface'] in interfaces}
        if set(selected) != set(interfaces):
            raise JumphostError('DHCP listener interfaces are not qualified management attachments')
        listeners = self.listener_inventory(expected,requirements)
        bindings = dns_listener_bindings(files['main']['content'])
        dns_listeners = self.listener_inventory(expected,sorted({v[:2] for v in bindings}),bindings=bindings) if bindings else []
        self.worker.dhcp_preflight(self.record)
        self.observe(expected,birth_nonce=expected.get('operation_nonce'))
        if self.listener_inventory(expected,requirements) != listeners:
            raise JumphostError('DHCP listener generation changed during readiness')
        if bindings and self.listener_inventory(expected,sorted({v[:2] for v in bindings}),bindings=bindings)!=dns_listeners:
            raise JumphostError('DNS proxy listener generation changed during readiness')
        return {'level':'dhcp-listeners','service':expected,'interfaces':selected,
            'dns_listeners':dns_listeners,
            'configuration_sha256':{name:hashlib.sha256(row['content'].encode()).hexdigest() for name,row in files.items()},
            'listeners':listeners,'packet_readiness_verified':False}

    def syntax(self, content):
        """Check a complete proposed config before touching live assets/service."""
        if not isinstance(content, str) or not content or '\x00' in content:
            raise JumphostError('complete proposed DHCP configuration required')
        self.recheck_container()
        self.worker.run(['docker', 'exec', '-i', self.container['Id'], 'dnsmasq',
                         '--test', '--conf-file=-'], input=content)
        self.recheck_container()
        return {'syntax_verified': True}

    def shutdown_status(self, expected):
        """Read-only recovery probe for an original persisted stop generation.

        An absent host PID or an original zombie proves exit only alongside a
        complete namespace inventory and unchanged container, files and mounts.
        PID reuse/foreign services remain conflicts; no signal is sent here.
        """
        dhcp_validate_identity(expected)
        self.worker.dhcp_preflight(self.record)
        self.recheck_container()
        if expected['container'] != self.container_proof:
            raise JumphostError('DHCP shutdown original container differs')
        directories = []
        for fd in (self.root, self.run_dir):
            info = os.fstat(fd)
            directories.append(namespace_identity(fd) | {'uid':info.st_uid,'gid':info.st_gid,
                'mode':stat.S_IMODE(info.st_mode),'directory':stat.S_ISDIR(info.st_mode)})
        if directories != expected['log']['directories']:
            raise JumphostError('DHCP shutdown parent directory differs')
        main = self.worker.dhcp_shutdown_main(self.record, expected) if self.record.get('dhcp_structure') else self.record['dhcp_assets']['files']['main']['content']
        if hashlib.sha256(main.encode()).hexdigest() != expected['log']['configuration_sha256']:
            raise JumphostError('DHCP shutdown original configuration differs')
        binary = self.open('dnsmasq', parent=self.root_directory(['usr','sbin']))
        if (file_identity(os.fstat(binary)) != expected['binary']
                or hash_descriptor(binary) != expected['binary_sha256']):
            raise JumphostError('DHCP shutdown image executable differs')
        log = self.open('dnlab-dhcp.log', parent=self.run_dir); info = os.fstat(log)
        if (file_identity(info) | {'nlink':info.st_nlink}) != expected['log']['file']:
            raise JumphostError('DHCP shutdown log generation differs')
        try: pidfile = self.open('dnlab-dnsmasq.pid', parent=self.run_dir)
        except FileNotFoundError: pass
        else:
            info = os.fstat(pidfile)
            if (file_identity(info) != expected['pid_file'] or info.st_nlink != 1
                    or os.read(pidfile,128).decode() != str(expected['pid']) + '\n'):
                raise JumphostError('DHCP shutdown PID file generation differs')
        alive = False
        try: original = self.open('/proc/' + str(expected['host_pid']), directory=True)
        except (FileNotFoundError,ProcessLookupError): original = None
        if original is not None:
            status = dict(line.split(':',1) for line in self.read('status',original).splitlines() if ':' in line)
            if (self.read('stat',original).rsplit(')',1)[1].split()[19] != expected['start']
                    or status.get('NSpid','').split()[-1:] != [str(expected['pid'])]
                    or self.ns(original,'pid') != expected['pid_namespace']):
                raise JumphostError('DHCP shutdown host PID replaced')
            alive = not status['State'].strip().startswith('Z')
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal(): continue
            try:
                scope = os.stat(path / 'ns/pid')
                if {'device':scope.st_dev,'inode':scope.st_ino} != expected['pid_namespace']: continue
                proc = self.open(str(path),directory=True)
                status = dict(line.split(':',1) for line in self.read('status',proc).splitlines() if ':' in line)
                start = self.read('stat',proc).rsplit(')',1)[1].split()[19]
                host = int(path.name); local = status.get('NSpid','').split()[-1:]
                original = host == expected['host_pid'] and local == [str(expected['pid'])] and start == expected['start']
                if (host == expected['host_pid'] or local == [str(expected['pid'])]) and not original:
                    raise JumphostError('DHCP shutdown namespace PID replaced')
                if status['State'].strip().startswith('Z'): continue
                executable = self.open('exe',parent=proc,nofollow=False)
                identity = file_identity(os.fstat(executable))
                daemon = (self.read('comm',proc).strip() == 'dnsmasq'
                          or (identity['device'],identity['inode']) == (expected['binary']['device'],expected['binary']['inode'])
                          or hash_descriptor(executable) == expected['binary_sha256'])
                if daemon and not original:
                    raise JumphostError('foreign DHCP service blocks shutdown recovery')
            except (FileNotFoundError,ProcessLookupError):
                try:
                    rows = dict(line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)
                    if not rows['State'].strip().startswith('Z'):
                        raise JumphostError('DHCP shutdown live inventory incomplete')
                except (FileNotFoundError,ProcessLookupError): pass
        self.recheck_container()
        if alive:
            self.observe(expected)
            return {'state':'running','service':expected}
        return {'state':'stopped','service':expected,'exit_verified':True}

    def stop(self, expected):
        """Graceful, generation-bound stop primitive for a journaled operation.

        Caller persists the structural intent first and records this receipt.
        No force, restart or file write follows a timeout or qualification error.
        """
        if expected is None:
            raise JumphostError('original DHCP process proof required before shutdown')
        self.worker.infrastructure(self.record)
        self.worker.verify_attachment(self.record, self.network_fd)
        self.worker.verify_extensions(self.record)
        value = self.observe(expected)
        fd = os.pidfd_open(value['host_pid']); self.stack.callback(os.close, fd)
        self.observe(expected)
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except ProcessLookupError:
            # An exit between observe and signal is accepted only when the same
            # pinned pidfd confirms it; a name/PID lookup cannot authorize this.
            pass
        poll = select.poll(); poll.register(fd, select.POLLIN)
        events = poll.poll(5000)
        if not any(pidfd == fd and flags & select.POLLIN
                   and not flags & (select.POLLNVAL | select.POLLERR) for pidfd, flags in events):
            raise JumphostError('DHCP shutdown not verified; structural recovery required')
        self.recheck_container()
        return {'service': value, 'exit_verified': True}

    def reload(self, expected, files):
        self.worker.dhcp_preflight(self.record)
        value = self.observe(expected)
        fd = os.pidfd_open(value['host_pid']); self.stack.callback(os.close, fd)
        assets = self.root_directory(['etc', 'dnlab-dhcp'])
        if namespace_identity(assets) != self.record['dhcp_assets']['directory']:
            raise JumphostError('DHCP mount directory identity differs')
        for name, digest in files.items():
            asset = self.open(name, parent=assets)
            actual = hash_descriptor(asset)
            if actual != digest: raise JumphostError('DHCP mounted content differs')
        self.worker.run(['docker', 'exec', self.container['Id'], 'dnsmasq', '--test', '--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf'])
        log = self.open('dnlab-dhcp.log', parent=self.run_dir); info = os.fstat(log)
        if file_identity(info) | {'nlink': info.st_nlink} != value['log']['file']:
            raise JumphostError('DHCP log generation changed')
        offset = info.st_size
        self.worker.dhcp_preflight(self.record)
        self.observe(expected)
        signal.pidfd_send_signal(fd, signal.SIGHUP)
        deadline = time.monotonic() + 5
        while True:
            current = self.open('dnlab-dhcp.log', parent=self.run_dir)
            if (file_identity(os.fstat(current)) | {'nlink': os.fstat(current).st_nlink}) != value['log']['file'] or os.fstat(current).st_size < offset:
                raise JumphostError('DHCP log generation changed')
            lines = os.pread(log, 1024 * 1024, offset).decode(errors='replace')
            if 'read /etc/dnlab-dhcp/hosts' in lines and 'read /etc/dnlab-dhcp/options' in lines: break
            if time.monotonic() >= deadline: raise JumphostError('DHCP reload acknowledgement missing')
            time.sleep(.05)
        self.observe(expected)
        return {'service': value, 'reload_verified': True}



# Executed in the pinned namespace; mutations address kernel indices, never names.
MUTATE_PROGRAM = r"""import ipaddress,json,os,socket,struct,subprocess,sys
p=json.loads(sys.argv[1]);fd=os.stat('/proc/self/ns/net');scope={'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),'device':fd.st_dev,'inode':fd.st_ino}
if scope!=p['context']:raise RuntimeError('mutation namespace differs')
links=json.loads(subprocess.check_output(['ip','-j','-d','link','show']))
for v in links:
 if 'link_index' not in v and 'link' in v:
  other=next((x for x in links if x['ifname']==v['link']),None)
  if other:v['link_index']=other['ifindex']
def sig(v):return {k:v.get(k) for k in ('ifname','ifindex','address','ifalias','link_index')}|{'kind':v.get('linkinfo',{}).get('info_kind')}
def owned(expected):
 v=next((v for v in links if v['ifindex']==expected['ifindex']),None)
 if not v or sig(v)!=expected:raise RuntimeError('kernel identity changed before mutation')
 return v
owned(p['link']);index=p['link']['ifindex']
def attr(kind,data):
 size=4+len(data);return struct.pack('=HH',size,kind)+data+b'\0'*((-size)%4)
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
 sock.bind((0,0));sock.settimeout(10);port=sock.getsockname()[0];seq=int.from_bytes(os.urandom(4),'little') or 1
 op=p['operation'];flags=5;kind=16;change=0;linkflags=0;attrs=b''
 if op=='alias':attrs=attr(20,p['value'].encode()+b'\0')
 elif op=='up':change=1;linkflags=1
 elif op=='master':
  owned(p['value']);attrs=attr(10,struct.pack('=I',p['value']['ifindex']))
 elif op=='address':
  ip=ipaddress.ip_interface(p['value']);kind=20;flags|=0x500
  body=struct.pack('=BBBBI',socket.AF_INET if ip.version==4 else socket.AF_INET6,ip.network.prefixlen,0,0,index)
  attrs=attr(1,ip.ip.packed)+attr(2,ip.ip.packed)
 else:raise RuntimeError('unsupported kernel mutation')
 if kind==16:body=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,linkflags,change)
 body+=attrs;sock.sendto(struct.pack('=IHHII',16+len(body),kind,flags,seq,port)+body,(0,0))
 data,sender=sock.recvfrom(65536)
 if len(data)<20:raise RuntimeError('short kernel ACK')
 length,reply,rflags,rseq,rport=struct.unpack_from('=IHHII',data);error=struct.unpack_from('=i',data,16)[0]
 if sender!=(0,0) or length<20 or length>len(data) or reply!=2 or rseq!=seq or rport!=port or error:raise RuntimeError('kernel mutation not acknowledged: '+str(error))
print('{}')
"""

class Worker:
    def __init__(self, lab, *, directory='/var/lib/dnlab/jumphost', run=execute,
                 host_context=context, open_ns=None, delete_link=None, management_directory='/var/lib/dnlab/management'):
        if not isinstance(lab, str) or not lab: raise JumphostError('lab identity required')
        self.lab, self.directory, self.run, self.host_context = lab, Path(directory), run, host_context
        self.key = digest(['jumphost-v1', lab])
        self.path = self.directory / (self.key + '.json')
        self.management_directory = Path(management_directory)
        self.open_ns = open_ns or (lambda pid: os.open(f'/proc/{pid}/ns/net', os.O_RDONLY))
        self.delete_link = delete_link or self.delete_index

    @contextmanager
    def locked(self):
        d = self.directory
        if d.resolve() != d.absolute(): raise JumphostError('journal directory is a symlink')
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = d.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise JumphostError('journal directory ownership differs')
        fd = os.open(d / 'jumphost.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise JumphostError('journal lock ownership differs')
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise JumphostError('jumphost worker busy') from None
            yield
        finally: os.close(fd)

    def read(self):
        try: fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError: return None
        with os.fdopen(fd) as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
                raise JumphostError('journal ownership differs')
            value = json.load(stream)
        if (value['config']['lab'] != self.lab or value['context'] != self.host_context()
                or not re.fullmatch('[0-9a-f]{32}', value.get('nonce', ''))):
            raise JumphostError('journal lab/context differs')
        validate(value['config'])
        self.extension_rows(value)
        return value

    def extension_rows(self, record):
        rows = record.get('management_attachments', {})
        if not isinstance(rows, dict): raise JumphostError('invalid additional management journal')
        segments = {record['config']['attachment']['segment']}
        peers = {record['config']['attachment']['interface']}
        networks = {record['config']['attachment']['network']}
        bridges = {record['config']['attachment']['bridge']}
        for segment, row in rows.items():
            if not isinstance(row, dict) or not isinstance(row.get('config'), dict):
                raise JumphostError('incomplete additional management attachment')
            config = validate(row['config']); attachment = config['attachment']
            expected = dict(record['config'], attachment=attachment, management_intent=config.get('management_intent'))
            if (config != expected or attachment['segment'] != segment or segment in segments
                    or attachment['interface'] in peers or attachment['network'] in networks or attachment['bridge'] in bridges
                    or row.get('container_id') != record.get('container_id') or row.get('context') != record['context']
                    or row.get('namespace') != record.get('namespace') or row.get('started_at') != record.get('started_at')
                    or row.get('phase') not in ('creating','active','recovery_required','cleaned')):
                raise JumphostError('additional management identity or reservation differs')
            segments.add(segment); peers.add(attachment['interface']); networks.add(attachment['network']); bridges.add(attachment['bridge'])
        return rows

    def verify_extensions(self, record, *, cleanup=False):
        for row in self.extension_rows(record).values():
            worker = AttachmentWorker(self, record, row)
            if cleanup:
                worker.preflight_cleanup(row, bind=True)
            else:
                if row['phase'] != 'active': raise JumphostError('additional management requires explicit recovery')
                worker.infrastructure(row)
                with worker.namespace(row) as fd: worker.verify_attachment(row, fd)

    def extensions_cleaned(self, record):
        for segment, row in self.extension_rows(record).items():
            if (row['phase'] != 'cleaned' or not row.get('cleanup_verified')
                    or self.find(names(self.lab, segment)) is not None):
                raise JumphostError('additional management cleanup pending or endpoint replaced')

    def segment_operation(self, record, action, request):
        if not record or record['phase'] != 'active': raise JumphostError('active original jumphost required')
        fields = {'request_id','container_id','generation','attachment','management_intent'}
        if (not isinstance(request, dict) or set(request) != fields
                or not isinstance(request['request_id'], str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', request['request_id'])
                or request['container_id'] != record.get('container_id') or request['generation'] != record['config']['generation']):
            raise JumphostError('additional management request parent identity differs')
        config = validate(dict(record['config'], attachment=request['attachment'], management_intent=request['management_intent']))
        segment = config['attachment']['segment']
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', segment): raise JumphostError('invalid additional management segment')
        self.infrastructure(record)
        with self.namespace(record) as fd: self.verify_attachment(record, fd)
        rows = self.extension_rows(record); row = rows.get(segment)
        if segment == record['config']['attachment']['segment']: raise JumphostError('default attachment cannot be replaced')
        if any(value['request']['request_id'] == request['request_id'] and key != segment for key,value in rows.items()):
            raise JumphostError('additional management request already used')
        for key,value in rows.items():
            if key == segment: continue
            if value['phase'] != 'active': raise JumphostError('another management attachment requires recovery')
            existing = AttachmentWorker(self, record, value)
            existing.infrastructure(value)
            with existing.namespace(value) as fd: existing.verify_attachment(value, fd)
        if row:
            if row['request'] != request: raise JumphostError('additional management request/configuration changed')
            if row['phase'] == 'active':
                worker = AttachmentWorker(self, record, row); worker.infrastructure(row)
                with worker.namespace(row) as fd: worker.verify_attachment(row, fd)
                return record
            if row['phase'] == 'cleaned': raise JumphostError('cleaned attachment cannot be implicitly restarted')
            if action != 'segment-recover': raise JumphostError('explicit additional management recovery required')
        elif action == 'segment-recover': raise JumphostError('original additional management intent missing')
        else:
            selected = config['attachment']
            for attachment in [record['config']['attachment'], *[v['config']['attachment'] for v in rows.values()]]:
                if any(selected[k] == attachment[k] for k in ('interface','network','bridge')):
                    raise JumphostError('additional management port/network reservation conflict')
                for field in ('ipv4','ipv6'):
                    if selected[field] and attachment[field] and ipaddress.ip_interface(selected[field]).network.overlaps(ipaddress.ip_interface(attachment[field]).network):
                        raise JumphostError('additional management subnets overlap')
            bridge = self.find(selected['bridge'])
            management = self.management_network(config)
            if not bridge or bridge.get('linkinfo',{}).get('info_kind') != 'bridge': raise JumphostError('additional management bridge missing')
            with self.namespace(record) as fd:
                if self.find(names(self.lab,segment)) or self.find(selected['interface'],fd):
                    raise JumphostError('additional management endpoint name occupied')
            nonce = uuid.uuid4().hex
            raw = bytearray(bytes.fromhex(digest([nonce,'peer'])[:12])); raw[0] = (raw[0] & 0xfc) | 2
            row = {'request':json.loads(canonical(request)), 'config':config, 'context':record['context'],
                   'container_id':record['container_id'], 'namespace':record['namespace'], 'started_at':record['started_at'],
                   'nonce':nonce, 'alias':'dnlab-jumphost-attachment:'+nonce, 'host_mac':bridge['address'],
                   'peer_mac':':'.join(f'{v:02x}' for v in raw), 'bridge':signature(bridge), 'management_network':management,
                   'phase':'creating', 'step':'intent'}
            record.setdefault('management_attachments',{})[segment] = row
            self.extension_rows(record); self.save(record)
        worker = AttachmentWorker(self,record,row)
        try:
            worker.attach(row); row.update(phase='active',step='verified'); worker.save(row)
        except Exception as error:
            row.update(phase='recovery_required',error_type=type(error).__name__); worker.save(row); raise
        return record

    def save(self, record):
        fd, temporary = tempfile.mkstemp(dir=self.directory, prefix='.jumphost-')
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(canonical(record)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            fd = os.open(self.directory, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def containers(self):
        values = []
        for line in self.run(['docker', 'ps', '-a', '--no-trunc', '--format', '{{json .}}']).splitlines():
            value = json.loads(line)
            if not re.fullmatch('[0-9a-f]{64}', value.get('ID', '')):
                raise JumphostError('invalid container inventory')
            values.append(value)
        return values

    def container(self, record, *, bind=False):
        matches = [v for v in self.containers() if v.get('Names') == record['config']['name']]
        cid = record.get('container_id')
        if not cid:
            candidates = self.run(['docker', 'ps', '-a', '--no-trunc', '--filter', 'label=org.dnlab.jumphost.nonce=' + record['nonce'], '--format', '{{.ID}}']).split()
            if candidates and (len(candidates) != 1 or len(matches) != 1 or matches[0]['ID'] != candidates[0]):
                raise JumphostError('ambiguous or renamed pending jumphost birth')
        if len(matches) > 1: raise JumphostError('ambiguous jumphost name')
        if not matches:
            # Inspect the recorded ID as well, so a rename cannot masquerade as absence.
            if cid and any(v['ID'] == cid for v in self.containers()):
                raise JumphostError('recorded jumphost was renamed')
            return None
        if cid and matches[0]['ID'] != cid: raise JumphostError('jumphost generation replaced')
        values = json.loads(self.run(['docker', 'inspect', matches[0]['ID']]))
        if not isinstance(values, list) or len(values) != 1: raise JumphostError('invalid container inspection')
        value = values[0]
        if value.get('Id') != matches[0]['ID'] or value.get('Name') != '/' + record['config']['name']:
            raise JumphostError('jumphost identity changed')
        self.verify_container(record, value)
        if not cid:
            if not bind: raise JumphostError('unbound jumphost requires explicit recovery')
            record['container_id'] = value['Id']; self.save(record)
        return value

    def labels(self, record):
        return {'org.dnlab.jumphost.scope': self.key, 'org.dnlab.jumphost.nonce': record['nonce'],
                'org.dnlab.jumphost.config': digest(record['config'])}

    def verify_container(self, record, value):
        c = record['config']; cfg = value.get('Config', {}); host = value.get('HostConfig', {})
        image = record['image']; original = image.get('Config', {})
        expected_env = dict(item.split('=', 1) for item in original.get('Env') or [])
        expected_env.update(c['env'])
        actual_env = cfg.get('Env') or []
        labels = dict(original.get('Labels') or {}); labels.update(self.labels(record))
        ports = {'22/tcp': [{'HostIp': c['bind_ip'], 'HostPort': str(c['port'])}]}
        if (value.get('Image') != image['Id'] or cfg.get('Image') != image['Id']
                or cfg.get('Labels') != labels or len(actual_env) != len(expected_env)
                or dict(item.split('=', 1) for item in actual_env) != expected_env
                or cfg.get('Entrypoint') != original.get('Entrypoint') or cfg.get('Cmd') != original.get('Cmd')
                or host.get('NetworkMode') != record['network']['Id'] or host.get('Privileged') is not False
                or set(host.get('CapAdd') or []) not in ({'NET_ADMIN', 'NET_RAW'}, {'CAP_NET_ADMIN', 'CAP_NET_RAW'})
                or not same_bind_mounts(host.get('Binds') or [], self.binds(record)) or (host.get('Dns') or []) != c['dns']
                or host.get('PortBindings') != ports or host.get('RestartPolicy', {}).get('Name') != 'no'
                or host.get('PidMode', '') != '' or host.get('IpcMode') != 'private'
                or host.get('Sysctls') != {'net.ipv4.ip_forward': '1', 'net.ipv6.conf.all.forwarding': '1'}):
            raise JumphostError('jumphost ownership/configuration differs')
        networks = value.get('NetworkSettings', {}).get('Networks', {})
        if set(networks) != {c['network']['name']}: raise JumphostError('jumphost networks differ')
        endpoint = networks[c['network']['name']]
        if endpoint.get('IPAMConfig', {}).get('IPv4Address') != c['ip']:
            raise JumphostError('jumphost requested address differs')
        if value.get('State', {}).get('Running'):
            if endpoint.get('NetworkID') != record['network']['Id'] or endpoint.get('IPAddress') != c['ip']:
                raise JumphostError('jumphost endpoint differs')

    def links(self, fd=None):
        argv = ['ip', '-j', '-d', 'link', 'show']
        values = json.loads(self.run(argv if fd is None else ['nsenter', '--net=/proc/self/fd/' + str(fd)] + argv,
                                     **({} if fd is None else {'pass_fds': (fd,)})))
        for value in values:
            if 'link_index' not in value and 'link' in value:
                peer = next((v for v in values if v.get('ifname') == value['link']), None)
                if peer: value['link_index'] = peer['ifindex']
        return values

    def find(self, name, fd=None):
        matches = [v for v in self.links(fd) if v.get('ifname') == name]
        if len(matches) > 1: raise JumphostError('ambiguous kernel interface')
        return matches[0] if matches else None

    def network(self, config):
        values = json.loads(self.run(['docker', 'network', 'inspect', config['network']['name']]))
        if len(values) != 1: raise JumphostError('invalid shared network inspection')
        value = values[0]; expected = config['network']
        if (not re.fullmatch('[0-9a-f]{64}', value.get('Id', '')) or value.get('Name') != expected['name']
                or value.get('Driver') != 'bridge' or value.get('Options', {}).get('com.docker.network.bridge.name') != expected['bridge']
                or value.get('IPAM', {}).get('Config') != [{'Subnet': expected['subnet'], 'Gateway': expected['gateway']}]):
            raise JumphostError('shared jumphost network differs')
        return {key: value.get(key) for key in ('Id', 'Name', 'Driver', 'Options', 'IPAM', 'Labels', 'Internal', 'EnableIPv6')}

    def bridge(self, record):
        value = self.find(record['config']['attachment']['bridge'])
        if not value or signature(value) != record['bridge'] or value['linkinfo'].get('info_kind') != 'bridge':
            raise JumphostError('management bridge identity changed')
        return value

    @contextmanager
    def management_origin(self):
        directory = self.management_directory
        if directory.resolve() != directory.absolute(): raise JumphostError('management origin path is a symlink')
        try: info = directory.stat()
        except FileNotFoundError: raise JumphostError('management origin journal required; refusing adoption') from None
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise JumphostError('management origin directory ownership differs')
        lock = os.open(directory / '.lock', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                raise JumphostError('management origin lock ownership differs')
            try: fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError: raise JumphostError('management origin operation busy') from None
            path = directory / (digest(['management-host-v1', self.lab]) + '.json')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise JumphostError('management origin record ownership differs')
                origin = json.load(stream)
            if (origin.get('context') != self.host_context() or origin.get('phase') != 'active'
                    or origin.get('plan', {}).get('lab') != self.lab
                    or not re.fullmatch('[0-9a-f]{32}', origin['plan'].get('generation', ''))
                    or origin.get('network_operation', {}).get('phase') != 'done'):
                raise JumphostError('management origin generation or operation not ready')
            yield origin
        finally: os.close(lock)

    def management_network(self, config):
        c = config['attachment']
        with self.management_origin() as origin:
            row = origin.get('networks', {}).get(c['segment']); plan = origin['plan']
            if (not row or row.get('phase') != 'active' or not re.fullmatch('[0-9a-f]{64}', row.get('id') or '')
                    or not re.fullmatch('[0-9a-f]{32}', row.get('nonce', ''))):
                raise JumphostError('management network birth proof not ready')
            expected = row['expected']; segment = plan['segments'].get(c['segment'])
            address4 = ipaddress.ip_interface(c['ipv4'])
            address6 = ipaddress.ip_interface(c['ipv6']) if c['ipv6'] else None
            if (config.get('management_intent', expected) != expected or expected.get('lab') != self.lab
                    or expected.get('network') != c['network'] or expected.get('bridge') != c['bridge']
                    or expected.get('vrf') != plan['vrf'] or expected.get('driver') != 'dnlab-vrf'
                    or expected.get('ipam_driver') != 'dnlab-vrf' or not segment or segment['bridge'] != c['bridge']
                    or expected.get('ipv4_subnet') != str(address4.network)
                    or bool(expected.get('ipv6_subnet')) != bool(address6)
                    or address6 and (expected['ipv6_subnet'] != str(address6.network)
                                     or expected.get('ipv6_gateway') != str(address6.ip))
                    or str(ipaddress.ip_interface(segment['address']).ip) != expected.get('ipv4_gateway')
                    or str(ipaddress.ip_interface(segment['address']).network) != str(address4.network)):
                raise JumphostError('management attachment differs from origin intent')
            values = json.loads(self.run(['docker', 'network', 'inspect', row['id']]))
            named = json.loads(self.run(['docker', 'network', 'inspect', c['network']]))
            stable = ('Id','Name','Driver','Options','IPAM','Labels','Internal','EnableIPv6')
            if (len(values) != 1 or len(named) != 1
                    or any(values[0].get(k) != named[0].get(k) for k in stable)):
                raise JumphostError('management network name/ID inspection differs')
            value = values[0]
            options = value.get('Options') or {}; options = options.get('com.docker.network.generic', options)
            labels = dict(expected['labels'], **{'org.dnlab.management.creator':row['nonce']})
            configs = [{'Subnet':expected['ipv4_subnet'], 'Gateway':expected['ipv4_gateway']}]
            if address6: configs.append({'Subnet':expected['ipv6_subnet'], 'Gateway':expected['ipv6_gateway']})
            ipam = {'Driver':'dnlab-vrf', 'Options':{'dnlab.tenant':expected['network'],
                'dnlab.reserved':','.join(expected['reserved']), 'dnlab.host-index':str(expected['host_index']),
                'dnlab.host-count':str(expected['host_count'])}, 'Config':configs}
            if (value.get('Id') != row['id'] or value.get('Name') != expected['network']
                    or value.get('Driver') != 'dnlab-vrf' or value.get('Labels') != labels
                    or options != {'dnlab.lab':self.lab, 'dnlab.bridge':c['bridge'], 'dnlab.vrf':expected['vrf']}
                    or value.get('IPAM') != ipam or value.get('EnableIPv6') is not bool(address6)
                    or value.get('Internal') is not False):
                raise JumphostError('management network identity/IPAM/configuration differs')
            bridge = self.find(c['bridge']); vrf = self.find(expected['vrf'])
            def kernel_proof(actual, name, kind):
                proof = origin.get('resources', {}).get(name, {})
                observed = {k:actual.get(k) for k in ('ifname','ifindex','address','ifalias')} | {'kind':actual.get('linkinfo',{}).get('info_kind')} if actual else None
                if (not actual or proof.get('phase') != 'active' or proof.get('identity') != observed
                        or observed['kind'] != kind): raise JumphostError('management kernel origin identity differs')
                return observed
            bridge_proof = kernel_proof(bridge, c['bridge'], 'bridge')
            vrf_proof = kernel_proof(vrf, expected['vrf'], 'vrf')
            if (bridge.get('master') not in (vrf['ifname'], vrf['ifindex'])
                    or vrf.get('linkinfo', {}).get('info_data', {}).get('table') != plan['table']):
                raise JumphostError('management bridge/VRF origin differs')
            snapshot = {key:value.get(key) for key in ('Id','Name','Driver','Options','IPAM','Labels','Internal','EnableIPv6')}
            return {'network':snapshot, 'vrf':signature(vrf), 'vrf_data':vrf.get('linkinfo',{}).get('info_data'),
                    'origin':{'generation':plan['generation'], 'network_nonce':row['nonce'],
                              'expected':expected, 'bridge':bridge_proof, 'vrf':vrf_proof}}

    def infrastructure(self, record):
        if record['context'] != self.host_context(): raise JumphostError('host identity changed')
        if self.network(record['config']) != record['network']: raise JumphostError('shared network generation changed')
        self.bridge(record)
        if record.get('container_id') and record['config']['dhcp']:
            self.verify_asset(record)
        if self.management_network(record['config']) != record['management_network']:
            raise JumphostError('management network generation changed')

    @contextmanager
    def namespace(self, record, *, capture=False):
        value = self.container(record)
        state = value.get('State', {}) if value else {}
        if state.get('Running') is not True or type(state.get('Pid')) is not int or state['Pid'] <= 0:
            raise JumphostError('jumphost is not running')
        fd = self.open_ns(state['Pid'])
        try:
            info = os.fstat(fd); identity = {'device': info.st_dev, 'inode': info.st_ino}
            current = self.container(record)
            if not current or current['State']['Pid'] != state['Pid'] or current['State']['StartedAt'] != state['StartedAt']:
                raise JumphostError('jumphost process changed')
            if record.get('namespace') and (record['namespace'] != identity or record['started_at'] != state['StartedAt']):
                raise JumphostError('jumphost namespace generation changed')
            if not record.get('namespace'):
                if not capture: raise JumphostError('namespace proof missing; explicit recovery required')
                record['namespace'] = identity; record['started_at'] = state['StartedAt']; self.save(record)
            yield fd
        finally: os.close(fd)

    def endpoint(self, record, fd, *, absent=False, capture=False):
        c = record['config']['attachment']; host = self.find(names(self.lab, c['segment'])); peer = self.find(c['interface'], fd)
        if host is None and peer is None:
            if absent: return None
            raise JumphostError('management attachment absent')
        if not host or not peer: raise JumphostError('partial or replaced management veth')
        qualifying = record.get('qualifying') is True or (record['step'] == 'veth_create' and not record.get('host'))
        for value, side in ((host, 'host'), (peer, 'peer')):
            alias_ok = value.get('ifalias') == record['alias'] or qualifying and not value.get('ifalias')
            if (not alias_ok or value.get('address') != record[side + '_mac']
                    or value.get('linkinfo', {}).get('info_kind') != 'veth'):
                raise JumphostError('unqualified management veth')
            if record.get(side):
                actual, expected = signature(value), dict(record[side])
                if qualifying: actual.pop('ifalias'); expected.pop('ifalias')
                if actual != expected: raise JumphostError('management veth identity changed')
        if host.get('link_index') != peer.get('ifindex') or peer.get('link_index') != host.get('ifindex'):
            raise JumphostError('management peer differs')
        if host.get('master') not in (None, c['bridge'], record['bridge']['ifindex']):
            raise JumphostError('management endpoint belongs to another bridge')
        if capture:
            record['qualifying'] = qualifying
            record['host'], record['peer'] = signature(host), signature(peer); self.save(record)
        elif not record.get('host'): raise JumphostError('unrecorded attachment requires recovery')
        return host

    def preflight_new(self, config):
        if any(v['Names'] == config['name'] for v in self.containers()):
            raise JumphostError('unqualified existing jumphost; refusing replacement')
        legacy = ''.join(ch for ch in self.lab if ch.isalnum())[:8] or 'lab'
        for name in (names(self.lab, config['attachment']['segment']), 'jh-' + legacy, 'jhc-' + legacy):
            if self.find(name): raise JumphostError('management endpoint name occupied; explicit recovery required')
        bridge = self.find(config['attachment']['bridge'])
        if not bridge or bridge.get('linkinfo', {}).get('info_kind') != 'bridge':
            raise JumphostError('management bridge missing or invalid')
        if not re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', bridge.get('address', '')) or int(bridge['address'][:2], 16) & 1 or bridge['address'] == '00:00:00:00:00:00':
            raise JumphostError('qualified unicast bridge MAC required')
        return signature(bridge)

    def dhcp_directory(self, record):
        return self.directory / (self.key + '-' + record['nonce'] + '.dhcp')

    @staticmethod
    def asset_identity(path, directory=False):
        info = path.lstat()
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o755 if directory else 0o644)
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
            raise JumphostError('DHCP asset ownership differs')
        return {'device': info.st_dev, 'inode': info.st_ino}

    def dhcp_verify(self, record):
        if record.get('dhcp_structural_operation'):
            self.dhcp_structural_validate(record)
        if record.get('dhcp_structure'):
            self.dhcp_structure_assets(record).verify()
            return
        directory = self.dhcp_directory(record); proofs = record.get('dhcp_assets') or {}
        if not proofs.get('directory') or self.asset_identity(directory, True) != proofs['directory']:
            raise JumphostError('DHCP directory generation differs')
        operation = record.get('dhcp_operation') or {}
        allowed = {'main', 'hosts', 'options'} | {v['temporary'] for v in operation.get('writes', {}).values() if v.get('temporary')}
        if {p.name for p in directory.iterdir()} - allowed: raise JumphostError('unqualified DHCP directory contents')
        if record.get('container_id') and set(proofs.get('files', {})) != {'main', 'hosts', 'options'}:
            raise JumphostError('incomplete DHCP asset proof')
        for key in ('main', 'hosts', 'options'):
            path = directory / key
            if path.exists() and key not in proofs.get('files', {}) and key not in operation.get('writes', {}):
                raise JumphostError('unqualified DHCP target file')
        for key, proof in proofs.get('files', {}).items():
            path = directory / key; actual = self.asset_identity(path)
            if actual == proof['identity'] and path.read_text() == proof['content']: continue
            write = operation.get('writes', {}).get(key, {})
            if actual != write.get('identity') or not write.get('synced') or path.read_text() != operation['files'][key]:
                raise JumphostError('DHCP asset identity/content differs')

    @staticmethod
    def dhcp_structural_binding(record, op):
        return digest({'request':op['request'],'original_service':op['original_service'],
            'previous':op['previous'],'birth_nonce':record['nonce'],'config':digest(record['config'])})

    def dhcp_structural_validate(self, record):
        """Validate a private enclosing operation without authorizing mutations."""
        try:
            op = record['dhcp_structural_operation']; request = op['request']; service = op['original_service']
            container = service['container']; dhcp_validate_identity(service)
            if (record['action'] != 'dhcp-structure'
                    or record['phase'] not in ('dhcp_structure_pending','recovery_required')
                    or op['phase'] not in ('stopping','writing','launching','service-ready')
                    or set(request) != {'container','generation','request_id','content'}
                    or request['container'] != record['config']['name']
                    or request['generation'] != record['config']['generation']
                    or not re.fullmatch('[0-9a-f]{32}',request['request_id'])
                    or op['fingerprint'] != self.dhcp_structural_binding(record,op)
                    or container['id'] != record['container_id'] or container['image'] != record['image']['Id']
                    or container['started_at'] != record['started_at'] or container['host'] != record['context']
                    or container['net_namespace'] != record['namespace']
                    or set(op['previous']) != set(JournaledDHCPAssets.NAMES)
                    or op['stop']['id'] != request['request_id'] or op['stop']['service'] != service):
                raise ValueError()
            JournaledDHCPStop(op['stop'],lambda:None,lambda expected:None,lambda expected:None)
            if op['phase'] != 'stopping' and op['stop']['phase'] != 'stopped': raise ValueError()
            child = record.get('dhcp_structure')
            if op['phase'] == 'stopping':
                if child or record['dhcp_assets']['files'] != op['previous']: raise ValueError()
            elif child:
                if (child['request'] != request or child['previous'] != op['previous']
                        or child['receipt'] != op['stop']['receipt']): raise ValueError()
            elif op['phase'] != 'writing': raise ValueError()
            launch = op['launch']
            if op['phase'] in ('stopping','writing'):
                if launch is not None: raise ValueError()
            else:
                if (launch['nonce'] != digest([request['request_id'],'dhcp-launch'])[:32]
                        or launch['container'] != container or child['assets']['phase'] != 'ready'):
                    raise ValueError()
                self.dhcp_structure_cleanup_preflight(record)
                if op['phase'] == 'service-ready' and (launch['phase'] != 'ready' or op['service'] != launch['service']):
                    raise ValueError()
            return op
        except (KeyError,TypeError,ValueError,AttributeError):
            raise JumphostError('original structural DHCP lifecycle binding required') from None

    def begin_dhcp_structural_operation(self, record, request):
        """Private admission, caller holds lock/offline fence through readiness.

        The entire desired operation is durable before TERM. This does not
        expose a CLI action or release the coordinator's workload barrier.
        """
        if (record.get('phase') != 'active' or record.get('dhcp_layout') != 2
                or record.get('dhcp_operation') or record.get('dhcp_structure')
                or record.get('dhcp_structural_operation')):
            raise JumphostError('active DHCP generation required for structural admission')
        if (set(request) != {'container','generation','request_id','content'}
                or request['container'] != record['config']['name']
                or request['generation'] != record['config']['generation']
                or not isinstance(request['request_id'],str)
                or not re.fullmatch('[0-9a-f]{32}',request['request_id'])):
            raise JumphostError('original structural DHCP request required')
        if any(value['request']['request_id'] == request['request_id'] for value in record.get('dhcp_structural_history',[])):
            raise JumphostError('structural DHCP request already finalized; verify original finalization')
        files = dhcp_files(request['content'])
        interfaces,_ = dhcp_listener_requirements(files['main'])
        attachments = [record['config']['attachment']] + [row['config']['attachment'] for row in self.extension_rows(record).values()]
        if not set(interfaces) <= {row['interface'] for row in attachments}:
            raise JumphostError('structural DHCP target interface is not a qualified management attachment')
        for value in files.values():
            if len(value.encode()) > JournaledDHCPMain.LIMIT:
                raise JumphostError('structural DHCP target too large')
        self.dhcp_preflight(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:
                if service.syntax(request['content']) != {'syntax_verified':True}:
                    raise JumphostError('structural DHCP syntax not verified')
                original = service.observe(record.get('dhcp_expected_service'))
        op = json.loads(canonical({'request':request,'original_service':original,
            'previous':record['dhcp_assets']['files'],'phase':'stopping','launch':None,'service':None,
            'stop':{'id':request['request_id'],'service':original,'phase':'intent','attempted':False,'receipt':None}}))
        op['fingerprint'] = self.dhcp_structural_binding(record,op)
        record.update(dhcp_structural_operation=op,action='dhcp-structure',phase='dhcp_structure_pending')
        self.dhcp_structural_validate(record); self.save(record)

    def dhcp_structural_probe(self, record, expected):
        self.dhcp_structural_validate(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:return service.shutdown_status(expected)

    def dhcp_structural_stop(self, record, expected):
        op = self.dhcp_structural_validate(record)
        if op['phase'] != 'stopping' or op['stop']['service'] != expected or not op['stop']['attempted']:
            raise JumphostError('persisted structural DHCP stop intent required')
        self.dhcp_preflight(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:return service.stop(expected)

    def dhcp_structural_exec_preflight(self, record):
        op = self.dhcp_structural_validate(record)
        if op['phase'] not in ('launching','service-ready'):
            raise JumphostError('persisted structural DHCP launch intent required')
        self.dhcp_preflight(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:
                if service.container_proof != op['original_service']['container']:
                    raise JumphostError('structural DHCP launch container differs')
        value = self.container(record)
        return {'container':op['original_service']['container'],'exec_ids':value.get('ExecIDs') or []}

    def dhcp_structural_observe_launch(self, record):
        op = self.dhcp_structural_validate(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:
                return service.observe_launch(op['original_service'],op['launch']['nonce'])

    def resume_dhcp_structural_operation(self, record, *, docker=None):
        """Resume original phases; service-ready retains the offline fence."""
        op = self.dhcp_structural_validate(record)
        if op['phase'] == 'stopping':
            JournaledDHCPStop(op['stop'],lambda:self.save(record),
                lambda expected:self.dhcp_structural_probe(record,expected),
                lambda expected:self.dhcp_structural_stop(record,expected)).run()
            op['phase'] = 'writing'; self.save(record)
        if op['phase'] == 'writing':
            if not record.get('dhcp_structure'):
                self.begin_dhcp_structure_assets(record,op['request'],op['stop']['receipt'])
            self.write_dhcp_structure_assets(record)
            nonce = digest([op['request']['request_id'],'dhcp-launch'])[:32]
            op['launch'] = {'nonce':nonce,'container':op['original_service']['container'],'phase':'intent',
                'exec_id':None,'create_attempts':0,'start_attempted':False,'observed_exec_ids':[],'service':None}
            op['phase'] = 'launching'; self.save(record)
        service = JournaledDHCPExec(op['launch'],lambda:self.save(record),
            lambda:self.dhcp_structural_exec_preflight(record),
            lambda:self.dhcp_structural_observe_launch(record),docker=docker).run()
        dhcp_validate_identity(service)
        if op['phase'] != 'service-ready':
            op['service'] = service; op['phase'] = 'service-ready'; self.save(record)
        return service

    def finalize_dhcp_structural_operation(self, record, request):
        """Commit a listener-qualified helper, never release the lab fence.

        The coordinator still owns all-host readiness and workload admission.
        Explicit retry verifies the same committed service without launching.
        """
        op = record.get('dhcp_structural_operation')
        replay = op is None
        if replay:
            matches = [value for value in record.get('dhcp_structural_history',[])
                       if value['request']['request_id'] == request.get('request_id')]
            if len(matches) != 1 or record['phase'] != 'active':
                raise JumphostError('original structural DHCP finalization intent required')
            op = matches[0]
            if record.get('dhcp_expected_service') != op.get('service'):
                raise JumphostError('structural DHCP finalization generation superseded')
        else:
            self.dhcp_structural_validate(record)
        if op['request'] != request or op['phase'] != 'service-ready':
            raise JumphostError('structural DHCP finalization request/phase differs')
        files = dhcp_files(request['content'])
        if files != {name:row['content'] for name,row in record['dhcp_assets']['files'].items()}:
            raise JumphostError('structural DHCP finalization assets superseded')
        self.dhcp_preflight(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:proof = service.readiness(op['service'])
        interfaces,requirements = dhcp_listener_requirements(files['main'])
        if (not isinstance(proof,dict) or proof.get('level') != 'dhcp-listeners'
                or proof.get('service') != op['service']
                or proof.get('configuration_sha256') != {name:hashlib.sha256(value.encode()).hexdigest() for name,value in files.items()}
                or set(proof.get('interfaces',{})) != set(interfaces)
                or {(v.get('table'),v.get('port')) for v in proof.get('listeners',[])} != set(requirements)
                or proof.get('packet_readiness_verified') is not False):
            raise JumphostError('complete original DHCP listener readiness required')
        if replay:
            if proof != op.get('readiness'):
                raise JumphostError('structural DHCP committed readiness differs')
            return proof
        op['readiness'] = proof
        record.setdefault('dhcp_structural_history',[]).append(record.pop('dhcp_structural_operation'))
        record.setdefault('dhcp_structure_history',[]).append(record.pop('dhcp_structure'))
        record.update(dhcp_expected_service=op['service'],dhcp_service_nonce=op['launch']['nonce'],
                      dhcp_current=files,phase='active',action='ensure')
        self.save(record)
        return proof

    @staticmethod
    def dhcp_structure_binding(record, op):
        return digest({'request':op['request'],'container':op['container'],'receipt':op['receipt'],
            'previous':op['previous'],'birth_nonce':record['nonce'],'config':digest(record['config'])})

    def dhcp_structure_assets(self, record):
        """Read-only qualification of an owned writing stage, never admission.

        Caller must hold the worker lock and the enclosing offline fence. This
        private stage does not stop/start a service or release that fence.
        """
        try:
            op = record['dhcp_structure']; request = op['request']; receipt = op['receipt']
            if (record['action'] != 'dhcp-structure'
                    or record['phase'] not in ('dhcp_structure_pending','recovery_required')
                    or op['phase'] != 'writing' or record.get('dhcp_operation')
                    or set(request) != {'container','generation','request_id','content'}
                    or request['container'] != record['config']['name']
                    or request['generation'] != record['config']['generation']
                    or not re.fullmatch('[0-9a-f]{32}', request['request_id'])
                    or op['fingerprint'] != self.dhcp_structure_binding(record,op)
                    or set(receipt) != {'service','exit_verified'} or receipt['exit_verified'] is not True):
                raise ValueError()
            service = dhcp_validate_identity(receipt['service']); container = op['container']
            if (service['container'] != container or container['id'] != record['container_id']
                    or container['image'] != record['image']['Id']
                    or container['started_at'] != record['started_at'] or container['host'] != record['context']
                    or container['net_namespace'] != record['namespace']):
                raise ValueError()
            assets = op['assets']; previous = op['previous']; desired = dhcp_files(request['content'])
            if (assets['id'] != request['request_id'] or assets['container'] != container
                    or assets['service_exit'] != receipt
                    or {k:assets['directory'][k] for k in ('device','inode')} != record['dhcp_assets']['directory']
                    or set(previous) != set(JournaledDHCPAssets.NAMES)):
                raise ValueError()
            committed = {}
            for name in JournaledDHCPAssets.NAMES:
                child = assets['files'][name]
                identity = {k:child['file'][k] for k in ('device','inode')}
                if (identity != previous[name]['identity'] or child['old'] != previous[name]['content']
                        or child['new'] != desired[name]):
                    raise ValueError()
                committed[name] = {'identity':identity,'content':desired[name]}
            current = record['dhcp_assets']['files']
            if current != previous and not (assets['phase'] == 'ready' and current == committed):
                raise ValueError()
            if hashlib.sha256(previous['main']['content'].encode()).hexdigest() != service['log']['configuration_sha256']:
                raise ValueError()
            return JournaledDHCPAssets(self.dhcp_directory(record),assets,lambda:self.save(record),
                lambda:self.dhcp_structure_closed(record,service))
        except (KeyError,TypeError,ValueError,AttributeError):
            raise JumphostError('original structural DHCP worker binding required') from None

    def dhcp_structure_cleanup_preflight(self, record):
        runner = self.dhcp_structure_assets(record); runner.verify()
        committed = {name:{'identity':{k:child['file'][k] for k in ('device','inode')},
            'content':child['new']} for name,child in runner.intent['files'].items()}
        if runner.intent['phase'] != 'ready' or record['dhcp_assets']['files'] != committed:
            raise JumphostError('structural DHCP asset recovery required before cleanup')

    def dhcp_shutdown_main(self, record, expected):
        self.dhcp_structure_assets(record).verify()
        op = record['dhcp_structure']
        if op['receipt']['service'] != expected:
            raise JumphostError('structural DHCP original shutdown service differs')
        return op['previous']['main']['content']

    def dhcp_structure_closed(self, record, expected):
        self.dhcp_preflight(record)
        with self.namespace(record) as fd:
            with DHCPHostService(self,record,fd) as service:
                status = service.shutdown_status(expected)
        receipt = {'service':expected,'exit_verified':True}
        if status != {'state':'stopped',**receipt}:
            raise JumphostError('verified original DHCP shutdown required for asset writes')
        return {'container':expected['container'],'service_exit':receipt}

    def begin_dhcp_structure_assets(self, record, request, receipt):
        """Persist the writing sub-intent after the enclosing stop has committed.

        Internal only: lock, offline fence and prior stop intent belong to the
        enclosing operation. No public CLI action admits this incomplete flow.
        """
        parent = record.get('dhcp_structural_operation')
        if parent:
            self.dhcp_structural_validate(record)
            if (parent['phase'] != 'writing' or parent['request'] != request
                    or parent['stop']['receipt'] != receipt):
                raise JumphostError('structural DHCP parent writing intent differs')
        if (record.get('phase') != ('dhcp_structure_pending' if parent else 'active') or record.get('dhcp_layout') != 2
                or record.get('dhcp_structure') or record.get('dhcp_operation')):
            raise JumphostError('active qualified DHCP generation required for structural assets')
        if (set(request) != {'container','generation','request_id','content'}
                or request['container'] != record['config']['name']
                or request['generation'] != record['config']['generation']
                or not isinstance(request['request_id'],str)
                or not re.fullmatch('[0-9a-f]{32}', request['request_id'])
                or set(receipt) != {'service','exit_verified'} or receipt['exit_verified'] is not True):
            raise JumphostError('complete original structural DHCP request/receipt required')
        expected = dhcp_validate_identity(receipt['service'])
        self.dhcp_structure_closed(record,expected)
        # JSON roundtrip snapshots caller-owned dictionaries; later caller edits
        # cannot change the target or original proof after admission.
        op = json.loads(canonical({'request':request,'container':expected['container'],
            'receipt':receipt,'previous':record['dhcp_assets']['files'],'phase':'writing'}))
        op['assets'] = JournaledDHCPAssets.prepare(self.dhcp_directory(record),op['previous'],
            dhcp_files(op['request']['content']),op['container'],op['receipt'],op['request']['request_id'])
        op['fingerprint'] = self.dhcp_structure_binding(record,op)
        record.update(dhcp_structure=op,action='dhcp-structure',phase='dhcp_structure_pending')
        self.dhcp_structure_assets(record).verify()
        self.save(record)

    def write_dhcp_structure_assets(self, record):
        runner = self.dhcp_structure_assets(record)
        committed = runner.run()
        record['dhcp_assets']['files'] = committed
        self.save(record)
        # Remain pending: all files ready does not establish a running service.
        return committed

    @staticmethod
    def sync_asset_directory(directory):
        fd = os.open(directory, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def dhcp_preflight(self, record):
        """Qualify the original container and every management attachment."""
        self.infrastructure(record)
        with self.namespace(record) as fd: self.verify_attachment(record, fd)
        self.verify_extensions(record)

    def dhcp_write(self, record):
        directory = self.dhcp_directory(record); proofs = record['dhcp_assets']; op = record['dhcp_operation']
        if self.asset_identity(directory, True) != proofs['directory']: raise JumphostError('DHCP directory replaced')
        for key, content in op['files'].items():
            # Birth writes precede the container. Live refreshes must qualify
            # every attached L2 again at each write/replace boundary.
            if record.get('action') == 'dhcp': self.dhcp_preflight(record)
            self.dhcp_verify(record)
            old = proofs['files'].get(key); target = directory / key
            if old and old['content'] == content: continue
            write = op['writes'].get(key)
            if write and target.exists() and self.asset_identity(target) == write['identity']:
                if not write.get('synced') or target.read_text() != content: raise JumphostError('DHCP pending replace content differs')
            else:
                temporary = directory / ('.' + key + '-' + op['id'])
                if not write:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                    try: os.fchmod(fd, 0o644)
                    finally: os.close(fd)
                    write = {'temporary': temporary.name, 'identity': self.asset_identity(temporary), 'synced': False}
                    op['writes'][key] = write; self.save(record)
                elif self.asset_identity(temporary) != write['identity']:
                    raise JumphostError('DHCP temporary asset replaced')
                if record.get('action') == 'dhcp': self.dhcp_preflight(record)
                fd = os.open(temporary, os.O_WRONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'w') as stream:
                    info = os.fstat(stream.fileno())
                    if {'device': info.st_dev, 'inode': info.st_ino} != write['identity']: raise JumphostError('DHCP temporary identity changed')
                    stream.truncate(); stream.write(content); stream.flush(); os.fsync(stream.fileno())
                write['synced'] = True; self.save(record)
                if record.get('action') == 'dhcp': self.dhcp_preflight(record)
                os.replace(temporary, target); self.sync_asset_directory(directory)
            proofs['files'][key] = {'identity': write['identity'], 'content': content}; self.save(record)

    def dhcp_service(self, record, action='inspect', expected=None):
        if action == 'reload': self.dhcp_preflight(record)
        with self.namespace(record) as network_fd:
            with DHCPHostService(self, record, network_fd) as service:
                if action == 'inspect': return service.observe(expected or record.get('dhcp_expected_service'))
                if action != 'reload' or expected is None: raise JumphostError('qualified DHCP reload intent required')
                files = {k: hashlib.sha256(v.encode()).hexdigest() for k,v in record['dhcp_operation']['files'].items()}
                return service.reload(expected, files)

    def dhcp_refresh(self, record, request=None):
        if record.get('dhcp_layout') != 2: raise JumphostError('DHCP refresh requires explicit new-generation layout; legacy preserved')
        if request is not None:
            if set(request) != {'container', 'generation', 'content', 'request_id'} or request['container'] != record['config']['name'] or request['generation'] != record['config']['generation']:
                raise JumphostError('DHCP request generation/container differs')
            if not re.fullmatch('[0-9a-f]{32}', request['request_id']): raise JumphostError('DHCP request ID required')
            files = dhcp_files(request['content'])
            self.dhcp_preflight(record)
            if files['main'] != record['dhcp_assets']['files']['main']['content']:
                raise JumphostError('structural DHCP change requires separate operation')
            for previous in record.get('dhcp_history', []):
                if previous['request_id'] == request['request_id']:
                    if previous['files'] != files: raise JumphostError('DHCP request ID content conflict')
                    if record['phase'] != 'active' or record['dhcp_current'] != files: raise JumphostError('historical DHCP request superseded')
                    self.dhcp_preflight(record); self.dhcp_service(record, expected=previous['service']); return record
            if record['phase'] != 'active': raise JumphostError('explicit DHCP recovery required')
            self.dhcp_preflight(record)
            service = self.dhcp_service(record)
            record['dhcp_operation'] = {'id': request['request_id'], 'files': files, 'writes': {}, 'service': service}
            record['phase'] = 'dhcp_pending'; record['action'] = 'dhcp'; self.save(record)
        op = record.get('dhcp_operation')
        if not op: raise JumphostError('DHCP recovery operation missing')
        self.dhcp_preflight(record)
        self.dhcp_service(record, expected=op['service'])
        self.dhcp_write(record)
        self.dhcp_preflight(record)
        self.dhcp_service(record, 'reload', op['service'])
        self.dhcp_preflight(record)
        record['dhcp_current'] = op['files']
        record.setdefault('dhcp_history', []).append({'request_id': op['id'], 'files': op['files'], 'service': op['service']})
        record['dhcp_operation'] = None; record['phase'] = 'active'; record['action'] = 'ensure'; self.save(record)
        return record

    def inventory_preflight(self, record):
        self.infrastructure(record)
        with self.namespace(record) as fd: self.verify_attachment(record, fd)
        self.verify_extensions(record)

    def inventory_exec(self, record, request):
        self.inventory_preflight(record)
        program = globals().get('INVENTORY_PROGRAM')
        if program is None:
            program = (Path(__file__).resolve().parents[2] / 'jumphost/inventory.py').read_text()
        result = self.run(['docker', 'exec', '-i', record['container_id'], 'python3', '-c', program],
                          input=canonical(request))
        self.inventory_preflight(record)
        return json.loads(result)

    def inventory_native_profile(self,record,request):
        if any(':custom:' in row for row in request['relays'].splitlines()):
            labels=record['image'].get('Config',{}).get('Labels') or {}
            if 'qualified-relay-inventory-v1' not in labels.get('io.dnlab.jumphost.capabilities','').split(','):
                raise JumphostError('jumphost image lacks qualified relay inventory capability')

    def inventory_refresh(self, record, request=None):
        if request is not None:
            fields = {'lab','generation','container_id','request_id','vds','relays','motd'}
            if (not isinstance(request, dict) or set(request) != fields
                    or request['lab'] != self.lab or request['generation'] != record['config']['generation']
                    or request['container_id'] != record.get('container_id')
                    or not isinstance(request['request_id'], str) or not re.fullmatch('[0-9a-f]{32}', request['request_id'])
                    or any(not isinstance(request[k], str) or len(request[k].encode()) > 1048576 for k in ('vds','relays','motd'))):
                raise JumphostError('inventory request identity or content differs')
            token = r'[A-Za-z0-9][A-Za-z0-9_.-]*'
            vds = request['vds'].splitlines(); relays = request['relays'].splitlines()
            if (any(not re.fullmatch(token + '=' + token, v) for v in vds)
                    or any(not re.fullmatch(token + '=' + token + r':[0-9]{1,5}:' + token + r'(?::custom:[0-9a-f]{64})?', v) for v in relays)):
                raise JumphostError('invalid inventory mappings')
            vd_rows = [v.split('=',1) for v in vds]; relay_rows = [v.split('=',1) for v in relays]
            if (len({v[0] for v in vd_rows}) != len(vd_rows)
                    or len({v[1] for v in vd_rows}) != len(vd_rows)
                    or len({v[0] for v in relay_rows}) != len(relay_rows)
                    or {v[1] for v in vd_rows} != {v[0] for v in relay_rows}
                    or any(not 1 <= int(v[1].split(':')[1]) <= 65535 for v in relay_rows)):
                raise JumphostError('incomplete or conflicting relay inventory')
            self.inventory_native_profile(record,request)
            if record['phase'] != 'active': raise JumphostError('explicit inventory recovery required')
            for old in record.get('inventory_history', []):
                if old['request_id'] == request['request_id']:
                    if old != request or record.get('inventory_current') != request:
                        raise JumphostError('inventory request superseded or changed')
                    if self.inventory_exec(record, {'action':'inspect'}) != request:
                        raise JumphostError('persistent inventory differs')
                    return record
            previous = record.get('inventory_current')
            if self.inventory_exec(record, {'action':'inspect'}) != previous:
                raise JumphostError('persistent inventory differs')
            record['inventory_operation'] = {'desired':json.loads(canonical(request)), 'previous':previous}
            record['phase'] = 'inventory_pending'; record['action'] = 'inventory'; self.save(record)
        op = record.get('inventory_operation')
        if not op: raise JumphostError('inventory recovery intent missing')
        self.inventory_native_profile(record,op['desired'])
        result = self.inventory_exec(record, {'action':'apply', **op})
        if result != op['desired']: raise JumphostError('inventory publication acknowledgement differs')
        record['inventory_current'] = result
        record.setdefault('inventory_history', []).append(result)
        record['inventory_operation'] = None
        record['phase'] = 'active'; record['action'] = 'ensure'; self.save(record)
        return record

    def binds(self, record):
        if record.get('dhcp_layout') == 2:
            directory = str(self.dhcp_directory(record))
            return record['config']['binds'] + [directory + ':/etc/dnlab-dhcp:ro',
                directory + '/main:/etc/dnsmasq.d/dnlab-mgmt.conf:ro']
        extra = [str(self.directory / (self.key + '-' + record['nonce'] + '.conf')) + ':/etc/dnsmasq.d/dnlab-mgmt.conf:ro'] if record['config']['dhcp'] else []
        return record['config']['binds'] + extra

    def verify_asset(self, record):
        if record.get('dhcp_layout') == 2: self.dhcp_verify(record); return
        path = Path(self.binds(record)[-1].split(':', 1)[0])
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or stream.read() != record['config']['dhcp']:
                raise JumphostError('DHCP asset ownership/content differs')

    def assets(self, record):
        if not record['config']['dhcp']: return
        if record.get('dhcp_layout') == 2:
            directory = self.dhcp_directory(record)
            if not record.get('dhcp_assets'):
                directory.mkdir(mode=0o755); directory.chmod(0o755); self.sync_asset_directory(self.directory)
                record['dhcp_assets'] = {'directory': self.asset_identity(directory, True), 'files': {}}
                record['dhcp_operation'] = {'id': uuid.uuid4().hex, 'files': dhcp_files(record['config']['dhcp']), 'writes': {}}
                self.save(record)
            if record.get('dhcp_operation'): self.dhcp_write(record)
            record['dhcp_current'] = dhcp_files(record['config']['dhcp']); record['dhcp_operation'] = None
            self.save(record); self.dhcp_verify(record); return
        path = Path(self.binds(record)[-1].split(':', 1)[0])
        try: fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or stream.read() != record['config']['dhcp']:
                    raise JumphostError('DHCP asset ownership/content differs')
            return
        with os.fdopen(fd, 'w') as stream:
            stream.write(record['config']['dhcp']); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(self.directory, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def create(self, record):
        if not same_bind_mounts(self.binds(record), self.binds(record)):
            raise JumphostError('ambiguous or invalid jumphost bind destinations')
        c = record['config']; argv = ['docker', 'create', '--name', c['name'], '--network', record['network']['Id'], '--ip', c['ip'],
            '-p', ('[' + c['bind_ip'] + ']' if ':' in c['bind_ip'] else c['bind_ip']) + ':' + str(c['port']) + ':22',
            '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--sysctl', 'net.ipv4.ip_forward=1',
            '--sysctl', 'net.ipv6.conf.all.forwarding=1']
        for key, value in self.labels(record).items(): argv.extend(['--label', key + '=' + value])
        for key, value in c['env'].items(): argv.extend(['-e', key + '=' + value])
        for dns in c['dns']: argv.extend(['--dns', dns])
        for bind in self.binds(record): argv.extend(['-v', bind])
        argv.append(record['image']['Id'])
        self.infrastructure(record); self.preflight_new(c); self.assets(record)
        record['step'] = 'create'; self.save(record)
        cid = self.run(argv).strip()
        if not re.fullmatch('[0-9a-f]{64}', cid): raise JumphostError('invalid create response; recovery required')
        record['container_id'] = cid; self.save(record)
        if not self.container(record): raise JumphostError('created jumphost missing')

    def attach(self, record):
        c = record['config']['attachment']
        self.infrastructure(record)
        with self.namespace(record, capture=True) as fd:
            endpoint = self.endpoint(record, fd, absent=True, capture=True)
            if endpoint is None:
                if record.get('host'): raise JumphostError('recorded management veth disappeared')
                record['step'] = 'veth_create'; record['qualifying'] = True; self.save(record)
                self.infrastructure(record); self.container(record)
                self.run(['ip', 'link', 'add', names(self.lab, c['segment']), 'address', record['host_mac'], 'alias', record['alias'],
                          'type', 'veth', 'peer', 'name', c['interface'], 'address', record['peer_mac'], 'alias', record['alias'],
                          'netns', '/proc/self/fd/' + str(fd)], pass_fds=(fd,))
                self.endpoint(record, fd, capture=True)
            def step(name, side, operation, value=None):
                self.infrastructure(record); self.container(record); self.endpoint(record, fd)
                record['step'] = name; self.save(record)
                scope = record['context'] if side == 'host' else dict(record['namespace'], boot_id=record['context']['boot_id'])
                payload = {'context': scope, 'link': record[side], 'operation': operation, 'value': value}
                argv = ['python3', '-c', MUTATE_PROGRAM, canonical(payload)]
                self.run((['nsenter', '--net=/proc/self/fd/' + str(fd)] if side == 'peer' else []) + argv,
                         **({'pass_fds': (fd,)} if side == 'peer' else {}))
                self.endpoint(record, fd, capture=True)
            if record.get('qualifying'):
                step('alias_host', 'host', 'alias', record['alias'])
                step('alias_peer', 'peer', 'alias', record['alias'])
                record['qualifying'] = False; self.save(record)
                self.endpoint(record, fd)
            step('ipv4', 'peer', 'address', c['ipv4'])
            if c['ipv6']: step('ipv6', 'peer', 'address', c['ipv6'])
            step('bind', 'host', 'master', record['bridge'])
            step('host_up', 'host', 'up')
            step('peer_up', 'peer', 'up')
            self.verify_attachment(record, fd)

    def verify_attachment(self, record, fd):
        host = self.endpoint(record, fd); c = record['config']['attachment']
        if host.get('master') not in (c['bridge'], record['bridge']['ifindex']) or 'UP' not in host.get('flags', []):
            raise JumphostError('management bridge attachment incomplete')
        peer = self.find(c['interface'], fd)
        if 'UP' not in peer.get('flags', []): raise JumphostError('management peer down')
        addresses = json.loads(self.run(['nsenter', '--net=/proc/self/fd/' + str(fd), 'ip', '-j', 'addr', 'show', 'dev', c['interface']], pass_fds=(fd,)))
        actual = {str(v['local']) + '/' + str(v['prefixlen']) for item in addresses for v in item['addr_info']}
        if not {v for v in (c['ipv4'], c['ipv6']) if v} <= actual:
            raise JumphostError('management addresses missing')

    def delete_index(self, expected, scope):
        # Never address a replacement by its reused name. Socket remains in this namespace.
        if self.host_context() != scope: raise JumphostError('host namespace changed')
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
            sock.bind((0, 0)); sock.settimeout(10); port = sock.getsockname()[0]
            value = self.find(expected['ifname'])
            if value is None: return
            if signature(value) != expected: raise JumphostError('management veth replaced before delete')
            seq = int.from_bytes(os.urandom(4), 'little') or 1
            body = struct.pack('=BBHiII', socket.AF_UNSPEC, 0, 0, expected['ifindex'], 0, 0)
            packet = struct.pack('=IHHII', 16 + len(body), 17, 5, seq, port) + body
            sock.sendto(packet, (0, 0)); data, sender = sock.recvfrom(65536)
            if len(data) < 20: raise JumphostError('invalid netlink reply')
            length, kind, flags, got_seq, got_port = struct.unpack_from('=IHHII', data)
            error = struct.unpack_from('=i', data, 16)[0]
            if sender != (0, 0) or length < 20 or length > len(data) or kind != 2 or got_seq != seq or got_port != port or error not in (0, -19):
                raise JumphostError('management veth delete not acknowledged')

    def preflight_cleanup(self, record, *, bind=False):
        self.infrastructure(record)
        value = self.container(record, bind=bind and not record.get('container_id'))
        if value and value.get('State', {}).get('Running'):
            with self.namespace(record, capture=bind) as fd: self.endpoint(record, fd, absent=True, capture=bind)
        host = self.find(names(self.lab, record['config']['attachment']['segment']))
        if host and (not record.get('host') or signature(host) != record['host']):
            raise JumphostError('unqualified or replaced cleanup endpoint')
        self.verify_extensions(record, cleanup=True)
        return value

    def verify_cleaned(self, record):
        """Read-only cleanup qualification; never bind or recover a resource."""
        if record['phase'] != 'cleaned' or not record.get('cleanup_verified'):
            raise JumphostError('jumphost cleanup journal pending')
        if self.container(record) or self.find(names(self.lab, record['config']['attachment']['segment'])):
            raise JumphostError('cleaned jumphost generation replaced')
        self.extensions_cleaned(record)
        if record.get('dhcp_layout') == 2 and self.dhcp_directory(record).exists():
            raise JumphostError('cleaned DHCP assets remain or were replaced')
        return record

    def dhcp_cleanup_assets(self, record, mutate=True):
        directory = self.dhcp_directory(record); proofs = record.get('dhcp_assets')
        if directory.exists():
            if not proofs or self.asset_identity(directory, True) != proofs['directory']:
                raise JumphostError('DHCP cleanup directory differs')
            expected = dict(proofs.get('files', {})); op = record.get('dhcp_operation') or {}
            for key, write in op.get('writes', {}).items():
                if write.get('temporary'):
                    expected[write['temporary']] = {'identity': write['identity'], 'content': op['files'][key] if write.get('synced') else None}
                target = directory / key
                if target.exists() and self.asset_identity(target) == write['identity']:
                    expected[key] = {'identity': write['identity'], 'content': op['files'][key]}
            if {p.name for p in directory.iterdir()} - set(expected): raise JumphostError('unqualified DHCP cleanup file')
            for name, proof in expected.items():
                path = directory / name
                if path.exists() and (self.asset_identity(path) != proof['identity'] or proof['content'] is not None and path.read_text() != proof['content']):
                    raise JumphostError('DHCP cleanup file replaced')
            if not mutate: return
            for name, proof in expected.items():
                path = directory / name
                if path.exists():
                    if self.asset_identity(path) != proof['identity']: raise JumphostError('DHCP cleanup identity changed')
                    path.unlink()
            directory.rmdir(); self.sync_asset_directory(self.directory)
        if mutate:
            record['phase'] = 'cleaned'; record['cleanup_verified'] = True; self.save(record)

    def cleanup(self, record):
        if record.get('dhcp_structural_operation'):
            self.dhcp_structural_validate(record)
        if record.get('dhcp_structure'):
            self.dhcp_structure_cleanup_preflight(record)
        if record.get('step') == 'dhcp_assets_cleanup':
            if self.container(record) or self.find(names(self.lab, record['config']['attachment']['segment'])):
                raise JumphostError('DHCP asset cleanup has remaining consumers')
            self.extensions_cleaned(record)
            self.dhcp_cleanup_assets(record); return
        value = self.preflight_cleanup(record, bind=True)
        if record.get('dhcp_structure'):
            record.setdefault('dhcp_structure_history',[]).append(record.pop('dhcp_structure'))
        if record.get('dhcp_structural_operation'):
            record.setdefault('dhcp_structural_history',[]).append(record.pop('dhcp_structural_operation'))
        record['phase'] = 'cleanup_pending'; record['action'] = 'delete'; self.save(record)
        if value and value['State']['Running']:
            self.container(record); self.run(['docker', 'kill', '--signal', 'TERM', value['Id']])
            deadline = time.monotonic() + 15
            while True:
                value = self.container(record)
                if not value or not value['State']['Running']: break
                if time.monotonic() >= deadline: raise JumphostError('jumphost shutdown timed out; recovery required')
                time.sleep(.1)
        # Namespace exit may already have removed the pair. A replacement is refused.
        host = self.find(names(self.lab, record['config']['attachment']['segment']))
        if host:
            if not record.get('host') or signature(host) != record['host']:
                raise JumphostError('cleanup endpoint identity changed')
            self.infrastructure(record); self.delete_link(record['host'], record['context'])
        if self.find(names(self.lab, record['config']['attachment']['segment'])):
            raise JumphostError('cleanup endpoint remains')
        for row in self.extension_rows(record).values(): AttachmentWorker(self,record,row).cleanup_attachment(row)
        self.extensions_cleaned(record)
        value = self.container(record)
        if value:
            if value['State']['Running']: raise JumphostError('refusing running jumphost removal')
            self.run(['docker', 'rm', value['Id']])
        if self.container(record) is not None: raise JumphostError('jumphost removal incomplete')
        if record.get('dhcp_layout') == 2:
            record['step'] = 'dhcp_assets_cleanup'; self.save(record)
            self.dhcp_cleanup_assets(record); return
        record['phase'] = 'cleaned'; record['cleanup_verified'] = True; self.save(record)

    def operate(self, action, config=None):
        if action not in ('read', 'ensure', 'provision', 'recover', 'delete', 'attach', 'preflight-delete', 'verify-cleaned', 'dhcp-refresh','inventory-refresh','segment-add','segment-recover'):
            raise JumphostError('unsupported jumphost action')
        with self.locked():
            record = self.read()
            if action == 'recover' and config is not None and (not record or validate(config) != record['config']):
                raise JumphostError('recovery original jumphost configuration differs')
            if record and (record.get('dhcp_structure') or record.get('dhcp_structural_operation')):
                if action not in ('read','delete','preflight-delete','verify-cleaned'):
                    raise JumphostError('private structural DHCP recovery required; public mutation refused')
                if action in ('preflight-delete','verify-cleaned'):
                    if record.get('dhcp_structural_operation'): self.dhcp_structural_validate(record)
                    if record.get('dhcp_structure'): self.dhcp_structure_cleanup_preflight(record)
            if record and record.get('inventory_operation') and action not in ('read','recover','preflight-delete'):
                raise JumphostError('explicit inventory recovery required')
            if action == 'inventory-refresh' or action == 'recover' and record and record.get('action') == 'inventory':
                if not record: raise JumphostError('inventory original birth missing')
                try: return self.inventory_refresh(record, config if action == 'inventory-refresh' else None)
                except Exception as error:
                    if record.get('inventory_operation'):
                        record['phase'] = 'recovery_required'; record['error_type'] = type(error).__name__; self.save(record)
                    raise
            if action in ('segment-add','segment-recover'):
                return self.segment_operation(record,action,config)
            if action == 'recover' and record and record['phase'] == 'active' and any(
                    row['phase'] in ('creating','recovery_required') for row in self.extension_rows(record).values()):
                for row in list(self.extension_rows(record).values()):
                    if row['phase'] in ('creating','recovery_required'): self.segment_operation(record,'segment-recover',row['request'])
                return record
            if action == 'read':
                if not record: return {'phase': 'absent'}
                if record['phase'] == 'active':
                    self.infrastructure(record)
                    with self.namespace(record) as fd: self.verify_attachment(record, fd)
                    self.verify_extensions(record)
                return record
            if action in ('preflight-delete', 'verify-cleaned'):
                if not record: raise JumphostError('jumphost journal missing')
                if config is not None:
                    expected = {'container': record['config']['name']}
                    if 'generation' in config: expected['generation'] = record['config']['generation']
                    if config != expected: raise JumphostError('requested cleanup generation differs from birth')
                if record['phase'] == 'cleaned' and record.get('cleanup_verified'):
                    self.verify_cleaned(record)
                elif record.get('step') == 'dhcp_assets_cleanup' and action == 'preflight-delete':
                    if self.container(record) or self.find(names(self.lab, record['config']['attachment']['segment'])):
                        raise JumphostError('DHCP cleanup consumers remain')
                    self.dhcp_cleanup_assets(record, mutate=False)
                elif action == 'verify-cleaned': raise JumphostError('jumphost cleanup journal pending')
                else: self.preflight_cleanup(record)
                return record
            if action == 'dhcp-refresh' or action == 'recover' and record and record.get('action') == 'dhcp':
                if not record: raise JumphostError('DHCP original birth missing')
                try: return self.dhcp_refresh(record, config if action == 'dhcp-refresh' else None)
                except Exception as error:
                    if record.get('dhcp_operation'):
                        record['phase'] = 'recovery_required'; record['error_type'] = type(error).__name__; self.save(record)
                    raise
            if action == 'delete' and record and config is not None:

                if config != {'generation': record['config']['generation']}:
                    raise JumphostError('stale coordinator cleanup generation')
            if action == 'provision':
                config = validate(config)
                if not record or record['phase'] != 'cleaned' or record.get('cleanup_verified') is not True:
                    raise JumphostError('provision requires verified previous cleanup')
                if self.container(record) or self.find(names(self.lab, record['config']['attachment']['segment'])):
                    raise JumphostError('previous jumphost generation replaced')
                self.extensions_cleaned(record)
                if record.get('dhcp_layout') == 2 and self.dhcp_directory(record).exists():
                    raise JumphostError('previous DHCP assets remain or were replaced')
                if config['generation'] == record['config']['generation']:
                    raise JumphostError('new provisioning requires a new coordinator generation')
                for path in self.directory.glob(self.key + '-*.json'):
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd) as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                            raise JumphostError('historical generation ownership differs')
                        if json.load(stream)['config']['generation'] == config['generation']:
                            raise JumphostError('obsolete coordinator generation')
                archive = self.directory / (self.key + '-' + record['nonce'] + '.json')
                try: fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                except FileExistsError:
                    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd) as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or json.load(stream) != record:
                            raise JumphostError('previous generation archive differs')
                else:
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(canonical(record)); stream.flush(); os.fsync(stream.fileno())
                fd = os.open(self.directory, os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
                record = None
                action = 'ensure'
            if action == 'ensure':
                config = validate(config)
                if config['lab'] != self.lab: raise JumphostError('lab configuration differs')
                if record:
                    if record['config'] != config: raise JumphostError('jumphost configuration changed; explicit lifecycle required')
                    if record['phase'] != 'active': raise JumphostError('explicit jumphost recovery required')
                    self.infrastructure(record)
                    with self.namespace(record) as fd: self.verify_attachment(record, fd)
                    self.verify_extensions(record)
                    return record
                bridge = self.preflight_new(config); network = self.network(config); management_network = self.management_network(config)
                image = json.loads(self.run(['docker', 'image', 'inspect', config['image']]))[0]
                if image.get('Config', {}).get('Volumes'):
                    raise JumphostError('unqualified anonymous jumphost image volumes')
                if not re.fullmatch('sha256:[0-9a-f]{64}', image.get('Id', '')):
                    raise JumphostError('immutable jumphost image required')
                nonce = uuid.uuid4().hex
                def mac(side):
                    raw = bytearray(bytes.fromhex(digest([nonce, side])[:12])); raw[0] = (raw[0] & 0xfc) | 2
                    return ':'.join(f'{v:02x}' for v in raw)
                record = {'config': config, 'context': self.host_context(), 'nonce': nonce, 'image': image,
                          'network': network, 'management_network': management_network, 'bridge': bridge, 'phase': 'creating', 'action': 'ensure',
                          'step': 'intent', 'alias': 'dnlab-jumphost:' + self.key + ':' + nonce,
                          # Linux normally inherits a port MAC on the bridge. Using
                          # its existing MAC for this unaddressed host end avoids
                          # changing the bridge identity when attaching the pair.
                          'host_mac': bridge['address'], 'peer_mac': mac('peer')}
                if config['dhcp']: record['dhcp_layout'] = 2
                self.save(record)
            elif not record:
                # Legacy resources are never removed without their birth record.
                raise JumphostError('jumphost journal missing; refusing adoption or cleanup')
            elif action == 'attach':
                if config != record['config']['attachment']: raise JumphostError('attachment configuration differs')
                if record['phase'] != 'active': raise JumphostError('explicit jumphost recovery required')
                self.infrastructure(record)
                with self.namespace(record) as fd: self.verify_attachment(record, fd)
                self.verify_extensions(record)
                return record
            if record['phase'] == 'cleaned':
                if action in ('delete', 'recover') and record.get('cleanup_verified'):
                    if self.container(record) or self.find(names(self.lab, record['config']['attachment']['segment'])):
                        raise JumphostError('cleaned generation replaced')
                    self.extensions_cleaned(record)
                    return record
                raise JumphostError('new jumphost generation requires explicit provisioning')
            try:
                if action == 'delete' or record['action'] == 'delete':
                    self.cleanup(record); return record
                if action == 'ensure': self.create(record)
                else:
                    self.infrastructure(record)
                    value = self.container(record, bind=True)
                    if value is None:
                        if record.get('container_id'): raise JumphostError('recorded jumphost disappeared')
                        if record['step'] != 'intent':
                            raise JumphostError('attempted birth has no observable generation; explicit cleanup required')
                        self.create(record)
                value = self.container(record)
                if not value['State']['Running']:
                    if record.get('started_at') or value['State'].get('StartedAt', '0001').startswith('0001') is False:
                        raise JumphostError('jumphost exited; refusing implicit restart')
                    record['step'] = 'start'; self.save(record); self.infrastructure(record)
                    self.container(record); self.run(['docker', 'start', value['Id']])
                self.verify_extensions(record)
                self.attach(record)
                self.verify_extensions(record)
                record['phase'] = 'active'; record['step'] = 'verified'; self.save(record)
                return record
            except Exception as error:
                record['phase'] = 'recovery_required'; record['error_type'] = type(error).__name__
                self.save(record); raise


class AttachmentWorker(Worker):
    """Reuse the index/namespace-bound primitives without changing birth labels."""
    def __init__(self, base, parent, row):
        super().__init__(base.lab,directory=base.directory,run=base.run,host_context=base.host_context,
                         open_ns=base.open_ns,delete_link=base.delete_link,management_directory=base.management_directory)
        self.base,self.parent,self.row=base,parent,row

    def save(self, record):
        self.parent['management_attachments'][record['config']['attachment']['segment']]=record
        self.base.save(self.parent)

    def container(self, record, *, bind=False):
        return self.base.container(self.parent)

    def infrastructure(self, record):
        self.base.infrastructure(self.parent)
        self.bridge(record)
        if self.management_network(record['config']) != record['management_network']:
            raise JumphostError('additional management network generation changed')

    def cleanup_attachment(self, record):
        value=self.preflight_cleanup(record)
        if value and value['State']['Running']:raise JumphostError('verified jumphost exit required before attachment cleanup')
        host=self.find(names(self.lab,record['config']['attachment']['segment']))
        if host:
            if not record.get('host') or signature(host)!=record['host']:
                raise JumphostError('additional cleanup endpoint replaced')
            self.delete_link(record['host'],record['context'])
        if self.find(names(self.lab,record['config']['attachment']['segment'])):
            raise JumphostError('additional management endpoint remains')
        record.update(phase='cleaned',cleanup_verified=True);self.save(record)


def main():
    if os.getuid() != 0: raise JumphostError('root worker required')
    request = json.loads(sys.argv[1]) if len(sys.argv) > 1 else json.load(sys.stdin)
    print(canonical(Worker(request['lab'], directory=request.get('directory', '/var/lib/dnlab/jumphost'),
        management_directory=request.get('management_directory', '/var/lib/dnlab/management')).operate(request['action'], request.get('config'))))


if __name__ == '__main__': main()
