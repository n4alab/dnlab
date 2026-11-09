"""Standalone guard for persistent, shared jumphost external infrastructure.

No lab teardown deletes this network. Only a structured Docker 404 establishes
absence; transport/authorization errors never authorize an allocation.
"""
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote
import uuid


class NetworkError(RuntimeError):
    pass


class DockerError(NetworkError):
    def __init__(self, status, method, path):
        self.status = status
        super().__init__(f'Docker HTTP {status}: {method} {path}')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def context():
    info = os.stat('/proc/self/ns/net')
    return dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), device=info.st_dev, inode=info.st_ino)


def execute(argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise NetworkError(f'network kernel inspection failed: {argv[0]} rc={result.returncode}: {result.stderr[-1000:]}')
    return json.loads(result.stdout)


class Docker:
    def __init__(self, path='/var/run/docker.sock'):
        if not isinstance(path, str) or not path.startswith('/'):
            raise NetworkError('Docker Unix socket required')
        self.path = path

    def call(self, method, path, body=None, *, absent=False):
        connection = http.client.HTTPConnection('localhost', timeout=30)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(30)
        try:
            connection.sock.connect(self.path)
            connection.request(method, path, None if body is None else canonical(body), {'Content-Type': 'application/json'})
            response = connection.getresponse(); raw = response.read()
            try: value = json.loads(raw)
            except (ValueError, UnicodeDecodeError): raise NetworkError('invalid Docker HTTP response') from None
            if absent and response.status == 404 and isinstance(value, dict) and isinstance(value.get('message'), str):
                return None
            if not 200 <= response.status < 300:
                raise DockerError(response.status, method, path)
            return value
        except (OSError, http.client.HTTPException) as error:
            raise NetworkError('Docker transport failed; no absence established: ' + str(error)) from None
        finally:
            connection.close()

    def inspect(self, identity):
        value = self.call('GET', '/networks/' + quote(identity, safe=''), absent=True)
        if value is not None and (not isinstance(value, dict) or not re.fullmatch('[0-9a-f]{64}', value.get('Id', ''))):
            raise NetworkError('invalid Docker network identity')
        return value

    def inventory(self):
        values = self.call('GET', '/networks')
        if (not isinstance(values, list) or any(not isinstance(v, dict) or not re.fullmatch('[0-9a-f]{64}', v.get('Id', ''))
                or not isinstance(v.get('Name'), str) for v in values)
                or len({v['Id'] for v in values}) != len(values)):
            raise NetworkError('invalid Docker network inventory')
        return values

    def create(self, payload):
        value = self.call('POST', '/networks/create', payload)
        if not isinstance(value, dict) or not re.fullmatch('[0-9a-f]{64}', value.get('Id', '')):
            raise NetworkError('network create response lacks qualified ID; recovery required')
        return value['Id']


def config(value):
    if not isinstance(value, dict) or set(value) != {'network', 'bridge', 'subnet', 'gateway'}:
        raise NetworkError('complete external network configuration required')
    for key, pattern in [('network', '[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'), ('bridge', '[A-Za-z][A-Za-z0-9_-]{0,14}')]:
        if not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]):
            raise NetworkError('invalid external network ' + key)
    try:
        subnet = ipaddress.IPv4Network(value['subnet'], strict=True); gateway = ipaddress.IPv4Address(value['gateway'])
    except (ValueError, TypeError): raise NetworkError('invalid external network IPAM') from None
    if (gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address)
            or subnet.prefixlen > 30 or subnet.is_multicast or gateway.is_unspecified):
        raise NetworkError('invalid external network subnet/gateway')
    return dict(value, subnet=str(subnet), gateway=str(gateway))


class Worker:
    def __init__(self, value, *, directory='/var/lib/dnlab/jumphost-network', docker=None, run=execute, host_context=context):
        self.config = config(value); self.directory = Path(directory)
        self.docker = docker or Docker(); self.run = run; self.host_context = host_context
        self.key = digest(['jumphost-shared-network-v1', self.config['network']])
        self.path = self.directory / (self.key + '.json')

    def desired(self, record):
        return dict(Name=self.config['network'], CheckDuplicate=True, Driver='bridge', EnableIPv6=False,
            Internal=False, Attachable=False, Ingress=False,
            Options={'com.docker.network.bridge.name': self.config['bridge'],
                     'com.docker.network.bridge.enable_ip_masquerade': 'true', 'com.docker.network.bridge.enable_icc': 'true'},
            Labels={'org.dnlab.jumphost.network.version': '1', 'org.dnlab.jumphost.network.scope': self.key,
                    'org.dnlab.jumphost.network.creator': record['nonce'], 'org.dnlab.jumphost.network.config': digest(self.config)},
            IPAM={'Driver': 'default', 'Options': {}, 'Config': [{'Subnet': self.config['subnet'], 'Gateway': self.config['gateway']}]})

    def directory_check(self):
        if self.directory.resolve() != self.directory.absolute(): raise NetworkError('network journal directory is a symlink')
        if self.directory.exists():
            info = self.directory.stat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: raise NetworkError('network journal directory ownership differs')

    def read(self):
        self.directory_check()
        try: fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError: return None
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
                raise NetworkError('network journal ownership differs')
            value = json.load(stream)
        if (value.get('config') != self.config or value.get('context') != self.host_context()
                or not re.fullmatch('[0-9a-f]{32}', value.get('nonce', ''))
                or value.get('phase') not in ('creating', 'active', 'recovery_required')
                or value.get('id') is not None and not re.fullmatch('[0-9a-f]{64}', value['id'])):
            raise NetworkError('network intent configuration/context differs')
        return value

    def save(self, record):
        fd, name = tempfile.mkstemp(dir=self.directory, prefix='.network-')
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(canonical(record)); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
            fd = os.open(self.directory, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if os.path.exists(name): os.unlink(name)

    def bridge(self):
        values = [v for v in self.run(['ip', '-j', '-d', 'link', 'show']) if v.get('ifname') == self.config['bridge']]
        if len(values) > 1: raise NetworkError('ambiguous external network bridge')
        return values[0] if values else None

    @staticmethod
    def signature(value):
        return {key: value.get(key) for key in ('ifname', 'ifindex', 'address', 'ifalias')}

    def observe(self):
        inventory = self.docker.inventory()
        matches = [v for v in inventory if v['Name'] == self.config['network']]
        if len(matches) > 1: raise NetworkError('ambiguous external network name')
        value = self.docker.inspect(self.config['network'])
        if bool(matches) != (value is not None) or value is not None and value['Id'] != matches[0]['Id']:
            raise NetworkError('external network inventory changed; retry read-only preflight')
        return value, inventory

    def absent(self):
        value, inventory = self.observe()
        if value is not None: raise NetworkError('unqualified shared network exists; refusing adoption')
        if self.bridge() is not None: raise NetworkError('external bridge name occupied')
        for other in inventory:
            if (other.get('Options') or {}).get('com.docker.network.bridge.name') == self.config['bridge']:
                raise NetworkError('external bridge name reserved')
            for entry in (other.get('IPAM') or {}).get('Config') or []:
                if entry.get('Subnet'):
                    subnet = ipaddress.ip_network(entry['Subnet'])
                    if subnet.version == 4 and subnet.overlaps(ipaddress.ip_network(self.config['subnet'])):
                        raise NetworkError('external subnet overlaps another Docker network')

    def verify(self, record, value):
        if value is None: raise NetworkError('recorded external network absent; refusing recreation')
        wanted = self.desired(record)
        if (record.get('id') is not None and value['Id'] != record['id']
                or any(value.get(k) != wanted[k] for k in ('Name', 'Driver', 'EnableIPv6', 'Internal', 'Attachable', 'Ingress', 'Options', 'Labels'))
                or value.get('Scope') != 'local' or value.get('ConfigOnly', False) is not False
                or not isinstance(value.get('Containers'), dict)):
            raise NetworkError('external network ownership/configuration differs')
        ipam = value.get('IPAM')
        if not isinstance(ipam, dict): raise NetworkError('external network IPAM malformed')
        ipam = dict(ipam)
        if 'Options' in ipam and (ipam['Options'] is None or type(ipam['Options']) is dict and not ipam['Options']): ipam['Options'] = {}
        if ipam != wanted['IPAM']: raise NetworkError('external network IPAM differs')
        if record['phase'] != 'active' and value['Containers']: raise NetworkError('unbound network has unadmitted endpoints')
        if record.get('id'):
            original = self.docker.inspect(record['id'])
            if original is None or original['Id'] != value['Id']: raise NetworkError('original external network identity unavailable')
        bridge = self.bridge()
        if (not bridge or bridge.get('linkinfo', {}).get('info_kind') != 'bridge'
                or type(bridge.get('ifindex')) is not int or bridge['ifindex'] <= 0
                or not re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', bridge.get('address', ''))
                or record.get('bridge') is not None and self.signature(bridge) != record['bridge']):
            raise NetworkError('external bridge identity differs')
        addresses = self.run(['ip', '-j', 'address', 'show', 'dev', self.config['bridge']])
        actual = [(v.get('local'), v.get('prefixlen')) for row in addresses for v in row.get('addr_info', []) if v.get('family') == 'inet']
        if actual != [(self.config['gateway'], ipaddress.ip_network(self.config['subnet']).prefixlen)]:
            raise NetworkError('external bridge gateway differs')
        return bridge

    def preflight(self):
        record = self.read(); value, _ = self.observe()
        if record:
            if record['phase'] != 'active': raise NetworkError('shared network requires explicit recovery')
            self.verify(record, value)
        else: self.absent()
        return {'status': 'verified', 'network_id': value['Id'] if value else None}

    def operate(self, action='ensure'):
        if action not in ('ensure', 'recover'): raise NetworkError('unsupported shared network action')
        self.directory_check()
        missing = []; parent = self.directory
        while not parent.exists():
            missing.append(parent); parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            parent_fd = os.open(directory.parent, os.O_DIRECTORY)
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
        self.directory_check()
        fd = os.open(self.directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600: raise NetworkError('network lock ownership differs')
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise NetworkError('shared network operation busy') from None
            record = self.read(); value, _ = self.observe()
            if record and record['phase'] == 'active':
                self.verify(record, value)
                return {'status': 'active', 'network_id': value['Id'], 'nonce': record['nonce']}
            if record:
                if action != 'recover': raise NetworkError('shared network requires explicit recovery')
                if value is not None:
                    bridge = self.verify(record, value)
                    record.update(id=value['Id'], bridge=self.signature(bridge), phase='active'); self.save(record)
                    return {'status': 'active', 'network_id': value['Id'], 'nonce': record['nonce']}
                if record.get('id'): raise NetworkError('original external network absent; refusing recreation')
            elif action == 'recover': raise NetworkError('missing shared network intent; refusing adoption')
            self.absent()
            if record is None:
                record = dict(config=self.config, context=self.host_context(), nonce=uuid.uuid4().hex, id=None, bridge=None, phase='creating')
            record['phase'] = 'creating'; self.save(record)
            try:
                self.absent()  # Repeat admission after the durable birth intent.
                identity = self.docker.create(self.desired(record))
                record['id'] = identity; self.save(record)  # Before verification or attachments.
                value, _ = self.observe(); bridge = self.verify(record, value)
                record.update(bridge=self.signature(bridge), phase='active'); self.save(record)
                return {'status': 'active', 'network_id': identity, 'nonce': record['nonce']}
            except Exception:
                record['phase'] = 'recovery_required'; self.save(record); raise
        finally:
            os.close(fd)


def main():
    if os.getuid() != 0: raise NetworkError('root shared network worker required')
    request = json.load(sys.stdin)
    worker = Worker(request['config'], directory=request['directory'], docker=Docker(request['socket']))
    action = request['action']
    print(canonical(worker.preflight() if action == 'preflight' else worker.operate(action)))


if __name__ == '__main__': main()
