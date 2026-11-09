"""Root-local DNS birth, asset, reload and cleanup journal.

The SSH wrapper injects the existing stdlib journal primitives. No name alone
allows adoption, signals or deletion. Pending operations require recovery.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

try:
    _BaseWorker
except NameError:
    from dnlab_multinode.services.jumphost_host import Worker as _BaseWorker
    from dnlab_multinode.services.jumphost_host import JumphostError, canonical, digest


class DNSError(JumphostError):
    pass


def validate(config):
    if not isinstance(config, dict) or set(config) != {'lab', 'generation', 'name', 'image', 'network', 'ip', 'upstream'}:
        raise DNSError('complete DNS configuration required')
    if not re.fullmatch('[0-9a-f]{32}', config['generation']): raise DNSError('DNS generation required')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,200}', config['name']): raise DNSError('invalid DNS name')
    if not config['lab'] or not isinstance(config['image'], str) or not config['image']: raise DNSError('DNS lab/image required')
    network = config['network']
    if not isinstance(network, dict) or set(network) != {'name', 'bridge', 'subnet', 'gateway'}:
        raise DNSError('complete DNS external network required')
    subnet = ipaddress.IPv4Network(network['subnet'], strict=True)
    if ipaddress.IPv4Address(config['ip']) not in subnet: raise DNSError('DNS address outside network')
    ipaddress.IPv4Address(network['gateway'])
    if not isinstance(config['upstream'], list) or not config['upstream']: raise DNSError('DNS upstream required')
    for address in config['upstream']: ipaddress.ip_address(address)
    return json.loads(canonical(config))


class Worker(_BaseWorker):
    def __init__(self, lab, **kwargs):
        super().__init__(lab, **kwargs)
        self.key = digest(['dns-v1', lab]); self.path = self.directory / (self.key + '.json')

    def read(self):
        try: fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError: return None
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise DNSError('DNS journal ownership differs')
            record = json.load(stream)
        validate(record['config'])
        if record['config']['lab'] != self.lab or record['context'] != self.host_context():
            raise DNSError('DNS journal lab/namespace differs')
        if not re.fullmatch('[0-9a-f]{32}', record['nonce']): raise DNSError('DNS birth nonce differs')
        return record

    def labels(self, record):
        return {'org.dnlab.dns.scope': self.key, 'org.dnlab.dns.nonce': record['nonce'],
                'org.dnlab.dns.config': digest(record['config'])}

    def asset_directory(self, record):
        return self.directory / (self.key + '-' + record['nonce'])

    @staticmethod
    def identity(path, *, directory=False):
        info = path.lstat()
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o755 if directory else 0o644)
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
            raise DNSError('DNS asset ownership differs')
        return {'device': info.st_dev, 'inode': info.st_ino}

    def assets(self, record):
        directory = self.asset_directory(record)
        if not record.get('asset_directory') or self.identity(directory, directory=True) != record['asset_directory']:
            raise DNSError('DNS asset directory identity differs')
        allowed = {'hosts'}
        if record.get('file_operation'): allowed.add('.hosts-' + record['file_operation']['id'])
        if set(p.name for p in directory.iterdir()) - allowed: raise DNSError('DNS directory has unqualified files')
        host = directory / 'hosts'
        if record.get('file'):
            if self.identity(host) != record['file']['identity'] or host.read_text() != record['file']['content']:
                raise DNSError('DNS hosts file identity/content differs')
        elif host.exists():
            raise DNSError('unqualified DNS hosts file')

    def infrastructure(self, record):
        if self.network(record['config']) != record['network']: raise DNSError('DNS network generation differs')
        self.assets(record)

    def container(self, record, *, bind=False):
        values = self.containers(); name = record['config']['name']; cid = record.get('container_id')
        matches = [v for v in values if v.get('Names') == name]
        if not cid:
            candidates = self.run(['docker', 'ps', '-a', '--no-trunc', '--filter',
                'label=org.dnlab.dns.nonce=' + record['nonce'], '--format', '{{.ID}}']).split()
            if candidates and (len(candidates) != 1 or len(matches) != 1 or candidates[0] != matches[0]['ID']):
                raise DNSError('ambiguous or renamed pending DNS birth')
        if len(matches) > 1: raise DNSError('ambiguous DNS name')
        if not matches:
            if cid and any(v['ID'] == cid for v in values): raise DNSError('DNS container renamed')
            return None
        actual = matches[0]['ID']
        if cid and actual != cid: raise DNSError('DNS container generation replaced')
        value = json.loads(self.run(['docker', 'inspect', actual]))
        if len(value) != 1 or value[0].get('Id') != actual or value[0].get('Name') != '/' + name:
            raise DNSError('DNS container identity differs')
        value = value[0]; self.verify_container(record, value)
        if not cid:
            if not bind or not record.get('attempted'): raise DNSError('DNS unbound birth requires recovery')
            record['container_id'] = actual; self.save(record)
        return value

    def verify_container(self, record, value):
        c = record['config']; image = record['image']; original = image.get('Config', {})
        cfg = value.get('Config', {}); host = value.get('HostConfig', {})
        env = dict(v.split('=', 1) for v in original.get('Env') or [])
        env['UPSTREAM_DNS'] = ' '.join(c['upstream'])
        labels = dict(original.get('Labels') or {}); labels.update(self.labels(record))
        actual_env = cfg.get('Env') or []
        if (value.get('Image') != image['Id'] or cfg.get('Image') != image['Id'] or cfg.get('Labels') != labels
                or len(actual_env) != len(env) or dict(v.split('=', 1) for v in actual_env) != env
                or cfg.get('Entrypoint') != original.get('Entrypoint') or cfg.get('Cmd') != original.get('Cmd')
                or host.get('NetworkMode') != record['network']['Id'] or host.get('Privileged') is not False
                or set(host.get('CapAdd') or []) not in ({'NET_ADMIN'}, {'CAP_NET_ADMIN'})
                or (host.get('Binds') or []) != [str(self.asset_directory(record)) + ':/etc/dnlab-dns:ro']
                or host.get('PortBindings') not in ({}, None) or host.get('RestartPolicy', {}).get('Name') != 'no'
                or host.get('PidMode', '') != '' or host.get('IpcMode') != 'private'):
            raise DNSError('DNS container configuration/ownership differs')
        endpoints = value.get('NetworkSettings', {}).get('Networks', {})
        if set(endpoints) != {c['network']['name']}: raise DNSError('DNS endpoints differ')
        endpoint = endpoints[c['network']['name']]
        if (endpoint.get('IPAMConfig') or {}).get('IPv4Address') != c['ip']: raise DNSError('DNS requested IP differs')
        if value.get('State', {}).get('Running') and (endpoint.get('NetworkID') != record['network']['Id'] or endpoint.get('IPAddress') != c['ip']):
            raise DNSError('DNS running endpoint differs')

    def write_hosts(self, record):
        op = record['file_operation']; directory = self.asset_directory(record); target = directory / 'hosts'
        if self.identity(directory, directory=True) != record['asset_directory']: raise DNSError('DNS asset directory replaced')
        temporary = directory / ('.hosts-' + op['id'])
        # A saved temp identity proves the original inode, including a crash
        # after replace but before the new committed file proof was saved.
        if op.get('proof') and target.exists() and self.identity(target) == op['proof']:
            if target.read_text() != op['content']: raise DNSError('DNS committed hosts content differs')
        else:
            self.assets(record)
            if op.get('proof'):
                if self.identity(temporary) != op['proof'] or temporary.read_text() != op['content']:
                    raise DNSError('DNS pending hosts identity/content differs')
            else:
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, 'w') as stream:
                    os.fchmod(stream.fileno(), 0o644)
                    stream.write(op['content']); stream.flush(); os.fsync(stream.fileno())
                op['proof'] = self.identity(temporary); self.save(record)
            os.replace(temporary, target)
            self.sync_assets(directory)
        record['file'] = {'identity': op['proof'], 'content': op['content']}
        record['file_operation'] = None; self.save(record)

    @staticmethod
    def sync_assets(directory):
        fd = os.open(directory, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def progress(self, record):
        c = record['config']
        if record['phase'] == 'creating':
            if not record.get('asset_directory'):
                directory = self.asset_directory(record); directory.mkdir(mode=0o755)
                directory.chmod(0o755)
                self.sync_assets(self.directory)
                record['asset_directory'] = self.identity(directory, directory=True); self.save(record)
            if record.get("file_operation"): self.write_hosts(record)
            self.infrastructure(record)
            value = self.container(record, bind=True)
            if not value:
                if record.get('container_id'): raise DNSError('DNS observed birth missing; recovery required')
                record['attempted'] = True; self.save(record)
                argv = ['docker', 'create', '--name', c['name'], '--network', record['network']['Id'], '--ip', c['ip'],
                        '--cap-add', 'NET_ADMIN', '-v', str(self.asset_directory(record)) + ':/etc/dnlab-dns:ro',
                        '-e', 'UPSTREAM_DNS=' + ' '.join(c['upstream'])]
                for key, val in self.labels(record).items(): argv.extend(['--label', key + '=' + val])
                argv.append(record['image']['Id'])
                cid = self.run(argv).strip()
                if not re.fullmatch('[0-9a-f]{64}', cid): raise DNSError('invalid DNS create response')
                record['container_id'] = cid; self.save(record); self.container(record)
            record['phase'] = 'starting'; self.save(record)
        if record['phase'] == 'starting':
            self.infrastructure(record); value = self.container(record)
            if not value: raise DNSError('DNS birth disappeared')
            if not value['State']['Running']: self.run(['docker', 'start', value['Id']])
            value = self.container(record)
            if not value or not value['State']['Running']: raise DNSError('DNS failed to remain running')
            record['phase'] = 'active'; self.save(record)
        if record['phase'] == 'reload_pending':
            value = self.container(record)
            if not value or not value['State']['Running']: raise DNSError('DNS reload requires original running container')
            if record.get('file_operation'): self.write_hosts(record)
            self.infrastructure(record); self.container(record)
            self.run(['docker', 'kill', '--signal', 'HUP', value['Id']])
            record['phase'] = 'active'; self.save(record)
        return record

    def preflight_delete(self, record):
        if record['phase'] == 'assets_cleanup':
            if self.container(record): raise DNSError('DNS container remains during assets cleanup')
            directory = self.asset_directory(record)
            if directory.exists():
                if self.identity(directory, directory=True) != record['asset_directory']: raise DNSError('DNS asset directory replaced')
                if set(p.name for p in directory.iterdir()) - {'hosts'}: raise DNSError('DNS directory has unqualified files')
                if (directory / 'hosts').exists(): self.assets(record)
            return None
        if record['phase'] == 'cleaned':
            if self.container(record) or self.asset_directory(record).exists(): raise DNSError('DNS cleanup resources replaced')
            return None
        if not record.get('asset_directory'):
            if self.asset_directory(record).exists() or record.get('attempted'):
                raise DNSError('unqualified pending DNS assets')
            if self.container(record): raise DNSError('unqualified pending DNS container')
            return None
        self.infrastructure(record)
        return self.container(record, bind=True)

    def finish_assets_cleanup(self, record):
        self.preflight_delete(record)
        if self.container(record): raise DNSError('DNS container remains during asset cleanup')
        directory = self.asset_directory(record)
        if directory.exists():
            if self.identity(directory, directory=True) != record['asset_directory']: raise DNSError('DNS asset directory replaced')
            if set(p.name for p in directory.iterdir()) - {'hosts'}: raise DNSError('DNS directory has unqualified files')
            host = directory / 'hosts'
            if host.exists():
                self.assets(record); host.unlink()
            directory.rmdir(); self.sync_assets(self.directory)
        record['phase'] = 'cleaned'; record['cleanup_verified'] = True; self.save(record)

    def cleanup(self, record):
        if record['phase'] == 'assets_cleanup':
            self.finish_assets_cleanup(record); return
        value = self.preflight_delete(record)
        record['phase'] = 'cleanup_pending'; record['action'] = 'delete'; self.save(record)
        if value and value['State']['Running']:
            self.container(record); self.run(['docker', 'kill', '--signal', 'TERM', value['Id']])
            deadline = time.monotonic() + 15
            while True:
                value = self.container(record)
                if not value or not value['State']['Running']: break
                if time.monotonic() >= deadline: raise DNSError('DNS shutdown timeout; recovery required')
                time.sleep(.1)
        value = self.container(record)
        if value: self.run(['docker', 'rm', value['Id']])
        if self.container(record): raise DNSError('DNS removal incomplete')
        if not record.get('asset_directory'):
            record['phase'] = 'cleaned'; record['cleanup_verified'] = True; self.save(record); return
        self.assets(record)
        directory = self.asset_directory(record)
        if set(p.name for p in directory.iterdir()) - {'hosts'}: raise DNSError('DNS directory has unqualified files')
        record['phase'] = 'assets_cleanup'; self.save(record)
        self.finish_assets_cleanup(record)

    def operate(self, action, config=None, content=None):
        with self.locked():
            record = self.read()
            if action == 'recover' and config is not None:
                if not record or validate(config) != record['config']:
                    raise DNSError('recovery original DNS configuration differs')
                desired = record.get('file_operation', {}).get('content') if record.get('file_operation') else record.get('file', {}).get('content')
                if content != desired: raise DNSError('recovery original DNS content differs')
            if action == 'preflight':
                if not record:
                    if any(v['Names'] == 'dnlab-' + self.lab + '-dns' for v in self.containers()):
                        raise DNSError('unqualified DNS name occupied')
                    return {'phase': 'absent'}
                if record['phase'] == 'active':
                    self.infrastructure(record)
                    if not self.container(record): raise DNSError('DNS original container missing')
                elif record['phase'] == 'cleaned': self.preflight_delete(record)
                else: raise DNSError('DNS explicit recovery required')
                return record
            if action == 'read': return record or {'phase': 'absent'}
            if action in ('preflight-delete', 'verify-cleaned', 'delete'):
                if not record: raise DNSError('DNS birth proof missing; legacy resources protected')
                if config and config != {'generation': record['config']['generation']}: raise DNSError('DNS generation request differs')
                if action == 'verify-cleaned':
                    if record['phase'] != 'cleaned' or not record.get('cleanup_verified'): raise DNSError('DNS cleanup not verified')
                    self.preflight_delete(record); return record
                if action == 'preflight-delete': self.preflight_delete(record); return record
                if record['phase'] == 'cleaned': self.preflight_delete(record); return record
                self.cleanup(record); return record
            if action == 'provision':
                config = validate(config)
                if not record or record['phase'] != 'cleaned' or not record.get('cleanup_verified'):
                    raise DNSError('DNS provision requires verified previous cleanup')
                self.preflight_delete(record)
                historical = [record] + [json.loads(p.read_text()) for p in self.directory.glob(self.key + '-*.json')]
                if any(v['config']['generation'] == config['generation'] for v in historical):
                    raise DNSError('DNS historical generation cannot be reused')
                archive = self.directory / (self.key + '-' + record['nonce'] + '.json')
                try: os.link(self.path, archive, follow_symlinks=False)
                except FileExistsError:
                    if archive.read_bytes() != self.path.read_bytes(): raise DNSError('DNS history differs')
                self.sync_assets(self.directory)
                record = None; action = 'ensure'
            if action == 'ensure':
                config = validate(config)
                if config['lab'] != self.lab or not isinstance(content, str): raise DNSError('DNS request differs')
                if record:
                    if config != record['config'] or record['phase'] != 'active': raise DNSError('DNS explicit recovery or new generation required')
                    self.infrastructure(record); value = self.container(record)
                    if not value or not value['State']['Running']: raise DNSError('DNS original generation unavailable')
                    if content != record['file']['content']: raise DNSError('DNS content change requires reload')
                    return record
                if any(v['Names'] == config['name'] for v in self.containers()): raise DNSError('unqualified DNS name occupied')
                network = self.network(config)
                image = json.loads(self.run(['docker', 'image', 'inspect', config['image']]))[0]
                if not re.fullmatch('sha256:[0-9a-f]{64}', image.get('Id', '')) or image.get('Config', {}).get('Volumes'):
                    raise DNSError('DNS image must have immutable identity and no anonymous volumes')
                record = {'config': config, 'context': self.host_context(), 'nonce': uuid.uuid4().hex,
                          'network': network, 'image': image, 'phase': 'creating', 'action': 'ensure',
                          'file_operation': {'id': uuid.uuid4().hex, 'content': content}}
                self.save(record)
            elif action == 'reload':
                if not record or record['phase'] != 'active' or not isinstance(content, str): raise DNSError('DNS reload requires active generation')
                if config is not None and config != {'generation': record['config']['generation']}:
                    raise DNSError('DNS reload generation differs')
                self.infrastructure(record); value = self.container(record)
                if not value or not value['State']['Running']: raise DNSError('DNS reload container unavailable')
                record['phase'] = 'reload_pending'; record['action'] = 'reload'
                record['file_operation'] = {'id': uuid.uuid4().hex, 'content': content}; self.save(record)
            elif action == 'recover':
                if not record: raise DNSError('DNS recovery intent missing')
                if record['action'] == 'delete':
                    if record['phase'] == 'cleaned': self.preflight_delete(record)
                    else: self.cleanup(record)
                    return record
                if record['phase'] == 'active':
                    self.infrastructure(record)
                    value = self.container(record)
                    if not value or not value['State']['Running']: raise DNSError('DNS active generation unavailable')
            else: raise DNSError('unsupported DNS action')
            return self.progress(record)


def main():
    request = json.load(sys.stdin)
    print(canonical(Worker(request['lab'], directory=request['directory']).operate(
        request['action'], request.get('config'), request.get('content'))))


if __name__ == '__main__': main()
