"""Standalone management infrastructure worker. No implicit legacy adoption.

One durable host journal per lab, shared VRF and independent segment lifetimes.
The coordinator preflights all hosts before calling ensure/cleanup; the worker
repeats preflight under its local lock before every recorded mutation.
"""
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile


class ManagementError(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def context():
    s = os.stat('/proc/self/ns/net')
    return dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), device=s.st_dev, inode=s.st_ino)


def execute(args):
    p = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if p.returncode:
        raise ManagementError(f'management command failed: {shlex.join(args[:5])} rc={p.returncode}: {p.stderr[-2000:]}')
    return p.stdout


def signature(v):
    return {k: v.get(k) for k in ('ifname', 'ifindex', 'address', 'ifalias')} | {'kind': v.get('linkinfo', {}).get('info_kind')}


def validate(p):
    if not isinstance(p, dict) or set(p) != {'lab', 'generation', 'vrf', 'table', 'segments'}:
        raise ManagementError('complete management intent required')
    if not isinstance(p['lab'], str) or not p['lab'] or not re.fullmatch('[0-9a-f]{32}', p['generation']):
        raise ManagementError('management lab/generation required')
    def name(v):
        if not isinstance(v, str) or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', v):
            raise ManagementError('invalid management interface name')
    name(p['vrf'])
    if type(p['table']) is not int or not 1 <= p['table'] < 2**31:
        raise ManagementError('invalid VRF table')
    if not isinstance(p['segments'], dict) or not p['segments']:
        raise ManagementError('management segments required')
    names = [p['vrf']]; vnis = []
    for key, s in p['segments'].items():
        if not isinstance(key, str) or not key or set(s) != {'bridge', 'vxlan', 'vni', 'underlay', 'local', 'remotes', 'address'}:
            raise ManagementError('invalid management segment')
        for n in ('bridge', 'vxlan', 'underlay'): name(s[n])
        names += [s['bridge'], s['vxlan']]; vnis.append(s['vni'])
        if type(s['vni']) is not int or not 1 <= s['vni'] <= 16777215:
            raise ManagementError('invalid management VNI')
        if ipaddress.ip_address(s['local']).version != 4 or ipaddress.ip_interface(s['address']).version != 4:
            raise ManagementError('IPv4 underlay and technical address required')
        if not isinstance(s['remotes'], list) or len(s['remotes']) != len(set(s['remotes'])):
            raise ManagementError('invalid management FDB destinations')
        for remote in s['remotes']:
            if ipaddress.ip_address(remote).version != 4 or remote == s['local']:
                raise ManagementError('invalid management FDB destination')
    if len(names) != len(set(names)) or len(vnis) != len(set(vnis)):
        raise ManagementError('duplicate management resource')
    return copy.deepcopy(p)


# One namespace-pinned process, index-bound updates/deletions, atomic birth alias.
# The full source is sent with the worker, no installed host dependency.
KERNEL = r"""import json,os,socket,struct,subprocess,sys,ipaddress
p=json.loads(sys.argv[1]);s=os.stat('/proc/self/ns/net')
if {'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),'device':s.st_dev,'inode':s.st_ino}!=p['context']:raise RuntimeError('management namespace differs')
def attr(k,v):
 n=4+len(v);return struct.pack('=HH',n,k)+v+b'\0'*((-n)%4)
def u32(v):return struct.pack('=I',v)
def text(v):return v.encode()+b'\0'
def sig(v):return {k:v.get(k) for k in ('ifname','ifindex','address','ifalias')}|{'kind':v.get('linkinfo',{}).get('info_kind')}
links=json.loads(subprocess.check_output(['ip','-j','-d','link','show']))
def owned(v):
 x=next((x for x in links if x['ifindex']==v['ifindex']),None)
 if not x or sig(x)!=v:raise RuntimeError('management kernel identity differs')
 return x
op=p['op'];flags=5;kind=16;attrs=b'';index=0;lf=0;change=0
if op=='create':
 v=p['value'];name=v['name'];k=v['kind'];c=v['config'];flags|=0x600
 if any(x['ifname']==name for x in links):raise RuntimeError('management name occupied')
 attrs=attr(3,text(name))+attr(20,text(v['alias']))+attr(1,bytes.fromhex(v['mac'].replace(':','')))
 if k=='bridge':data=b''
 elif k=='vrf':data=attr(1,u32(c['table']))
 elif k=='vxlan':
  underlay=owned(p['underlay']);data=attr(1,u32(c['id']))+attr(3,u32(underlay['ifindex']))+attr(4,ipaddress.ip_address(c['local']).packed)+attr(7,b'\0')+attr(15,struct.pack('!H',4789))
 else:raise RuntimeError('unsupported management kind')
 attrs+=attr(18,attr(1,text(k))+attr(2,data))
else:
 owned(p['link']);index=p['link']['ifindex']
 if op=='delete':kind=17
 elif op=='alias':attrs=attr(20,text(p['value']))
 elif op=='up':lf=1;change=1
 elif op=='master':owned(p['value']);attrs=attr(10,u32(p['value']['ifindex']))
 elif op=='address':
  v=ipaddress.ip_interface(p['value']);kind=20;flags|=0x600
  body=struct.pack('=BBBBI',socket.AF_INET, v.network.prefixlen,0,0,index);attrs=attr(1,v.ip.packed)+attr(2,v.ip.packed)
 elif op in ('fdb-add','fdb-delete'):
  kind=28 if op=='fdb-add' else 29
  if op=='fdb-add':flags|=0xc00
  body=struct.pack('=BBHiHBB',socket.AF_BRIDGE,0,0,index,0x80,2,0)
  attrs=attr(2,b'\0'*6)+attr(1,ipaddress.ip_address(p['value']).packed)
 else:raise RuntimeError('unsupported management mutation')
if kind in (16,17):body=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,lf,change)
body+=attrs
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
 sock.bind((0,0));sock.settimeout(10);port=sock.getsockname()[0];seq=int.from_bytes(os.urandom(4),'little') or 1
 sock.sendto(struct.pack('=IHHII',16+len(body),kind,flags,seq,port)+body,(0,0));data,sender=sock.recvfrom(65536)
 if len(data)<20:raise RuntimeError('short management ACK')
 length,reply,fl,rs,rp=struct.unpack_from('=IHHII',data);err=struct.unpack_from('=i',data,16)[0]
 if sender!=(0,0) or length<20 or length>len(data) or reply!=2 or rs!=seq or rp!=port or err:raise RuntimeError('management kernel ACK: '+str(err))
print('{}')
"""


class Worker:
    def __init__(self, plan, *, directory='/var/lib/dnlab/management', run=execute, host_context=context, kernel=None):
        self.plan = validate(plan); self.directory = Path(directory); self.run = run; self.host_context = host_context
        self.key = digest(['management-host-v1', plan['lab']]); self.path = self.directory / (self.key + '.json')
        self.kernel = kernel or (lambda payload: self.run(['python3', '-c', KERNEL, json.dumps(payload)]))

    @contextmanager
    def locked(self):
        d = self.directory
        if d.resolve() != d.absolute(): raise ManagementError('management journal path is a symlink')
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        if d.stat().st_uid != 0 or stat.S_IMODE(d.stat().st_mode) != 0o700:
            raise ManagementError('management journal ownership differs')
        fd = os.open(d / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise ManagementError('management lock ownership differs')
            fcntl.flock(fd, fcntl.LOCK_EX); yield
        finally: os.close(fd)

    def load(self):
        try: fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError: return None
        with os.fdopen(fd) as f:
            info = os.fstat(f.fileno())
            if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise ManagementError('management record ownership differs')
            r = json.load(f)
        return r

    def read(self):
        r = self.load()
        if r is None: return None
        if r['plan']['lab'] != self.plan['lab'] or r['plan']['generation'] != self.plan['generation']:
            raise ManagementError('management generation differs')
        for k in ('vrf', 'table'):
            if r['plan'][k] != self.plan[k]: raise ManagementError('management VRF contract differs')
        for k, s in r['plan']['segments'].items():
            current = self.plan['segments'].get(k)
            if (current is None or {x:v for x,v in current.items() if x != 'remotes'} != {x:v for x,v in s.items() if x != 'remotes'}
                    or not set(s['remotes']) <= set(current['remotes'])):
                raise ManagementError('management segment contract differs')
        if r['context'] != self.host_context(): raise ManagementError('management host boot/namespace differs; recovery required')
        return r

    def preflight_provision(self):
        if (self.directory / (self.key + '-' + self.plan['generation'] + '.json')).exists():
            raise ManagementError('historical management generation cannot be reused')
        old = self.load()
        if old is None or old['plan']['generation'] == self.plan['generation']:
            self.preflight(self.read()); return None
        previous = Worker(old['plan'], directory=self.directory, run=self.run, host_context=self.host_context, kernel=self.kernel)
        if hasattr(self,'network_factory'): previous.network_factory=self.network_factory
        previous.verify_cleaned_record(old)
        # The new plan must independently pass the unowned-name/configuration checks.
        self.preflight(None)
        return old

    def provision(self, *, recover=False):
        with self.locked():
            old = self.preflight_provision()
            if old is not None:
                archive = self.directory / (self.key + '-' + old['plan']['generation'] + '.json')
                if archive.exists(): raise ManagementError('management generation already archived')
                os.link(self.path, archive, follow_symlinks=False)
                os.unlink(self.path)
                fd = os.open(self.directory, os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
        return self.ensure(recover=recover)

    def verify_networks_closed(self, r, segments=None):
        keys = set(r.get('networks', {})) if segments is None else set(segments) & r.get('networks', {}).keys()
        if not keys: return
        factory = getattr(self, 'network_factory', None) or globals().get('_NetworkGuard')
        if factory is None:
            from .management_network_host import NetworkGuard
            factory = NetworkGuard
        guard = factory(self, {k:r['networks'][k]['expected'] for k in keys}, **r['network_transport'])
        guard.preflight(r, action='verify-cleaned')
        for key in keys:
            row = r['networks'][key]
            if row['phase'] != 'cleaned' or guard.observe(row, missing=True) is not None:
                raise ManagementError('Docker network cleanup must complete before kernel teardown')

    def verify_cleaned_record(self, r):
        if r is None or r['phase'] != 'cleaned': raise ManagementError('management cleanup pending')
        self.verify_networks_closed(r)
        _, observed = self.preflight(r)
        if any(n in self.links() for n in self.desired()) or any(observed.values()):
            raise ManagementError('management cleanup has residual resources')

    def save(self, r):
        fd, tmp = tempfile.mkstemp(prefix='.management-', dir=self.directory)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(r, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, self.path)
            fd = os.open(self.directory, os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    def links(self):
        values = json.loads(self.run(['ip', '-j', '-d', 'link', 'show']))
        if not isinstance(values, list) or len({v['ifname'] for v in values}) != len(values):
            raise ManagementError('invalid management link inventory')
        return {v['ifname']: v for v in values}

    def desired(self):
        p = self.plan; result = {p['vrf']: dict(kind='vrf', config={'table': p['table']}, segment=None)}
        for key, s in p['segments'].items():
            result[s['bridge']] = dict(kind='bridge', config={}, segment=key)
            result[s['vxlan']] = dict(kind='vxlan', config={'id': s['vni'], 'local': s['local'], 'port': 4789, 'learning': False}, segment=key)
        for name, v in result.items():
            token = digest([self.key, p['generation'], name]); raw = bytearray(bytes.fromhex(token[:12])); raw[0] = (raw[0] & 0xfc) | 2
            v.update(name=name, alias='dnlab-management:' + token, mac=':'.join(f'{b:02x}' for b in raw))
        return result

    def rules(self, inactive=()):
        bridges = sorted(s['bridge'] for k,s in self.plan['segments'].items() if k not in inactive)
        comment = 'dnlab-management:' + digest([self.key, self.plan['generation']])
        # Routed traffic between different segments must traverse the jumphost.
        drops = [['FORWARD', '-i', self.plan['vrf'], '-m', 'comment', '--comment', comment, '-j', 'DROP']] + [['FORWARD', '-i', a, '-o', b, '-m', 'comment', '--comment', comment, '-j', 'DROP']
                 for a in bridges for b in bridges if a != b]
        accepts = [['FORWARD', '-' + d, b, '-m', 'comment', '--comment', comment, '-j', 'ACCEPT']
                   for b in bridges for d in ('i', 'o')]
        return drops + accepts

    def firewall(self, r):
        expected = self.rules(); observed = {}
        for tool in ('iptables', 'ip6tables'):
            lines = self.run([tool + '-save', '-t', 'filter']).splitlines()
            if ':FORWARD ' not in '\n'.join(lines): raise ManagementError(tool + ' FORWARD chain missing')
            rules = [shlex.split(line)[1:] for line in lines if line.startswith('-A ')]
            own = [v for v in rules if any(a.startswith('dnlab-management:') and a == expected[0][-3] for a in v)]
            if any(v not in expected for v in own) or len({tuple(v) for v in own}) != len(own):
                raise ManagementError('management firewall ownership/configuration differs')
            known = (r or {}).get('firewall', {}).get(tool, {})
            for rule in own:
                if digest(rule) not in known: raise ManagementError('unjournaled management firewall rule')
            vrf_drop = expected[0]
            if vrf_drop in own and any(rule[-1] == 'ACCEPT' for rule in own[:own.index(vrf_drop)]):
                raise ManagementError('management VRF DROP follows a bridge ACCEPT')
            observed[tool] = own
        return observed

    def preflight(self, r, *, deleting=()):
        links = self.links(); desired = self.desired(); resources = (r or {}).get('resources', {})
        for other in links.values():
            if (other.get('linkinfo', {}).get('info_kind') == 'vrf'
                    and other['linkinfo'].get('info_data', {}).get('table') == self.plan['table']
                    and other['ifname'] != self.plan['vrf']):
                raise ManagementError('management VRF table occupied')
        for name, v in desired.items():
            actual = links.get(name); proof = resources.get(name)
            if actual is None:
                if proof and proof.get('identity') and proof.get('phase') not in ('deleting', 'deleted'):
                    raise ManagementError('owned management resource disappeared: ' + name)
                continue
            pending_birth = (proof and proof.get('phase') == 'creating' and proof.get('identity') is None
                and not actual.get('ifalias') and actual.get('address') == v['mac'])
            if (not proof or proof.get('birth') != v or (actual.get('ifalias') != v['alias'] and not pending_birth)
                    or actual.get('linkinfo', {}).get('info_kind') != v['kind']
                    or proof.get('identity') and signature(actual) != proof['identity']
                    or any(actual.get('linkinfo', {}).get('info_data', {}).get(k) != val for k, val in v['config'].items())):
                raise ManagementError('unqualified/replaced management resource: ' + name)
            if actual.get('address') != v['mac']:
                raise ManagementError('management birth MAC differs')
            if v['kind'] == 'bridge' and (r or {}).get('steps', {}).get('address:' + name) == 'done':
                address = ipaddress.ip_interface(self.plan['segments'][v['segment']]['address'])
                actual_addresses = json.loads(self.run(['ip', '-j', 'addr', 'show', 'dev', name]))
                if not any(x.get('local') == str(address.ip) and x.get('prefixlen') == address.network.prefixlen
                        for interface in actual_addresses for x in interface.get('addr_info', [])):
                    raise ManagementError('management technical gateway disappeared or changed')
            if v['kind'] == 'vrf':
                if deleting and all(k in set(deleting) | set((r or {}).get('cleaned_segments', [])) for k in self.plan['segments']):
                    owned_bridges = {x['bridge'] for x in self.plan['segments'].values()}
                    if any(x.get('master') in (name, actual['ifindex']) and x['ifname'] not in owned_bridges for x in links.values()):
                        raise ManagementError('management VRF has unqualified child')
                for other in links.values():
                    if other['ifname'] != name and other.get('linkinfo', {}).get('info_kind') == 'vrf' and other['linkinfo'].get('info_data', {}).get('table') == self.plan['table']:
                        raise ManagementError('management VRF table occupied')
            else:
                s = self.plan['segments'][v['segment']]
                master = self.plan['vrf'] if v['kind'] == 'bridge' else s['bridge']
                expected_master = (master, links.get(master, {}).get('ifindex'))
                if ((actual.get('master') is not None or (r or {}).get('steps', {}).get('master:' + name) == 'done')
                        and actual.get('master') not in expected_master):
                    raise ManagementError('management resource belongs to another master')
                if v['segment'] in deleting and v['kind'] == 'bridge':
                    if any(x.get('master') in (name, actual['ifindex']) and x['ifname'] != s['vxlan'] for x in links.values()):
                        raise ManagementError('management bridge still has attached ports')
        for key, s in self.plan['segments'].items():
            underlay = links.get(s['underlay'])
            if not underlay: raise ManagementError('management underlay missing')
            if r and r.get('underlays', {}).get(key) not in (None, signature(underlay)):
                raise ManagementError('management underlay identity differs')
            for link in links.values():
                data = link.get('linkinfo', {}).get('info_data', {})
                if link.get('linkinfo', {}).get('info_kind') == 'vxlan' and data.get('id') == s['vni'] and link['ifname'] != s['vxlan']:
                    raise ManagementError('management VNI occupied by another tunnel')
            vx = links.get(s['vxlan'])
            if vx and vx.get('linkinfo', {}).get('info_data', {}).get('link') not in (s['underlay'], underlay['ifindex']):
                raise ManagementError('management VXLAN underlay differs')
            if vx:
                fdb = json.loads(self.run(['bridge', '-j', 'fdb', 'show', 'dev', s['vxlan']]))
                floods = [x for x in fdb if x.get('mac') == '00:00:00:00:00:00']
                recorded = (r or {}).get('fdb', {}).get(key, {})
                if (any(x.get('dst') not in s['remotes'] or x.get('dst') not in recorded
                        or set(x) != {'mac', 'dst', 'flags', 'state'} or x.get('flags') != ['self'] or x.get('state') != 'permanent' for x in floods)
                        or len(floods) != len({x.get('dst') for x in floods})):
                    raise ManagementError('management FDB ownership/configuration differs')
        observed = self.firewall(r)
        return links, observed

    def mutate(self, r, op, link=None, value=None, underlay=None):
        payload = dict(context=r['context'], op=op, value=value)
        if link is not None: payload['link'] = link
        if underlay is not None: payload['underlay'] = underlay
        return self.kernel(payload)

    def insert_rule(self, tool, rule):
        rules = [shlex.split(line)[1:] for line in self.run([tool + '-save', '-t', 'filter']).splitlines() if line.startswith('-A FORWARD ')]
        vrf_drop = self.rules()[0]
        if rule == vrf_drop: position = 1
        else:
            if vrf_drop not in rules: raise ManagementError('management VRF DROP must precede bridge accepts')
            position = rules.index(vrf_drop) + 2
        return self.run([tool, '-w', '-I', rule[0], str(position), *rule[1:]])

    def qualify_birth(self, r, name):
        self.preflight(r)
        proof = r['resources'][name]; actual = self.links()[name]
        if actual.get('ifalias') != proof['birth']['alias']:
            self.step(r, 'alias:' + name, lambda: self.mutate(r, 'alias', signature(actual), proof['birth']['alias']))
            actual = self.links()[name]
        self.preflight(r)
        proof['identity'] = signature(actual); proof['phase'] = 'active'; self.save(r)
        return proof

    def step(self, r, key, action):
        self.preflight(r)
        r['steps'][key] = 'intent'; self.save(r)
        action()
        r['steps'][key] = 'done'; self.save(r)

    def ensure(self, *, recover=False):
        with self.locked():
            r = self.read(); self.preflight(r)
            if r and r['phase'] != 'active' and not recover: raise ManagementError('management recovery required')
            if r and r['phase'] in ('cleaned', 'cleanup_pending'): raise ManagementError('management teardown cannot be restarted implicitly')
            r = r or dict(plan=self.plan, context=self.host_context(), phase='applying', resources={}, underlays={}, fdb={}, firewall={}, steps={})
            r['plan'] = self.plan; r['phase'] = 'applying'; self.save(r)
            try:
                for name, birth in self.desired().items():
                    if birth['segment'] in r.get('cleaned_segments', []): continue
                    links, _ = self.preflight(r)
                    s = self.plan['segments'].get(birth['segment'])
                    if s: r['underlays'].setdefault(birth['segment'], signature(links[s['underlay']]))
                    proof = r['resources'].setdefault(name, dict(birth=birth, phase='creating', identity=None)); self.save(r)
                    if name not in links:
                        self.step(r, 'create:' + name, lambda: self.mutate(r, 'create', value=birth,
                            underlay=signature(links[s['underlay']]) if birth['kind'] == 'vxlan' else None))
                    # Some kernels ignore IFALIAS at birth. The unpredictable MAC
                    # is set atomically, then qualifies an index-bound alias update.
                    proof = self.qualify_birth(r, name)
                    if s:
                        master = self.plan['vrf'] if birth['kind'] == 'bridge' else s['bridge']
                        self.step(r, 'master:' + name, lambda: self.mutate(r, 'master', proof['identity'], signature(self.links()[master])))
                    self.step(r, 'up:' + name, lambda: self.mutate(r, 'up', proof['identity']))
                    if birth['kind'] == 'bridge':
                        addresses = json.loads(self.run(['ip', '-j', 'addr', 'show', 'dev', name]))
                        ip = ipaddress.ip_interface(s['address'])
                        if not any(a.get('local') == str(ip.ip) and a.get('prefixlen') == ip.network.prefixlen for v in addresses for a in v.get('addr_info', [])):
                            self.step(r, 'address:' + name, lambda: self.mutate(r, 'address', proof['identity'], s['address']))
                    if birth['kind'] == 'vxlan':
                        for remote in s['remotes']:
                            r['fdb'].setdefault(birth['segment'], {})[remote] = 'intent'; self.save(r)
                            rows = json.loads(self.run(['bridge', '-j', 'fdb', 'show', 'dev', name]))
                            if not any(x.get('mac') == '00:00:00:00:00:00' and x.get('dst') == remote for x in rows):
                                self.step(r, 'fdb:' + name + ':' + remote, lambda: self.mutate(r, 'fdb-add', proof['identity'], remote))
                            r['fdb'][birth['segment']][remote] = 'done'; self.save(r)
                # Install the VRF guard first, then insert new selectors immediately
                # after it. An added segment must never precede the existing guard.
                for tool in ('iptables', 'ip6tables'):
                    rules = self.rules(r.get('cleaned_segments', []))
                    for rule in [rules[0], *reversed(rules[1:])]:
                        _, observed = self.preflight(r)
                        if rule not in observed[tool]:
                            r['firewall'].setdefault(tool, {})[digest(rule)] = 'intent'; self.save(r)
                            self.step(r, tool + ':' + digest(rule), lambda: self.insert_rule(tool, rule))
                            r['firewall'][tool][digest(rule)] = 'done'; self.save(r)
                self.preflight(r); r['phase'] = 'active'; self.save(r)
                return {'status': 'active', 'plan': digest(self.plan), 'context': r['context']}
            except Exception:
                # Intent was durable before the failing action. Never mask the original diagnostic.
                raise

    def cleanup(self, segments=None):
        selected = set(self.plan['segments'] if segments is None else segments)
        if not selected <= self.plan['segments'].keys(): raise ManagementError('unknown cleanup segment')
        with self.locked():
            r = self.read()
            if r is None: raise ManagementError('management cleanup requires birth journal')
            self.preflight(r, deleting=selected)
            self.verify_networks_closed(r, selected)
            r['phase'] = 'cleanup_pending'; r['cleanup_selection'] = sorted(selected); self.save(r)
            names = [s[k] for n, s in self.plan['segments'].items() if n in selected for k in ('vxlan', 'bridge')]
            remaining = set(self.plan['segments']) - selected - set(r.get('cleaned_segments', []))
            if not remaining: names.append(self.plan['vrf'])
            for name in names:
                proof = r['resources'].get(name)
                if not proof: continue
                self.preflight(r, deleting=selected)
                if name in self.links() and proof['identity'] is None: self.qualify_birth(r, name)
                proof['phase'] = 'deleting'; self.save(r)
                def remove():
                    if name in self.links(): self.mutate(r, 'delete', proof['identity'] or signature(self.links()[name]))
                    if name in self.links(): raise ManagementError('management link still present after delete')
                self.step(r, 'delete:' + name, remove)
                proof['phase'] = 'deleted'; self.save(r)
            for tool in ('iptables', 'ip6tables'):
                for rule in self.rules():
                    # Preserve rules for all still-active segments.
                    if remaining and not any(self.plan['segments'][n]['bridge'] in rule for n in selected): continue
                    _, observed = self.preflight(r, deleting=selected)
                    if rule in observed[tool]:
                        self.step(r, 'delete:' + tool + ':' + digest(rule), lambda: self.run([tool, '-w', '-D', *rule]))
            r['cleaned_segments'] = sorted(selected | set(r.get('cleaned_segments', [])))
            r['phase'] = 'active' if remaining else 'cleaned'; self.save(r)
            return {'status': r['phase'], 'plan': digest(self.plan)}

    def verify_ready(self, r):
        """Read-only readiness; admission alone allows not-yet-created objects."""
        if r is None or r['phase'] != 'active' or r['plan'] != self.plan or r.get('cleaned_segments'):
            raise ManagementError('complete active management generation required')
        links, firewall = self.preflight(r)
        identities = {}
        for name, birth in self.desired().items():
            actual = links.get(name); proof = r['resources'].get(name)
            if (actual is None or not proof or proof['phase'] != 'active' or not proof.get('identity')
                    or signature(actual) != proof['identity'] or 'UP' not in actual.get('flags', [])):
                raise ManagementError('management resource not ready: ' + name)
            segment = self.plan['segments'].get(birth['segment'])
            if segment:
                master = self.plan['vrf'] if birth['kind'] == 'bridge' else segment['bridge']
                if actual.get('master') not in (master, links[master]['ifindex']):
                    raise ManagementError('management master not ready: ' + name)
            identities[name] = proof['identity']
        for key, segment in self.plan['segments'].items():
            if r.get('underlays', {}).get(key) != signature(links[segment['underlay']]):
                raise ManagementError('management underlay proof not ready')
            address = ipaddress.ip_interface(segment['address'])
            rows = json.loads(self.run(['ip', '-j', 'addr', 'show', 'dev', segment['bridge']]))
            if not any(v.get('local') == str(address.ip) and v.get('prefixlen') == address.network.prefixlen
                       for row in rows for v in row.get('addr_info', [])):
                raise ManagementError('management technical gateway not ready')
            floods = json.loads(self.run(['bridge', '-j', 'fdb', 'show', 'dev', segment['vxlan']]))
            if any(r.get('fdb', {}).get(key, {}).get(remote) != 'done'
                   or not any(v.get('mac') == '00:00:00:00:00:00' and v.get('dst') == remote for v in floods)
                   for remote in segment['remotes']):
                raise ManagementError('management flood entry not ready')
        for tool in ('iptables', 'ip6tables'):
            if any(rule not in firewall[tool] for rule in self.rules()):
                raise ManagementError('management firewall not ready')
        proof = dict(context=r['context'], resources=identities,
                     underlays=r['underlays'], fdb=r.get('fdb', {}),
                     firewall={tool:self.rules() for tool in ('iptables', 'ip6tables')})
        return dict(status='ready', plan=digest(self.plan), proof=proof, fingerprint=digest(proof))

    def operate(self, action, segments=None):
        if action == 'verify-ready' and not self.directory.exists():
            raise ManagementError('complete active management generation required')
        if action == 'provision': return self.provision()
        if action == 'recover-provision': return self.provision(recover=True)
        if action == 'preflight-provision':
            if self.directory.exists():
                with self.locked(): self.preflight_provision()
            else: self.preflight(None)
            return {'status': 'verified', 'plan': digest(self.plan)}
        if action == 'ensure': return self.ensure()
        if action == 'recover':
            with self.locked(): r = self.read()
            if r and r['phase'] == 'cleanup_pending': return self.cleanup(r['cleanup_selection'])
            return self.ensure(recover=True)
        if action == 'cleanup': return self.cleanup(segments)
        if action in ('read', 'preflight') and not self.directory.exists():
            if action == 'read': return {'status': 'read', 'record': None, 'plan': digest(self.plan)}
            self.preflight(None)
            return {'status': 'verified', 'phase': 'absent', 'plan': digest(self.plan)}
        with self.locked():
            r = self.read(); self.preflight(r)
            if action == 'verify-ready': return self.verify_ready(r)
            if action == 'read': return {'status': 'read', 'plan': digest(self.plan), 'record': r}
            if action == 'preflight-cleanup':
                self.preflight(r, deleting=set(self.plan['segments']))
                if r is None: raise ManagementError('management cleanup requires birth journal')
                return {'status': 'verified', 'plan': digest(self.plan)}
            if action == 'preflight': return {'status': 'verified', 'phase': r['phase'] if r else 'absent', 'plan': digest(self.plan)}
            if action == 'verify-cleaned':
                self.verify_cleaned_record(r)
                return {'status': 'cleaned', 'plan': digest(self.plan)}
            raise ManagementError('unknown management action')


if __name__ == '__main__':
    p = json.load(sys.stdin)
    worker = Worker(p['plan'], directory=p['directory'])
    if p['action'].startswith('network-'):
        result = _NetworkGuard(worker, p['networks'], socket_path=p['socket_path'],plugin_path=p['plugin_path']).operate(p['action'][8:],p.get('operation_id'))
    else: result = worker.operate(p['action'],p.get('segments'))
    print(json.dumps(result))
