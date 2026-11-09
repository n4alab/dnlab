"""Experimental local VXLAN/TC primitive with durable intent and owned cleanup.

Scheduling and VNI allocation remain with multinode. This primitive is not
wired to the production API. It accepts a previously qualified host veth,
never creates/removes that veth, and never changes guest carrier or bootstrap.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import threading
import uuid

from .link_identity import VxlanIdentity
from .manifest import Conflict, canonical
from .tc_ownership import reserve, qualified, require_capture
from .endpoint_reservations import require_available

PREF = 49152


def link_signature(link):
    return {key: link.get(key) for key in ('ifname', 'ifindex', 'ifalias', 'address', 'link_index')}


class VxlanLinux:
    def __init__(self, linux):
        self.linux = linux

    def network_identity(self):
        return self.linux.network_identity()

    def links(self):
        return json.loads(self.linux.run(['ip', '-j', '-d', 'link', 'show']))

    def qdiscs(self, name):
        return json.loads(self.linux.run(['tc', '-j', 'qdisc', 'show', 'dev', name]))

    def filters(self, name):
        return json.loads(self.linux.run(['tc', '-j', 'filter', 'show', 'dev', name, 'ingress']))

    def run(self, args):
        return self.linux.run(args)


def owned_filter(filters, target):
    """A single all-frame redirect at our reserved handle/priority."""
    # iproute2 emits a classifier header followed by its rule details.
    # Accept only one exact metadata header plus one detailed rule.
    if len(filters) == 2:
        header, rule = filters
        keys = {'protocol', 'pref', 'kind', 'chain'}
        if set(header) != keys or any(header[key] != rule.get(key) for key in keys):
            return False
    elif len(filters) == 1:
        rule = filters[0]
    else:
        return False
    options = rule.get('options', {})
    actions = options.get('actions', [])
    return (rule.get('kind') == 'matchall' and rule.get('pref') == PREF
            and rule.get('protocol') == 'all' and rule.get('chain', 0) == 0
            and type(options.get('handle')) in (int, str)
            and options.get('handle') in (1, '0x1', '1') and len(actions) == 1
            and actions[0].get('kind') == 'mirred'
            and actions[0].get('mirred_action') == 'redirect'
            and actions[0].get('direction') == 'egress'
            and actions[0].get('to_dev') == target
            and actions[0].get('control_action', {}).get('type') == 'stolen')


class VxlanManager:
    def __init__(self, journal, linux, *, check=None):
        self.journal, self.linux = journal, linux
        self.check = check or (lambda: None)
        with journal.lock:
            if not hasattr(journal, 'vxlan_execution_lock'):
                journal.vxlan_execution_lock = threading.RLock()
            self.lock = journal.vxlan_execution_lock
            self.lock_path = Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent / 'vxlan.lock'
        with journal.transaction():
            journal.db.execute('''CREATE TABLE IF NOT EXISTS local_vxlans (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, phase TEXT NOT NULL)''')

    @contextmanager
    def execution(self):
        with self.lock:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise Conflict('VXLAN execution lock ownership/mode mismatch')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Conflict('another VXLAN operation is running') from None
                yield
            finally:
                os.close(fd)

    def row(self, key):
        with self.journal.lock:
            row = self.journal.db.execute('SELECT * FROM local_vxlans WHERE id=?', (key,)).fetchone()
        return {'payload': json.loads(row['payload']), 'phase': row['phase']} if row else None

    def save(self, key, payload, phase):
        with self.journal.transaction():
            self.journal.db.execute('INSERT INTO local_vxlans VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,phase=excluded.phase', (key, canonical(payload), phase))

    def context(self, payload):
        if payload.get('network_identity') != self.linux.network_identity():
            raise Conflict('VXLAN network namespace or host boot changed; refusing mutation')

    def underlay(self, payload):
        self.context(payload)
        expected = payload['underlay_identity']
        actual = next((x for x in self.linux.links() if x['ifname'] == expected['ifname']), None)
        if not actual or link_signature(actual) != expected:
            raise Conflict('VXLAN underlay identity changed')
        if actual.get('mtu', 0) < payload['config']['mtu'] + 50:
            raise Conflict('VXLAN underlay MTU decreased')

    def source(self, payload):
        self.context(payload)
        before = payload['source']
        links = self.linux.links()
        found = next((x for x in links if x['ifname'] == before['ifname']), None)
        if found is None:
            if any(x['ifindex'] == before['ifindex'] for x in links):
                raise Conflict('VXLAN source was renamed; refusing mutation')
            return None
        if link_signature(found) != before:
            raise Conflict('VXLAN source identity changed; refusing mutation')
        return found

    def tunnel(self, identity, payload, *, complete=False):
        self.context(payload)
        links = self.linux.links()
        selectors = [x for x in links if x.get('ifname') == identity.kernel_name
                     or identity.altname in x.get('altnames', [])
                     or identity.ownership in x.get('altnames', [])]
        if not selectors:
            return None
        if len(selectors) != 1:
            raise Conflict('ambiguous VXLAN identity')
        link = selectors[0]
        config = payload['config']
        data = link.get('linkinfo', {}).get('info_data', {})
        parent = next((x for x in links if x['ifname'] == data.get('link')), None)
        # Bind by ifindex so owned cleanup also works after underlay rename.
        parent_index = parent['ifindex'] if parent else data.get('link')
        if (link.get('ifname') != identity.kernel_name
                or not payload.get('creator_mac') or link.get('address') != payload['creator_mac']
                or (payload.get('alias_committed') and link.get('ifalias') != payload['creator'])
                or (not payload.get('alias_committed') and link.get('ifalias') not in (None, '', payload['creator']))
                or link.get('linkinfo', {}).get('info_kind') != 'vxlan'
                or data.get('id') != identity.vni or data.get('remote') != config['remote']
                or data.get('local') != config['local']
                or parent_index != payload['underlay_identity']['ifindex']
                or data.get('port') != 14789 or data.get('learning') is not True
                or link.get('mtu') != config['mtu']
                or (payload.get('tunnel_index') is not None and link['ifindex'] != payload['tunnel_index'])):
            # Preserve raw ownership/configuration evidence in the private journal
            # before cleanup attempts; do not weaken the mutation guard.
            payload['tunnel_identity_failure'] = {'expected_creator': payload['creator'],
                                                  'observed': link}
            raise Conflict('VXLAN creator/configuration/kernel identity mismatch')
        if complete:
            identity.resolve(links, expected_index=payload['tunnel_index'])
        return link

    def intent(self, identity, payload, step, argv):
        self.underlay(payload)
        if self.source(payload) is None:
            raise Conflict('VXLAN source disappeared')
        payload['step'] = step
        self.save(identity.digest, payload, 'creating')
        self.check()
        self.linux.run(argv)

    def create(self, identity, *, source, underlay, local, remote, mtu):
        if not isinstance(identity, VxlanIdentity):
            raise Conflict('VXLAN identity required')
        for address in (local, remote):
            if not isinstance(address, str) or ipaddress.ip_address(address).version != 4:
                raise Conflict('this VXLAN primitive qualifies IPv4 underlay only')
        if source.get('ifname') != identity.host_endpoint or not source.get('ifalias', '').startswith('dnlab-runtime:'):
            raise Conflict('qualified runtime-owned host endpoint required')
        if type(mtu) is not int or mtu < 68:
            raise Conflict('invalid VXLAN MTU')
        config = {'source': link_signature(source), 'underlay': underlay, 'local': local, 'remote': remote, 'mtu': mtu}
        with self.execution():
            from .management_barrier import check as management_check
            management_check(self.journal,identity.lab_id)
            from .lab_closure import get
            fence=get(self.journal,identity.lab_id)
            if fence and fence['phase']!='open':raise Conflict('lab is closing or closed')
            require_available(self.journal,[identity.host_endpoint],owner_table='local_vxlans',owner_id=identity.digest)
            prior = self.row(identity.digest)
            if prior and prior['phase'] != 'cleaned':
                if prior['payload']['config'] != config:
                    raise Conflict('existing VXLAN cannot be implicitly reconfigured')
                if prior['phase'] != 'active':
                    raise Conflict('VXLAN requires explicit recovery before retry')
                self.verify(identity, prior['payload'])
                return prior['payload']
            links = self.linux.links()
            observed = next((x for x in links if x['ifname'] == identity.host_endpoint), None)
            if not observed or observed.get('linkinfo', {}).get('info_kind') != 'veth' or link_signature(observed) != config['source']:
                raise Conflict('source is not the qualified host veth')
            parent = next((x for x in links if x['ifname'] == underlay), None)
            if not parent or type(parent.get('mtu')) is not int or mtu > parent['mtu'] - 50:
                raise Conflict('underlay missing or insufficient MTU')
            if identity.resolve(links) is not None:
                raise Conflict('VXLAN exists without this journal; refusing adoption')
            if self.linux.filters(identity.host_endpoint):
                raise Conflict('source ingress already has filters; refusing replacement')
            ingress = [x for x in self.linux.qdiscs(identity.host_endpoint) if x['kind'] in ('ingress', 'clsact')]
            payload = {'lab_id':identity.lab_id,'config': config, 'source': config['source'], 'creator': 'dnlab-vxlan:' + uuid.uuid4().hex,
                       'source_qdisc_created': not bool(ingress), 'step': 'reserved',
                       'network_identity': self.linux.network_identity(),
                       'underlay_identity': link_signature(parent)}
            # MAC is retained atomically by kernel link creation; ifalias is not.
            # Persist this random per-attempt proof before the first mutation.
            mac = bytearray(hashlib.sha256(payload['creator'].encode()).digest()[:6])
            mac[0] = (mac[0] & 0xfc) | 0x02  # Local unicast, 46 bits of nonce entropy.
            payload['creator_mac'] = ':'.join(f'{octet:02x}' for octet in mac)
            payload['alias_committed'] = False
            # Reserve source, endpoint altname and short kernel name in this journal.
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO local_vxlans VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,phase=excluded.phase', (identity.digest, canonical(payload), 'creating'))
            try:
                self.intent(identity, payload, 'create_tunnel', ['ip', 'link', 'add', identity.kernel_name, 'address', payload['creator_mac'],
                    'mtu', str(mtu), 'type', 'vxlan', 'id', str(identity.vni), 'local', local, 'remote', remote,
                    'dev', underlay, 'dstport', '14789', 'learning'])
                payload['tunnel_index'] = self.tunnel(identity, payload)['ifindex']
                self.intent(identity, payload, 'set_alias', ['ip', 'link', 'set', 'dev', identity.kernel_name, 'alias', payload['creator']])
                payload['alias_committed'] = True
                self.tunnel(identity, payload)
                for name in (identity.altname, identity.ownership):
                    self.intent(identity, payload, 'add_altname', ['ip', 'link', 'property', 'add', 'dev', identity.kernel_name, 'altname', name])
                self.intent(identity, payload, 'tunnel_up', ['ip', 'link', 'set', 'dev', identity.kernel_name, 'up'])
                if payload['source_qdisc_created']:
                    self.intent(identity, payload, 'source_qdisc', ['tc', 'qdisc', 'add', 'dev', identity.host_endpoint, 'ingress'])
                self.intent(identity, payload, 'tunnel_qdisc', ['tc', 'qdisc', 'add', 'dev', identity.kernel_name, 'ingress'])
                records=self.linux.links()
                pairs=((identity.kernel_name, identity.host_endpoint), (identity.host_endpoint, identity.kernel_name))
                payload['tc_proofs']={src:reserve(next(v for v in records if v['ifname']==src),
                                                next(v for v in records if v['ifname']==dst)) for src,dst in pairs}
                self.save(identity.digest,payload,'creating')
                for src, dst in pairs:
                    self.intent(identity, payload, 'redirect', ['tc', 'filter', 'add', 'dev', src, 'ingress', 'protocol', 'all',
                        'pref', str(PREF), 'handle', '1', 'matchall', 'action', 'mirred', 'egress', 'redirect', 'dev', dst,
                        'cookie',payload['tc_proofs'][src]['cookie']])
                    require_capture(self.linux.filters(src),dst,owned_filter,payload['tc_proofs'][src],self.linux.links())
                    self.save(identity.digest,payload,'creating')
                self.check()
                self.verify(identity, payload)
                self.save(identity.digest, payload, 'active')
                return payload
            except Exception as error:
                payload['error'] = f'{type(error).__name__}: {error}'
                try:
                    self._cleanup(identity, payload)
                except Exception as cleanup_error:
                    payload['cleanup_error'] = f'{type(cleanup_error).__name__}: {cleanup_error}'
                    self.save(identity.digest, payload, 'recovery_required')
                raise

    def owned_redirect(self,payload,values,target,source):
        if 'tc_proofs' in payload and source not in payload['tc_proofs']:return False
        return qualified(values,target,owned_filter,payload.get('tc_proofs',{}).get(source),self.linux.links())

    def verify(self, identity, payload):
        self.underlay(payload)
        if self.source(payload) is None:
            raise Conflict('VXLAN source missing')
        tunnel = self.tunnel(identity, payload, complete=True)
        if not tunnel or 'UP' not in tunnel.get('flags', []):
            raise Conflict('VXLAN not up')
        source_rules = self.linux.filters(identity.host_endpoint)
        tunnel_rules = self.linux.filters(identity.kernel_name)
        payload['tc_verification'] = {'source': source_rules, 'tunnel': tunnel_rules}
        if not self.owned_redirect(payload,source_rules,identity.kernel_name,identity.host_endpoint):
            raise Conflict('source redirect verification failed')
        if not self.owned_redirect(payload,tunnel_rules,identity.host_endpoint,identity.kernel_name):
            raise Conflict('tunnel redirect verification failed')

    def cleanup_preflight(self, identity, payload):
        source = self.source(payload)
        tunnel = self.tunnel(identity, payload)
        if source:
            rules = self.linux.filters(identity.host_endpoint)
            if rules and not self.owned_redirect(payload,rules,identity.kernel_name,identity.host_endpoint):
                raise Conflict('foreign or changed source filters; refusing cleanup')
            if payload['source_qdisc_created']:
                ingress = [x for x in self.linux.qdiscs(identity.host_endpoint) if x['kind'] in ('ingress', 'clsact')]
                if ingress and (len(ingress) != 1 or ingress[0]['kind'] != 'ingress'):
                    raise Conflict('source qdisc changed; refusing deletion')
        if tunnel:
            rules = self.linux.filters(identity.kernel_name)
            if rules and not self.owned_redirect(payload,rules,identity.host_endpoint,identity.kernel_name):
                raise Conflict('foreign or changed tunnel filters; refusing cleanup')
        return source,tunnel

    def _cleanup(self, identity, payload):
        self.cleanup_preflight(identity,payload)
        self.save(identity.digest, payload, 'deleting')
        source = self.source(payload)
        tunnel = self.tunnel(identity, payload)
        if source:
            rules = self.linux.filters(identity.host_endpoint)
            if rules:
                if not self.owned_redirect(payload,rules,identity.kernel_name,identity.host_endpoint):
                    raise Conflict('foreign or changed source filters; refusing cleanup')
                self.linux.run(['tc', 'filter', 'delete', 'dev', identity.host_endpoint, 'ingress',
                                'protocol', 'all', 'pref', str(PREF), 'handle', '1', 'matchall'])
            if payload['source_qdisc_created']:
                ingress = [x for x in self.linux.qdiscs(identity.host_endpoint) if x['kind'] in ('ingress', 'clsact')]
                if ingress:
                    if len(ingress) != 1 or ingress[0]['kind'] != 'ingress' or self.linux.filters(identity.host_endpoint):
                        raise Conflict('source qdisc changed; refusing deletion')
                    self.linux.run(['tc', 'qdisc', 'delete', 'dev', identity.host_endpoint, 'ingress'])
        if tunnel:
            self.tunnel(identity, payload)  # Recheck ownership before destructive step.
            self.linux.run(['ip', 'link', 'delete', 'dev', identity.kernel_name])
        if self.tunnel(identity, payload) is not None:
            raise Conflict('VXLAN cleanup incomplete')
        self.save(identity.digest, payload, 'cleaned')

    def delete(self, identity):
        with self.execution():
            row = self.row(identity.digest)
            if row is None:
                raise Conflict('VXLAN not tracked by this journal')
            if row['phase'] == 'cleaned':
                return
            try:
                self._cleanup(identity, row['payload'])
            except Exception as error:
                row['payload']['cleanup_error'] = f'{type(error).__name__}: {error}'
                self.save(identity.digest, row['payload'], 'recovery_required')
                raise

    def recover(self, identity):
        # Explicit per-link recovery, never scans/mutates another VD or lab.
        self.delete(identity)
