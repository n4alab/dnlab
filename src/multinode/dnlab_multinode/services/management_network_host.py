"""Standalone Docker management-network birth and generation guard.

Uses the kernel worker's lock and durable journal. Docker endpoint attachment
must be preceded by mark-used; losing a used network never authorizes creation.
"""
import copy
import http.client
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
from urllib.parse import quote
import uuid


class NetworkError(RuntimeError):
    pass


class Docker:
    def __init__(self, path):
        if not isinstance(path, str) or not path.startswith('/'): raise NetworkError('Docker Unix socket required')
        self.path = path

    def call(self, method, path, body=None, *, absent=False):
        connection = http.client.HTTPConnection('localhost', timeout=30)
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(30)
        try:
            connection.sock.connect(self.path)
            payload = None if body is None else json.dumps(body)
            connection.request(method, path, payload, {'Content-Type': 'application/json'})
            response = connection.getresponse(); raw = response.read()
            if 200 <= response.status < 300 and not raw:
                if method == 'GET': raise NetworkError('empty Docker GET response is not absence')
                value = None
            else:
                try: value = json.loads(raw)
                except (ValueError, UnicodeDecodeError): raise NetworkError('invalid Docker HTTP response') from None
            if absent and response.status == 404 and isinstance(value, dict) and isinstance(value.get('message'), str): return None
            if not 200 <= response.status < 300: raise NetworkError(f'Docker HTTP {response.status}: {str(value)[:500]}')
            return value
        except (OSError, http.client.HTTPException) as error: raise NetworkError('Docker transport failed; recovery required: ' + str(error)) from None
        finally: connection.close()

    def inspect(self, identity):
        value = self.call('GET', '/networks/' + quote(identity, safe=''), absent=True)
        if value is not None and (not isinstance(value, dict) or not re.fullmatch('[0-9a-f]{64}', value.get('Id', ''))):
            raise NetworkError('invalid Docker network inspection')
        return value

    def create(self, config): return self.call('POST', '/networks/create', config)
    def delete(self, identity): return self.call('DELETE', '/networks/' + quote(identity, safe=''), absent=True)


def plugin_state(path):
    try: fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error: raise NetworkError('plugin state unavailable: ' + str(error)) from None
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise NetworkError('plugin state ownership/mode differs')
        value = json.load(stream)
    if (not isinstance(value, dict) or value.get('version') != 2
            or any(not isinstance(value.get(k), dict) for k in ('networks', 'endpoints', 'pools'))):
        raise NetworkError('invalid plugin state')
    return value


def desired(expected):
    required = {'driver','ipam_driver','network','bridge','vrf','lab','ipv4_subnet','ipv4_gateway','host_index','host_count','reserved','labels'}
    if (not isinstance(expected, dict) or not required <= expected.keys()
            or set(expected) - required - {'ipv6_subnet','ipv6_gateway'}): raise NetworkError('complete network configuration required')
    if expected['driver'] != 'dnlab-vrf' or expected['ipam_driver'] != 'dnlab-vrf': raise NetworkError('dnlab-vrf network/IPAM required')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', expected['network']): raise NetworkError('invalid network name')
    if type(expected['host_count']) is not int or type(expected['host_index']) is not int or not 0 <= expected['host_index'] < expected['host_count']:
        raise NetworkError('invalid IPAM host partition')
    configs = []
    for family in (4, 6):
        subnet, gateway = expected.get(f'ipv{family}_subnet'), expected.get(f'ipv{family}_gateway')
        if not subnet and not gateway: continue
        network = ipaddress.ip_network(subnet, strict=True); ip = ipaddress.ip_address(gateway)
        if network.version != family or ip.version != family or ip not in network: raise NetworkError('invalid IPAM subnet/gateway')
        configs.append(dict(Subnet=str(network), Gateway=str(ip)))
    labels = {'io.dnlab.managed':'mgmt-vrf', 'io.dnlab.lab':expected['lab']}
    if expected['labels'] != labels: raise NetworkError('management ownership labels differ')
    return dict(Name=expected['network'], CheckDuplicate=True, Driver='dnlab-vrf', EnableIPv6=bool(expected.get('ipv6_subnet')),
        Internal=False, Attachable=False, Ingress=False, Labels=labels,
        Options={'dnlab.bridge':expected['bridge'],'dnlab.vrf':expected['vrf'],'dnlab.lab':expected['lab']},
        IPAM=dict(Driver='dnlab-vrf', Options={'dnlab.tenant':expected['network'],'dnlab.reserved':','.join(expected['reserved']),
            'dnlab.host-index':str(expected['host_index']),'dnlab.host-count':str(expected['host_count'])},Config=configs))


class NetworkGuard:
    def __init__(self, worker, networks, *, docker=None, socket_path='/var/run/docker.sock', plugin_path='/var/lib/dnlab-vrf-plugin/state.json', plugin=None):
        self.operation_id = None
        self.worker = worker; self.networks = copy.deepcopy(networks)
        self.transport = dict(socket_path=socket_path,plugin_path=plugin_path)
        self.docker = docker or Docker(socket_path); self.plugin = plugin or (lambda: plugin_state(plugin_path))
        if not isinstance(networks, dict) or not networks or not networks.keys() <= worker.plan['segments'].keys():
            raise NetworkError('network segment intent required')
        names = []
        for key, expected in networks.items():
            config = desired(expected); segment = worker.plan['segments'][key]; names.append(config['Name'])
            if (expected['lab'] != worker.plan['lab'] or expected['vrf'] != worker.plan['vrf'] or expected['bridge'] != segment['bridge']
                    or str(ipaddress.ip_interface(segment['address']).ip) != expected['ipv4_gateway']
                    or str(ipaddress.ip_interface(segment['address']).network) != expected['ipv4_subnet']):
                raise NetworkError('network intent and kernel segment differ')
        if len(names) != len(set(names)): raise NetworkError('duplicate Docker network name')

    @staticmethod
    def config(row):
        value = desired(row['expected']); value['Labels']['org.dnlab.management.creator'] = row['nonce']
        return value

    def read(self):
        record = self.worker.read()
        if record is None: raise NetworkError('kernel management journal required before network mutation')
        if record.get('network_transport', self.transport) != self.transport: raise NetworkError('network transport identity differs')
        for key, row in record.get('networks', {}).items():
            if key in self.networks and row['expected'] != self.networks[key]: raise NetworkError('network desired configuration changed')
        return record

    def plugin_check(self, row, actual):
        state = self.plugin(); expected = row['expected']; identity = actual['Id'] if actual else row.get('id')
        for key, network in state['networks'].items():
            if not isinstance(network, dict): raise NetworkError('invalid plugin network record')
            if network.get('bridge') == expected['bridge'] and key != identity:
                raise NetworkError('plugin bridge is bound to another network generation')
        endpoints = [v for v in state['endpoints'].values() if v.get('network_id') == identity] if identity else []
        pools = [v for v in state['pools'].values() if isinstance(v,dict) and v.get('tenant') == expected['network']]
        if actual is not None:
            cidrs = {expected['ipv4_subnet']} | ({expected['ipv6_subnet']} if expected.get('ipv6_subnet') else set())
            if {v.get('pool') for v in pools} != cidrs or len(pools) != len(cidrs):
                raise NetworkError('plugin IPAM pool inventory differs')
            for pool in pools:
                family = ipaddress.ip_network(pool['pool']).version
                reserved = sorted(v for v in expected['reserved'] if ipaddress.ip_address(v).version == family)
                if (pool.get('host_index') != expected['host_index'] or pool.get('host_count') != expected['host_count']
                        or pool.get('v6') is not (family == 6) or pool.get('reserved') != reserved
                        or not isinstance(pool.get('allocated'),list)):
                    raise NetworkError('plugin IPAM partition/reservations differ')
        if actual is None:
            if pools: raise NetworkError('plugin IPAM pool recovery pending')
            if identity in state['networks'] or endpoints: raise NetworkError('plugin network/endpoint recovery pending')
        else:
            network = state['networks'].get(identity)
            if network is None: raise NetworkError('Docker network has no plugin generation proof')
            wanted = {'bridge':expected['bridge'], 'vrf':expected['vrf'], 'lab':expected['lab'],
                      'ipv4_subnet':expected['ipv4_subnet'],'ipv4_gateway':expected['ipv4_gateway'],
                      'ipv6_subnet':expected.get('ipv6_subnet',''),'ipv6_gateway':expected.get('ipv6_gateway','')}
            if any(network.get(k, '') != v for k,v in wanted.items()): raise NetworkError('plugin network configuration differs')
        return endpoints

    def observe(self, row, *, missing=False, pending=False):
        actual = self.docker.inspect(row['expected']['network'])
        original = self.docker.inspect(row['id']) if row.get('id') else None
        if row.get('id'):
            if actual is not None and actual['Id'] != row['id']: raise NetworkError('Docker management network was replaced')
            if original is not None and (actual is None or original['Id'] != actual['Id']): raise NetworkError('Docker network name/ID disagree')
        if actual is None:
            self.plugin_check(row, None)
            if not missing: raise NetworkError('management network disappeared; explicit restore required')
            return None
        if not row.get('id') and not pending: raise NetworkError('network birth response requires explicit recovery')
        wanted = self.config(row)
        keys = ('Name','Driver','EnableIPv6','Internal','Attachable','Ingress','Labels','Options')
        if any(actual.get(k) != wanted[k] for k in keys) or actual.get('Scope') != 'local' or actual.get('ConfigOnly',False) is not False:
            raise NetworkError('Docker network ownership/configuration differs')
        if actual.get('IPAM') != wanted['IPAM']: raise NetworkError('Docker network IPAM differs')
        if not isinstance(actual.get('Containers'), dict): raise NetworkError('invalid Docker endpoint inventory')
        if actual['Containers'] and not row['used']: raise NetworkError('network has unadmitted endpoints')
        self.plugin_check(row, actual)
        return actual

    def preflight(self, record, *, action='ensure'):
        # This path may precede the initial kernel allocation: it performs only reads.
        if record is not None:
            if action == 'restore' and self.operation_id in record.get('network_restore_requests',{}):
                if record['network_restore_requests'][self.operation_id] != self.networks:raise NetworkError('restore request definition/targets changed')
            if record.get('network_transport',self.transport) != self.transport: raise NetworkError('network transport differs')
            self.worker.preflight(record)
            if record['phase'] != 'active' and not (action == 'provision-recover' and record['phase'] == 'applying') and action not in ('cleanup','verify-cleaned','inspect-teardown'):
                raise NetworkError('kernel infrastructure recovery required first')
            if action == 'provision-recover' and (record.get('cleaned_segments') or record.get('network_operation',{}).get('phase') == 'pending' and record.get('network_operation',{}).get('action') in ('cleanup','restore')):
                raise NetworkError('network teardown/restore needs its original recovery operation')
        for key, expected in self.networks.items():
            row = (record or {}).get('networks', {}).get(key)
            if row is None:
                if self.docker.inspect(expected['network']) is not None: raise NetworkError('unqualified legacy Docker network; no adoption')
                self.plugin_check(dict(expected=expected,id=None),None)
                if action not in ('ensure','recover','cleanup','verify-cleaned','provision-recover'): raise NetworkError('network birth journal missing')
                continue
            if row['expected'] != expected: raise NetworkError('network configuration changed')
            actual = self.observe(row, missing=action in ('recover','restore','cleanup','verify-cleaned','inspect-teardown','provision-recover'), pending=action in ('recover','cleanup','provision-recover') or action=='restore' and row.get('restore_id')==self.operation_id)
            if action == 'provision-recover' and row['phase'] not in ('active','creating'):
                raise NetworkError('network birth/active generation required for provisioning recovery')
            if action == 'cleanup' and actual and (actual['Containers'] or self.plugin_check(row,actual)):
                raise NetworkError('network still has endpoints')
            if action == 'restore' and row.get('restore_id') != self.operation_id:
                if any(v.get('restore_id') == self.operation_id for v in row.get('history',[])): raise NetworkError('historical restore request cannot be reused')
                if actual is not None: raise NetworkError('restore requires original network absence on all hosts')
                bridge = self.worker.links().get(expected['bridge'],{})
                if any(v.get('master') in (expected['bridge'],bridge.get('ifindex')) and v.get('master') is not None
                       and v['ifname'] != self.worker.plan['segments'][key]['vxlan'] for v in self.worker.links().values()):
                    raise NetworkError('restore requires attachment cleanup on all hosts')
            if action in ('recover','provision-recover') and actual is None and (row['used'] or row['id'] is not None) and row['phase'] not in ('deleting','cleaned'):
                raise NetworkError('network disappeared; explicit restore required')
            if action == 'ensure' and row['phase'] != 'active': raise NetworkError('network operation requires explicit recovery')

    def operate(self, action, operation_id=None):
        if operation_id is not None and not re.fullmatch('[0-9a-f]{32}',operation_id): raise NetworkError('invalid network operation identity')
        self.operation_id = operation_id or (uuid.uuid4().hex if action in ('restore','preflight-restore') else None)
        if action == 'verify-ready' and not self.worker.directory.exists():
            raise NetworkError('active management network journal required')
        # Admission before journal creation is strictly read-only.
        if action in ('preflight','preflight-provision-recover') and not self.worker.directory.exists():
            self.preflight(None,action='provision-recover' if action=='preflight-provision-recover' else 'ensure'); return self.receipt('verified')
        with self.worker.locked():
            loaded = self.worker.load()
            if loaded is not None and loaded['plan']['generation'] != self.worker.plan['generation']:
                if action not in ('preflight','preflight-provision-recover'): raise NetworkError('kernel generation must be provisioned explicitly first')
                self.worker.preflight_provision();self.preflight(None);return self.receipt('verified')
            record = self.read() if loaded is not None else None
            if action in ('recover','preflight-recover') and record and record.get('network_operation',{}).get('action') == 'restore' and record['network_operation'].get('phase') == 'pending':
                self.operation_id = record['network_operation']['id']
                action = 'restore' if action == 'recover' else 'preflight-restore'
            if action.startswith('preflight-'):
                mode = {'preflight-cleanup':'cleanup','preflight-restore':'restore','preflight-recover':'recover','preflight-teardown':'inspect-teardown','preflight-provision-recover':'provision-recover'}[action]
                if mode == 'recover' and record and record.get('network_operation',{}).get('action')=='cleanup': mode='cleanup'
                self.preflight(record,action=mode); return self.receipt('verified')
            if action == 'preflight': self.preflight(record); return self.receipt('verified')
            if record is None: raise NetworkError('kernel management journal required')
            if action == 'verify-ready':
                kernel = self.worker.verify_ready(record)
                if record.get('network_operation', {}).get('phase') != 'done':
                    raise NetworkError('management network operation still pending')
                proofs = {}
                self.preflight(record)
                for key in self.networks:
                    row = record.get('networks', {}).get(key)
                    if not row or row['phase'] != 'active' or not row.get('id'):
                        raise NetworkError('management network not ready')
                    actual = self.observe(row)
                    proofs[key] = dict(id=actual['Id'], nonce=row['nonce'], expected=row['expected'])
                proof = dict(kernel=kernel, networks=proofs)
                encoded = json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()
                return dict(self.receipt('ready'), proof=proof, fingerprint=hashlib.sha256(encoded).hexdigest())
            # Cleanup can finish absent resources, but may never bind a replacement.
            if action == 'recover' and record.get('network_operation',{}).get('action') == 'cleanup': action='cleanup'
            mode = action
            self.preflight(record, action=mode)
            if action == 'verify-cleaned':
                if any(record.get('networks',{}).get(k,{}).get('phase') != 'cleaned' for k in self.networks):
                    raise NetworkError('network cleanup journal pending')
                if any(self.docker.inspect(v['network']) is not None for v in self.networks.values()): raise NetworkError('network cleanup has residual objects')
                return self.receipt('cleaned')
            if action not in ('ensure','recover','restore','mark-used','cleanup'): raise NetworkError('invalid network action')
            record.setdefault('network_transport',self.transport)
            if action == 'restore':record.setdefault('network_restore_requests',{}).setdefault(self.operation_id,copy.deepcopy(self.networks))
            record['network_operation']=dict(id=self.operation_id,action=action,segments=sorted(self.networks),phase='pending');self.worker.save(record)
            for key, expected in self.networks.items():
                row = record.setdefault('networks',{}).get(key)
                if row is None:
                    if action not in ('ensure','recover','cleanup'): raise NetworkError('network birth intent missing')
                    row = dict(expected=copy.deepcopy(expected),nonce=uuid.uuid4().hex,id=None,phase='creating',used=False,attempted=False,history=[])
                    record['networks'][key] = row; self.worker.save(record)
                if action == 'cleanup':
                    actual = self.observe(row,missing=True,pending=True)
                    if actual and (actual['Containers'] or self.plugin_check(row,actual)): raise NetworkError('network still has endpoints')
                    if actual and not row['id']: row['id']=actual['Id'];self.worker.save(record)
                    row['phase']='deleting';self.worker.save(record)
                    if actual:
                        self.observe(row)  # Repeat identity immediately before ID-bound deletion.
                        self.docker.delete(row['id'])
                    if self.observe(row,missing=True) is not None: raise NetworkError('network remains after delete')
                    row['phase']='cleaned';self.worker.save(record);continue
                if action == 'mark-used':
                    self.observe(row)
                    if row['phase'] != 'active': raise NetworkError('network is not ready')
                    row['used']=True;self.worker.save(record);continue
                actual = self.observe(row,missing=True,pending=action=='recover' or action=='restore' and row.get('restore_id')==self.operation_id)
                if action == 'restore' and row.get('restore_id') == self.operation_id:
                    if actual is not None:
                        if row['id'] is None: row['id']=actual['Id'];row['phase']='active';self.worker.save(record)
                        continue
                    if row['id'] is not None or row['used']: raise NetworkError('restored network disappeared; new explicit restore required')
                elif action == 'restore':
                    if actual is not None: raise NetworkError('restore requires original network to be absent')
                    if row['phase'] not in ('active','creating'): raise NetworkError('network teardown cannot be restored')
                    if any(v.get('master') in (expected['bridge'], self.worker.links().get(expected['bridge'],{}).get('ifindex'))
                           and v['ifname'] != self.worker.plan['segments'][key]['vxlan'] for v in self.worker.links().values()):
                        raise NetworkError('restore requires previous attachments to be cleaned explicitly')
                    row['history'].append({k:copy.deepcopy(v) for k,v in row.items() if k!='history'})
                    row.update(nonce=uuid.uuid4().hex,id=None,phase='creating',used=False,attempted=False,restore_id=self.operation_id);self.worker.save(record)
                elif actual is not None:
                    if row['id'] is None:row['id']=actual['Id'];row['phase']='active';self.worker.save(record)
                    continue
                elif row['used'] or row['id'] is not None:
                    raise NetworkError('network disappeared; explicit restore required')
                elif row['attempted'] and action != 'recover':raise NetworkError('network creation requires explicit recovery')
                if row['phase'] != 'creating': raise NetworkError('new network generation requires explicit restore')
                self.worker.preflight(record);row['attempted']=True;self.worker.save(record)
                result = self.docker.create(self.config(row))
                if not isinstance(result,dict) or not re.fullmatch('[0-9a-f]{64}',result.get('Id','')): raise NetworkError('invalid network create acknowledgement')
                row['id']=result['Id'];self.worker.save(record)
                self.observe(row);row['phase']='active';self.worker.save(record)
            record['network_operation']['phase']='done';self.worker.save(record)
            return self.receipt('cleaned' if action=='cleanup' else 'active')

    def receipt(self,status):
        # Request digest ties acknowledgements to both kernel generation and all network definitions.
        return dict(status=status,plan=hashlib.sha256(json.dumps(self.worker.plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),networks=self.networks)
