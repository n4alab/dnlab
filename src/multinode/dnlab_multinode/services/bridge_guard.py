"""Ownership checks for local bridges before attachment, reuse or teardown."""
import hashlib
import json
import re
import shlex

from dnlab_multinode.utils import naming


class BridgeOwnershipError(RuntimeError):
    pass


def interface(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}',value):
        raise BridgeOwnershipError('invalid bridge or endpoint name')
    return value


def signature(link):
    return {key:link.get(key) for key in ('ifname','ifindex','address','ifalias','link_index')}


class LocalBridgeGuard:
    def __init__(self,client,link,bridge):
        self.client,self.link,self.bridge=client,link,interface(bridge)
        self.endpoints=[interface(link.host_endpoint_a),interface(link.host_endpoint_b)]
        if len(set(self.endpoints))!=2:raise BridgeOwnershipError('bridge requires two distinct endpoints')
        scope=link.lab_name or '|'.join(sorted((link.container_a,link.container_b,*self.endpoints)))
        payload=json.dumps(['local-bridge',scope,link.id],ensure_ascii=True,separators=(',',':'))
        digest=hashlib.sha256(payload.encode()).hexdigest()
        self.alias='dnlab-runtime:bridge:'+digest
        data=bytearray(bytes.fromhex(digest[:12]));data[0]=(data[0]&0xfc)|2
        self.mac=':'.join(f'{byte:02x}' for byte in data)
        self.created=False

    def run(self,*args):
        return self.client.run(shlex.join(list(args)))

    def links(self):
        value=json.loads(self.run('ip','-j','-d','link','show'))
        if not isinstance(value,list):raise BridgeOwnershipError('invalid kernel link inventory')
        return value

    def context(self):
        source="import json,os; p=os.stat('/proc/self/ns/net'); print(json.dumps({'boot_id':open('/proc/sys/kernel/random/boot_id').read().strip(),'device':p.st_dev,'inode':p.st_ino}))"
        value=json.loads(self.run('python3','-c',source))
        if not isinstance(value,dict) or set(value)!={'boot_id','device','inode'}:
            raise BridgeOwnershipError('invalid host namespace identity')
        return value

    def record(self):
        return self.link.resource_identities.get('local_bridge')

    def inspect(self):
        records=self.links()
        candidates=[value for value in records if value.get('ifname')==self.bridge or value.get('ifalias')==self.alias]
        if not candidates:return None
        if len(candidates)!=1:raise BridgeOwnershipError('ambiguous local bridge ownership')
        value=candidates[0]
        if (value.get('ifname')!=self.bridge or value.get('ifalias')!=self.alias
                or value.get('address')!=self.mac or value.get('linkinfo',{}).get('info_kind')!='bridge'
                or type(value.get('ifindex')) is not int):
            raise BridgeOwnershipError('unqualified legacy or foreign bridge; explicit recovery required')
        prior=self.record()
        if prior and (prior['context']!=self.context() or prior['bridge']!=signature(value)):
            raise BridgeOwnershipError('bridge identity or host namespace changed')
        for port in records:
            if port.get('master') in (self.bridge,value['ifindex']) and port.get('ifname') not in self.endpoints:
                raise BridgeOwnershipError('bridge contains a foreign port')
        if prior:
            for expected in prior['sources']:
                current=next((x for x in records if x.get('ifname')==expected['ifname']),None)
                if current and signature(current)!=expected:
                    raise BridgeOwnershipError('bridge endpoint identity changed')
        return value

    def sources(self):
        records=self.links();result=[]
        for name in self.endpoints:
            value=next((x for x in records if x.get('ifname')==name),None)
            if not value or value.get('linkinfo',{}).get('info_kind')!='veth':
                raise BridgeOwnershipError('bridge endpoint missing or not a veth')
            if value.get('master') not in (None,self.bridge):
                bridge=next((x for x in records if x.get('ifname')==self.bridge),None)
                if not bridge or value.get('master')!=bridge['ifindex']:
                    raise BridgeOwnershipError('endpoint belongs to another bridge')
            result.append(signature(value))
        return result

    def ensure(self):
        existing=self.inspect()
        sources=self.sources()
        context=self.context()
        if existing:
            if not self.record():
                # Tagged resources can be qualified, untagged legacy ones cannot.
                self.link.resource_identities['local_bridge']={'bridge':signature(existing),'sources':sources,'context':context}
            return existing
        if self.record() and self.record()['context']!=context:
            raise BridgeOwnershipError('bridge host namespace changed')
        self.link.resource_identities.pop('local_bridge',None)
        self.run('ip','link','add',self.bridge,'address',self.mac,'type','bridge')
        self.created=True
        self.run('ip','link','set','dev',self.bridge,'alias',self.alias)
        existing=self.inspect()
        if not existing:raise BridgeOwnershipError('created bridge is absent')
        self.link.resource_identities['local_bridge']={'bridge':signature(existing),'sources':sources,'context':context}
        return existing

    def delete(self):
        if not self.inspect():return
        self.run('ip','link','delete',self.bridge)
        if any(value.get('ifname')==self.bridge for value in self.links()):
            raise BridgeOwnershipError('bridge still exists after deletion')
