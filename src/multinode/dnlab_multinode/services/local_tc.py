"""Owned LLDP/LACP forwarding without taking ownership of shared clsact state."""
import json

from .bridge_guard import BridgeOwnershipError,signature

PROTOCOLS=(('0x88cc',49140),('0x8809',49141))


def protocol_matches(value,protocol):
    number=int(protocol,16)
    return value in (protocol,protocol[2:],f'[{number}]') or (number==0x88cc and value in ('LLDP','lldp'))


def owned_rule(values,protocol,pref,target):
    if len(values)==2:
        header,rule=values
        keys={'protocol','pref','kind','chain'}
        if set(header)!=keys or any(header[k]!=rule.get(k) for k in keys):return False
    elif len(values)==1:rule=values[0]
    else:return False
    options=rule.get('options',{})
    actions=options.get('actions',[])
    if len(actions)!=1:return False
    action=actions[0]
    return (rule.get('pref')==pref and rule.get('chain',0)==0 and rule.get('kind')=='flower'
            and protocol_matches(rule.get('protocol'),protocol)
            and type(options.get('handle')) in (int,str) and options.get('handle') in (1,'1','0x1')
            and options.get('keys')=={'eth_type':protocol[2:]}
            and action.get('kind')=='mirred' and action.get('mirred_action')=='redirect'
            and action.get('direction')=='egress' and action.get('to_dev')==target
            and action.get('control_action',{}).get('type')=='stolen')


class LocalTCGuard:
    def __init__(self,client,link,bridge_guard):
        self.client,self.link,self.guard=client,link,bridge_guard
        self.ports={link.host_endpoint_a:link.host_endpoint_b,link.host_endpoint_b:link.host_endpoint_a}

    def read(self,*args):
        value=json.loads(self.guard.run('tc','-j',*args))
        if not isinstance(value,list):raise BridgeOwnershipError('invalid TC inventory')
        return value

    def filters(self,iface,direction='ingress'):
        return self.read('filter','show','dev',iface,direction)

    def qdisc(self,iface):
        values=self.read('qdisc','show','dev',iface)
        ingress=[v for v in values if v.get('kind') in ('clsact','ingress')]
        if ingress and (len(ingress)!=1 or ingress[0].get('kind')!='clsact' or ingress[0].get('handle')!='ffff:'):
            raise BridgeOwnershipError('endpoint ingress qdisc is not qualified')
        return bool(ingress)

    def preflight(self,*,cleanup=False):
        self.guard.inspect()
        records=self.guard.links()
        context=self.guard.context()
        prior=self.link.resource_identities.get('local_tc')
        if prior and (prior.get('version')!=1 or prior.get('context')!=context
                      or prior.get('targets')!=self.ports):
            raise BridgeOwnershipError('TC ownership or host namespace changed')
        snapshot={}
        for iface,target in self.ports.items():
            source=next((v for v in records if v.get('ifname')==iface),None)
            if source is None:
                if cleanup:continue
                raise BridgeOwnershipError('TC endpoint missing')
            if prior and signature(source)!=prior['ports'][iface]['source']:
                raise BridgeOwnershipError('TC endpoint identity changed')
            qdisc=self.qdisc(iface)
            rules=self.filters(iface)
            for protocol,pref in PROTOCOLS:
                slot=[rule for rule in rules if rule.get('pref')==pref]
                if slot and (not prior or not owned_rule(slot,protocol,pref,target)):
                    raise BridgeOwnershipError('foreign or unqualified TC rule occupies link priority')
            snapshot[iface]={'source':signature(source),'qdisc_present':qdisc}
        return snapshot,context

    def ensure(self):
        snapshot,context=self.preflight()
        record=self.link.resource_identities.get('local_tc')
        if record is None:
            record={'version':1,'context':context,'targets':dict(self.ports),
                    'ports':{iface:{'source':value['source'],'created_qdisc':False} for iface,value in snapshot.items()}}
            self.link.resource_identities['local_tc']=record
        for iface,target in self.ports.items():
            # Persist creation intent in the operation's state before mutation.
            if not self.qdisc(iface):
                record['ports'][iface]['created_qdisc']=True
                self.guard.run('tc','qdisc','add','dev',iface,'clsact')
            for protocol,pref in PROTOCOLS:
                rules=self.filters(iface)
                slot=[rule for rule in rules if rule.get('pref')==pref]
                if slot:
                    if not owned_rule(slot,protocol,pref,target):
                        raise BridgeOwnershipError('TC rule changed before attachment')
                    continue
                self.guard.run('tc','filter','replace','dev',iface,'ingress','pref',str(pref),
                               'protocol',protocol,'flower','action','mirred','egress','redirect','dev',target)
                slot=[rule for rule in self.filters(iface) if rule.get('pref')==pref]
                if not owned_rule(slot,protocol,pref,target):
                    raise BridgeOwnershipError('installed TC rule is not qualified')

    def cleanup(self):
        snapshot,_=self.preflight(cleanup=True)
        record=self.link.resource_identities.get('local_tc')
        if record is None:return
        for iface in self.ports:
            if iface not in snapshot:
                record['ports'][iface]['created_qdisc']=False
                continue
            for protocol,pref in PROTOCOLS:
                slot=[rule for rule in self.filters(iface) if rule.get('pref')==pref]
                if not slot:continue
                if not owned_rule(slot,protocol,pref,self.ports[iface]):
                    raise BridgeOwnershipError('TC rule changed before cleanup')
                self.guard.run('tc','filter','del','dev',iface,'ingress','pref',str(pref),'protocol',protocol)
                if any(rule.get('pref')==pref for rule in self.filters(iface)):
                    raise BridgeOwnershipError('TC rule remains after removal')
            if record['ports'][iface]['created_qdisc']:
                if self.filters(iface) or self.filters(iface,'egress'):
                    # The qdisc has become shared; relinquish exclusive ownership.
                    record['ports'][iface]['created_qdisc']=False
                    continue
                if self.qdisc(iface):
                    self.guard.run('tc','qdisc','del','dev',iface,'clsact')
                    if self.qdisc(iface):raise BridgeOwnershipError('owned qdisc remains after removal')
                record['ports'][iface]['created_qdisc']=False
