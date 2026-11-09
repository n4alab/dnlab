"""Journalled local bridge primitive; no placement or distributed topology owner."""
import hashlib
import json
import shlex
import uuid

from .manifest import Conflict, canonical
from .tc_ownership import reserve, qualified, require_capture
from .endpoint_reservations import require_available
from .vxlan import VxlanLinux, VxlanManager, link_signature

PROTOCOLS=(('0x88cc',49140),('0x8809',49141))


def owned_flow(values,protocol,pref,target):
    if len(values)==2:
        header,rule=values
        keys={'protocol','pref','kind','chain'}
        if set(header)!=keys or any(header[k]!=rule.get(k) for k in keys):return False
    elif len(values)==1:rule=values[0]
    else:return False
    number=int(protocol,16)
    accepted=(protocol,protocol[2:],f'[{number}]')+(('LLDP','lldp') if number==0x88cc else ())
    options=rule.get('options',{});actions=options.get('actions',[])
    if len(actions)!=1:return False
    action=actions[0]
    return (rule.get('pref')==pref and rule.get('chain',0)==0 and rule.get('kind')=='flower'
            and rule.get('protocol') in accepted
            and type(options.get('handle')) in (int,str) and options.get('handle') in (1,'1','0x1')
            and options.get('keys')=={'eth_type':protocol[2:]}
            and action.get('kind')=='mirred' and action.get('mirred_action')=='redirect'
            and action.get('direction')=='egress' and action.get('to_dev')==target
            and action.get('control_action',{}).get('type')=='stolen')


class BridgeLinux(VxlanLinux):
    def filters(self,name,direction='ingress'):
        return json.loads(self.linux.run(['tc','-j','filter','show','dev',name,direction]))

    def forward_rules(self):
        return [shlex.split(line) for line in self.linux.run(['iptables','-S','FORWARD']).splitlines()]


class BridgeManager:
    def __init__(self,journal,linux,*,check=None):
        self.journal,self.linux=journal,linux
        self.check=check or (lambda:None)
        # Serialize bridge and VXLAN primitives on their shared journal resources.
        self.resource_lock=VxlanManager(journal,linux)
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS local_bridges (id TEXT PRIMARY KEY,payload TEXT NOT NULL,phase TEXT NOT NULL)')

    def row(self,key):
        with self.journal.lock:
            value=self.journal.db.execute('SELECT payload,phase FROM local_bridges WHERE id=?',(key,)).fetchone()
        return {'payload':json.loads(value['payload']),'phase':value['phase']} if value else None

    def save(self,identity,payload,phase):
        with self.journal.transaction():
            self.journal.db.execute('INSERT INTO local_bridges VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,phase=excluded.phase',
                                    (identity.digest,canonical(payload),phase))

    def context(self,payload):
        if payload['network_identity']!=self.linux.network_identity():
            raise Conflict('bridge namespace or host boot changed')

    def bridge(self,identity,payload):
        self.context(payload)
        candidates=[value for value in self.linux.links() if value.get('ifname')==identity.kernel_name
                    or value.get('ifalias')==payload['creator']]
        if not candidates:return None
        if len(candidates)!=1:raise Conflict('ambiguous bridge ownership')
        value=candidates[0]
        members=[port for port in self.linux.links() if port.get('master') in (identity.kernel_name,value['ifindex'])]
        # Linux resets an empty bridge to MTU 1500. Accept this only after the
        # final detach intent was committed, including a crash before its ACK.
        row=self.row(identity.digest)
        empty_teardown=(payload.get('detach_complete_intent') is True and not members
                        and row is not None and row['phase'] in ('deleting','recovery_required')
                        and row['payload'].get('detach_complete_intent') is True)
        mtu_matches=(value.get('mtu')==payload['config']['mtu']
                     or empty_teardown and value.get('mtu')==1500)
        if (value.get('ifname')!=identity.kernel_name or value.get('address')!=payload['creator_mac']
                or value.get('linkinfo',{}).get('info_kind')!='bridge' or not mtu_matches
                or payload.get('bridge_index') is not None and value.get('ifindex')!=payload['bridge_index']
                or payload['alias_committed'] and value.get('ifalias')!=payload['creator']
                or not payload['alias_committed'] and value.get('ifalias') not in (None,'',payload['creator'])):
            raise Conflict('bridge creator or kernel identity changed')
        ports={source['ifname'] for source in payload['config']['sources']}
        if any(port.get('ifname') not in ports for port in members):
            raise Conflict('bridge contains foreign member')
        return value

    def sources(self,identity,payload,*,missing_ok=False):
        self.context(payload);bridge=self.bridge(identity,payload);records=self.linux.links();found=[]
        for source in payload['config']['sources']:
            value=next((v for v in records if v.get('ifname')==source['ifname']),None)
            if value is None:
                if missing_ok and not any(v.get('ifindex')==source['ifindex'] for v in records):continue
                raise Conflict('bridge source missing or renamed')
            if link_signature(value)!=source:raise Conflict('bridge source identity changed')
            if value.get('master') not in (None,identity.kernel_name,bridge['ifindex'] if bridge else None):
                raise Conflict('source attached to foreign bridge')
            found.append(value)
        return found

    def clsact(self,name):
        ingress=[q for q in self.linux.qdiscs(name) if q.get('kind') in ('ingress','clsact')]
        if ingress and (len(ingress)!=1 or ingress[0].get('kind')!='clsact' or ingress[0].get('handle')!='ffff:'):
            raise Conflict('source ingress qdisc not qualified')
        return bool(ingress)

    def rules(self,identity,payload):
        expected=[['-A','FORWARD',direction,identity.kernel_name,'-m','comment','--comment',payload['creator'],'-j','ACCEPT'] for direction in ('-i','-o')]
        actual=self.linux.forward_rules()
        selected=[r for r in actual if '--comment' in r and r[r.index('--comment')+1]==payload['creator']]
        if any(r not in expected for r in selected) or any(selected.count(r)>1 for r in expected):
            raise Conflict('bridge forwarding rules changed or duplicated')
        return expected,selected

    def intent(self,identity,payload,step,argv,*,deleting=False):
        self.sources(identity,payload,missing_ok=deleting)
        payload['step']=step;self.save(identity,payload,'deleting' if deleting else 'creating')
        if not deleting:self.check()
        self.linux.run(argv)

    def create(self,identity,*,sources,mtu=1500):
        config={'sources':sorted([link_signature(source) for source in sources],key=lambda s:s['ifname']),'mtu':mtu}
        if len(sources)!=2 or len({s['ifname'] for s in sources})!=2 or type(mtu) is not int or not 576<=mtu<=9216:
            raise Conflict('bridge requires two qualified endpoints and valid MTU')
        with self.resource_lock.execution():
            from .management_barrier import check as management_check
            management_check(self.journal,identity.lab_id)
            from .lab_closure import get
            fence=get(self.journal,identity.lab_id)
            if fence and fence['phase']!='open':raise Conflict('lab is closing or closed')
            require_available(self.journal,[s['ifname'] for s in config['sources']],owner_table='local_bridges',owner_id=identity.digest)
            prior=self.row(identity.digest)
            if prior and prior['phase']=='active':
                if prior['payload']['config']!=config:raise Conflict('active bridge cannot be reconfigured')
                self.verify(identity,prior['payload']);return prior['payload']
            if prior and prior['phase']!='cleaned':raise Conflict('interrupted bridge needs explicit recovery')
            if any(v.get('ifname')==identity.kernel_name for v in self.linux.links()):
                raise Conflict('bridge name occupied; refusing adoption')
            actual=self.linux.links()
            for source in sources:
                found=next((v for v in actual if v.get('ifname')==source['ifname']),None)
                if (not found or link_signature(found)!=link_signature(source)
                        or found.get('linkinfo',{}).get('info_kind')!='veth'
                        or not found.get('ifalias','').startswith('dnlab-runtime:')
                        or found.get('master') is not None or found.get('mtu')!=mtu):
                    raise Conflict('bridge source is not a qualified free runtime veth')
                self.clsact(source['ifname'])
                if any(r.get('pref') in (49140,49141) for r in self.linux.filters(source['ifname'])):
                    raise Conflict('bridge TC priority occupied')
            creator=identity.alias+':'+uuid.uuid4().hex
            mac=bytearray(hashlib.sha256(creator.encode()).digest()[:6]);mac[0]=(mac[0]&0xfc)|2
            payload={'lab_id':identity.lab_id,'config':config,'creator':creator,'creator_mac':':'.join(f'{b:02x}' for b in mac),
                     'alias_committed':False,'bridge_index':None,'network_identity':self.linux.network_identity(),
                     'qdisc_created':{s['ifname']:not self.clsact(s['ifname']) for s in sources},'step':'validated'}
            payload['tc_proofs']={source['ifname']+':'+str(pref):reserve(source,next(s for s in config['sources'] if s!=source))
                                  for source in config['sources'] for _,pref in PROTOCOLS}
            self.save(identity,payload,'creating')
            try:
                self.intent(identity,payload,'create',['ip','link','add',identity.kernel_name,'address',payload['creator_mac'],'mtu',str(mtu),'type','bridge'])
                payload['bridge_index']=self.bridge(identity,payload)['ifindex']
                self.intent(identity,payload,'alias',['ip','link','set','dev',identity.kernel_name,'alias',creator])
                payload['alias_committed']=True
                expected,_=self.rules(identity,payload)
                for rule in expected:self.intent(identity,payload,'forward',['iptables','-I','FORWARD','1',*rule[2:]])
                self.intent(identity,payload,'up',['ip','link','set','dev',identity.kernel_name,'up'])
                for source in config['sources']:
                    name=source['ifname'];target=next(s['ifname'] for s in config['sources'] if s['ifname']!=name)
                    self.intent(identity,payload,'attach',['ip','link','set','dev',name,'master',identity.kernel_name])
                    if payload['qdisc_created'][name]:self.intent(identity,payload,'qdisc',['tc','qdisc','add','dev',name,'clsact'])
                    for protocol,pref in PROTOCOLS:
                        self.intent(identity,payload,'redirect',['tc','filter','add','dev',name,'ingress','pref',str(pref),'protocol',protocol,'handle','1',
                                                             'flower','action','mirred','egress','redirect','dev',target,
                                                             'cookie',payload['tc_proofs'][name+':'+str(pref)]['cookie']])
                        require_capture([r for r in self.linux.filters(name) if r.get('pref')==pref],target,
                                        lambda rows,dst:owned_flow(rows,protocol,pref,dst),
                                        payload['tc_proofs'][name+':'+str(pref)],self.linux.links())
                        self.save(identity,payload,'creating')
                self.check();self.verify(identity,payload);self.save(identity,payload,'active');return payload
            except Exception as error:
                payload['error']=f'{type(error).__name__}: {error}'
                try:self._cleanup(identity,payload)
                except Exception as cleanup_error:
                    payload['cleanup_error']=f'{type(cleanup_error).__name__}: {cleanup_error}';self.save(identity,payload,'recovery_required')
                raise

    def owned_redirect(self,payload,values,protocol,pref,target,name):
        if 'tc_proofs' in payload and name+':'+str(pref) not in payload['tc_proofs']:return False
        return qualified(values,target,lambda rows,dst:owned_flow(rows,protocol,pref,dst),
                         payload.get('tc_proofs',{}).get(name+':'+str(pref)),self.linux.links())

    def verify(self,identity,payload):
        sources=self.sources(identity,payload);bridge=self.bridge(identity,payload)
        if not bridge or 'UP' not in bridge.get('flags',[]):raise Conflict('bridge not up')
        for source in sources:
            name=source['ifname'];target=next(s['ifname'] for s in payload['config']['sources'] if s['ifname']!=name)
            if source.get('master') not in (identity.kernel_name,bridge['ifindex']) or not self.clsact(name):raise Conflict('bridge source not attached')
            for protocol,pref in PROTOCOLS:
                if not self.owned_redirect(payload,[r for r in self.linux.filters(name) if r.get('pref')==pref],protocol,pref,target,name):raise Conflict('bridge redirect verification failed')
        expected,actual=self.rules(identity,payload)
        if any(rule not in actual for rule in expected):raise Conflict('bridge forwarding rules incomplete')

    def cleanup_preflight(self,identity,payload):
        sources=self.sources(identity,payload,missing_ok=True);bridge=self.bridge(identity,payload)
        expected,rules=self.rules(identity,payload)
        # Check all owned priorities before the first destructive command.
        for source in sources:
            name=source['ifname'];target=next(s['ifname'] for s in payload['config']['sources'] if s['ifname']!=name)
            self.clsact(name)
            for protocol,pref in PROTOCOLS:
                slot=[r for r in self.linux.filters(name) if r.get('pref')==pref]
                if slot and not self.owned_redirect(payload,slot,protocol,pref,target,name):raise Conflict('foreign bridge TC rule; refusing cleanup')
        return sources,bridge,expected,rules

    def _cleanup(self,identity,payload):
        sources,bridge,expected,rules=self.cleanup_preflight(identity,payload)
        self.save(identity,payload,'deleting')
        for source in sources:
            name=source['ifname']
            for protocol,pref in PROTOCOLS:
                if any(r.get('pref')==pref for r in self.linux.filters(name)):
                    self.intent(identity,payload,'delete_filter',['tc','filter','del','dev',name,'ingress','pref',str(pref),'protocol',protocol],deleting=True)
            if payload['qdisc_created'][name]:
                if self.linux.filters(name) or self.linux.filters(name,'egress'):payload['qdisc_created'][name]=False
                elif self.clsact(name):
                    self.intent(identity,payload,'delete_qdisc',['tc','qdisc','del','dev',name,'clsact'],deleting=True)
                    if self.clsact(name):raise Conflict('bridge qdisc removal incomplete')
            if bridge and source.get('master') in (identity.kernel_name,bridge['ifindex']):
                members=[port for port in self.linux.links() if port.get('master') in (identity.kernel_name,bridge['ifindex'])]
                if len(members)==1 and members[0]['ifname']==name:
                    payload['detach_complete_intent']=True
                self.intent(identity,payload,'detach',['ip','link','set','dev',name,'nomaster'],deleting=True)
        for rule in rules:self.intent(identity,payload,'delete_forward',['iptables','-D',*rule[1:]],deleting=True)
        if bridge:self.intent(identity,payload,'delete_bridge',['ip','link','delete','dev',identity.kernel_name],deleting=True)
        if self.bridge(identity,payload) is not None or self.rules(identity,payload)[1]:raise Conflict('bridge cleanup incomplete')
        self.save(identity,payload,'cleaned')

    def delete(self,identity):
        with self.resource_lock.execution():
            row=self.row(identity.digest)
            if row is None:raise Conflict('bridge not tracked by this journal')
            if row['phase']=='cleaned':return
            try:self._cleanup(identity,row['payload'])
            except Exception as error:
                row['payload']['cleanup_error']=f'{type(error).__name__}: {error}'
                self.save(identity,row['payload'],'recovery_required');raise

    def recover(self,identity):self.delete(identity)
