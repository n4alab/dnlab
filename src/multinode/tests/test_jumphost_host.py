"""Real jumphost worker with stateful Docker/kernel simulation."""
import copy
import json
import os
import ipaddress
from pathlib import Path
import pytest
from dnlab_multinode.services.jumphost_host import Worker, JumphostError, names, signature, digest


def config(lab='breakout-alpha'):
    return {'lab': lab, 'generation':'1'*32, 'name': 'dnlab-'+lab+'-jumphost', 'image': 'jh:latest',
        'network': {'name': 'shared', 'bridge': 'br-ext', 'subnet': '192.0.2.0/24', 'gateway': '192.0.2.1'},
        'ip': '192.0.2.2', 'bind_ip': '127.0.0.1', 'port': 2200, 'env': {'JUMPHOST_PASSWORD': 'secret'},
        'dns': [], 'binds': [], 'dhcp': '', 'attachment': {'segment': 'default', 'network': 'mgmt-'+lab,
        'bridge': 'br-mgmt', 'interface': 'eth1', 'ipv4': '198.18.0.254/24', 'ipv6': ''}}


class World:
    def __init__(self, cfg):
        self.cfg = cfg
        self.image = {'Id': 'sha256:'+'b'*64, 'Config': {'Entrypoint': None, 'Cmd': ['sleep','infinity'], 'Env': ['PATH=/bin'], 'Labels': {}}}
        self.network = {'Id': 'a'*64, 'Name': 'shared', 'Driver': 'bridge', 'Options': {'com.docker.network.bridge.name':'br-ext'},
            'IPAM': {'Config':[{'Subnet':'192.0.2.0/24','Gateway':'192.0.2.1'}]}}
        self.management = {'Id':'c'*64, 'Name':cfg['attachment']['network'], 'Driver':'dnlab-vrf',
            'Labels': {'io.dnlab.lab':cfg['lab'], 'io.dnlab.managed':'mgmt-vrf'},
            'Options': {'dnlab.lab':cfg['lab'], 'dnlab.bridge':'br-mgmt', 'dnlab.vrf':'vrf-test'}}
        self.host = [self.link('vrf-test',3,'vrf'),self.link('br-mgmt',4,'bridge',master='vrf-test')]
        self.host[0]['linkinfo']['info_data'] = {'table':100}
        address = ipaddress.ip_interface(cfg['attachment']['ipv4']); subnet = str(address.network)
        expected = dict(driver='dnlab-vrf', ipam_driver='dnlab-vrf', network=cfg['attachment']['network'],
            bridge='br-mgmt', vrf='vrf-test', lab=cfg['lab'], ipv4_subnet=subnet,
            ipv4_gateway=str(address.network.network_address+1), host_index=0, host_count=1,
            reserved=[str(address.network.network_address+1),str(address.ip)], labels=copy.deepcopy(self.management['Labels']))
        self.management['Labels']['org.dnlab.management.creator'] = '4'*32
        self.management.update(Internal=False, EnableIPv6=False, IPAM={'Driver':'dnlab-vrf','Options':{
            'dnlab.tenant':expected['network'], 'dnlab.reserved':','.join(expected['reserved']),
            'dnlab.host-index':'0', 'dnlab.host-count':'1'}, 'Config':[{'Subnet':subnet,'Gateway':expected['ipv4_gateway']}]})
        def identity(value):
            return {k:value.get(k) for k in ('ifname','ifindex','address','ifalias')} | {'kind':value['linkinfo']['info_kind']}
        self.origin = {'plan':{'lab':cfg['lab'],'generation':'5'*32,'vrf':'vrf-test','table':100,
            'segments':{'default':{'bridge':'br-mgmt','address':expected['ipv4_gateway']+'/'+str(address.network.prefixlen)}}},
            'phase':'active','context':{'boot_id':'boot','device':1,'inode':2},'network_operation':{'phase':'done'},
            'resources':{v['ifname']:{'phase':'active','identity':identity(v)} for v in self.host},
            'networks':{'default':{'expected':expected,'phase':'active','nonce':'4'*32,'id':'c'*64}}}
        self.peer=[];self.addresses=[];self.values={};self.calls=[];self.lost=None
        self.before=lambda argv: None
        self.retain_veth_after_stop=False; self.stop_timeout=False

    def link(self,name,index,kind='veth',**extra):
        return {'ifname':name,'ifindex':index,'address':'02:00:00:00:00:01','ifalias':'',
                'linkinfo':{'info_kind':kind},'flags':['UP'],**extra}

    def run(self,argv,**kwargs):
        self.calls.append(list(argv));self.before(argv)
        guest=argv[0]=='nsenter'
        if guest:argv=argv[2:]
        if argv[:2]==['docker','ps']:
            if '--filter' in argv:
                nonce=argv[argv.index('--filter')+1].split('=',2)[-1]
                return '\n'.join(key for key,v in self.values.items() if v.get('Config',{}).get('Labels',{}).get('org.dnlab.jumphost.nonce')==nonce)
            return '\n'.join(json.dumps({'ID':key,'Names':v['Name'][1:]}) for key,v in self.values.items())
        if argv[:3]==['docker','image','inspect']:return json.dumps([self.image])
        if argv[:3]==['docker','network','inspect']:return json.dumps([self.network if argv[3]=='shared' else self.management])
        if argv[:2]==['docker','inspect']:return json.dumps([self.values[argv[2]]])
        if argv[:2]==['docker','create']:
            def option(k):return argv[argv.index(k)+1]
            labels={};env={'PATH':'/bin'};binds=[];dns=[]
            for i,arg in enumerate(argv[:-1]):
                if arg=='--label':k,v=argv[i+1].split('=',1);labels[k]=v
                if arg=='-e':k,v=argv[i+1].split('=',1);env[k]=v
                if arg=='-v':binds.append(argv[i+1])
                if arg=='--dns':dns.append(argv[i+1])
            cid=str(len(self.values)+1)*64
            self.values[cid]={'Id':cid,'Name':'/'+option('--name'),'Image':self.image['Id'],
                'Config':{'Image':self.image['Id'],'Entrypoint':None,'Cmd':['sleep','infinity'],'Labels':labels,'Env':[k+'='+v for k,v in env.items()]},
                'HostConfig':{'NetworkMode':option('--network'),'Privileged':False,'CapAdd':['NET_ADMIN','NET_RAW'],'Binds':binds,'Dns':dns,
                    'PortBindings':{'22/tcp':[{'HostIp':self.cfg['bind_ip'],'HostPort':str(self.cfg['port'])}]},
                    'Sysctls':{'net.ipv4.ip_forward':'1','net.ipv6.conf.all.forwarding':'1'},'RestartPolicy':{'Name':'no'},'PidMode':'','IpcMode':'private'},
                'NetworkSettings':{'Networks':{'shared':{'NetworkID':self.network['Id'],'IPAddress':self.cfg['ip'],'IPAMConfig':{'IPv4Address':self.cfg['ip']}}}},
                'State':{'Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}}
            if self.lost=='create':raise JumphostError('lost create response')
            return cid
        if argv[:2]==['docker','start']:
            self.values[argv[2]]['State']={'Running':True,'Pid':100,'StartedAt':'started-1'}
            if self.lost=='start':raise JumphostError('lost start response')
            return argv[2]
        if argv[:2]==['docker','kill']:
            if self.stop_timeout:return ''
            self.values[argv[-1]]['State']['Running']=False;self.values[argv[-1]]['State']['Pid']=0
            if not self.retain_veth_after_stop:self.host=[v for v in self.host if v['linkinfo']['info_kind']!='veth'];self.peer=[]
            return ''
        if argv[:2]==['docker','rm']:
            del self.values[argv[2]]
            if self.lost=='rm':raise JumphostError('lost remove response')
            return ''
        if argv==['ip','-j','-d','link','show']:return json.dumps(self.peer if guest else self.host)
        if argv[:3]==['ip','-j','addr']:
            return json.dumps([{'addr_info':[{'local':v.split('/')[0],'prefixlen':int(v.split('/')[1])} for v in self.addresses]}])
        if argv[:3]==['ip','link','add']:
            split=argv.index('peer');own=argv[:split];peer=argv[split:]
            self.host.append(self.link(argv[3],5,address=own[own.index('address')+1],ifalias='',link_index=6,flags=[]))
            self.peer.append(self.link(peer[peer.index('name')+1],6,address=peer[peer.index('address')+1],ifalias='',link_index=5,flags=[]))
            if self.lost=='veth':raise JumphostError('lost veth response')
            return ''
        if argv[:2]==['python3','-c']:
            payload=json.loads(argv[-1]);expected=payload['link'];op=payload['operation']
            current=next(v for v in (self.peer if guest else self.host) if v['ifindex']==expected['ifindex'])
            assert signature(current)==expected
            if op=='alias':
                current['ifalias']=payload['value']
                if self.lost=='alias':raise JumphostError('lost alias response')
            if op=='address':self.addresses.append(payload['value'])
            if op=='master':current['master']=payload['value']['ifname']
            if op=='up':current['flags']=['UP']
            return '{}'
        if argv[:3]==['ip','addr','replace'] or argv[:4]==['ip','-6','addr','replace']:
            self.addresses.append(argv[3] if argv[1]=='addr' else argv[4]);return ''
        if argv[:3]==['ip','link','set']:
            value=next(v for v in (self.peer if guest else self.host) if v['ifname']==argv[4])
            if 'master' in argv:value['master']=argv[-1]
            if argv[-1]=='up':value['flags']=['UP']
            return ''
        raise AssertionError(argv)

    def worker(self,path):
        directory = Path(path).parent/'management'; directory.mkdir(mode=0o700,exist_ok=True)
        lock = directory/'.lock'
        if not lock.exists(): lock.touch(mode=0o600)
        self.origin_path = directory/(digest(['management-host-v1',self.cfg['lab']])+'.json')
        if not self.origin_path.exists():
            self.origin_path.write_text(json.dumps(self.origin));self.origin_path.chmod(0o600)
        return Worker(self.cfg['lab'],directory=path,run=self.run,host_context=lambda:{'boot_id':'boot','device':1,'inode':2},
            open_ns=lambda pid:os.open('/dev/null',os.O_RDONLY),delete_link=self.delete,management_directory=directory)

    def delete(self,expected,scope):
        self.calls.append(['delete-index',str(expected['ifindex'])]);self.host=[v for v in self.host if signature(v)!=expected];self.peer=[]


@pytest.fixture
def world(tmp_path):
    w=World(config());return w,w.worker(tmp_path/'journal')


def test_full_lab_and_segment_names_are_distinct():
    assert len({names(lab,seg) for lab in ('breakout-alpha','breakout-beta') for seg in ('a','b')})==4
    assert len(names('breakout-alpha'))<=15


def test_admission_before_create_id_before_start(world):
    w,worker=world
    def before(argv):
        if argv[:2]==['docker','create']:
            r=worker.read();assert r['nonce'] and r['config']==w.cfg and r['step']=='create'
        if argv[:2]==['docker','start']:assert worker.read()['container_id']==argv[2]
        if argv[:3]==['ip','link','add']:
            r=worker.read();assert r['namespace'] and r['step']=='veth_create'
            assert 'netns' in argv and '/proc/self/fd/' in argv[-1]
    w.before=before
    r=worker.operate('ensure',w.cfg);assert r['phase']=='active';assert worker.operate('ensure',w.cfg)==r
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1
    assert all('del' not in c and '-f' not in c for c in w.calls)


@pytest.mark.parametrize('failure',['create','start','veth','alias'])
def test_explicit_recovery_after_lost_response(world,failure):
    w,worker=world;w.lost=failure
    with pytest.raises(JumphostError,match='lost'):worker.operate('ensure',w.cfg)
    assert worker.read()['phase']=='recovery_required'
    with pytest.raises(JumphostError,match='explicit'):worker.operate('ensure',w.cfg)
    w.lost=None;assert worker.operate('recover')['phase']=='active'
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1


@pytest.mark.parametrize('collision',['container','host','legacy','peer'])
def test_foreign_resources_preserved(world,collision):
    w,worker=world
    if collision=='container':w.values['f'*64]={'Id':'f'*64,'Name':'/'+w.cfg['name']}
    if collision=='host':w.host.append(w.link(names(w.cfg['lab']),77))
    if collision=='legacy':w.host.append(w.link('jh-breakout',77))
    if collision=='peer':w.peer.append(w.link('eth1',77))
    host=copy.deepcopy(w.host);peer=copy.deepcopy(w.peer)
    with pytest.raises(JumphostError):worker.operate('ensure',w.cfg)
    assert w.host==host and w.peer==peer
    assert not any(c[:2]==['docker','rm'] or c[:1]==['delete-index'] for c in w.calls)
    if collision!='peer':assert not any(c[:2]==['docker','create'] for c in w.calls)


@pytest.mark.parametrize('replacement',['id','label','image','network','bridge','peer','namespace'])
def test_identity_conflicts_refuse_cleanup_before_mutations(world,replacement):
    w,worker=world;r=worker.operate('ensure',w.cfg)
    if replacement=='id':v=w.values.pop(r['container_id']);v['Id']='f'*64;w.values['f'*64]=v
    if replacement=='label':w.values[r['container_id']]['Config']['Labels']={}
    if replacement=='image':w.values[r['container_id']]['Image']='sha256:'+'f'*64
    if replacement=='network':w.network['Id']='f'*64
    if replacement=='bridge':w.host[1]['ifindex']+=100
    if replacement=='peer':w.peer[0]['ifindex']+=100
    if replacement=='namespace':w.values[r['container_id']]['State']['StartedAt']='started-2'
    w.calls.clear()
    with pytest.raises(JumphostError):worker.operate('delete')
    assert not any(c[:2] in (['docker','kill'],['docker','rm']) or c[:1]==['delete-index'] for c in w.calls)
    assert worker.read()['phase']=='recovery_required'


@pytest.mark.parametrize('remain',[False,True])
def test_shutdown_before_unlink_without_force(world,remain):
    w,worker=world;worker.operate('ensure',w.cfg);w.calls.clear();w.retain_veth_after_stop=remain
    r=worker.operate('delete');assert r['phase']=='cleaned' and r['cleanup_verified'] is True
    assert worker.operate('delete')['phase']=='cleaned'
    stop=next(i for i,c in enumerate(w.calls) if c[:2]==['docker','kill'])
    remove=next(i for i,c in enumerate(w.calls) if c[:2]==['docker','rm']);assert stop<remove
    if remain:assert stop<next(i for i,c in enumerate(w.calls) if c[:1]==['delete-index'])<remove
    assert not any('-f' in c for c in w.calls)


def test_lost_remove_response_recovery(world):
    w,worker=world;worker.operate('ensure',w.cfg);w.lost='rm'
    with pytest.raises(JumphostError):worker.operate('delete')
    w.lost=None;assert worker.operate('recover')['phase']=='cleaned'
    assert sum(c[:2]==['docker','rm'] for c in w.calls)==1


def test_persistence_failure_prevents_allocation(world,monkeypatch):
    w,worker=world
    monkeypatch.setattr(worker,'save',lambda r:(_ for _ in ()).throw(OSError('fsync failed')))
    with pytest.raises(OSError):worker.operate('ensure',w.cfg)
    assert not w.values and not any(c[:2]==['docker','create'] for c in w.calls)


def test_new_generation_only_after_verified_cleanup(world):
    w,worker=world;first=worker.operate('ensure',w.cfg)
    with pytest.raises(JumphostError):worker.operate('provision',dict(w.cfg,generation='2'*32))
    worker.operate('delete')
    with pytest.raises(JumphostError):worker.operate('ensure',w.cfg)
    second=worker.operate('provision',dict(w.cfg,generation='2'*32));assert second['nonce']!=first['nonce']
    assert (worker.directory/(worker.key+'-'+first['nonce']+'.json')).exists()


def test_missing_journal_preserves_legacy_container(world):
    w,worker=world;w.values['f'*64]={'Id':'f'*64,'Name':'/'+w.cfg['name']}
    with pytest.raises(JumphostError,match='journal missing'):worker.operate('delete')
    assert 'f'*64 in w.values


def test_pending_birth_rename_is_not_recreated(world):
    w,worker=world;w.lost='create'
    with pytest.raises(JumphostError):worker.operate('ensure',w.cfg)
    next(iter(w.values.values()))['Name']='/renamed-external'
    w.lost=None
    with pytest.raises(JumphostError,match='renamed'):worker.operate('recover')
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1


def test_missing_attempted_birth_requires_cleanup_not_recreate(world):
    w,worker=world;w.lost='create'
    with pytest.raises(JumphostError):worker.operate('ensure',w.cfg)
    w.values.clear();w.lost=None
    with pytest.raises(JumphostError,match='no observable generation'):worker.operate('recover')
    assert sum(c[:2]==['docker','create'] for c in w.calls)==1
    assert worker.operate('delete')['phase']=='cleaned'


def test_shutdown_timeout_keeps_attachment_and_generation(world,monkeypatch):
    from dnlab_multinode.services import jumphost_host
    w,worker=world;r=worker.operate('ensure',w.cfg);w.stop_timeout=True;w.calls.clear()
    before=copy.deepcopy((w.host,w.peer));clock=iter((0,100))
    monkeypatch.setattr(jumphost_host.time,'monotonic',lambda:next(clock))
    with pytest.raises(JumphostError,match='timed out'):worker.operate('delete')
    assert (w.host,w.peer)==before and w.values[r['container_id']]['State']['Running']
    assert worker.read()['phase']=='recovery_required'
    assert not any(c[:2]==['docker','rm'] or c[:1]==['delete-index'] for c in w.calls)


def test_readonly_cleanup_preflight_does_not_advance_journal(world):
    w,worker=world;worker.operate('ensure',w.cfg);before=worker.path.read_bytes();w.calls.clear()
    worker.operate('preflight-delete',{'container':w.cfg['name']})
    assert worker.path.read_bytes()==before
    assert all(c[:2] not in (['docker','kill'],['docker','rm']) for c in w.calls)
    with pytest.raises(JumphostError):worker.operate('preflight-delete',{'container':'foreign'})


def test_new_generation_retries_after_archive_saved_before_new_intent(world,monkeypatch):
    w,worker=world;worker.operate('ensure',w.cfg);worker.operate('delete');original=worker.save
    monkeypatch.setattr(worker,'save',lambda r:(_ for _ in ()).throw(OSError('fsync')))
    with pytest.raises(OSError):worker.operate('provision',dict(w.cfg,generation='2'*32))
    monkeypatch.setattr(worker,'save',original)
    assert worker.operate('provision',dict(w.cfg,generation='2'*32))['phase']=='active'


def test_dhcp_asset_is_durable_and_verified_on_retry(world):
    w,worker=world;cfg=dict(w.cfg,dhcp='interface=eth1\ndhcp-authoritative\n')
    r=worker.operate('ensure',cfg)
    asset=worker.dhcp_directory(r)/'main'
    assert asset.read_text().startswith(cfg['dhcp']) and asset.stat().st_mode & 0o777==0o644
    asset.write_text('foreign content')
    with pytest.raises(JumphostError,match='asset identity/content differs'):worker.operate('ensure',cfg)
    w.calls.clear()
    with pytest.raises(JumphostError):worker.operate('delete')
    assert not any(c[:2] in (['docker','kill'],['docker','rm']) for c in w.calls)


def test_preflight_missing_namespace_proof_does_not_capture_or_mutate(world):
    w,worker=world;w.lost='start'
    with pytest.raises(JumphostError):worker.operate('ensure',w.cfg)
    before=worker.path.read_bytes()
    with pytest.raises(JumphostError,match='namespace proof missing'):worker.operate('preflight-delete')
    assert worker.path.read_bytes()==before


def test_stale_coordinator_cannot_delete_or_finalize_new_generation(world):
    w,worker=world;worker.operate('ensure',w.cfg);worker.operate('delete')
    newer=dict(w.cfg,generation='2'*32);worker.operate('provision',newer);w.calls.clear()
    with pytest.raises(JumphostError,match='stale coordinator'):worker.operate('delete',{'generation':'1'*32})
    with pytest.raises(JumphostError,match='generation differs'):worker.operate('preflight-delete',{'container':w.cfg['name'],'generation':'1'*32})
    assert not any(c[:2] in (['docker','kill'],['docker','rm']) for c in w.calls)
    worker.operate('delete',{'generation':'2'*32})
    with pytest.raises(JumphostError,match='obsolete'):worker.operate('provision',w.cfg)
