"""Relay lifecycle qualification with real private journals and a fake Docker API."""
from copy import deepcopy
from urllib.parse import unquote

import pytest

from dnlab_multinode.services.relay_host import Worker, RelayError


class API:
    def __init__(self):
        self.image={'Id':'sha256:'+'a'*64,'Config':{'Env':['PATH=/bin'],
                    'Entrypoint':['python3'],'Cmd':['relay.py'],'Labels':{
                    'io.dnlab.runtime-relay.capabilities':'lab-prefix-console-port-v1,multisession-console-v1'}}}
        self.values={};self.calls=[];self.creates=0;self.lose=None

    def call(self,method,path,payload=None,**kwargs):
        self.calls.append((method,path,deepcopy(payload)))
        if method=='GET' and path.startswith('/images/'):return deepcopy(self.image)
        if path=='/containers/json?all=1':
            return [{'Id':v['Id'],'Names':[v['Name']],'Labels':v['Config']['Labels']} for v in self.values.values()]
        if method=='POST' and path.startswith('/containers/create?name='):
            self.creates+=1;cid=format(self.creates,'064x')
            name=unquote(path.split('=',1)[1]);cfg={k:deepcopy(v) for k,v in payload.items() if k!='HostConfig'}
            self.values[cid]={'Id':cid,'Name':'/'+name,'Image':payload['Image'],'Config':cfg,
                              'HostConfig':deepcopy(payload['HostConfig']),'State':{'Running':False}}
            result={'Id':cid};event='create'
        else:
            cid=path.split('/')[2]
            if method=='GET':return deepcopy(self.values[cid])
            if path.endswith('/start'):self.values[cid]['State']['Running']=True;event='start'
            elif path.endswith('/stop?t=-1'):self.values[cid]['State']['Running']=False;event='stop'
            elif method=='DELETE':del self.values[cid];event='delete'
            else:raise AssertionError((method,path))
            result={}
        if self.lose==event:self.lose=None;raise OSError('lost response')
        return result


@pytest.fixture
def relay(tmp_path):
    api=API();worker=Worker('demo','master',directory=tmp_path/'relay',api=api,
                          host_context=lambda:{'boot':'fixture','namespace':'fixture'})
    c={'lab':'demo','host':'master','generation':'1'*32,'name':'dnlab-demo-runtime-relay','image':'fixture:relay',
       'bind_ip':'127.0.0.1','port':18080,'api_key':'secret-marker','allowed':['clab-dnlab-demo-R1-R1'],
       'prefix':'clab-dnlab-demo-','docker_socket':'/var/run/docker.sock'}
    return worker,api,c


def mutations(api):return [(m,p) for m,p,_ in api.calls if m!='GET']


def test_original_birth_reuse_and_cleanup_are_durable_and_id_bound(relay):
    worker,api,c=relay
    record=worker.control('ensure',c);cid=record['container_id']
    before=list(mutations(api));assert worker.control('ensure',c)==record
    assert mutations(api)==before and api.creates==1
    fresh=Worker('demo','master',directory=worker.directory,api=api,host_context=worker.host_context)
    assert fresh.control('preflight')['nonce']==record['nonce']
    assert fresh.control('delete',generation=c['generation'])['phase']=='cleaned'
    assert fresh.control('verify-cleaned',generation=c['generation'])['phase']=='cleaned'
    assert api.values=={} and ('DELETE','/containers/'+cid) in mutations(api)
    assert all('force' not in path for _,path in mutations(api))


@pytest.mark.parametrize('fault',['id','nonce','env','image','bind','name','privileged','port','capability'])
def test_replacements_and_configuration_drift_never_authorize_mutation(relay,fault):
    worker,api,c=relay;r=worker.control('ensure',c);v=api.values[r['container_id']]
    if fault=='id':
        replacement=deepcopy(v);replacement['Id']='f'*64;api.values={replacement['Id']:replacement}
    if fault=='nonce':v['Config']['Labels']['org.dnlab.relay.nonce']='f'*32
    if fault=='env':v['Config']['Env'].append('UNOWNED=true')
    if fault=='image':v['Image']='sha256:'+'f'*64
    if fault=='bind':v['HostConfig']['Binds']=['/foreign:/var/run/docker.sock:rw']
    if fault=='name':v['Name']='/renamed'
    if fault=='privileged':v['HostConfig']['Privileged']=True
    if fault=='port':v['HostConfig']['PortBindings']={'22/tcp':[]}
    if fault=='capability':v['Config']['Labels']['io.dnlab.runtime-relay.capabilities']='old'
    before=list(mutations(api));foreign=deepcopy(api.values)
    with pytest.raises(RelayError):worker.control('delete',generation=c['generation'])
    assert mutations(api)==before and api.values==foreign
    assert worker.read()['phase']=='cleanup_pending'


@pytest.mark.parametrize('event',['create','start','stop','delete'])
def test_lost_ack_recovery_uses_same_nonce_and_id_without_duplicate_mutations(relay,event):
    worker,api,c=relay
    if event in ('create','start'):
        api.lose=event
        with pytest.raises(OSError):worker.control('ensure',c)
    else:
        worker.control('ensure',c);api.lose=event
        with pytest.raises(OSError):worker.control('delete',generation=c['generation'])
    original=worker.read();nonce=original['nonce'];before=list(mutations(api))
    result=worker.control('recover')
    assert result['nonce']==nonce and api.creates==1
    assert result['phase']==('active' if event in ('create','start') else 'cleaned')
    if event=='create':assert len([p for m,p in mutations(api) if p.startswith('/containers/create')])==1
    if event=='delete':assert mutations(api)==before


def test_uncertain_create_absence_never_allows_new_allocation_or_final_cleanup(relay,monkeypatch):
    worker,api,c=relay;call=api.call
    def uncertain(method,path,payload=None,**kw):
        if method=='POST' and path.startswith('/containers/create'):raise OSError('delivery unknown')
        return call(method,path,payload,**kw)
    monkeypatch.setattr(api,'call',uncertain)
    with pytest.raises(OSError):worker.control('ensure',c)
    with pytest.raises(RelayError,match='uncertain'):worker.control('recover')
    with pytest.raises(RelayError,match='uncertain'):worker.control('delete',generation=c['generation'])
    assert worker.read()['phase']=='cleanup_pending' and api.values=={} and api.creates==0


def test_foreign_name_and_incompatible_image_are_refused_before_intent_or_create(relay):
    worker,api,c=relay
    api.values['f'*64]={'Id':'f'*64,'Name':'/'+c['name'],'Config':{'Labels':{}}}
    with pytest.raises(RelayError):worker.control('ensure',c)
    assert worker.read() is None and mutations(api)==[]
    api.values={};api.image['Config']['Labels']={}
    with pytest.raises(RelayError,match='capabilities'):worker.control('ensure',c)
    assert worker.read() is None and mutations(api)==[]


def test_save_failure_prevents_create_and_new_generation_requires_cleaned_history(relay,monkeypatch):
    worker,api,c=relay;save=worker.save
    monkeypatch.setattr(worker,'save',lambda r:(_ for _ in ()).throw(OSError('fsync failed')))
    with pytest.raises(OSError):worker.control('ensure',c)
    assert mutations(api)==[]
    monkeypatch.setattr(worker,'save',save);first=worker.control('ensure',c)
    changed={**c,'generation':'2'*32}
    with pytest.raises(RelayError):worker.control('ensure',changed)
    worker.control('delete',generation=c['generation'])
    with pytest.raises(RelayError):worker.control('ensure',changed)
    second=worker.control('provision',changed)
    assert second['nonce']!=first['nonce'] and second['container_id']!=first['container_id']
    assert second['history'][0]['nonce']==first['nonce']


@pytest.mark.parametrize('fault',['absent','stopped'])
def test_read_and_cleanup_still_allow_qualified_unavailable_original(relay,fault):
    worker,api,c=relay;r=worker.control('ensure',c)
    if fault=='absent':api.values.clear()
    else:api.values[r['container_id']]['State']['Running']=False
    before=deepcopy(worker.read())
    assert worker.control('preflight')==before
    assert worker.control('preflight-delete',generation=c['generation'])==before
    assert worker.control('delete',generation=c['generation'])['phase']=='cleaned'
    assert worker.control('verify-cleaned',generation=c['generation'])['phase']=='cleaned'
    assert api.values=={} and api.creates==1
