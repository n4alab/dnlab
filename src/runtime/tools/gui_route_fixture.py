"""Fixture adapter for real WebUI API routes with explicit synthetic inputs.

Database authorization and live-status production are controlled fixture inputs;
FastAPI routing, payload validation and the tunnel service remain real.
"""
import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import NAMESPACE_URL,uuid5


@contextmanager
def route_client(profile,service):
    import httpx
    from fastapi import FastAPI
    from app.config import settings
    from app.views.api import webui_routes as routes

    if settings.JUMPHOST_HOST!=profile['host']:
        raise RuntimeError('GUI configured connect host differs from fixture intent')
    lab_id=uuid5(NAMESPACE_URL,'dnlab-fixture:'+profile['lab'])
    lab=SimpleNamespace(id=lab_id,netname=profile['lab'],display_name=profile['lab'])
    selected={};requests=[];proxy_requests=[]
    async def session():yield None
    async def user():return SimpleNamespace(id=1)
    async def resolve(db,requested,identity):
        if db is not None or requested!=lab_id or identity.id!=1:
            raise RuntimeError('GUI fixture authorization input differs')
        return lab
    async def status(requested,*,emit_events=False):
        if requested is not lab or emit_events or not selected:
            raise RuntimeError('GUI fixture live input differs')
        return {'nodes':{selected.get('node','infrastructure-dns'):{'mgmt_ipv4':selected['ip']}},
                'infra':{'jumphost':{'ssh_port':profile['port'],'running':True}}}
    original=(routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service)
    app=FastAPI();app.include_router(routes.router)
    app.dependency_overrides[routes.get_session]=session
    app.dependency_overrides[routes.get_current_user]=user
    class Client:
        def open(self,target):
            if target not in profile['targets'] and target!=profile.get('http_target'):raise RuntimeError('GUI target outside original fixture intent')
            selected.clear();selected.update(target)
            node=target.get('node','infrastructure-dns');port=target.get('vd_port',53)
            async def request():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://dnlab.fixture.test') as client:
                    return await client.post('/api/labs/'+str(lab_id)+'/nodes/'+node+'/webui/open',
                                             json={'scheme':'http','port':port,'path':target.get('path','/')})
            result=asyncio.run(request())
            if result.status_code!=200:
                raise RuntimeError('GUI real route failed: '+str(result.status_code)+' '+result.text[:1024])
            data=result.json();tunnel=service.get(data['token'])
            if (tunnel is None or tunnel.lab_id!=str(lab_id) or tunnel.vd_ip!=target['ip']
                    or tunnel.vd_port!=port or tunnel.ssh_host!=profile['host'] or tunnel.ssh_port!=profile['port']
                    or tunnel.local_port!=data['local_port']):
                raise RuntimeError('GUI route response or effective endpoint differs')
            requests.append({'status':result.status_code,'target':dict(target),'local_port':data['local_port']})
            return tunnel
        def http_get(self,target):
            if target!=profile.get('http_target'):raise RuntimeError('original HTTP target required')
            tunnel=self.open(target)
            async def request():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://dnlab.fixture.test') as client:
                    return await asyncio.wait_for(client.get('/webui/'+tunnel.token+target['path']),timeout=10)
            response=asyncio.run(request())
            try:payload=response.json()
            except ValueError:payload={'invalid_json_prefix':response.text[:1024]}
            proof={'status':response.status_code,'node':target['node'],'ip':target['ip'],
                   'nonce':target['nonce'],'response_header':response.headers.get('x-dnlab-fixture'),
                   'response_body':payload,'verified':False,
                   'transport':'real GUI proxy over original SSH tunnel'}
            proxy_requests.append(proof)
            if (response.status_code!=200 or proof['response_header']!=target['nonce']
                    or payload!={'nonce':target['nonce'],'role':'dnlab-native-http'}):
                raise RuntimeError('GUI HTTP proxy response differs from original workload')
            proof['verified']=True
            return tunnel,proof

        @property
        def evidence(self):
            return {'http_requests':list(requests),'transport':'in-process ASGI to real router',
                    'authorization_and_live_status':'controlled fixture inputs','connect_host_source':'JUMPHOST_HOST',
                    'production_authentication_verified':False,'vd_http_verified':any(row['verified'] for row in proxy_requests),'proxy_requests':list(proxy_requests)}
    routes.resolve_for_read=resolve;routes.multinode_mod.multinode.status=status;routes.webui_service=service
    try:yield Client()
    finally:
        routes.resolve_for_read,routes.multinode_mod.multinode.status,routes.webui_service=original
        app.dependency_overrides.clear()
