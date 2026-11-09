"""Host-local relay birth and deletion; structured Docker calls only.

The injected base supplies the already qualified private journal/lock primitives.
An uncertain create is never retried or declared absent without a qualified ID.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from urllib.parse import quote

try:
    _BaseWorker
except NameError:
    from .jumphost_host import Worker as _BaseWorker, DockerExecHTTP, canonical, digest


class RelayError(RuntimeError):pass


def validate(c):
    fields={'lab','host','generation','name','image','bind_ip','port','api_key','allowed','prefix','docker_socket'}
    if not isinstance(c,dict) or set(c)!=fields:raise RelayError('complete relay configuration required')
    for field in ('lab','host','name'):
        if not isinstance(c[field],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,200}',c[field]):
            raise RelayError('invalid relay identity')
    if not re.fullmatch('[0-9a-f]{32}',c['generation']):raise RelayError('relay generation required')
    ipaddress.ip_address(c['bind_ip'])
    if type(c['port']) is not int or not 1<=c['port']<=65535:raise RelayError('invalid relay port')
    if (not isinstance(c['image'],str) or not c['image'] or not isinstance(c['api_key'],str) or not c['api_key']
            or not isinstance(c['docker_socket'],str) or not c['docker_socket'].startswith('/')
            or any('\x00' in c[k] for k in ('image','api_key','docker_socket')) or ':' in c['docker_socket']
            or c['prefix']!='clab-dnlab-'+c['lab']+'-'):
        raise RelayError('invalid relay image, credentials or scope')
    if (not isinstance(c['allowed'],list) or len(set(c['allowed']))!=len(c['allowed'])
            or any(not isinstance(v,str) or not v.startswith(c['prefix']) for v in c['allowed'])):
        raise RelayError('invalid relay allowlist')
    return json.loads(canonical(c))


class Worker(_BaseWorker):
    def __init__(self,lab,host,*,directory,api=None,socket_path='/var/run/docker.sock',**kwargs):
        super().__init__(lab,directory=directory,**kwargs)
        self.host=host;self.key=digest(['relay-v1',lab,host]);self.path=self.directory/(self.key+'.json')
        self.socket_path=socket_path;self.api=api or DockerExecHTTP(socket_path)

    def read(self):
        try:fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return None
        with os.fdopen(fd) as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise RelayError('relay journal ownership differs')
            r=json.load(f)
        validate(r['config'])
        if (r['config']['lab']!=self.lab or r['config']['host']!=self.host or r['context']!=self.host_context()
                or r['config']['docker_socket']!=self.socket_path
                or not re.fullmatch('[0-9a-f]{32}',r['nonce'])
                or r['intent_digest']!=digest({'config':r['config'],'image':r['image']})):
            raise RelayError('relay journal identity differs')
        return r

    def image(self,c):
        image=self.api.call('GET','/images/'+quote(c['image'],safe='')+'/json')
        caps=set((image.get('Config',{}).get('Labels') or {}).get('io.dnlab.runtime-relay.capabilities','').split(','))
        if (not re.fullmatch('sha256:[0-9a-f]{64}',image.get('Id',''))
                or image.get('Config',{}).get('StopSignal') not in (None,'','SIGTERM','15')
                or not {'lab-prefix-console-port-v1','multisession-console-v1'}<=caps):
            raise RelayError('relay image capabilities are not qualified')
        return image

    def labels(self,r):
        labels=dict(r['image'].get('Config',{}).get('Labels') or {})
        labels.update({'org.dnlab.relay.scope':self.key,'org.dnlab.relay.nonce':r['nonce'],
                       'org.dnlab.relay.config':digest(r['config'])})
        return labels

    def env(self,r):
        c=r['config'];env=dict(v.split('=',1) for v in r['image'].get('Config',{}).get('Env') or [])
        env.update(RELAY_BIND=c['bind_ip'],RELAY_PORT=str(c['port']),RELAY_API_KEY=c['api_key'],
                   RELAY_ALLOWED_CONTAINERS=' '.join(c['allowed']),RELAY_ALLOWED_PREFIX=c['prefix'])
        return env

    def inspect(self,r,*,bind=False):
        c=r['config'];cid=r.get('container_id')
        values=self.api.call('GET','/containers/json?all=1')
        matches=[v for v in values if '/'+c['name'] in v.get('Names',[])]
        born=[v for v in values if (v.get('Labels') or {}).get('org.dnlab.relay.nonce')==r['nonce']]
        if len(matches)>1 or len(born)>1:raise RelayError('ambiguous relay birth')
        if not matches:
            if born or cid and any(v['Id']==cid for v in values):raise RelayError('relay generation renamed')
            return None
        actual=matches[0]['Id']
        if cid and actual!=cid:raise RelayError('relay generation replaced')
        v=self.api.call('GET','/containers/'+actual+'/json')
        cfg=v.get('Config',{});host=v.get('HostConfig',{});base=r['image'].get('Config',{})
        entries=cfg.get('Env') or []
        if (v.get('Id')!=actual or v.get('Name')!='/'+c['name'] or v.get('Image')!=r['image']['Id']
                or cfg.get('Image')!=r['image']['Id'] or cfg.get('Labels')!=self.labels(r)
                or len(entries)!=len(self.env(r)) or dict(item.split('=',1) for item in entries)!=self.env(r)
                or cfg.get('Entrypoint')!=base.get('Entrypoint') or cfg.get('Cmd')!=base.get('Cmd')
                or host.get('NetworkMode')!='host' or host.get('Privileged') is not False
                or host.get('Binds')!=[c['docker_socket']+':/var/run/docker.sock:rw']
                or host.get('CapAdd') not in (None,[]) or host.get('PortBindings') not in (None,{})
                or host.get('RestartPolicy',{}).get('Name')!='unless-stopped'
                or host.get('PidMode','')!='' or host.get('IpcMode')!='private'):
            raise RelayError('relay configuration or ownership differs')
        if not cid:
            if not bind or not r.get('create_attempted'):raise RelayError('unbound relay birth requires recovery')
            r['container_id']=actual;self.save(r)
        return v

    def absent(self,c):
        values=self.api.call('GET','/containers/json?all=1')
        if any('/'+c['name'] in v.get('Names',[]) or (v.get('Labels') or {}).get('org.dnlab.relay.scope')==self.key for v in values):
            raise RelayError('existing unqualified relay; no implicit adoption')

    def preflight(self,c=None):
        if c is not None:
            c=validate(c)
            if c['lab']!=self.lab or c['host']!=self.host or c['docker_socket']!=self.socket_path:
                raise RelayError('relay request scope differs')
        r=self.read()
        if r:
            # With a desired config this is an ensure/provision preflight,
            # not an inventory or cleanup observation. Reject known blockers
            # before the coordinator can allocate on any other host.
            if c is not None and r['phase'] not in ('active','cleaned'):
                raise RelayError('relay explicit recovery required before ensure')
            if c is not None and r['phase']=='cleaned' and c['generation']==r['config']['generation']:
                raise RelayError('new relay generation required after cleanup')
            if c is not None and c!=r['config']:
                if r['phase']!='cleaned':raise RelayError('relay original configuration differs')
                if self.inspect(r) is not None:raise RelayError('cleaned relay reappeared')
                self.image(c);self.absent(c)
            value=self.inspect(r)
            if r['phase']=='cleaned' and value is not None:raise RelayError('cleaned relay reappeared')
            if c is not None and r['phase']=='active' and (value is None or value.get('State',{}).get('Running') is not True):
                raise RelayError('active relay generation unavailable before ensure')
            return r
        if c is not None:self.image(validate(c));self.absent(c)
        else:
            values=self.api.call('GET','/containers/json?all=1')
            if any('/dnlab-'+self.lab+'-runtime-relay' in v.get('Names',[]) for v in values):
                raise RelayError('legacy relay requires explicit qualification')
        return {'phase':'absent'}

    def create(self,r):
        self.absent(r['config']);c=r['config'];base=r['image'].get('Config',{})
        if r.get('create_attempted'):raise RelayError('relay create outcome uncertain; no retry allocation')
        r.update(create_attempted=True,phase='creating');self.save(r)
        result=self.api.call('POST','/containers/create?name='+quote(c['name'],safe=''),{
            'Image':r['image']['Id'],'Env':[k+'='+v for k,v in self.env(r).items()],
            'Labels':self.labels(r),'Entrypoint':base.get('Entrypoint'),'Cmd':base.get('Cmd'),
            'HostConfig':{'NetworkMode':'host','Binds':[c['docker_socket']+':/var/run/docker.sock:rw'],
                          'RestartPolicy':{'Name':'unless-stopped'},'Privileged':False,'IpcMode':'private'}})
        cid=result.get('Id')
        if not isinstance(cid,str) or not re.fullmatch('[0-9a-f]{64}',cid):raise RelayError('relay create acknowledgement differs')
        r['container_id']=cid;self.save(r)
        if self.inspect(r) is None:raise RelayError('acknowledged relay generation missing')

    def start(self,r):
        v=self.inspect(r)
        if v is None:raise RelayError('relay birth missing; no recreation')
        if not v['State']['Running']:
            if r.get('start_attempted'):raise RelayError('relay start outcome unverified')
            r['start_attempted']=True;self.save(r)
            self.api.call('POST','/containers/'+r['container_id']+'/start')
        v=self.inspect(r)
        if v is None or not v['State']['Running']:raise RelayError('relay process not running')
        r.update(phase='active');self.save(r)

    def cleanup(self,r):
        v=self.inspect(r)
        if v is None and r.get('create_attempted') and not r.get('container_id'):
            raise RelayError('relay create still uncertain; absence is not final')
        if v and v['State']['Running']:
            if r.get('stop_attempted'):raise RelayError('relay shutdown still unverified')
            r['stop_attempted']=True;self.save(r)
            # Docker marks this a manual stop; -1 never escalates to SIGKILL.
            self.api.call('POST','/containers/'+r['container_id']+'/stop?t=-1')
            v=self.inspect(r)
        if v:
            if v['State']['Running']:raise RelayError('relay shutdown unverified')
            self.inspect(r)
            self.api.call('DELETE','/containers/'+r['container_id'])
        if self.inspect(r) is not None:raise RelayError('relay deletion unverified')
        r.update(phase='cleaned');self.save(r)

    def control(self,action,c=None,generation=None):
        with self.locked():
            if action=='preflight':return self.preflight(c)
            r=self.read()
            if action in ('preflight-delete','verify-cleaned'):
                if not r or not generation or r['config']['generation']!=generation:raise RelayError('original relay generation required')
                value=self.inspect(r)
                if action=='verify-cleaned' and (r['phase']!='cleaned' or value is not None):raise RelayError('relay cleanup pending')
                return r
            if action in ('ensure','provision'):
                c=validate(c)
                if c['lab']!=self.lab or c['host']!=self.host or c['docker_socket']!=self.socket_path:
                    raise RelayError('relay request scope differs')
                if r and r['phase']=='active':
                    if r['config']!=c:raise RelayError('relay configuration changed; no replacement')
                    v=self.inspect(r)
                    if v is None or not v['State']['Running']:raise RelayError('active relay generation unavailable')
                    return r
                if r and (r['phase']!='cleaned' or action!='provision'):raise RelayError('relay explicit recovery or provision required')
                if r and r['config']['generation']==c['generation']:raise RelayError('new relay generation required after cleanup')
                image=self.image(c);self.absent(c)
                old=r
                r={'config':c,'image':image,'intent_digest':digest({'config':c,'image':image}),
                   'context':self.host_context(),'nonce':uuid.uuid4().hex,'phase':'planned','goal':'ensure',
                   'history':(old.get('history',[])+[{k:v for k,v in old.items() if k!='history'}]) if old else []}
                self.save(r)
            elif action in ('delete','recover'):
                if not r:raise RelayError('relay original intent missing')
                if generation and generation!=r['config']['generation']:raise RelayError('relay generation differs')
                if action=='delete':
                    if not generation:raise RelayError('relay deletion requires coordinator generation')
                    r.update(goal='delete',phase='cleanup_pending');self.save(r)
                if not r.get('container_id') and r.get('create_attempted'):
                    self.inspect(r,bind=True)
            else:raise RelayError('unsupported relay action')
            try:
                if r['goal']=='delete':self.cleanup(r)
                else:
                    if not r.get('container_id'):
                        if action=='recover' and r.get('create_attempted'):raise RelayError('relay create still uncertain')
                        self.create(r)
                    self.start(r)
                return r
            except Exception as error:
                r.update(phase='cleanup_pending' if r['goal']=='delete' else 'recovery_required',error_type=type(error).__name__)
                self.save(r);raise


if __name__=='__main__':
    request=json.load(sys.stdin)
    worker=Worker(request['lab'],request['host'],directory=request['directory'],socket_path=request['socket_path'])
    print(canonical(worker.control(request['action'],request.get('config'),request.get('generation'))))
