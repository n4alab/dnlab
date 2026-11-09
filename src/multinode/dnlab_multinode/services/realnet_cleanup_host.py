"""Standalone, root-only RealNet cleanup worker, sent over the existing SSH API.

The caller preflights every host before invoking cleanup on any host. This
worker repeats verification under a host lock and journals each deletion before
executing it. It never qualifies existing resources or deletes by name alone.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile


class OwnershipError(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def execute(argv,*,pass_fds=()):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=30,pass_fds=pass_fds)
    if result.returncode:raise OwnershipError('RealNet command failed: '+argv[0])
    return result.stdout


def context():
    info=os.stat('/proc/self/ns/net')
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'device':info.st_dev,'inode':info.st_ino}


def link_identity(value):
    return {key:value.get(key) for key in ('ifindex','address','ifalias','link_index')}


def bridge_create_argv(name,creator):
    """Create with a stable MAC; provisioning must journal creator beforehand."""
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',name) or not re.fullmatch('[0-9a-f]{32}',creator):
        raise OwnershipError('invalid RealNet bridge creation identity')
    data=bytearray(hashlib.sha256(creator.encode()).digest()[:6])
    data[0]=(data[0]&0xfc)|2
    mac=':'.join(f'{part:02x}' for part in data)
    return ['ip','link','add',name,'address',mac,'type','bridge']


def validate(plan):
    if not isinstance(plan,dict) or set(plan)!={'scope','context','links','router','firewall'}:
        raise OwnershipError('missing or invalid RealNet ownership proof')
    if not re.fullmatch('[0-9a-f]{64}',plan['scope']):raise OwnershipError('invalid RealNet scope')
    if set(plan['context'])!={'boot_id','device','inode'}:raise OwnershipError('invalid RealNet context proof')
    for name,record in plan['links'].items():
        if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}',name):raise OwnershipError('invalid RealNet link name')
        if record.get('kind') not in ('bridge','vxlan','veth') or set(record)!={'kind','identity','config'}:
            raise OwnershipError('invalid RealNet link proof')
        identity=record['identity']
        if set(identity)!={'ifindex','address','ifalias','link_index'} or type(identity['ifindex']) is not int:
            raise OwnershipError('invalid RealNet kernel identity')
        if not re.fullmatch('dnlab-runtime:realnet:'+plan['scope']+':[0-9a-f]{32}',identity.get('ifalias') or ''):
            raise OwnershipError('unqualified legacy RealNet link')
        if not isinstance(record['config'],dict):raise OwnershipError('invalid RealNet link configuration')
    router=plan['router']
    if router is not None:
        if set(router)!={'id','name','image','labels'}:raise OwnershipError('invalid RealNet router proof')
        if not re.fullmatch('[0-9a-f]{64}',router['id']) or not re.fullmatch('sha256:[0-9a-f]{64}',router['image']):
            raise OwnershipError('invalid immutable RealNet router identity')
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',router['name']):raise OwnershipError('invalid RealNet router name')
        labels=router['labels']
        if labels.get('org.dnlab.realnet.scope')!=plan['scope'] or not re.fullmatch('[0-9a-f]{32}',labels.get('org.dnlab.realnet.creator','')):
            raise OwnershipError('unqualified legacy RealNet router')
    for rule in plan['firewall']:
        if not isinstance(rule,list) or not all(isinstance(arg,str) for arg in rule):raise OwnershipError('invalid firewall proof')
        if (len(rule)!=9 or rule[0]!='FORWARD' or rule[1] not in ('-i','-o') or rule[2] not in plan['links']
                or plan['links'][rule[2]]['kind']!='bridge' or rule[3:6]!=['-m','comment','--comment']
                or not re.fullmatch('dnlab-runtime:realnet:'+plan['scope']+':[0-9a-f]{32}',rule[6])
                or rule[7:]!=['-j','ACCEPT']):raise OwnershipError('unqualified RealNet firewall rule')
    if len({tuple(rule) for rule in plan['firewall']})!=len(plan['firewall']):raise OwnershipError('duplicate firewall proof')


class Worker:
    def __init__(self,plan,*,run=execute,host_context=context,directory='/var/lib/dnlab/realnet-cleanup',attachment_directory='/var/lib/dnlab-runtime'):
        validate(plan)
        self.plan,self.run,self.host_context,self.directory=plan,run,host_context,Path(directory)
        self.attachment_directory=attachment_directory

    def links(self):
        values=json.loads(self.run(['ip','-j','-d','link','show']))
        if not isinstance(values,list) or len({x['ifname'] for x in values})!=len(values):raise OwnershipError('invalid RealNet link inventory')
        return {x['ifname']:x for x in values}

    def router(self):
        expected=self.plan['router']
        if expected is None:return None
        identity=self.run(['docker','ps','-aq','--no-trunc','--filter','name=^/'+expected['name']+'$']).strip()
        if not identity:return None
        if identity!=expected['id']:raise OwnershipError('RealNet router was replaced')
        values=json.loads(self.run(['docker','inspect',identity]))
        if not isinstance(values,list) or len(values)!=1:raise OwnershipError('invalid RealNet router inspection')
        value=values[0]
        if (value.get('Id')!=identity or value.get('Name')!='/'+expected['name'] or value.get('Image')!=expected['image']
                or (value.get('Config',{}).get('Labels') or {})!=expected['labels']):raise OwnershipError('RealNet router ownership changed')
        return value

    def firewall(self):
        rules=[]
        for line in self.run(['iptables-save','-t','filter']).splitlines():
            args=shlex.split(line)
            if args[:2]==['-A','FORWARD']:rules.append(args[1:])
        for expected in self.plan['firewall']:
            comment=expected[6]
            matches=[rule for rule in rules if '--comment' in rule and rule[rule.index('--comment')+1]==comment]
            # Both directions share a creator comment. Validate the whole group.
            permitted=[rule for rule in self.plan['firewall'] if rule[6]==comment]
            if any(rule not in permitted for rule in matches) or matches.count(expected)>1:
                raise OwnershipError('RealNet firewall ownership or configuration changed')
        return rules

    @staticmethod
    def attachments_signature(value):
        return {key:value.get(key) for key in ('ifname','ifindex','ifalias','address','link_index')}

    def attachments(self):
        if hasattr(self,'_attachments'):return self._attachments
        factory=globals().get('_InfrastructureAttachments')
        if factory is None:
            from .realnet_attachment_host import InfrastructureAttachments
            factory=InfrastructureAttachments
        self._attachments=factory(self.plan,directory=self.attachment_directory,
                       run=lambda args,**kwargs:self.run(args,**kwargs),host_context=self.host_context)
        return self._attachments

    def detach_attachments(self):
        self.preflight()
        try:return self.attachments().detach()
        except Exception as exc:raise OwnershipError('RealNet attachment recovery pending: '+str(exc)) from None

    def preflight(self):
        try:
            with self.attachments().execution(read_only=True):return self._preflight_locked()
        except OwnershipError:raise
        except Exception as exc:raise OwnershipError('RealNet attachment preflight failed: '+str(exc)) from None

    def _preflight_locked(self):
        if self.host_context()!=self.plan['context']:raise OwnershipError('RealNet host namespace or boot changed')
        links=self.links()
        try:qualified=self.attachments().preflight()
        except Exception as exc:raise OwnershipError('RealNet attachment preflight failed: '+str(exc)) from None
        for name,expected in self.plan['links'].items():
            value=links.get(name)
            if value is None:continue
            if (link_identity(value)!=expected['identity'] or value.get('linkinfo',{}).get('info_kind')!=expected['kind']
                    or any(value.get('linkinfo',{}).get('info_data',{}).get(key)!=wanted for key,wanted in expected['config'].items())):
                raise OwnershipError('RealNet link ownership or configuration changed: '+name)
            if expected['kind']=='bridge':
                for port in links.values():
                    if (port.get('master') in (name,value['ifindex']) and port['ifname'] not in self.plan['links']
                            and (port['ifname'] not in qualified or self.attachments_signature(port)!=qualified[port['ifname']])):
                        raise OwnershipError('RealNet bridge contains an unqualified port')
            else:
                master=value.get('master')
                allowed=[x for x,r in self.plan['links'].items() if r['kind']=='bridge']
                if master is not None and master not in allowed and master not in [links[x]['ifindex'] for x in allowed if x in links]:
                    raise OwnershipError('RealNet endpoint belongs to another bridge')
        self.router();self.firewall()
        return {'status':'verified','proof':digest(self.plan)}

    def read(self,path):
        try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return None
        with os.fdopen(fd) as stream:
            info=os.fstat(stream.fileno())
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:
                raise OwnershipError('RealNet journal ownership or mode differs')
            record=json.load(stream)
        if record.get('proof')!=self.plan:raise OwnershipError('RealNet cleanup journal proof differs')
        return record

    def save(self,path,record):
        fd,temporary=tempfile.mkstemp(dir=self.directory,prefix='.cleanup-')
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path)
            fd=os.open(self.directory,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)

    def cleanup(self):
        with self.attachments().execution():return self._cleanup_locked()

    def _cleanup_locked(self):
        if self.directory.resolve()!=self.directory.absolute():raise OwnershipError('RealNet journal directory is a symlink')
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.directory.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise OwnershipError('RealNet journal directory ownership or mode differs')
        lock=os.open(self.directory/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(lock)
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600:
                raise OwnershipError('RealNet journal lock ownership or mode differs')
            fcntl.flock(lock,fcntl.LOCK_EX)
            path=self.directory/(self.plan['scope']+'.json')
            record=self.read(path) or {'proof':self.plan,'phase':'cleanup_pending','steps':{}}
            self.preflight()
            if any(phase!='cleaned' for _,_,phase in self.attachments().records()):
                raise OwnershipError('RealNet data attachments must be detached before infrastructure cleanup')
            if record['phase']=='cleaned':
                self.verify_absent();return {'status':'cleaned','proof':digest(self.plan)}
            record['phase']='cleanup_pending';self.save(path,record)
            def step(key,action):
                self.preflight()
                record['steps'][key]='intent';self.save(path,record)
                action()
                record['steps'][key]='done';self.save(path,record)
            # Remove veth before the container: Docker can otherwise remove its
            # namespace peer as a side effect before we journal that deletion.
            ordered=sorted(self.plan['links'],key=lambda name:({'veth':0,'vxlan':1,'bridge':2}[self.plan['links'][name]['kind']],name))
            for name in ordered:
                def remove_link(name=name):
                    if name in self.links():self.run(['ip','link','delete','dev',name])
                    if name in self.links():raise OwnershipError('RealNet link still exists after deletion')
                step('link:'+name,remove_link)
            if self.plan['router']:
                def remove_router():
                    value=self.router()
                    if value is None:return
                    identity=value['Id']
                    if value['State']['Running']:
                        self.run(['docker','kill','--signal','SIGKILL',identity])
                        self.run(['docker','wait',identity])
                    value=self.router()
                    if value is not None:
                        if value['State']['Running']:raise OwnershipError('RealNet router did not stop')
                        self.run(['docker','rm',identity])
                    if self.router() is not None:raise OwnershipError('RealNet router still exists after deletion')
                step('router',remove_router)
            for index,rule in enumerate(self.plan['firewall']):
                def remove_rule(rule=rule):
                    if rule in self.firewall():self.run(['iptables','-w','5','-D',*rule])
                    if rule in self.firewall():raise OwnershipError('RealNet firewall rule still exists')
                step('firewall:'+str(index),remove_rule)
            self.verify_absent()
            record['phase']='cleaned';self.save(path,record)
            return {'status':'cleaned','proof':digest(self.plan)}
        finally:os.close(lock)

    def verify_absent(self):
        self.preflight()
        if any(name in self.links() for name in self.plan['links']) or self.router() is not None or any(rule in self.firewall() for rule in self.plan['firewall']):
            raise OwnershipError('RealNet cleanup remains incomplete')


    def verify_cleaned(self):
        """Read-only finalization proof, including firewall and durable steps."""
        if self.directory.resolve()!=self.directory.absolute():raise OwnershipError('RealNet journal directory is a symlink')
        if not self.directory.exists():raise OwnershipError('RealNet cleanup journal is missing')
        info=self.directory.stat()
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
            raise OwnershipError('RealNet journal directory ownership or mode differs')
        record=self.read(self.directory/(self.plan['scope']+'.json'))
        expected={'link:'+name for name in self.plan['links']}
        if self.plan['router']:expected.add('router')
        expected.update('firewall:'+str(index) for index in range(len(self.plan['firewall'])))
        if (not record or record.get('phase')!='cleaned' or set(record.get('steps',{}))!=expected
                or any(record['steps'][key]!='done' for key in expected)):
            raise OwnershipError('RealNet cleanup journal is incomplete')
        self.verify_absent()
        return {'status':'cleaned','proof':digest(self.plan)}


def main():
    action,encoded=sys.argv[1:]
    worker=Worker(json.loads(encoded))
    if action not in ('preflight','cleanup','verify_cleaned','detach_attachments'):raise OwnershipError('invalid RealNet cleanup action')
    print(json.dumps(getattr(worker,action)()))


if __name__=='__main__':main()
