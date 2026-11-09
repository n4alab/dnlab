"""Readonly local/NSS identity inspection, not account creation or adoption.

The caller supplies NSS lookup and the original provisioning window/preflight.
No host reads occur at import/construction. Shadow is read only after the exact
target account matches both local and NSS identity; no secret leaves the reader.
"""
from copy import deepcopy
import os
from pathlib import Path
import re

from .libvirt_provisioning import account_marker
from .manifest import Conflict
from .vm_bundle import metadata,pinned_file


def host_query(database,key):
    # These imports and calls are only reached from the explicit host entry.
    import pwd
    import grp
    try:
        if database=='passwd':
            row=pwd.getpwuid(key) if type(key) is int else pwd.getpwnam(key)
            return dict(name=row.pw_name,uid=row.pw_uid,gid=row.pw_gid)
        row=grp.getgrgid(key) if type(key) is int else grp.getgrnam(key)
        return dict(name=row.gr_name,gid=row.gr_gid)
    except KeyError:return None


def checked_lookup(database,key,query):
    try:row=query(database,key)
    except Exception as error:raise Conflict('NSS query failed: '+database+' '+str(key)+': '+type(error).__name__) from error
    if row is None:return None
    fields={'name','uid','gid'} if database=='passwd' else {'name','gid'}
    if (not isinstance(row,dict) or set(row)!=fields or not isinstance(row['name'],str)
            or not row['name'] or len(row['name'])>256 or '\0' in row['name']
            or any(type(row[k]) is not int or not 0<=row[k]<2**31 for k in fields-{'name'})):
        raise Conflict('NSS response is malformed: '+database+' '+str(key))
    selected='uid' if database=='passwd' else 'gid'
    if (type(key) is int and row[selected]!=key) or (isinstance(key,str) and row['name']!=key):
        raise Conflict('NSS response does not match query: '+database+' '+str(key))
    return deepcopy(row)



def validate_request(request):
    if (not isinstance(request,dict) or set(request)!={'intent_id','nonce','spec_sha256','kind','expected'}
            or not isinstance(request['intent_id'],str) or not request['intent_id']
            or not isinstance(request['nonce'],str) or not re.fullmatch(r'[0-9a-f]{32}',request['nonce'])
            or not isinstance(request['spec_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',request['spec_sha256'])
            or request['kind'] not in ('group','account')):
        raise Conflict('original account identity request required')
    expected=request['expected'];kind=request['kind']
    fields={'name','gid'} if kind=='group' else {'name','uid','gid','home','shell','locked','comment'}
    if (not isinstance(expected,dict) or set(expected)!=fields or not isinstance(expected['name'],str)
            or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',expected['name']) or expected['name']=='root'
            or type(expected['gid']) is not int or not 0<expected['gid']<2**31):
        raise Conflict('dedicated account identity required')
    if kind=='account' and (type(expected['uid']) is not int or not 0<expected['uid']<2**31
            or expected['shell']!='/usr/sbin/nologin' or expected['locked'] is not True
            or not isinstance(expected['home'],str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',expected['home'])
            or '..' in expected['home'].split('/')
            or expected['comment']!=account_marker(request['intent_id'],request['nonce'])):
        raise Conflict('original locked account identity required')
    return expected


class LocalAccountIdentity:
    def __init__(self,root,*,nss_query):
        self.root=Path(root)
        if not self.root.is_absolute() or not callable(nss_query):raise Conflict('explicit identity root and NSS query required')
        self.query=nss_query

    @staticmethod
    def _read(root,path):
        with pinned_file(root,path) as (fd,info):
            if info.st_uid!=0 or info.st_mode&0o022 or info.st_size>4*1024*1024:
                raise Conflict('bounded root-controlled account file required')
            data=b''
            while len(data)<=4*1024*1024:
                block=os.read(fd,min(65536,4*1024*1024+1-len(data)))
                if not block:break
                data+=block
            if len(data)>4*1024*1024:raise Conflict('account file exceeds bound')
            return dict(metadata=metadata(info),data=data)

    @staticmethod
    def _rows(raw,kind):
        rows=[]
        for line in raw.decode('utf-8').splitlines():
            if not line:continue
            fields=line.split(':');width=7 if kind=='account' else 4
            if (len(fields)!=width or not fields[0] or not fields[2].isdecimal()
                    or kind=='account' and not fields[3].isdecimal()):
                raise Conflict('local account database is malformed')
            rows.append(fields)
        return rows

    def _observe(self,root,request):
        expected=request['expected'];kind=request['kind']
        local={path:self._read(root,path) for path in ('etc/passwd','etc/group')}
        for database in ('passwd','group'):
            control=dict(name='root',gid=0)
            if database=='passwd':control['uid']=0
            for key in ('root',0):
                if checked_lookup(database,key,self.query)!=control:raise Conflict('NSS root control query differs')
        database='passwd' if kind=='account' else 'group';number=expected['uid'] if kind=='account' else expected['gid']
        nss=[checked_lookup(database,key,self.query) for key in (expected['name'],number)]
        rows=self._rows(local['etc/'+database]['data'],kind)
        names=[row for row in rows if row[0]==expected['name']]
        numbers=[row for row in rows if int(row[2])==number]
        if not names and not numbers and nss==[None,None]:
            return dict(local=local,nss=nss,identity=None)
        if len(names)!=1 or len(numbers)!=1 or names[0]!=numbers[0]:
            raise Conflict('account name or numeric identity is occupied or ambiguous')
        row=names[0]
        minimal=dict(name=row[0],gid=int(row[3] if kind=='account' else row[2]))
        if kind=='account':minimal['uid']=int(row[2])
        if nss!=[minimal,minimal]:raise Conflict('local and NSS target identity differ')
        if kind=='group':identity=dict(name=row[0],gid=int(row[2]))
        else:
            identity=dict(name=row[0],uid=int(row[2]),gid=int(row[3]),home=row[5],shell=row[6],comment=row[4],locked=True)
            # Reject unrelated/replaced local/NSS accounts before touching shadow.
            if identity!=expected or row[1]!='x':raise Conflict('original account attributes differ')
            shadow=self._read(root,'etc/shadow')
            selected=[line.split(':') for line in shadow['data'].decode('utf-8').splitlines()
                if line.split(':',1)[0]==expected['name']]
            if len(selected)!=1 or len(selected[0])!=9 or selected[0][1]!='!':
                raise Conflict('original target account lock differs')
            local['etc/shadow']=shadow
        if identity!=expected:raise Conflict('original group attributes differ')
        return dict(local=local,nss=nss,identity=identity)

    def __call__(self,request):
        validate_request(request)
        root=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            first=self._observe(root,request);second=self._observe(root,request)
            if first!=second:raise Conflict('account identity changed during observation')
            return deepcopy(first['identity'])
        finally:os.close(root)
