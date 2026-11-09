"""Fixture-only bounded SSH authentication to the original published jumphost."""
import base64
import hashlib
import os
from pathlib import Path
import stat
import time

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from dnlab_multinode.services.jumphost_host import Worker
from management_service_diagnostics import private_json


def prepare_key(root):
    key=Ed25519PrivateKey.generate();path=Path(root)/'fixture-ssh-key'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(key.private_bytes(Encoding.PEM,PrivateFormat.OpenSSH,NoEncryption()))
        stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    public=key.public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode()
    return {'path':str(path),'public':public,'fingerprint':hashlib.sha256(public.encode()).hexdigest()}


def public_key(worker,record):
    """Read a public host key under the original container root, without exec."""
    value=worker.container(record);state=value['State']
    if not state['Running']:raise RuntimeError('original jumphost not running')
    pid=state['Pid'];root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
    try:
        fd=os.open('etc/ssh/ssh_host_ed25519_key.pub',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=root)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());data=stream.read(4097);after=os.fstat(stream.fileno())
        signature=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,stat.S_IMODE(v.st_mode),v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        if (signature(before)!=signature(after) or not stat.S_ISREG(before.st_mode)
                or before.st_uid!=0 or before.st_mode&0o022 or len(data)>4096):
            raise RuntimeError('original SSH host public key identity differs')
        parts=data.decode().strip().split()
        if len(parts)<2 or parts[0]!='ssh-ed25519' or b'\n' in data.rstrip(b'\n'):
            raise RuntimeError('original SSH host key format differs')
        key=paramiko.Ed25519Key(data=base64.b64decode(parts[1],validate=True))
        current=worker.container(record)
        if current['Id']!=value['Id'] or any(current['State'][k]!=state[k] for k in ('Pid','StartedAt','Running')):
            raise RuntimeError('original jumphost changed while reading SSH key')
        return key,{'container_id':value['Id'],'nonce':record['nonce'],'pid':pid,'started_at':state['StartedAt'],
                    'namespace':record['namespace'],'public_key_sha256':hashlib.sha256(data).hexdigest(),
                    'file_identity':signature(before)}
    finally:os.close(root)


def authenticate(config,key_path,host_key,*,factory=paramiko.SSHClient):
    client=factory();transport=None
    try:
        host=config['bind_ip'];port=config['port']
        if host in ('0.0.0.0','::'):raise RuntimeError('fixture requires explicit reachable SSH bind address')
        token=host if port==22 else '['+host+']:'+str(port)
        client.get_host_keys().add(token,host_key.get_name(),host_key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(hostname=host,port=port,username='labuser',pkey=paramiko.Ed25519Key.from_private_key_file(key_path),
            allow_agent=False,look_for_keys=False,password=None,timeout=5,banner_timeout=5,auth_timeout=5,channel_timeout=5)
        transport=client.get_transport()
        if not transport or not transport.is_authenticated():raise RuntimeError('original SSH authentication not verified')
        stdin,stdout,stderr=client.exec_command('id -un',timeout=5)
        try:
            stdin.close();output=stdout.read(257);error=stderr.read(257)
            deadline=time.monotonic()+5
            while not stdout.channel.exit_status_ready():
                if time.monotonic()>=deadline:raise RuntimeError('SSH identity command exit uncertain')
                time.sleep(.02)
            status=stdout.channel.recv_exit_status()
            if output!=b'labuser\n' or error or status!=0:raise RuntimeError('SSH authenticated identity differs')
            return {'authenticated_user':'labuser','command':'id -un','exit_code':status,
                    'server_key_sha256':hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest(),
                    'vd_access_verified':False,'webui_verified':False}
        finally:
            stdin.close();stdout.close();stderr.close()
    finally:
        if transport is None:transport=client.get_transport()
        client.close()
        if transport:
            transport.join(timeout=3)
            if transport.is_alive():raise RuntimeError('SSH transport thread still alive; cleanup uncertain')


def probe(root,lab,config,key,*,worker=None,auth=authenticate):
    root=Path(root);path=root/'ssh-authentication.json'
    worker=worker or Worker(lab,directory=str(root/'jump'),management_directory=str(root/'management'))
    def observe():
        record=worker.read()
        if record['phase']!='active' or record['config']!=config:raise RuntimeError('original SSH helper intent differs')
        worker.infrastructure(record);worker.verify_extensions(record)
        with worker.namespace(record) as fd:worker.verify_attachment(record,fd)
        return public_key(worker,record)
    host_key,before=observe()
    row={'phase':'planned','original':before,'client_public_fingerprint':key['fingerprint'],'attempts':0}
    private_json(path,row)
    try:
        # Revalidate after the durable intent and before any authentication.
        check,proof=observe()
        if proof!=before or check.asbytes()!=host_key.asbytes():raise RuntimeError('SSH original proof changed before connect')
        row.update(phase='connecting',attempts=1);private_json(path,row)
        result=auth(config,key['path'],host_key)
        check,proof=observe()
        if proof!=before or check.asbytes()!=host_key.asbytes():raise RuntimeError('SSH original proof changed after connect')
        row.update(phase='completed',result=result,client_closed=True);private_json(path,row)
        return row
    except Exception as error:
        row.update(phase='failed',error_type=type(error).__name__,error=str(error));private_json(path,row);raise
