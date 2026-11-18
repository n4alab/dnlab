"""Bounded readonly API queries in the original process's pinned net namespace.

No helper process, proxy, redirect, retry or service discovery. Namespace changes
are confined to the calling thread and the original namespace is always restored.
"""
from contextlib import contextmanager
from copy import deepcopy
import http.client
import json
import os
import time

from cleanup_container_observer import LinuxProcess, config_digest
from image_build_observation import ImageBuildApiNotReady
from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import require


def net_identity(fd):
    info=os.fstat(fd);return dict(device=info.st_dev,inode=info.st_ino)


def thread_net():
    info=os.stat('/proc/thread-self/ns/net');return dict(device=info.st_dev,inode=info.st_ino)


class PinnedNetworkNamespace:
    def __init__(self, *, open_ns=os.open, identity=net_identity, current=thread_net,
                 switch=None, close=os.close):
        self.open,self.identity,self.current,self.close=open_ns,identity,current,close
        self.switch=getattr(os,'setns',None) if switch is None else switch
        require(callable(self.switch), 'native network namespace switching unavailable')

    @contextmanager
    def enter(self, capture, original_context):
        expected={key:capture['process']['namespaces']['net'][key] for key in ('device','inode')}
        original=original_context['namespaces']['net']
        saved=self.open('/proc/thread-self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        target=None
        try:
            require(self.identity(saved)==original and self.current()==original,
                    'original calling thread network namespace differs')
            target=self.open('/proc/'+str(capture['process']['pid'])+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
            require(self.identity(target)==expected, 'original API network namespace FD differs')
            failure=None
            try:
                self.switch(target,0)
                require(self.current()==expected, 'entered API namespace differs')
                yield
            except BaseException as error:failure=error
            try:
                self.switch(saved,0)
                require(self.current()==original and self.identity(saved)==original,
                        'original thread network namespace not restored')
            except BaseException as error:
                if failure is None:failure=error
                else:failure.add_note('network namespace restoration failed: '+type(error).__name__)
            if failure is not None:raise failure
        finally:
            if target is not None:self.close(target)
            self.close(saved)


def unique_object(pairs):
    result={}
    for key,value in pairs:
        require(key not in result, 'duplicate API JSON key')
        result[key]=value
    return result


class ImageBuildNamespaceQuery:
    def __init__(self, api, profile, *, read_context, process=None, namespace=None,
                 connection=http.client.HTTPConnection, clock=time.monotonic, port=8082):
        require(callable(read_context) and callable(connection) and callable(clock)
                and type(port) is int and 1<=port<=65535, 'qualified bounded readonly query providers required')
        self.api,self.profile,self.read_context=api,deepcopy(profile),read_context
        self.profile_sha256=fingerprint(profile)
        self.process=LinuxProcess() if process is None else process
        self.namespace=PinnedNetworkNamespace() if namespace is None else namespace
        self.connection,self.clock,self.port=connection,clock,port

    def _inspect(self, capture):
        value=self.api.inspect(self.profile['actor']['container_id'])
        require(value is not None and value.get('Id')==self.profile['actor']['container_id']
                and value.get('Image')==self.profile['actor']['image_id'], 'original query container differs')
        normalized=deepcopy(value);normalized['HostConfig']['RestartPolicy']=self.profile['policy']
        require(config_digest(normalized)==self.profile['actor']['config_sha256']
                and value['HostConfig']['RestartPolicy'] in (self.profile['policy'],NO_RESTART)
                and value['State']['Running'] is True and value['State']['Status']=='running'
                and value['State']['Pid']==capture['process']['pid'], 'original query lifecycle/configuration differs')
        return dict(pid=value['State']['Pid'],started_at=value['State']['StartedAt'],restart_count=value['RestartCount'],
                    config_sha256=config_digest(value),networks=value['NetworkSettings']['Networks'])

    def _get(self, path, limit, deadline):
        remaining=deadline-self.clock();require(remaining>0, 'image-build query deadline exceeded')
        connection=self.connection('127.0.0.1',self.port,timeout=min(3,remaining))
        try:
            connection.request('GET',path,headers={'Accept':'application/json','Connection':'close'})
            response=connection.getresponse()
            require(response.status==200, 'original readonly API response differs; no redirect or retry')
            data=bytearray()
            while True:
                remaining=deadline-self.clock();require(remaining>0, 'image-build query deadline exceeded')
                if connection.sock is not None:connection.sock.settimeout(min(3,remaining))
                block=response.read1(min(65536,limit+1-len(data)))
                if not block:break
                data.extend(block);require(len(data)<=limit, 'bounded image-build API response exceeded')
            require(self.clock()<=deadline, 'image-build query deadline exceeded')
            return json.loads(data,object_pairs_hook=unique_object,
                              parse_constant=lambda token:require(False,'non-finite API JSON value'))
        except ConnectionRefusedError as error:
            raise ImageBuildApiNotReady('original loopback API connection refused') from error
        finally:connection.close()

    def __call__(self, value, capture):
        profile=self.profile
        require(fingerprint(profile)==self.profile_sha256 and self.read_context()==profile['context']
                and value['actor']==profile['actor']
                and value['scope']['host_id']==profile['context']['host_id']
                and value['scope']['boot_id']==profile['context']['boot_id'], 'original query owner/context differs')
        before=self._inspect(capture)
        with self.process.capture(capture['process']['pid'],profile['actor']['container_id'],profile['copies']) as current:
            require(current==capture, 'original query process/source differs')
            deadline=self.clock()+15
            with self.namespace.enter(capture,profile['context']):
                result=dict(health=self._get('/health',8192,deadline),jobs=self._get('/jobs',8*1024*1024,deadline),
                            binding=self._get('/vrnetlab/binding',65536,deadline))
            require(self.read_context()==profile['context'], 'query context changed after namespace restoration')
        require(self._inspect(capture)==before and self.read_context()==profile['context'],
                'original API generation/context changed during query')
        return result
