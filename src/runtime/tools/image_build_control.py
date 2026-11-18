"""Bounded native image-build actions; callers own durable dispatch and drain.

No retry, name lookup, forced stop or fallback to Docker signals. These adapters
are not gate admission and do not infer shutdown/drain from an exited process.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import os
import re
import select
import signal
from urllib.parse import urlencode

from cleanup_container_observer import LinuxProcess
from dnlab_runtime.backend import UnixConnection
from dnlab_runtime.image_build_hold import policy
from dnlab_runtime.vm_template import digest, require


class ImageBuildEngine:
    """One explicit Docker ID; HTTP acknowledgements retain their semantics."""
    def __init__(self, container_id, *, socket_path='/var/run/docker.sock', connection=UnixConnection):
        require(digest(container_id) and callable(connection), 'original Docker ID and transport required')
        self.container_id,self.socket_path,self.connection=container_id,socket_path,connection

    def _request(self, suffix, payload, expected, *, method='POST', limit=65536):
        connection=self.connection(self.socket_path,timeout=10)
        try:
            body=None if payload is None else json.dumps(payload,separators=(',',':')).encode()
            connection.request(method,'/containers/'+self.container_id+suffix,body=body,
                               headers={'Content-Type':'application/json'})
            response=connection.getresponse();data=response.read(limit+1)
            require(len(data)<=limit and response.status==expected,
                    'original image-build action acknowledgement differs; no retry')
            return data
        finally:connection.close()

    def update_policy(self, restart):
        policy(restart)
        data=self._request('/update',dict(RestartPolicy=deepcopy(restart)),200)
        result=json.loads(data)
        require(type(result) is dict and set(result)=={'Warnings'} and result['Warnings'] in (None,[]),
                'image-build policy update warnings or response differ')

    def start(self):
        require(self._request('/start',None,204)==b'',
                'empty original start acknowledgement required')

    def shutdown_logs(self, started_at, namespace_pid):
        timestamp(started_at)
        query=urlencode(dict(stdout='1',stderr='1',timestamps='1',since=started_at,tail='4096'))
        raw=self._request('/logs?'+query,None,200,method='GET',limit=1024*1024)
        return shutdown_log_proof(raw,started_at,namespace_pid)


def timestamp(value):
    require(type(value) is str, 'original UTC Docker timestamp required')
    match=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z',value)
    require(match is not None, 'original UTC Docker timestamp required')
    datetime.fromisoformat(match[1])  # Reject impossible dates without local TZ conversion.
    return match[1]+'.'+(match[2] or '').ljust(9,'0')


def shutdown_log_proof(raw, started_at, namespace_pid):
    """Require the complete Uvicorn generation and shutdown sequence on stderr.

    This is log evidence only. The caller still requires original pidfd exit,
    Docker lifecycle, unchanged ledger/binding and an empty activity census.
    TTY/plain or truncated streams are refused rather than guessed.
    """
    require(type(raw) is bytes and len(raw)<=1024*1024 and type(namespace_pid) is int and namespace_pid>0,
            'bounded original non-TTY Docker log stream required')
    lower=timestamp(started_at);streams={1:bytearray(),2:bytearray()};offset=0
    while offset<len(raw):
        header=raw[offset:offset+8]
        require(len(header)==8 and header[0] in streams and header[1:4]==b'\0\0\0',
                'original Docker log frame header differs')
        size=int.from_bytes(header[4:],'big');offset+=8
        require(size<=1024*1024 and offset+size<=len(raw), 'truncated original Docker log frame')
        streams[header[0]].extend(raw[offset:offset+size]);offset+=size
    expected=[f'Started server process [{namespace_pid}]','Application startup complete.',
              'Shutting down','Waiting for application shutdown.','Application shutdown complete.',
              f'Finished server process [{namespace_pid}]']
    messages=[];last=None
    for line in bytes(streams[2]).decode('utf-8').splitlines():
        date,separator,content=line.partition(' ')
        require(separator and timestamp(date)>=lower, 'log timestamp predates original Docker generation')
        current=timestamp(date)
        require(last is None or current>=last, 'original Docker log timestamps reordered')
        last=current
        match=re.fullmatch(r'INFO:\s+(.+)',content)
        if match and match[1] in expected:messages.append(match[1])
        require(not re.search(r'(?:Started|Finished) server process \[(?!'+str(namespace_pid)+r'\])[0-9]+\]',content),
                'log contains another API process generation')
    require(messages==expected, 'original API startup/shutdown log sequence incomplete or repeated')
    return dict(log_sha256=hashlib.sha256(raw).hexdigest(),started_at=started_at,
                namespace_pid=namespace_pid,ordinary_shutdown_log_verified=True)


class OriginalImageBuildTerm:
    """Pin the original process before preflight and send at most one SIGTERM.

    The caller must record release_requested before calling term(). A failed or
    timed-out result is uncertain, never permission to call term() again. Closing
    the witness closes only its descriptor and sends no signal.
    """
    def __init__(self, *, process=None, pidfd_open=os.pidfd_open, poll_factory=select.poll,
                 send_signal=signal.pidfd_send_signal, namespace_pid=None):
        self.process=LinuxProcess() if process is None else process
        self.pidfd_open,self.poll_factory,self.send_signal=pidfd_open,poll_factory,send_signal
        self.namespace_pid=self._namespace_pid if namespace_pid is None else namespace_pid

    @staticmethod
    def _namespace_pid(pid):
        with open('/proc/'+str(pid)+'/status','rb') as stream:data=stream.read(65537)
        require(len(data)<=65536, 'bounded original process status required')
        values=re.findall(rb'^NSpid:\s*([0-9\t ]+)$',data,re.MULTILINE)
        require(len(values)==1, 'original namespace PID unavailable')
        parts=values[0].split()
        require(parts and all(part.isdigit() and int(part)>0 for part in parts), 'original namespace PID invalid')
        return int(parts[-1])

    @contextmanager
    def pin(self, capture, container_id, copies):
        require(type(capture) is dict and type(capture.get('process')) is dict and digest(container_id),
                'original complete API process capture required')
        pid=capture['process']['pid']
        require(type(pid) is int and pid>0, 'original API PID required')
        fd=self.pidfd_open(pid,0)
        try:
            require(type(fd) is int and fd>=0, 'original API pidfd required')
            poll=self.poll_factory();poll.register(fd,select.POLLIN)
            require(not poll.poll(0), 'original API process unavailable before capture')
            with self.process.capture(pid,container_id,copies) as observed:
                require(observed==capture, 'original API process/source capture differs')
                server_pid=self.namespace_pid(pid)
                require(type(server_pid) is int and server_pid>0, 'original API namespace PID required')
            require(not poll.poll(0) and self.process._view(pid)==capture['process']
                    and self.namespace_pid(pid)==server_pid, 'original API changed during pin')
            witness=_PinnedTerm(fd,poll,self.process,self.namespace_pid,self.send_signal,capture,server_pid)
            try:yield witness
            finally:witness.closed=True
        finally:os.close(fd)


class _PinnedTerm:
    def __init__(self,fd,poll,process,namespace_pid,send_signal,capture,server_pid):
        self.fd,self.poll,self.process,self.namespace_pid,self.send_signal=fd,poll,process,namespace_pid,send_signal
        self.capture,self.server_pid=deepcopy(capture),server_pid
        self.attempted,self.closed=False,False

    def term(self, *, preflight, timeout=30):
        require(not self.closed and not self.attempted and callable(preflight)
                and type(timeout) in (int,float) and 0<timeout<=60,
                'original unused TERM witness and bounded wait required')
        self.attempted=True
        # Full actor/window/ledger preflight runs with the original pidfd held.
        require(preflight() is True, 'original TERM preflight refused')
        pid=self.capture['process']['pid']
        require(not self.poll.poll(0) and self.process._view(pid)==self.capture['process']
                and self.namespace_pid(pid)==self.server_pid, 'original API changed before TERM')
        self.send_signal(self.fd,signal.SIGTERM,None,0)
        events=self.poll.poll(int(timeout*1000))
        require(events and all(type(event) in (tuple,list) and len(event)==2
                    and event[0]==self.fd and event[1]==select.POLLIN for event in events),
                'original API exit timeout or pidfd error; outcome uncertain')
        return dict(pidfd_exit_verified=True,term_count=1,force_used=False,namespace_pid=self.server_pid)
