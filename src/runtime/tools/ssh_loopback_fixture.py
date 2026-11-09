"""Ephemeral key-only SSH fixture restricted to one owned runtime CLI."""
import json
import shlex
import socket
import subprocess
import threading
import time

import paramiko


def allowed(command,prefix):
    try:args=shlex.split(command)
    except ValueError:return None
    if args[:len(prefix)]!=prefix:return None
    tail=args[len(prefix):]
    if tail[:1]==['--expected-journal-id']:
        import re
        if len(tail)<3 or not re.fullmatch(r'[0-9a-f]{32}',tail[1]):return None
        tail=tail[2:]
    if tail in (['capabilities'],['plan'],['submit'],['cancel-request'],['link-plan'],['link-submit']):return args
    if len(tail)==2 and tail[0] in ('lab-close','lab-finish','lab-reopen'):
        import re
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',tail[1]):return args
    if len(tail)==4 and tail[0]=='link-inspect':
        import re
        if all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',value) for value in tail[1:]):return args
    if len(tail)==3 and tail[0]=='inspect':
        import re
        if all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',value) for value in tail[1:]):return args
    if len(tail) in (4,5) and tail[0]=='request-status':
        import re
        if (len(tail)==4 or tail[4]=='--match-input') and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',value) for value in tail[1:4]):return args
    if len(tail) in (2,3) and tail[0] in ('status','cancel','reconcile','stop-stage','link-status'):
        import re
        if re.fullmatch(r'[0-9a-f]{32}',tail[1]) and (len(tail)==2 or tail==['reconcile',tail[1],'--force']):return args
    return None


class LoopbackSSH:
    def __init__(self,root,prefix,guard):
        from dnlab_multinode.services.ssh import SSHClient
        self.root=root;self.prefix=prefix;self.guard=guard;self.commands=[];self.stdin_calls=0
        self.drop_next_submit_ack=False
        self.drop_next_stage_ack=False
        self.drop_next_closure_ack=False
        self.stop=threading.Event();self.lock=threading.Lock();self.transports=[];self.workers=[];self.processes=set();self.events=[]
        self.host_key=paramiko.RSAKey.generate(2048);self.client_key=paramiko.RSAKey.generate(2048)
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(8);self.listener.settimeout(.2)
        self.port=self.listener.getsockname()[1]
        self.ssh=SSHClient('127.0.0.1','fixture','/unused-in-memory-key',name='runtime-loopback')
        fixture=self
        class Server(paramiko.ServerInterface):
            def check_auth_publickey(self,username,key):
                return paramiko.AUTH_SUCCESSFUL if username=='fixture' and key.asbytes()==fixture.client_key.asbytes() else paramiko.AUTH_FAILED
            def get_allowed_auths(self,username):return 'publickey'
            def check_channel_request(self,kind,chanid):
                return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_exec_request(self,channel,command):
                try:argv=allowed(command.decode('utf-8'),fixture.prefix)
                except UnicodeError:return False
                if argv is None:return False
                worker=threading.Thread(target=fixture.execute,args=(channel,argv),daemon=True)
                with fixture.lock:fixture.workers.append(worker)
                worker.start();return True
        self.server_type=Server
        self.acceptor=threading.Thread(target=self.accept,daemon=True);self.acceptor.start()
        try:self.reconnect()
        except Exception:self.close();raise

    def record(self,event):
        with self.lock:
            self.events.append(event)
            (self.root/'ssh-loopback-events.json').write_text(json.dumps(self.events,indent=2)+'\n')

    def accept(self):
        while not self.stop.is_set():
            try:connection,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:return
            transport=paramiko.Transport(connection)
            with self.lock:
                if self.stop.is_set():transport.close();return
                self.transports.append(transport)
            transport.add_server_key(self.host_key)
            try:transport.start_server(server=self.server_type())
            except Exception:transport.close()

    def execute(self,channel,argv):
        process=None;payload=None
        try:
            self.guard();channel.settimeout(30)
            position=len(self.prefix)+(2 if argv[len(self.prefix)]=='--expected-journal-id' else 0)
            action=argv[position]
            if action in ('plan','submit','cancel-request','stop-stage','lab-close','lab-finish','lab-reopen','link-plan','link-submit') or action=='request-status' and '--match-input' in argv:
                data=bytearray()
                while True:
                    chunk=channel.recv(65536)
                    if not chunk:break
                    data.extend(chunk)
                    if len(data)>1024*1024:raise RuntimeError('fixture stdin limit')
                payload=bytes(data)
            process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            with self.lock:self.processes.add(process)
            out,err=process.communicate(payload,timeout=30)
            self.record({'argv':argv,'stdin_bytes':len(payload or b''),'stdout_bytes':len(out),'stderr_bytes':len(err),'exit_code':process.returncode})
            if action=='submit' and process.returncode==0 and self.drop_next_submit_ack:
                self.drop_next_submit_ack=False
                self.record({'action':'submit-ack-dropped'})
                return
            if action in ('lab-close','lab-finish','lab-reopen') and process.returncode==0 and self.drop_next_closure_ack:
                self.drop_next_closure_ack=False
                self.record({'action':action+'-ack-dropped'})
                return
            if action=='stop-stage' and process.returncode==0 and self.drop_next_stage_ack:
                self.drop_next_stage_ack=False
                self.record({'action':'stop-stage-ack-dropped'})
                return
            if out:channel.sendall(out)
            if err:channel.sendall_stderr(err)
            channel.send_exit_status(process.returncode);channel.shutdown_write()
        except Exception as error:
            self.record({'action':'fixture-exec-error','error_type':type(error).__name__})
            try:channel.send_exit_status(1)
            except Exception:pass
        finally:
            if process is not None:
                if process.poll() is None:process.kill();process.communicate(timeout=5)
                with self.lock:self.processes.discard(process)
            channel.close()

    def reconnect(self):
        self.ssh.close();client=paramiko.SSHClient()
        client.get_host_keys().add(f'[127.0.0.1]:{self.port}',self.host_key.get_name(),self.host_key)
        client.connect('127.0.0.1',port=self.port,username='fixture',pkey=self.client_key,
                       look_for_keys=False,allow_agent=False,timeout=5)
        self.ssh._client=client

    def run(self,command):
        self.commands.append(command);return self.ssh.run(command)

    def run_input(self,command,payload):
        self.commands.append(command);self.stdin_calls+=1
        return self.ssh.run_input(command,payload)

    def close(self):
        self.ssh.close();self.stop.set();self.listener.close()
        with self.lock:transports=list(self.transports);processes=list(self.processes)
        for transport in transports:transport.close()
        for process in processes:
            if process.poll() is None:process.kill()
        self.acceptor.join(5)
        deadline=time.monotonic()+5
        with self.lock:workers=list(self.workers)
        for worker in workers:worker.join(max(0,deadline-time.monotonic()))
        assert not self.acceptor.is_alive() and not any(worker.is_alive() for worker in workers)
        assert not self.processes
