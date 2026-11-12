"""Local Unix HTTP transport and bounded sequential operation worker."""

from __future__ import annotations

import fcntl
import http.client
import json
import os
import socket
import socketserver
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .execution import ExecutionBusy
from .backend import UnixConnection
from .manifest import Conflict, RuntimeErrorBase, capabilities, identifier

MAX_BODY = 1024 * 1024
MAX_PENDING = 128


class DeliveryUncertain(RuntimeErrorBase):
    """The original request may have arrived; inspect/recover, never resend."""
    status = 503


class Client:
    def __init__(self, socket_path: str, *, expected_journal_id=None):
        self.socket_path = socket_path
        self.expected_journal_id=expected_journal_id

    def request(self, method: str, path: str, payload=None):
        connection = UnixConnection(self.socket_path)
        try:
            body = json.dumps(payload).encode() if payload is not None else None
            headers={"Content-Type":"application/json"}
            if self.expected_journal_id is not None:headers['X-Dnlab-Journal']=self.expected_journal_id
            send_error = None
            try:
                connection.request(method, path, body, headers)
            except (OSError,http.client.HTTPException) as error:
                # A peer may have replied before the body finished sending.
                # Read only this connection; a new connection could duplicate
                # an operation whose delivery/commit is already uncertain.
                send_error = error
            try:
                response = connection.getresponse()
                if response.status >= 400:
                    length = response.getheader('Content-Length')
                    if (not isinstance(length,str) or not length.isdecimal()
                            or not 0 < int(length) <= MAX_BODY
                            or response.getheader('Content-Type','').split(';',1)[0].strip().lower() != 'application/json'
                            or not 400 <= response.status <= 599):
                        raise ValueError('unqualified runtime error response')
                    raw = response.read(int(length))
                    if len(raw) != int(length): raise ValueError('incomplete runtime error response')
                    data = json.loads(raw)
                    if not isinstance(data,dict) or not isinstance(data.get('error'),str) or not data['error']:
                        raise ValueError('invalid runtime error response')
                else:
                    if send_error is not None: raise send_error
                    data = json.loads(response.read())
            except (OSError,http.client.HTTPException,ValueError) as error:
                raise DeliveryUncertain('runtime request outcome is uncertain; inspect or recover the original request; no automatic retry') from (send_error or error)
            if response.status >= 400:
                raise RuntimeErrorBase(data['error'])
            return data
        finally:
            connection.close()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, path: str, engine):
        self.engine = engine
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.submission_lock = threading.Lock()
        super().__init__(path, Handler)
        os.chmod(path, 0o600)
        self.worker = threading.Thread(target=self._work, name="runtime-operations", daemon=True)
        self.worker.start()

    def _work(self):
        while not self.stopping.is_set():
            self.wake.clear()
            for operation_id in self.engine.journal.pending():
                if self.stopping.is_set():
                    return
                try:self.engine.execute(operation_id)
                except ExecutionBusy:break
            for operation_id in self.engine.links.pending():
                if self.stopping.is_set():
                    return
                try:self.engine.links.execute(operation_id)
                except ExecutionBusy:break
            if getattr(self.engine,'vm_tap_tasks',None) is not None:
                for operation_id in self.engine.vm_tap_tasks.pending():
                    if self.stopping.is_set():
                        return
                    try:self.engine.vm_tap_tasks.execute(operation_id)
                    except ExecutionBusy:break
            self.wake.wait(0.5)

    def server_close(self):
        self.stopping.set()
        self.wake.set()
        if hasattr(self, "worker"):
            # Let a bounded in-flight operation finish; never close its SQLite connection.
            self.worker.join()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        try:
            path = urlsplit(self.path).path
            parts = [unquote(p) for p in path.strip("/").split("/")]
            expected=self.headers.get('X-Dnlab-Journal')
            if expected is not None and expected!=self.server.engine.journal.identity:
                self._discard_rejected_body()
                raise Conflict('runtime journal identity differs')
            if method == "GET" and path == "/v1/capabilities":
                return self._reply(200, {**capabilities(),'journal_id':self.server.engine.journal.identity})
            if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "link-operations"]:
                return self._reply(200, self.server.engine.links.get(identifier(parts[2], "operation_id")))
            if method == "GET" and len(parts) == 5 and parts[:2] == ["v1", "links"]:
                return self._reply(200, self.server.engine.links.inspect(*(identifier(p, "link identity") for p in parts[2:])))
            if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "operations"]:
                return self._reply(200, self.server.engine.journal.get(identifier(parts[2], "operation_id")))
            if method=='GET' and len(parts)==5 and parts[:2]==['v1','operation-requests']:
                lab,node,request_id=(identifier(value,'request context') for value in parts[2:])
                return self._reply(200,{'lab_id':lab,'node_id':node,'request_id':request_id,
                    'operation':self.server.engine.journal.find_request(lab,node,request_id)})
            if method == "GET" and len(parts) == 4 and parts[:2] == ["v1", "nodes"]:
                return self._reply(200, self.server.engine.inspect(identifier(parts[2], "lab"), identifier(parts[3], "node")))
            if method != "POST":
                return self._reply(404, {"error": "route not found"})
            payload = self._body()
            if len(parts)==5 and parts[:2]==['v1','labs'] and parts[3]=='management-barrier' and parts[4] in ('plan','acquire','activate','cancel','release'):
                if expected is None:raise Conflict('management barrier requires journal binding')
                from .management_barrier import control
                return self._reply(200,control(self.server.engine,parts[2],parts[4],payload))
            if len(parts)==5 and parts[:2]==['v1','labs'] and parts[3]=='closure' and parts[4] in ('close','finish','reopen'):
                from .lab_closure import control
                return self._reply(200,control(self.server.engine,parts[2],parts[4],payload))
            if path=='/v1/operation-requests':
                operation=self.server.engine.journal.find_matching_request(payload)
                return self._reply(200,{key:payload[key] for key in ('lab_id','node_id','request_id')}|{'operation':operation})
            if path=='/v1/cancel-requests':
                with self.server.submission_lock:operation=self.server.engine.journal.cancel_request(payload)
                self.server.wake.set()
                return self._reply(202,operation)
            if path == "/v1/link-plan":
                return self._reply(200, self.server.engine.links.plan(payload))
            if path == "/v1/link-operations":
                with self.server.submission_lock:
                    operation = self.server.engine.links.submit(payload, max_pending=MAX_PENDING)
                self.server.wake.set()
                return self._reply(202, operation)
            if len(parts) == 4 and parts[:2] == ["v1", "link-operations"] and parts[3] == "cancel":
                if payload:
                    raise RuntimeErrorBase("link cancellation takes no options")
                result = self.server.engine.links.cancel(identifier(parts[2], "operation_id"))
                self.server.wake.set()
                return self._reply(202, result)
            if path == "/v1/plan":
                return self._reply(200, self.server.engine.plan(payload))
            if path == "/v1/operations":
                with self.server.submission_lock:
                    if payload.get("action") == "stop":
                        try:context=tuple(identifier(payload.get(key),key) for key in ('lab_id','node_id','request_id'))
                        except RuntimeErrorBase:context=None
                        prior=self.server.engine.journal.find_request(*context) if context else None
                        if prior is None and payload.get('stop_mode')!='coordinated':self.server.engine.links.node_free(payload.get("lab_id"), payload.get("node_id"))
                    operation = self.server.engine.journal.submit(payload, max_pending=MAX_PENDING)
                self.server.wake.set()
                return self._reply(202, operation)
            if len(parts)==4 and parts[:2]==['v1','operations'] and parts[3]=='stop-stage':
                if set(payload)!={'lab_id','node_id','stage'}:raise RuntimeErrorBase('complete stop stage context required')
                with self.server.submission_lock:
                    result=self.server.engine.stops.request_stage(identifier(parts[2],'operation_id'),
                        identifier(payload['lab_id'],'lab_id'),identifier(payload['node_id'],'node_id'),payload['stage'])
                self.server.wake.set()
                return self._reply(202,result)
            if len(parts) == 4 and parts[:2] == ["v1", "operations"] and parts[3] == "cancel":
                result = self.server.engine.journal.cancel(identifier(parts[2], "operation_id"))
                self.server.wake.set()
                return self._reply(202, result)
            if len(parts) == 4 and parts[:2] == ["v1", "operations"] and parts[3] == "reconcile":
                operation_id = identifier(parts[2], "operation_id")
                if set(payload) - {"force"}:
                    raise RuntimeErrorBase("unknown recovery fields")
                self.server.engine.journal.queue_recovery(operation_id, force=payload.get("force", False))
                self.server.wake.set()
                return self._reply(202, self.server.engine.journal.get(operation_id))
            return self._reply(404, {"error": "route not found"})
        except RuntimeErrorBase as exc:
            self._reply(exc.status, {"error": str(exc)})
        except (ValueError, TypeError):
            self._reply(400, {"error": "invalid request"})
        except Exception:
            self._reply(500, {"error": "internal runtime error"})

    def _discard_rejected_body(self):
        """Drain a bounded framed body without parsing it or reaching the engine.

        The rejection decision has already been made. Consuming an ordinary
        body lets the client finish its send and receive that exact rejection.
        Unknown/oversized framing is never drained; the client reports an
        uncertain outcome if an error response cannot be recovered.
        """
        lengths = self.headers.get_all('Content-Length',[])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1: return
        value = lengths[0]
        if not value.isdecimal(): return
        number = value.lstrip('0') or '0'
        if len(number) > len(str(MAX_BODY)) or int(number) > MAX_BODY: return
        remaining = int(number); deadline = time.monotonic() + 10
        try:
            while remaining:
                budget = deadline - time.monotonic()
                if budget <= 0: break
                self.connection.settimeout(budget)
                # read1 performs at most one underlying read: the absolute
                # deadline also bounds a sender that trickles body bytes.
                chunk = self.rfile.read1(min(65536,remaining))
                if not chunk: break
                remaining -= len(chunk)
        except OSError:
            pass
        finally:
            self.connection.settimeout(10)

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            raise RuntimeErrorBase("chunked requests are unsupported")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise RuntimeErrorBase("invalid Content-Length") from None
        if not 0 <= length <= MAX_BODY:
            raise RuntimeErrorBase("request exceeds size limit")
        value = json.loads(self.rfile.read(length)) if length else {}
        if not isinstance(value, dict):
            raise RuntimeErrorBase("JSON object required")
        return value

    def _reply(self, code, value):
        body = json.dumps(value, allow_nan=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Instance:
    """Lifetime lock plus ownership-checked removal of a stale socket."""

    def __init__(self, state: Path, path: Path):
        self.state, self.path = state, path
        self.lock = None

    def __enter__(self):
        for directory in (self.state, self.path.parent):
            if directory.is_symlink():
                raise RuntimeErrorBase("runtime directory must not be a symlink")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if directory.stat().st_uid != os.geteuid():
                raise RuntimeErrorBase("runtime directory is not owned by the daemon user")
            os.chmod(directory, 0o700)
        lock_path = self.state / "daemon.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "w")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.path.exists() or self.path.is_symlink():
                info = self.path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                    raise RuntimeErrorBase("refusing to replace an unowned/non-socket path")
                probe = socket.socket(socket.AF_UNIX)
                try:
                    probe.connect(str(self.path))
                except ConnectionRefusedError:
                    self.path.unlink()
                else:
                    raise RuntimeErrorBase("runtime socket already active")
                finally:
                    probe.close()
            return self
        except BaseException:
            self.lock.close()
            raise

    def __exit__(self, *args):
        if self.path.exists():
            info = self.path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid():
                self.path.unlink()
        self.lock.close()
