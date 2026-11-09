"""Durable intents, resource reservations and revision checks."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from .manifest import Busy, Conflict, NotFound, canonical, fingerprint, identifier, validate_request

TERMINAL = {"completed", "cancelled", "failed", "recovery_required"}
PARKED = {"awaiting_link_cleanup", "awaiting_finalization"}


class Journal:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        self.closed=False
        self.lock = threading.RLock()
        from .execution import execution_gate
        self.execution_lock=execution_gate(directory)
        self.management_execution_lock=self.execution_lock
        self.db = sqlite3.connect(directory / "journal.sqlite3", check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        os.chmod(directory / "journal.sqlite3", 0o600)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS workload_generations (
                lab TEXT NOT NULL,node TEXT NOT NULL,generation INTEGER NOT NULL,
                creator TEXT NOT NULL,nonce TEXT NOT NULL,spec TEXT NOT NULL,
                container_id TEXT,phase TEXT NOT NULL,committed_revision INTEGER,
                container_name TEXT NOT NULL,PRIMARY KEY(lab,node,generation));
            CREATE TABLE IF NOT EXISTS management_network_proofs (lab TEXT NOT NULL,node TEXT NOT NULL,generation INTEGER NOT NULL,name TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,node,generation,name));
            CREATE TABLE IF NOT EXISTS endpoint_preflights (operation_id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS management_assignments (lab TEXT NOT NULL,node TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,node));
            CREATE TABLE IF NOT EXISTS metadata (version INTEGER NOT NULL);
            INSERT INTO metadata SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM metadata);
            CREATE TABLE IF NOT EXISTS operations (
                id TEXT PRIMARY KEY, lab TEXT NOT NULL, node TEXT NOT NULL,
                request_id TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL,
                phase TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
                recovery_force INTEGER NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT (unixepoch()),
                updated INTEGER NOT NULL DEFAULT (unixepoch()), UNIQUE(lab, request_id));
            CREATE TABLE IF NOT EXISTS nodes (
                lab TEXT NOT NULL, node TEXT NOT NULL, revision INTEGER NOT NULL,
                spec TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(lab,node));
            CREATE TABLE IF NOT EXISTS resources (
                key TEXT PRIMARY KEY, lab TEXT NOT NULL, node TEXT NOT NULL,
                operation_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS stop_sessions (
                operation_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS stop_reservations (
                lab TEXT NOT NULL, node TEXT NOT NULL, operation_id TEXT NOT NULL,
                PRIMARY KEY(lab,node));
            CREATE TABLE IF NOT EXISTS stop_link_children (
                operation_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL, hash TEXT NOT NULL);
        """)
        if self.db.execute("SELECT version FROM metadata").fetchone()[0] != 1:
            raise Conflict("unsupported journal schema")
        from .lab_closure import initialize
        initialize(self.db)
        from .management_barrier import initialize as initialize_management_barrier
        initialize_management_barrier(self.db)
        self.db.execute('CREATE TABLE IF NOT EXISTS journal_identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1),identity TEXT NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO journal_identity VALUES(1,?)',(uuid.uuid4().hex,))
        self.identity=self.db.execute('SELECT identity FROM journal_identity WHERE singleton=1').fetchone()[0]
        if not isinstance(self.identity,str) or len(self.identity)!=32 or any(c not in '0123456789abcdef' for c in self.identity):
            raise Conflict('invalid runtime journal identity')

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        with self.lock:
            self.db.close()
            self.closed=True

    def get(self, operation_id: str, *, private: bool = False) -> dict:
        with self.lock:
            row = self.db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise NotFound("operation not found")
        out = dict(row)
        out["cancel_requested"] = bool(out["cancel_requested"])
        out["recovery_force"] = bool(out["recovery_force"])
        if private:
            out["payload"] = json.loads(out["payload"])
        else:
            out.pop("payload")
            out.pop("hash")
        with self.lock:
            session = self.db.execute('SELECT payload FROM stop_sessions WHERE operation_id=?', (operation_id,)).fetchone()
        if session:
            value = json.loads(session[0])
            out['stop_stage'] = value['stage']
            out['shutdown_verified'] = value['stage'] in {'exit_verified', 'cleanup_requested', 'links_cleaned', 'finalizing', 'finished'}
        return out

    def node(self, lab: str, node: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM nodes WHERE lab=? AND node=?", (lab, node)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["spec"] = json.loads(result["spec"])
        return result

    def available_resources(self, request, spec):
        """Read-only check, also called inside submit's admission transaction."""
        from .backend import Backend
        keys=[f"container:{spec['container_name']}"]
        keys += [f"interface:{e['host_interface']}" for e in spec.get('endpoints',[])]
        keys += [f"interface:{Backend.staging_name(e)}" for e in spec.get('endpoints',[])]
        keys += [f"port:{p['host_ip']}:{p['host_port']}/{p['protocol']}" for p in spec.get('ports',[])]
        management=spec.get('management') or {}
        if management.get('mac'):keys.append('management-mac:'+management['network']+':'+management['mac'])
        with self.lock:
            from .backend_reservations import available
            available(self,request['lab_id'],request['node_id'],'docker')
            for key in keys:
                owner=self.db.execute('SELECT lab,node FROM resources WHERE key=?',(key,)).fetchone()
                if owner and tuple(owner)!=(request['lab_id'],request['node_id']):
                    raise Conflict(f'resource reserved: {key}')
        return keys

    def submit(self, raw: dict, *, max_pending: int = 128) -> dict:
        request = validate_request(raw)
        digest = fingerprint(request)
        lab, node = request["lab_id"], request["node_id"]
        with self.transaction():
            prior = self.db.execute("SELECT id, hash FROM operations WHERE lab=? AND request_id=?", (lab, request["request_id"])).fetchone()
            if prior:
                if prior["hash"] != digest:
                    raise Conflict("request_id already used with different content")
                return self.get(prior["id"])
            from .lab_closure import check
            check(self,request)
            from .management_authority import available
            available(self,lab,node)
            from .stop_protocol import unreserved
            unreserved(self,lab,node)
            if len(self.pending()) >= max_pending:
                raise Busy("operation queue is full; retry with the same request_id")
            current = self.node(lab, node)
            revision = current["revision"] if current else 0
            if request["expected_revision"] != revision:
                raise Conflict(f"stale revision; current revision is {revision}")
            busy = self.db.execute("SELECT 1 FROM operations WHERE lab=? AND node=? AND phase NOT IN ('completed','cancelled','failed') LIMIT 1", (lab, node)).fetchone()
            if busy:
                raise Conflict("node has an active operation or requires recovery")
            if request["action"] == "stop" and current is None:
                raise NotFound("node has no committed spec")
            if request["action"] == "start" and current and current["state"] == "running" and fingerprint(current["spec"]) != fingerprint(request["spec"]):
                raise Conflict("running node cannot be implicitly reconfigured")
            spec = request["spec"] if request["action"] == "start" else current["spec"]
            if request['action']=='start':
                from .management_authority import effective
                proof=request.get('management_preflight')
                if effective(self,request,spec) is not None and proof is None:
                    raise Conflict('management start requires the original preflight proof')
                if proof is not None and proof['journal_id']!=self.identity:
                    raise Conflict('management preflight journal differs')
            from .manifest import check_management_identity
            check_management_identity(request,current)
            keys = self.available_resources(request,spec)
            operation_id = uuid.uuid4().hex
            self.db.execute("INSERT INTO operations(id,lab,node,request_id,payload,hash,phase) VALUES(?,?,?,?,?,?,?)", (operation_id, lab, node, request["request_id"], canonical(request), digest, "queued"))
            for key in keys:
                self.db.execute("INSERT INTO resources VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET operation_id=excluded.operation_id", (key, lab, node, operation_id))
        return self.get(operation_id)

    def phase(self, operation_id: str, phase: str, error: str = ""):
        with self.transaction():
            self.db.execute("UPDATE operations SET phase=?,error=?,updated=unixepoch() WHERE id=?", (phase, error, operation_id))

    def cancel(self, operation_id: str) -> dict:
        with self.transaction():
            operation = self.get(operation_id)
            if operation["phase"] not in TERMINAL:
                self.db.execute("UPDATE operations SET cancel_requested=1,updated=unixepoch() WHERE id=?", (operation_id,))
        return self.get(operation_id)

    def find_request(self, lab, node, request_id):
        for value,label in ((lab,'lab'),(node,'node'),(request_id,'request_id')):identifier(value,label)
        with self.lock:
            row=self.db.execute('SELECT id,node FROM operations WHERE lab=? AND request_id=?',(lab,request_id)).fetchone()
            if row is None:return None
            if row['node']!=node:raise Conflict('request belongs to another node')
            return self.get(row['id'])

    def cancel_request(self, raw):
        """Cancel an accepted request, or seal its key before a delayed submit."""
        request=validate_request(raw);digest=fingerprint(request)
        lab,node=request['lab_id'],request['node_id']
        with self.transaction():
            prior=self.db.execute('SELECT id,node,hash,phase FROM operations WHERE lab=? AND request_id=?',
                                  (lab,request['request_id'])).fetchone()
            if prior:
                if prior['node']!=node or prior['hash']!=digest:raise Conflict('request_id already used with different content')
                operation_id=prior['id']
                if prior['phase'] not in TERMINAL:
                    self.db.execute('UPDATE operations SET cancel_requested=1,updated=unixepoch() WHERE id=?',(operation_id,))
            else:
                from .lab_closure import check
                check(self,request)
                operation_id=uuid.uuid4().hex
                self.db.execute('INSERT INTO operations(id,lab,node,request_id,payload,hash,phase,cancel_requested) VALUES(?,?,?,?,?,?,?,1)',
                                (operation_id,lab,node,request['request_id'],canonical(request),digest,'cancelled'))
        return self.get(operation_id)

    def find_matching_request(self,raw):
        request=validate_request(raw)
        with self.lock:
            row=self.db.execute('SELECT id,hash FROM operations WHERE lab=? AND request_id=?',
                                (request['lab_id'],request['request_id'])).fetchone()
            if row is None:return None
            if row['hash']!=fingerprint(request):raise Conflict('request_id already used with different content')
            return self.get(row['id'])

    def pending(self) -> list[str]:
        with self.lock:
            rows = self.db.execute("SELECT id,phase FROM operations ORDER BY rowid").fetchall()
        return [r["id"] for r in rows if r["phase"] not in TERMINAL | PARKED]

    def queue_recovery(self, operation_id: str, *, force: bool = False):
        if type(force) is not bool:
            raise Conflict("recovery force must be boolean")
        with self.transaction():
            operation = self.get(operation_id)
            from .lab_closure import check
            check(self,self.get(operation_id,private=True)["payload"])
            if operation["phase"] != "recovery_required":
                raise Conflict("only recovery_required operations can be reconciled")
            self.db.execute("UPDATE operations SET phase='queued',recovery_force=?,updated=unixepoch() WHERE id=?", (int(force or operation["recovery_force"]), operation_id))
        return self.get(operation_id)

    def finish(self, operation_id: str, spec: dict, state: str, *, stop_finished: bool = False):
        with self.transaction():
            operation = self.get(operation_id, private=True)
            if operation["cancel_requested"] and not stop_finished:
                raise Conflict("cancellation pending at commit")
            request = operation["payload"]
            current = self.node(operation["lab"], operation["node"])
            revision = current["revision"] if current else 0
            if revision != request["expected_revision"]:
                raise Conflict("revision changed before commit")
            from .workload_generation import committed
            committed(self,operation,spec,state,revision+1)
            self.db.execute("INSERT INTO nodes VALUES(?,?,?,?,?) ON CONFLICT(lab,node) DO UPDATE SET revision=excluded.revision,spec=excluded.spec,state=excluded.state", (operation["lab"], operation["node"], revision + 1, canonical(spec), state))
            self.db.execute("UPDATE operations SET phase='completed',updated=unixepoch() WHERE id=?", (operation_id,))
            if operation["cancel_requested"] and stop_finished:
                self.db.execute("UPDATE operations SET error=? WHERE id=?", ("cancellation arrived after process exit; stop completed", operation_id))
            from .management_authority import assignment,put
            management=assignment(self,operation['lab'],operation['node'])
            if management:
                candidate=management.pop('restart',None)
                if candidate and state=='running':
                    if candidate['operation_id']!=operation_id or candidate['birth_fingerprint']!=fingerprint(spec):
                        raise Conflict('management restart changed before lifecycle commit')
                    if candidate['clear']:
                        self.db.execute('DELETE FROM management_assignments WHERE lab=? AND node=?',(operation['lab'],operation['node']))
                        management=None
                    else:management.update(container_id=candidate['container_id'],birth_fingerprint=candidate['birth_fingerprint'],phase='stable')
            if management:
                management['revision']=revision+1
                if state=='stopped':management['phase']='stopped'
                put(self,operation['lab'],operation['node'],management)
            if state == "stopped":
                self.db.execute("DELETE FROM resources WHERE lab=? AND node=?", (operation["lab"], operation["node"]))
                session = self.db.execute('SELECT payload FROM stop_sessions WHERE operation_id=?', (operation_id,)).fetchone()
                if session:
                    value = json.loads(session[0]); value['stage'] = 'finished'
                    self.db.execute('UPDATE stop_sessions SET payload=? WHERE operation_id=?', (canonical(value),operation_id))
                    self.db.execute('DELETE FROM stop_reservations WHERE operation_id=?', (operation_id,))

    def rollback_finished(self, operation_id: str, phase: str, error: str = ""):
        with self.transaction():
            operation = self.get(operation_id, private=True)
            current = self.node(operation["lab"], operation["node"])
            self.db.execute("UPDATE operations SET phase=?,error=?,updated=unixepoch() WHERE id=?", (phase, error, operation_id))
            # Keep reservations for committed nodes; release new failed/cancelled starts.
            if current is None or current["state"] == "stopped":
                from .management_authority import assignment,put
                management=assignment(self,operation['lab'],operation['node'])
                if management:
                    management.pop('restart',None)
                    management['phase']='stopped'
                    put(self,operation['lab'],operation['node'],management)
                self.db.execute("DELETE FROM resources WHERE operation_id=?", (operation_id,))
