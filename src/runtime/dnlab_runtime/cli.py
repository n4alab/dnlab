"""Service or small local/SSH client. Mutations require explicit submit."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path
from urllib.parse import quote

from .backend import Backend, Docker
from .engine import Engine
from .journal import Journal
from .manifest import RuntimeErrorBase
from .transport import Client, Instance, Server


def parser():
    result = argparse.ArgumentParser(prog="dnlab-runtime")
    result.add_argument("--socket", default="/run/dnlab-runtime/runtime.sock")
    result.add_argument('--expected-journal-id')
    commands = result.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--state-dir", type=Path, default=Path("/var/lib/dnlab-runtime"))
    serve.add_argument("--docker-socket", default="/var/run/docker.sock")
    commands.add_parser("capabilities")
    for action in ('close','finish','reopen'):commands.add_parser('lab-'+action).add_argument('lab_id')
    for action in ('plan','acquire','activate','cancel','release'):commands.add_parser('management-'+action).add_argument('lab_id')
    commands.add_parser("plan")
    commands.add_parser("submit")
    commands.add_parser('cancel-request')
    commands.add_parser('stop-stage').add_argument('operation_id')
    lookup=commands.add_parser('request-status')
    for name in ('lab_id','node_id','request_id'):lookup.add_argument(name)
    lookup.add_argument('--match-input',action='store_true')
    commands.add_parser("link-plan")
    commands.add_parser("link-submit")
    for name in ("link-status", "link-cancel"):
        command = commands.add_parser(name)
        command.add_argument("operation_id")
    link_inspect = commands.add_parser("link-inspect")
    link_inspect.add_argument("lab_id")
    link_inspect.add_argument("link_id")
    link_inspect.add_argument("host_interface")
    for name in ("status", "cancel", "reconcile"):
        command = commands.add_parser(name)
        command.add_argument("operation_id")
        if name == "reconcile":
            command.add_argument("--force", action="store_true")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("lab_id")
    inspect.add_argument("node_id")
    return result


def serve(args):
    if os.geteuid() != 0:
        raise RuntimeErrorBase("daemon must run as root for host namespace operations")
    os.umask(0o077)
    with Instance(args.state_dir, Path(args.socket)):
        journal = Journal(args.state_dir)
        engine = Engine(journal, Backend(Docker(args.docker_socket)))
        try:
            with Server(args.socket, engine) as server:
                def stop(signum, frame):
                    threading.Thread(target=server.shutdown, daemon=True).start()
                previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
                try:
                    server.serve_forever(poll_interval=0.2)
                finally:
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)
        finally:
            journal.close()


def main():
    args = parser().parse_args()
    try:
        if args.command == "serve":
            serve(args)
            return
        client = Client(args.socket,expected_journal_id=args.expected_journal_id)
        if args.command == "capabilities":
            result = client.request("GET", "/v1/capabilities")
        elif args.command in {"link-plan", "link-submit"}:
            result = client.request("POST", "/v1/link-plan" if args.command == "link-plan" else "/v1/link-operations", json.load(sys.stdin))
        elif args.command in {"link-status", "link-cancel"}:
            identity = quote(args.operation_id, safe="")
            result = client.request("GET" if args.command == "link-status" else "POST", f"/v1/link-operations/{identity}" + ("/cancel" if args.command == "link-cancel" else ""))
        elif args.command == "link-inspect":
            path = "/v1/links/" + "/".join(quote(p, safe="") for p in (args.lab_id,args.link_id,args.host_interface))
            result = client.request("GET", path)
        elif args.command in {"plan", "submit",'cancel-request'}:
            result = client.request("POST", {'plan':'/v1/plan','submit':'/v1/operations','cancel-request':'/v1/cancel-requests'}[args.command], json.load(sys.stdin))
        elif args.command=='request-status':
            if args.match_input:
                request=json.load(sys.stdin)
                if any(request.get(key)!=getattr(args,key) for key in ('lab_id','node_id','request_id')):
                    raise RuntimeErrorBase('request lookup context differs')
                result=client.request('POST','/v1/operation-requests',request)
            else:result=client.request('GET','/v1/operation-requests/'+'/'.join(quote(value,safe='') for value in (args.lab_id,args.node_id,args.request_id)))
        elif args.command=='stop-stage':
            result=client.request('POST',f'/v1/operations/{quote(args.operation_id,safe="")}/stop-stage',json.load(sys.stdin))
        elif args.command in ('lab-close','lab-finish','lab-reopen'):
            result=client.request('POST','/v1/labs/'+quote(args.lab_id,safe='')+'/closure/'+args.command[4:],json.load(sys.stdin))
        elif args.command in ('management-plan','management-acquire','management-activate','management-cancel','management-release'):
            result=client.request('POST','/v1/labs/'+quote(args.lab_id,safe='')+'/management-barrier/'+args.command.removeprefix('management-'),json.load(sys.stdin))
        elif args.command == "inspect":
            result = client.request("GET", f"/v1/nodes/{args.lab_id}/{args.node_id}")
        elif args.command == "status":
            result = client.request("GET", f"/v1/operations/{args.operation_id}")
        else:
            result = client.request("POST", f"/v1/operations/{args.operation_id}/{args.command}", {"force": args.force} if args.command == "reconcile" else {})
        print(json.dumps(result, sort_keys=True))
    except (RuntimeErrorBase, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
