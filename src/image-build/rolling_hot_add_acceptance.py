#!/usr/bin/env python3
"""Rolling hot-add acceptance with one permanent FRR node."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


CANDIDATES = [
    ("openwrt", "openwrt", "vrnetlab/openwrt_openwrt_v2:25.12.2-dnlab", 8),
    ("opnsense", "freebsd", "vrnetlab/dnlab_opnsense:26.1.6-dnlab", 8),
    ("cumulus", "generic_vm", "vrnetlab/nvidia_cumulusvx:5.16.1-vx-amd64-dnlab", 32),
    ("routeros", "mikrotik_ros", "vrnetlab/mikrotik_routeros:7.22.2-dnlab", 16),
    ("vios", "cisco_vios", "vrnetlab/cisco_vios_v2:adventerprisek9-m.spa.159-3.m10-dnlab", 15),
    ("viosl2", "cisco_vios", "vrnetlab/cisco_vios_l2_v2:L2-20200929-dnlab", 15),
    ("vjrouter252", "juniper_vjunosrouter", "vrnetlab/juniper_vjunos-router_v2:25.2R1.9-dnlab", 16),
    ("vjrouter254", "juniper_vjunosrouter", "vrnetlab/juniper_vjunos-router_v2:25.4R1.12-dnlab", 16),
    ("vjswitch", "juniper_vjunosswitch", "vrnetlab/juniper_vjunos-switch_v2:25.4R1.12-dnlab", 16),
    ("vjevolved", "juniper_vjunosevolved", "vrnetlab/juniper_vjunosevolved_v2:25.4R1.13-EVO-dnlab", 16),
    ("n9k9300", "cisco_n9kv", "vrnetlab/cisco_n9kv_v2:9300-10.5.5.M-dnlab", 16),
    ("n9k9500", "cisco_n9kv", "vrnetlab/cisco_n9kv_v2:9500-10.5.5.M-dnlab", 16),
    ("cat9k", "cisco_cat9kv", "vrnetlab/cisco_cat9kv_v2:17.15.03-dnlab", 9),
    ("c9800", "cisco_cat9kv", "vrnetlab/cisco_c9800cl_v2:17.15.05-dnlab", 3),
    ("xrv9k", "cisco_xrv9k", "vrnetlab/cisco_xrv9k_v2:25.2.2-dnlab", 16),
]
LAB_NAME = "haddacc7f3"


def api(base: str, path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=3600) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{path} returned HTTP {exc.code}: {detail}") from exc


def ssh(host: str, command: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", f"root@{host}", command],
        check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def topology(candidate: tuple[str, str, str, int] | None, *, linked: bool) -> str:
    lines = [
        f"name: {LAB_NAME}", "mgmt:",
        "  ipv4-subnet: 198.18.199.0/24", "  ipv4-gw: 198.18.199.1",
        "topology:", "  nodes:", "    frr:", "      kind: linux",
        "      image: vrnetlab/dnlab_frr:10.6.1-dnlab", "      env:",
        '        CLAB_MGMT_PASSTHROUGH: "true"', '        DNLAB_WARM_PORTS: "8"',
        '        DNLAB_NIC_POLL_INTERVAL: "0.05"',
    ]
    if candidate:
        name, kind, image, ports = candidate
        lines += [
            f"    {name}:", f"      kind: {kind}", f"      image: {image}",
            "      env:", '        CLAB_MGMT_PASSTHROUGH: "true"',
            '        DNLAB_WARM_LINKS_EXPERIMENTAL: "true"',
            f'        DNLAB_WARM_PORTS: "{ports}"',
            '        DNLAB_NIC_POLL_INTERVAL: "0.05"',
        ]
    if candidate and linked:
        lines.append("  links:")
        lines.append(f'    - endpoints: ["frr:eth1", "{candidate[0]}:eth1"]')
    else:
        lines.append("  links: []")
    return "\n".join(lines) + "\n"


def inspect(host: str, container: str) -> dict:
    fmt = "{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.RestartCount}}|{{.State.StartedAt}}"
    result = ssh(host, f"docker inspect {shlex.quote(container)} --format {shlex.quote(fmt)}")
    identity, status, health, restarts, started = result.stdout.strip().split("|", 4)
    return {"id": identity, "status": status, "health": health, "restarts": int(restarts), "started_at": started}


def wait_healthy(host: str, container: str, timeout: int) -> float:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        state = inspect(host, container)
        if state["status"] in {"exited", "dead"}:
            raise RuntimeError(f"{container} entered {state['status']}")
        if state["health"] == "healthy" or (state["status"] == "running" and not state["health"]):
            return time.monotonic() - started
        time.sleep(10)
    raise TimeoutError(f"health timeout for {container}")


def metrics(host: str, container: str) -> dict:
    script = "pid=$(pgrep -o -f 'qemu-system|qemu-kvm'); f=$(find /proc/$pid/fd -mindepth 1 -maxdepth 1 | wc -l); t=$(for d in /sys/class/net/eth* /sys/class/net/tap*; do test -e \"$d\" || continue; tc filter show dev $(basename \"$d\") ingress 2>/dev/null; tc filter show dev $(basename \"$d\") egress 2>/dev/null; done | wc -l); r=$(awk '/VmRSS:/{print $2}' /proc/$pid/status); echo $f'|'$t'|'$r"
    command = f"docker exec {shlex.quote(container)} sh -c {shlex.quote(script)}"
    fds, filters, rss = ssh(host, command).stdout.strip().split("|")
    return {"qemu_fds": int(fds), "tc_filter_lines": int(filters), "qemu_rss_kib": int(rss)}


def linkctl(host: str, container: str, iface: str, state: str, *, check: bool = True):
    return ssh(host, f"docker exec {shlex.quote(container)} dnlab-linkctl {iface} {state}", check=check)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://198.18.2.3:8081")
    parser.add_argument("--topology", default="/tmp/dnlab-hotadd-acceptance.clab.yml")
    parser.add_argument("--hosts", default="/etc/dnlab/hosts.yml")
    parser.add_argument("--report", default="/tmp/dnlab-hotadd-acceptance.json")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--start", type=int, default=0)
    args = parser.parse_args()
    topo = Path(args.topology)
    report_path = Path(args.report)
    if args.start and report_path.exists():
        prior = json.loads(report_path.read_text())
        results = [item for item in prior if item.get("status") == "passed"][:args.start]
    else:
        results = []
    base = {"topology_file": str(topo), "hosts_file": args.hosts}
    nodes = api(args.api, "/labs/nodes", base)["nodes"]
    frr = nodes["frr"]
    frr_before = inspect(frr["host"], frr["container"])

    for position, candidate in enumerate(CANDIDATES[args.start:], args.start + 1):
        name, _kind, image, ports = candidate
        print(f"[{position}/{len(CANDIDATES)}] start {name} {image}", flush=True)
        topo.write_text(topology(candidate, linked=True))
        started = time.monotonic()
        result = {"name": name, "image": image, "ports": ports, "status": "failed"}
        try:
            state = api(args.api, "/labs/nodes/start", {**base, "node": name})
            runtime = state["node_runtime"][name]
            host, container = runtime["host"], runtime["container"]
            result.update({"host": host, "container": container})
            result["boot_seconds"] = round(wait_healthy(host, container, args.timeout), 3)
            before = inspect(host, container)
            metrics_before = metrics(host, container)
            tested = sorted({1, max(1, (ports + 1) // 2), ports})
            for index in tested:
                linkctl(host, container, f"eth{index}", "down")
                linkctl(host, container, f"eth{index}", "up")
                linkctl(host, container, f"eth{index}", "down")
            invalid = linkctl(host, container, f"eth{ports + 1}", "up", check=False)
            if invalid.returncode == 0 or "exceeds configured warm-port count" not in invalid.stderr:
                raise RuntimeError("out-of-range port was not rejected")
            topo.write_text(topology(candidate, linked=False))
            detach_state = api(args.api, "/labs/nodes/reconcile", {
                **base, "node": "frr",
            })
            detached = [
                link for link in detach_state.get("runtime_links", [])
                if {
                    link.get("endpoint_a", {}).get("node"),
                    link.get("endpoint_b", {}).get("node"),
                } == {"frr", name}
            ]
            if detached:
                raise RuntimeError("removed link remained in runtime state after detach")
            topo.write_text(topology(candidate, linked=True))
            reattach = api(args.api, "/labs/links/reconcile", {
                **base, "source": "frr", "source_iface": "eth1",
                "target": name, "target_iface": "eth1",
            })
            after = inspect(host, container)
            metrics_after = metrics(host, container)
            if before != after:
                raise RuntimeError(f"candidate identity changed: {before} -> {after}")
            if metrics_before["qemu_fds"] != metrics_after["qemu_fds"]:
                raise RuntimeError("candidate QEMU FD count changed")
            frr_now = inspect(frr["host"], frr["container"])
            if frr_now != frr_before:
                raise RuntimeError(f"permanent FRR changed: {frr_before} -> {frr_now}")
            stopped = api(args.api, "/labs/nodes/stop", {**base, "node": name})
            stopped_link = next(
                (
                    link for link in stopped.get("runtime_links", [])
                    if {
                        link.get("endpoint_a", {}).get("node"),
                        link.get("endpoint_b", {}).get("node"),
                    } == {"frr", name}
                ),
                None,
            )
            if not stopped_link or stopped_link.get("state") != "partial":
                raise RuntimeError("stopped candidate link was not recorded partial")
            api(args.api, "/labs/nodes/remove", {**base, "node": name})
            topo.write_text(topology(None, linked=False))
            api(args.api, "/labs/nodes/reconcile", {**base, "node": "frr"})
            result.update({
                "status": "passed", "container_before": before,
                "metrics_before": metrics_before, "metrics_after": metrics_after,
                "tested_ports": tested, "detach": "removed", "reattach": reattach,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            })
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            results.append(result)
            report_path.write_text(json.dumps(results, indent=2) + "\n")
            print(result["error"], flush=True)
            return 1
        results.append(result)
        report_path.write_text(json.dumps(results, indent=2) + "\n")
        print(f"[{position}/{len(CANDIDATES)}] passed {name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
