"""CLI entrypoint — click-based command interface."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from dnlab_multinode.services.logging_config import setup_service_logging

console = Console()


def _setup_logging(debug: bool = False) -> None:
    setup_service_logging(
        service="multinode",
        filename="dnlab-multinode.log",
        debug=debug,
    )


@click.group()
@click.option("-d", "--debug", is_flag=True, help="Enable debug logging")
def main(debug: bool) -> None:
    """ContainerLab Multi-Node Orchestrator."""
    _setup_logging(debug)


@main.group('realnet-infra')
def realnet_infra_group():
    """Explicit operations on shared RealNet infrastructure."""


@realnet_infra_group.command('qualify-reflector')
@click.option('-t','--topo',required=True,help='Topology providing the shared infrastructure configuration')
@click.option('--hosts','hosts_file',default=None,help='Path to global hosts file')
def qualify_reflector(topo,hosts_file):
    """Verify and register an existing compatible reflector without restarting it."""
    from dnlab_multinode.services.config import parse_topology
    from dnlab_multinode.services.realnet import qualify_route_reflector
    from dnlab_multinode.services.ssh import SSHClient
    try:
        topology=parse_topology(topo,hosts_file=hosts_file);host=topology.master
        with SSHClient(host=host.host,user=host.ssh_user,key_path=host.ssh_key,name=host.name) as master:
            result=qualify_route_reflector(topology,master)
        console.print('Shared reflector qualified: '+result['container_id'])
    except Exception as error:
        console.print('[red]Reflector qualification failed: '+str(error)+'[/red]')
        raise SystemExit(1) from None


@realnet_infra_group.command('recover-wan')
@click.option('-t','--topo',required=True,help='Topology providing shared WAN configuration')
@click.option('--hosts','hosts_file',default=None,help='Path to global hosts file')
def recover_wan(topo,hosts_file):
    """Recover a traced WAN creation without replacing existing infrastructure."""
    from dnlab_multinode.services.config import parse_topology
    from dnlab_multinode.services.realnet_wan import ensure_wan
    from dnlab_multinode.services.ssh import SSHClient
    try:
        topology=parse_topology(topo,hosts_file=hosts_file);host=topology.master
        with SSHClient(host=host.host,user=host.ssh_user,key_path=host.ssh_key,name=host.name) as master:
            result=ensure_wan(master,topology.realnet_infra,action='recover')
        console.print('Shared WAN recovery verified: '+result['network_id'])
    except Exception as error:
        console.print('[red]WAN recovery failed: '+str(error)+'[/red]')
        raise SystemExit(1) from None


# ── plan ─────────────────────────────────────────────────────────────

@main.command()
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file (default: /etc/dnlab/hosts.yml "
                   "or $DNLAB_MULTINODE_HOSTS)")
@click.option("--no-cache", is_flag=True, help="Ignore image resource cache")
def plan(topo: str, hosts_file: str | None, no_cache: bool) -> None:
    """Show scheduling plan without executing."""
    from dnlab_multinode.controllers.plan import PlanController, PlanError

    try:
        ctrl = PlanController(topo, no_cache, hosts_file=hosts_file)
        schedule = ctrl.run()

        _print_plan(ctrl, schedule)

    except PlanError as e:
        console.print(f"\n[red][✗] {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red][✗] Error: {e}[/red]")
        sys.exit(1)


# ── deploy ───────────────────────────────────────────────────────────

@main.command()
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file (default: /etc/dnlab/hosts.yml "
                   "or $DNLAB_MULTINODE_HOSTS)")
@click.option("--no-cache", is_flag=True, help="Ignore image resource cache")
def deploy(topo: str, hosts_file: str | None, no_cache: bool) -> None:
    """Deploy the distributed lab."""
    from dnlab_multinode.controllers.plan import PlanController, PlanError
    from dnlab_multinode.controllers.deploy import DeployController, DeployError

    try:
        # Show plan first
        planner = PlanController(topo, no_cache, hosts_file=hosts_file)
        schedule = planner.run()
        _print_plan(planner, schedule)

        console.print()

        # Deploy
        ctrl = DeployController(topo, no_cache, hosts_file=hosts_file)
        state = ctrl.run()

        # Print results
        console.print("\n[green][✓] Lab deployed![/green]")

        if state.dns:
            console.print(f"    DNS:       {state.dns.mgmt_ip} "
                          f"({state.dns.entries} records, "
                          f"upstream: {', '.join(state.dns.upstream)})")

        if state.runtime_relays:
            allowed_total = sum(len(rr.allowed) for rr in state.runtime_relays.values())
            console.print(f"    Runtime:   {len(state.runtime_relays)} relays, "
                          f"{allowed_total} VD allowlist entries")

        if state.jumphost:
            host_ip = state.jumphost.host_ip.split("/")[0] if state.jumphost.host_ip else "N/A"
            console.print(f"    Jump host: ssh labuser@{host_ip}  [dim](from master)[/dim]")
            console.print(f"    Password:  [bold]{state.jumphost.password}[/bold]")
            console.print(f"    Mgmt IP:   {state.jumphost.mgmt_ip}")
            if state.jumphost.ext_network:
                console.print(f"    Ext net:   {state.jumphost.ext_network}")
            if state.jumphost.resolver:
                console.print(f"    Resolver:  {state.jumphost.resolver}")

        if state.realnets:
            for rn in state.realnets:
                mode = "BGP" if rn.bgp else "NAT"
                bgp = f", AS {rn.bgp_as}" if rn.bgp_as else ""
                console.print(
                    f"    RealNet:   {rn.name} {rn.lan_ipv4} "
                    f"({mode}, WAN {rn.router_wan_ip or 'pending'}{bgp})"
                )

        console.print(f"    State:     .{state.lab_name}.multinode.json")

    except (PlanError, DeployError) as e:
        console.print(f"\n[red][✗] {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red][✗] Error: {e}[/red]")
        sys.exit(1)


# ── destroy ──────────────────────────────────────────────────────────

@main.command()
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
def destroy(topo: str, hosts_file: str | None) -> None:
    """Teardown the distributed lab."""
    from dnlab_multinode.controllers.destroy import DestroyController, DestroyError

    try:
        ctrl = DestroyController(topo, hosts_file=hosts_file)
        ctrl.run()
        console.print("\n[green][✓] Lab destroyed.[/green]")

    except DestroyError as e:
        console.print(f"\n[red][✗] {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red][✗] Error: {e}[/red]")
        sys.exit(1)


# ── inspect ──────────────────────────────────────────────────────────

@main.command()
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
def inspect(topo: str, hosts_file: str | None) -> None:
    """Show current deployment state."""
    from dnlab_multinode.services.config import parse_topology
    from dnlab_multinode.services.state import load_state

    try:
        topo_obj = parse_topology(topo, hosts_file=hosts_file)
        state = load_state(topo_obj.name, Path(topo).parent)

        if not state:
            console.print(f"[yellow]No deployment found for '{topo_obj.name}'[/yellow]")
            return

        console.print(f"\n[bold]Lab:[/bold] {state.lab_name}")
        console.print(f"[bold]Deployed at:[/bold] {state.deployed_at}")

        if state.scheduling:
            table = Table(title="Scheduling")
            table.add_column("Host")
            table.add_column("VDs")
            table.add_column("CPU")
            table.add_column("RAM (MB)")
            for hname, hs in state.scheduling.items():
                table.add_row(
                    hname,
                    ", ".join(hs.vd),
                    str(hs.resources_used.get("cpu", 0)),
                    str(hs.resources_used.get("ram_mb", 0)),
                )
            console.print(table)

        if state.dns:
            console.print(f"\n[bold]DNS:[/bold] {state.dns.mgmt_ip}")
            console.print(f"  Container: {state.dns.container}")
            console.print(f"  Records:   {state.dns.entries}")
            console.print(f"  Upstream:  {', '.join(state.dns.upstream)}")

        if state.runtime_relays:
            table = Table(title="Runtime Relays")
            table.add_column("Host")
            table.add_column("Container")
            table.add_column("Bind")
            table.add_column("Allowed VDs", justify="right")
            for host_name, rr in state.runtime_relays.items():
                table.add_row(
                    host_name,
                    rr.container,
                    f"{rr.bind_ip}:{rr.port}",
                    str(len(rr.allowed)),
                )
            console.print(table)

        if state.jumphost:
            host_ip = state.jumphost.host_ip.split("/")[0] if state.jumphost.host_ip else "N/A"
            console.print(f"\n[bold]Jump host:[/bold] ssh labuser@{host_ip}  [dim](from master)[/dim]")
            console.print(f"  Password: {state.jumphost.password}")
            console.print(f"  Mgmt IP:  {state.jumphost.mgmt_ip}")
            if state.jumphost.ext_network:
                console.print(f"  Ext net:  {state.jumphost.ext_network}")
            if state.jumphost.resolver:
                console.print(f"  Resolver: {state.jumphost.resolver}")

        if state.vxlan_dataplane:
            table = Table(title="VxLAN Dataplane")
            table.add_column("ID")
            table.add_column("Link")
            table.add_column("Status")
            for vl in state.vxlan_dataplane:
                table.add_row(str(vl.id), vl.link, vl.status)
            console.print(table)

        if state.realnets:
            table = Table(title="Real Networks")
            table.add_column("Name")
            table.add_column("LAN")
            table.add_column("WAN IP")
            table.add_column("Mode")
            table.add_column("BGP AS")
            for rn in state.realnets:
                mode = "BGP" if rn.bgp else "NAT"
                table.add_row(
                    rn.name, rn.lan_ipv4, rn.router_wan_ip,
                    mode, str(rn.bgp_as or "-"),
                )
            console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# ── get-status ──────────────────────────────────────────────────────

@main.command("get-status")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON for programmatic use")
def get_status(topo: str, hosts_file: str | None, as_json: bool) -> None:
    """Show live status of a deployed lab (VDs, hosts, infra)."""
    import json
    from dnlab_multinode.controllers.status import StatusController

    try:
        ctrl = StatusController(topo, hosts_file=hosts_file)
        report = ctrl.run()

        if as_json:
            click.echo(json.dumps(report.to_dict(), indent=2))
            return

        if not report.deployed:
            console.print(f"[yellow]Lab '{report.lab_name}' is not deployed[/yellow]")
            return

        console.print(f"\n[bold]Lab:[/bold] {report.lab_name}")
        console.print(f"[bold]Deployed at:[/bold] {report.deployed_at}")

        h_table = Table(title="Hosts")
        h_table.add_column("Host")
        h_table.add_column("IP")
        h_table.add_column("Reachable")
        h_table.add_column("VDs", justify="right")
        h_table.add_column("CPU", justify="right")
        h_table.add_column("RAM (MB)", justify="right")
        for hs in report.hosts.values():
            h_table.add_row(
                hs.name, hs.host,
                "[green]yes[/green]" if hs.reachable else f"[red]no[/red] ({hs.error})",
                str(hs.vd_count), str(hs.cpu_used), str(hs.ram_mb_used),
            )
        console.print(h_table)

        n_table = Table(title="Virtual Devices")
        n_table.add_column("Name")
        n_table.add_column("Host")
        n_table.add_column("Kind")
        n_table.add_column("Mgmt IPv4")
        n_table.add_column("State")
        for ns in report.nodes.values():
            color = {
                "running": "green", "exited": "red", "missing": "yellow",
                "unreachable": "magenta",
            }.get(ns.state, "white")
            n_table.add_row(
                ns.name, ns.host or "-", ns.kind, ns.mgmt_ipv4 or "-",
                f"[{color}]{ns.state}[/{color}]",
            )
        console.print(n_table)

        console.print(f"\nCross-host links: {report.cross_host_links}")

        if report.infra.dns:
            d = report.infra.dns
            running = _fmt_bool(d.get("running"))
            console.print(f"DNS:       {d['container']}@{d['host']} "
                          f"({d['mgmt_ip']}, {d['entries']} records) — {running}")
        if report.infra.jumphost:
            j = report.infra.jumphost
            running = _fmt_bool(j.get("running"))
            console.print(f"Jumphost:  {j['container']}@{j['host']} "
                          f"(mgmt {j['mgmt_ip']}, ext {j['ext_ip']}) — {running}")
        if report.infra.runtime_relays:
            for host_name, rr in report.infra.runtime_relays.items():
                running = _fmt_bool(rr.get("running"))
                console.print(f"Runtime:   {rr['container']}@{host_name} "
                              f"({rr['bind_ip']}:{rr['port']}, "
                              f"{rr['allowed']} allowed) — {running}")

    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


def _fmt_bool(v: bool | None) -> str:
    if v is True:
        return "[green]running[/green]"
    if v is False:
        return "[red]stopped[/red]"
    return "[yellow]unknown[/yellow]"


# ── node lifecycle ──────────────────────────────────────────────────

@main.group("node")
def node_group() -> None:
    """Manage single VD runtime state."""


@node_group.command("list")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None, help="Path to global hosts file")
def node_list(topo: str, hosts_file: str | None) -> None:
    from dnlab_multinode.controllers.node import NodeLifecycleController

    try:
        ctrl = NodeLifecycleController(topo, hosts_file=hosts_file)
        table = Table(title="VD Runtime")
        table.add_column("Node")
        table.add_column("State")
        table.add_column("Host")
        table.add_column("Container")
        table.add_column("Mgmt IPv4")
        for runtime in ctrl.list_nodes().values():
            table.add_row(
                runtime.node,
                runtime.state,
                runtime.host or "-",
                runtime.container or "-",
                runtime.mgmt_ipv4 or "-",
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


@node_group.command("stop")
@click.argument("node")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None, help="Path to global hosts file")
@click.option("--force", is_flag=True, help="Explicitly request a forced stop")
def node_stop(node: str, topo: str, hosts_file: str | None, force: bool = False) -> None:
    from dnlab_multinode.controllers.node import NodeLifecycleController

    try:
        state = NodeLifecycleController(topo, hosts_file=hosts_file).stop(node, force=force)
        runtime = state.node_runtime[node]
        console.print(f"[green][✓] {node}: {runtime.state}[/green]")
    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


@node_group.command("start")
@click.argument("node")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None, help="Path to global hosts file")
def node_start(node: str, topo: str, hosts_file: str | None) -> None:
    from dnlab_multinode.controllers.node import NodeLifecycleController

    try:
        state = NodeLifecycleController(topo, hosts_file=hosts_file).start(node)
        runtime = state.node_runtime[node]
        console.print(f"[green][✓] {node}: {runtime.state}[/green]")
    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


@node_group.command("reconcile")
@click.argument("node", required=False)
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None, help="Path to global hosts file")
def node_reconcile(node: str | None, topo: str, hosts_file: str | None) -> None:
    from dnlab_multinode.controllers.node import NodeLifecycleController

    try:
        NodeLifecycleController(topo, hosts_file=hosts_file).reconcile(node)
        target = node or "all nodes"
        console.print(f"[green][✓] Reconciled {target}[/green]")
    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


# ── sync-images ──────────────────────────────────────────────────────

@main.command("sync-images")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
def sync_images(topo: str, hosts_file: str | None) -> None:
    """Synchronize missing Docker images from master to workers."""
    from dnlab_multinode.controllers.sync import SyncController

    try:
        ctrl = SyncController(topo, hosts_file=hosts_file)
        synced = ctrl.run()

        if not synced:
            console.print("[green][✓] All images already aligned[/green]")
        else:
            for img, hosts in synced.items():
                if hosts:
                    console.print(f"  [green]✓[/green] {img} → {', '.join(hosts)}")
                else:
                    console.print(f"  [red]✗[/red] {img} — sync failed")

    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


# ── refresh-dns ──────────────────────────────────────────────────────

@main.command("refresh-dns")
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
def refresh_dns_cmd(topo: str, hosts_file: str | None) -> None:
    """Rebuild the centralized DNS zone from every node's /etc/hosts."""
    from dnlab_multinode.services.config import parse_topology
    from dnlab_multinode.services.ssh import create_clients
    from dnlab_multinode.services import dns as dns_svc
    from dnlab_multinode.services.hostsfile import HostEntry
    from dnlab_multinode.services.state import load_state

    try:
        topo_obj = parse_topology(topo, hosts_file=hosts_file)
        clients = create_clients(topo_obj.all_hosts)
        state = load_state(topo_obj.name, Path(topo).parent)
        runtime_entries: list[HostEntry] = []
        if state:
            for runtime in (state.node_runtime or {}).values():
                if not runtime.mgmt_ipv4:
                    continue
                runtime_entries.append(HostEntry(runtime.container, runtime.mgmt_ipv4, "A"))
                runtime_entries.append(HostEntry(runtime.node, runtime.mgmt_ipv4, "A"))

        try:
            for client in clients.values():
                client.connect()

            count, entries = dns_svc.refresh_dns(
                topo_obj.name, clients["master"], clients,
                extra_entries=runtime_entries,
                generation=state.dns.generation if state and state.dns else "",
            )

            console.print(f"[green][✓] DNS refreshed:[/green] {count} records")
            for e in entries:
                console.print(f"  {e.family:<4} {e.ip:<40} {e.name}")
        finally:
            for client in clients.values():
                client.close()

    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


# ── cleanup-labs ─────────────────────────────────────────────────────

@main.command("cleanup-labs")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
@click.option("--dry-run/--execute", default=True,
              help="Plan cleanup without mutating hosts (default: dry-run)")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON for programmatic use")
@click.option("--state-file", default=None, help="Override cleanup state file path")
@click.option("--topologies-dir", default=None, help="Override topology/state directory")
def cleanup_labs_cmd(
    hosts_file: str | None,
    dry_run: bool,
    as_json: bool,
    state_file: str | None,
    topologies_dir: str | None,
) -> None:
    """Reconcile stale dNLab artifacts left by incomplete lab cleanup."""
    import json
    from dnlab_multinode.services.hosts_config import load_hosts_config
    from dnlab_multinode.services.lab_cleanup import reconcile_once, DEFAULT_STATE_FILE
    from dnlab_multinode.services.paths import PATHS

    try:
        hosts = load_hosts_config(hosts_file)
        report = reconcile_once(
            hosts,
            state_file=Path(state_file) if state_file else DEFAULT_STATE_FILE,
            topologies_dir=Path(topologies_dir) if topologies_dir else PATHS.topologies_dir,
            dry_run=dry_run,
        )
        data = report.to_dict()
        if as_json:
            click.echo(json.dumps(data, indent=2, sort_keys=True))
            return

        actions = sum(len(plan.actions) for plan in report.labs.values())
        protected = sum(1 for plan in report.labs.values() if plan.protected)
        mode = "planned" if report.dry_run else "executed"
        console.print(
            f"[green][✓] Lab cleanup {mode}:[/green] "
            f"{len(report.labs)} labs, {protected} protected, {actions} actions"
        )
        for lab, plan in sorted(report.labs.items()):
            marker = "protected" if plan.protected else f"{len(plan.actions)} actions"
            console.print(f"  {lab}: {marker}")
            for reason in plan.reasons:
                console.print(f"    - {reason}")
            for warning in plan.warnings:
                console.print(f"    - warn: {warning}")
    except Exception as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


# ── generate ─────────────────────────────────────────────────────────

@main.command()
@click.option("-t", "--topo", required=True, help="Path to topology YAML file")
@click.option("--hosts", "hosts_file", default=None,
              help="Path to global hosts file")
@click.option("-o", "--output-dir", default="./generated", help="Output directory")
@click.option("--no-cache", is_flag=True, help="Ignore image resource cache")
def generate(topo: str, hosts_file: str | None, output_dir: str, no_cache: bool) -> None:
    """Generate per-node topology files without deploying."""
    from dnlab_multinode.controllers.plan import PlanController, PlanError
    from dnlab_multinode.services.generator import generate_topology_files

    try:
        ctrl = PlanController(topo, no_cache, hosts_file=hosts_file)
        schedule = ctrl.run()
        _print_plan(ctrl, schedule)

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        topo_files = generate_topology_files(ctrl.topo, schedule)
        for host_name, content in topo_files.items():
            path = out / f"{ctrl.topo.name}-{host_name}.clab.yml"
            path.write_text(content)
            console.print(f"  [green]✓[/green] {path}")

    except PlanError as e:
        console.print(f"[red][✗] {e}[/red]")
        sys.exit(1)


# ── Helpers ──────────────────────────────────────────────────────────

def _print_plan(ctrl, schedule):
    """Pretty-print the scheduling plan."""
    topo = ctrl.topo

    console.print(f"\n[bold][*] Topology:[/bold] {topo.name}")
    console.print(f"    {len(topo.nodes)} nodes, {len(topo.links)} links, "
                  f"{1 + len(topo.workers)} hosts\n")

    # VD resources
    table = Table(title="VD Resources")
    table.add_column("Node")
    table.add_column("Image")
    table.add_column("CPU", justify="right")
    table.add_column("RAM (MB)", justify="right")
    table.add_column("Weight", justify="right")
    for name, vd in ctrl.vd_resources.items():
        table.add_row(name, vd.image, str(vd.cpu), str(vd.ram_mb), str(vd.weight))
    console.print(table)

    # Schedule
    table = Table(title="Scheduling Plan")
    table.add_column("Host")
    table.add_column("VDs")
    table.add_column("CPU", justify="right")
    table.add_column("RAM (MB)", justify="right")
    for hname, assignment in schedule.assignments.items():
        if assignment.vd_names:
            table.add_row(
                hname,
                ", ".join(assignment.vd_names),
                str(assignment.cpu_used),
                str(assignment.ram_mb_used),
            )
    console.print(table)

    console.print(f"\n    Cross-host links: {len(schedule.cross_host_links)}")
    if schedule.cross_host_links:
        vxlan_ids = [cl.vxlan_id for cl in schedule.cross_host_links]
        console.print(f"    VxLAN IDs: {min(vxlan_ids)}-{max(vxlan_ids)}")
    console.print(f"    Mgmt VxLAN ID: {schedule.mgmt_vxlan_id}  VRF table: {schedule.vrf_table_id}")


if __name__ == "__main__":
    main()
