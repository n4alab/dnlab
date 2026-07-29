"""Deploy controller — full orchestration of multi-node deployment."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from dnlab_multinode.controllers.plan import PlanController
from dnlab_multinode.models.state import (
    DeploymentState, MgmtState, JumphostState, DnsState,
    HostScheduleState, VxlanLinkState, WebUIAllocation,
    NodeRuntimeState, MgmtAnchorState, RuntimeRelayState,
)
from dnlab_multinode.services import (
    generator, netsetup, vxlan, jumphost, dns as dns_svc, state as state_svc,
    webui_ports as webui_ports_svc, realnet as realnet_svc,
    persistence as persistence_svc, runtime_links as runtime_links_svc,
    runtime_relay as runtime_relay_svc, warm_links as warm_links_svc,
    mgmt_network as mgmt_network_svc,
)
from dnlab_multinode.services.hostsfile import HostEntry
from dnlab_multinode.services.progress import (
    ProgressCallback, make_timer, NullProgress,
)
from dnlab_multinode.services.ssh import SSHClient, create_clients
from dnlab_multinode.utils import naming
from dnlab_multinode.utils.naming import micro_vd_container_name

log = logging.getLogger(__name__)


class DeployError(Exception):
    pass


class DeployController:
    """Orchestrates the full deploy sequence."""

    def __init__(
        self,
        topology_file: str,
        no_cache: bool = False,
        *,
        hosts_file: str | None = None,
        progress: ProgressCallback | None = None,
    ):
        self.topology_file = topology_file
        self.no_cache = no_cache
        self.hosts_file = hosts_file
        self._progress = make_timer(progress)
        self._clients: dict[str, SSHClient] = {}
        self._state: DeploymentState | None = None
        # Underlay IPs resolved at deploy-time by querying each host directly
        # (not whatever the user wrote in `host:`, which may be a hostname).
        self._underlay_ips: dict[str, str] = {}

    def run(self) -> DeploymentState:
        """Execute the full deploy pipeline."""

        # ── Phase 0: Planning ────────────────────────────────────────
        self._progress.emit("plan", "start", detail="Parsing topology + scheduling")
        planner = PlanController(
            self.topology_file, self.no_cache, hosts_file=self.hosts_file,
        )
        plan = planner.run()
        topo = planner.topo
        self._progress.emit(
            "plan", "ok",
            detail=f"{len(topo.nodes)} VDs on {len(topo.all_hosts)} hosts, "
                   f"{len(plan.cross_host_links)} cross-host links",
        )

        # Init state
        self._state = DeploymentState(
            lab_name=topo.name,
            topology_file=self.topology_file,
            deployed_at=datetime.now().isoformat(timespec="seconds"),
            vrf_table_id=plan.vrf_table_id,
            runtime_mode="per-vd",
        )
        self._state.mgmt_ip_reservations = dict(
            topo.raw.get("dnlab_mgmt_ip_reservations") or {}
        )

        # Connect SSH
        self._clients = create_clients(topo.all_hosts)
        try:
            for client in self._clients.values():
                client.connect()

            self._phase("image-capabilities", "Inspecting warm-link image capabilities",
                        self._inspect_image_capabilities, topo, plan)
            self._phase("underlay", "Resolving underlay IPs",
                        self._resolve_underlay_ips, topo)
            self._phase("mgmt-setup", "Setting up mgmt infrastructure",
                        self._deploy_mgmt, topo, plan)
            self._phase("mgmt-network", "Creating Docker mgmt networks",
                        self._deploy_mgmt_network, topo)
            self._phase("webui-ports", "Allocating Web UI host ports",
                        self._allocate_webui_ports, topo)
            self._phase("realnet-setup", "Setting up real_net infrastructure",
                        self._deploy_realnets, topo, plan)
            self._phase("persistence", "Preparing persistent overlays",
                        self._prepare_persistence, topo, plan)
            self._phase("mgmt-anchor", "Deploying management anchors",
                        self._deploy_mgmt_anchors, topo, plan)
            self._phase("dnlab-deploy", "Deploying containerlab on each host",
                        self._deploy_clab, topo, plan)
            self._phase("health-check", "Checking VD container health",
                        self._health_check_vds, topo, plan)
            self._phase("runtime-links", "Reconciling runtime dataplane links",
                        self._deploy_runtime_links, topo, plan)
            self._phase("runtime-relay", "Starting runtime relays",
                        self._deploy_runtime_relays, topo, plan)
            self._phase("dns", "Starting centralized DNS",
                        self._deploy_dns, topo, plan)
            self._phase("jumphost", "Starting jump host",
                        self._deploy_jumphost, topo, plan)
            self._phase("vd-routes", "Setting VD default routes",
                        self._set_vd_default_routes, topo)
            self._phase("verify", "Verifying tunnels + DNS",
                        self._verify, topo, plan)

            # Save state
            state_svc.save_state(self._state, Path(self.topology_file).parent)
            persistence_svc.save_placement_history(
                topo, plan, Path(self.topology_file).parent,
            )

            self._progress.emit(
                "deploy", "ok",
                detail=f"Lab '{topo.name}' deployed",
                data={"jumphost_ip": self._state.jumphost.host_ip if self._state.jumphost else ""},
            )
            return self._state

        except Exception as exc:
            log.error("Deploy failed: %s — initiating rollback", exc)
            self._progress.emit("rollback", "start", detail=str(exc))
            try:
                self._rollback(topo)
                self._progress.emit("rollback", "ok", detail="Rollback complete")
            except Exception as rb_exc:
                self._progress.emit("rollback", "error", detail=str(rb_exc))
            raise DeployError(f"Deploy fallito: {exc}") from exc
        finally:
            for client in self._clients.values():
                client.close()

    def _phase(self, phase: str, detail: str, fn, *args, **kwargs):
        """Emit start/ok/error progress events around a phase call."""
        self._progress.emit(phase, "start", detail=detail)
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            self._progress.emit(phase, "error", detail=str(exc))
            raise
        self._progress.emit(phase, "ok", detail=f"{detail} — done")
        return result

    def _inspect_image_capabilities(self, topo, plan):
        """Trust capability labels from the exact image on its assigned host.

        Repository tags are intentionally insufficient: a reused tag may point
        at a different digest.  ``apply.py`` emits ``validated`` only when the
        base repository, tag and digest match the qualification registry.
        """
        for node_name, node in topo.nodes.items():
            if not warm_links_svc.profile_for_node(node):
                continue
            host = plan.host_for_vd(node_name)
            if not host or host not in self._clients:
                node.env[warm_links_svc.IMAGE_STATUS_ENV] = "missing"
                continue
            status = warm_links_svc.inspect_image_on_host(
                node, self._clients[host],
            )
            log.info(
                "[%s] image capability for %s (%s): %s base=%s",
                host, node_name, node.image, status,
                node.env.get(warm_links_svc.BASE_DIGEST_ENV, "unknown"),
            )

    # ── Phase 1: Resolve underlay IPs ───────────────────────────────

    def _resolve_underlay_ips(self, topo):
        """Query each host for the IP on its underlay interface.

        The YAML ``host:`` field may be a hostname, which cannot be fed to
        ``containerlab tools vxlan create --remote`` or to ``bridge fdb append
        ... dst``. Those commands need a literal IP routable from the peer's
        kernel. We discover the truth by asking each host directly.
        """
        log.info("Phase 1: Resolving underlay IPs (iface=%s)", topo.underlay_iface)
        iface = topo.underlay_iface
        cmd = (
            f"ip -4 -o addr show dev {iface} "
            f"| awk '{{print $4}}' | cut -d/ -f1 | head -n1"
        )
        for host_name, client in self._clients.items():
            rc, out, err = client.run_no_check(cmd)
            ip = (out or "").strip()
            if rc != 0 or not ip:
                raise DeployError(
                    f"[{host_name}] Could not read IPv4 address of underlay "
                    f"interface '{iface}': rc={rc} out={out!r} err={err!r}"
                )
            self._underlay_ips[host_name] = ip
            log.info("[%s] underlay %s → %s", host_name, iface, ip)

    # ── Phase 2: Mgmt infrastructure ────────────────────────────────

    def _deploy_mgmt(self, topo, plan):
        log.info("Phase 2: Setting up mgmt infrastructure")
        all_ips = self._underlay_ips

        # Determine if DHCP is needed (any node without static mgmt IP)
        needs_dhcp = any(not n.mgmt_ipv4 for n in topo.nodes.values())

        def _setup_host(host_name):
            client = self._clients[host_name]
            netsetup.setup_mgmt_infra(topo, plan, client, host_name, all_ips)
            return host_name

        with ThreadPoolExecutor(max_workers=len(self._clients)) as pool:
            futures = {pool.submit(_setup_host, h): h for h in self._clients}
            for f in as_completed(futures):
                host = futures[f]
                try:
                    f.result()
                    log.info("[%s] Mgmt infra OK", host)
                except Exception as e:
                    raise DeployError(f"[{host}] Mgmt setup failed: {e}")

        # DHCP on master if needed
        if needs_dhcp:
            netsetup.setup_dhcp(topo, self._clients["master"], "master")

        self._state.mgmt = MgmtState(
            subnet=topo.mgmt.ipv4_subnet,
            gateway=topo.mgmt.ipv4_gw,
            bridge=topo.mgmt.bridge,
            vrf=naming.vrf_name(topo.name),
            vxlan_id=plan.mgmt_vxlan_id,
            vxlan_iface=naming.mgmt_vxlan_iface(topo.name),
            network=topo.mgmt.network,
            network_driver=mgmt_network_svc.NETWORK_DRIVER,
            ipam_driver=mgmt_network_svc.IPAM_DRIVER,
        )
        self._state.phases_completed.append("mgmt")

    def _deploy_mgmt_network(self, topo):
        """Create the managed Docker network after its bridge/VRF exists."""
        if "mgmt_network" not in self._state.phases_completed:
            # Track the phase before fan-out so rollback also removes a network
            # that was created successfully on only a subset of hosts.
            self._state.phases_completed.append("mgmt_network")

        def _ensure_host(host_name: str) -> str:
            mgmt_network_svc.ensure_mgmt_network(topo, self._clients[host_name])
            return host_name

        with ThreadPoolExecutor(max_workers=len(self._clients)) as pool:
            futures = {pool.submit(_ensure_host, host): host for host in self._clients}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    future.result()
                    log.info("[%s] Docker management network ready", host)
                except Exception as exc:
                    raise DeployError(f"[{host}] Docker mgmt network setup failed: {exc}") from exc

    # ── Phase 2.5: Allocate Web UI host ports ─────────────────────────
    def _allocate_webui_ports(self, topo):
        """Riserva le porte host-side per le Web UI dei VD.

        Per ogni nodo della ``topo.webui_wishlist`` (popolata dal
        sidecar ``# dnlab-gui-webui:`` lasciato dalla GUI nel YAML),
        chiama l'allocator del pool ``hosts.webui_ports`` e popola
        ``self._state.webui_allocations``. Sticky reuse:

        * carica la state precedente (``state_svc.load_state``);
        * per ogni (node, container_port) già presente nella state,
          tenta riconferma della stessa host_port via ``preferred=``;
        * solo se quella porta è ora occupata da un altro lab passa a
          una nuova allocazione.

        Le allocazioni vengono poi consumate da
        :func:`generator.generate_topology_files` per scrivere
        ``ports: ["<host>:<container>/tcp", ...]`` in ogni node block.
        """
        if not topo.webui_wishlist:
            log.info("Phase 2.5: no Web UI to expose, skip allocator")
            return

        master_client = self._clients["master"]
        bind_ip    = topo.webui_ports.bind_ip
        port_range = topo.webui_ports.port_range

        # Preferred (sticky) hints dalla state precedente, se esiste.
        prev = state_svc.load_state(topo.name, Path(self.topology_file).parent)
        prev_alloc: dict[str, dict[int, int]] = {}
        if prev is not None:
            for node, allocs in (prev.webui_allocations or {}).items():
                prev_alloc[node] = {a.container_port: a.host_port for a in allocs}

        # Allocator chiama docker ps su master ad ogni invocazione: per
        # not collide among the allocations of THIS deploy (none
        # delle quali è ancora visibile a docker ps), passiamo il set
        # cumulativo ad ``used_extra``.
        used_in_this_deploy: set[int] = set()
        new_allocs: dict[str, list[WebUIAllocation]] = {}

        for node_name, wishlist in topo.webui_wishlist.items():
            entries: list[WebUIAllocation] = []
            for w in wishlist:
                cport = int(w.get("container_port") or 0)
                if cport <= 0:
                    continue
                preferred = prev_alloc.get(node_name, {}).get(cport)
                hport = webui_ports_svc.allocate_webui_port(
                    master_client,
                    bind_ip,
                    port_range,
                    used_extra=used_in_this_deploy,
                    preferred=preferred,
                )
                used_in_this_deploy.add(hport)
                entries.append(WebUIAllocation(
                    container_port=cport,
                    host_port=hport,
                    bind_ip=bind_ip,
                    proto="tcp",
                ))
                log.info(
                    "Phase 2.5: %s/%s host_port=%d → container=%d (sticky=%s)",
                    topo.name, node_name, hport, cport,
                    "yes" if preferred == hport else "no",
                )
            if entries:
                new_allocs[node_name] = entries

        self._state.webui_allocations = new_allocs
        self._state.phases_completed.append("webui-ports")

    # ── Phase 3-4: Generate + deploy clab ────────────────────────────

    def _deploy_realnets(self, topo, plan):
        if not topo.real_nets:
            return
        master = self._clients["master"]
        if any(rn.nat and not rn.bgp for rn in topo.real_nets.values()):
            realnet_svc.ensure_realnet_wan_network(master, topo)
        if any(rn.bgp for rn in topo.real_nets.values()):
            realnet_svc.deploy_route_reflector(topo, master)
        states = realnet_svc.setup_bridges(topo, self._clients, self._underlay_ips)
        for rn_state in states:
            rn = topo.real_nets[rn_state.name]
            realnet_svc.deploy_router(topo, rn, rn_state, master)
        self._state.realnets = states
        self._state.phases_completed.append("realnet")

    def _prepare_persistence(self, topo, plan):
        persistence_svc.prepare_persistence(
            topo, plan, self._clients, Path(self.topology_file).parent, self._progress,
        )
        self._state.phases_completed.append("persistence")

    def _deploy_clab(self, topo, plan):
        log.info("Phase 3-4: Generating and deploying containerlab")

        # Generate topology files
        # Le allocazioni Web UI host-side (porta master:443→8456) sono già
        # state computate dalla phase ``webui-ports`` e vivono in
        # ``self._state.webui_allocations``. Le passiamo al generator
        # come dict serializzabili così le materializza in ``ports:``.
        webui_alloc_dicts = {
            node: [
                {
                    "container_port": a.container_port,
                    "host_port":      a.host_port,
                    "bind_ip":        a.bind_ip,
                    "proto":          a.proto,
                }
                for a in allocs
            ]
            for node, allocs in (self._state.webui_allocations or {}).items()
        }
        topo_files = generator.generate_micro_topology_files(
            topo, plan, webui_allocations=webui_alloc_dicts,
        )

        # Pre-create the persist dirs for every VD that declares a
        # /persist bind. Without this, containerlab refuses to bind-mount
        # a non-existent host path. The root is owned by root with 0755
        # so both the orchestrator and docker (running as root) can read
        # and clab's vrnetlab launchers (also root) can write.
        for host_name, assignment in plan.assignments.items():
            persist_dirs = [
                generator.persist_dir_for_node(
                    topo.name,
                    vd,
                    topo.nodes[vd].persist_id,
                    topo.persistence.root,
                )
                for vd in assignment.vd_names
                if generator._needs_persist_bind(topo.nodes[vd].image)
            ]
            for vd in assignment.vd_names:
                for remote_path in generator.render_node_feature_files(topo, vd):
                    persist_dirs.append(str(Path(remote_path).parent))
            if not persist_dirs:
                continue
            client = self._clients[host_name]
            # Quote every path so any odd lab/VD name stays safe.
            quoted = " ".join(f"'{p}'" for p in sorted(set(persist_dirs)))
            client.run(f"mkdir -p {quoted}")
            log.info("[%s] Ensured %d persist dir(s)", host_name, len(persist_dirs))

        # Upload runtime node assets to the host that will run the
        # scheduled VD. The generator binds these assets from /tmp, so
        # nothing topology-local under /root/dnlab-topologies has to be
        # mirrored across workers.
        for host_name, assignment in plan.assignments.items():
            assets = self._runtime_assets_for_host(topo, assignment.vd_names)
            if not assets:
                continue
            client = self._clients[host_name]
            for remote_path, content in assets.items():
                remote_dir = str(Path(remote_path).parent)
                client.run(f"mkdir -p '{remote_dir}'")
                client.upload_text(content, remote_path)
            log.info("[%s] Uploaded %d runtime asset file(s)", host_name, len(assets))

        # Upload and deploy every VD micro-topology. Deploys are
        # sequential per Docker daemon because all micro-topologies on a
        # host share the same management network; concurrent clab deploys
        # race while creating that network. Hosts still run in parallel.
        def _deploy_host(host_name, host_files):
            client = self._clients[host_name]
            deployed = []
            for vd_name, yaml_content in host_files.items():
                remote_path = naming.micro_topology_file(topo.name, vd_name, host_name)

                client.upload_text(yaml_content, remote_path)
                log.info("[%s] Uploaded micro-topology %s → %s", host_name, vd_name, remote_path)

                try:
                    client.deploy_clab(remote_path)
                except Exception as e:
                    raise DeployError(
                        f"[{host_name}] containerlab deploy failed for "
                        f"{vd_name} ({remote_path}): {e}"
                    ) from e
                log.info("[%s] containerlab deploy OK for %s", host_name, vd_name)

                vd = topo.nodes[vd_name]
                deployed.append(NodeRuntimeState(
                    node=vd_name,
                    state="starting",
                    host=host_name,
                    container=micro_vd_container_name(topo.name, vd_name),
                    topology_file=remote_path,
                    kind=vd.kind,
                    image=vd.image,
                    mgmt_ipv4=vd.mgmt_ipv4,
                    warm_ports=warm_links_svc.capacity_for_node(topo, vd_name),
                    hot_links_status=warm_links_svc.status_for_node(vd),
                ))
            return host_name, deployed

        active_hosts = {
            host_name: host_files
            for host_name, host_files in topo_files.items()
            if host_files
        }
        with ThreadPoolExecutor(max_workers=max(1, len(active_hosts))) as pool:
            futures = {
                pool.submit(_deploy_host, host_name, host_files): host_name
                for host_name, host_files in active_hosts.items()
            }
            for f in as_completed(futures):
                host = futures[f]
                try:
                    _, deployed_nodes = f.result()
                except Exception as e:
                    raise DeployError(f"[{host}] containerlab deploy failed: {e}")
                for runtime in deployed_nodes:
                    self._state.node_runtime[runtime.node] = runtime

        for host_name, assignment in plan.assignments.items():
            if not assignment.vd_names:
                continue
            self._state.scheduling[host_name] = HostScheduleState(
                host=self._underlay_ips[host_name],
                topology_file="",
                vd=assignment.vd_names,
                resources_used={
                    "cpu": assignment.cpu_used,
                    "ram_mb": assignment.ram_mb_used,
                },
            )

        self._state.phases_completed.append("dnlab")

    def _deploy_mgmt_anchors(self, topo, plan):
        log.info("Phase 3a: Deploying management anchor topologies")
        anchor_files = generator.generate_mgmt_anchor_topology_files(topo, plan)
        if not anchor_files:
            return

        if "mgmt_anchor" not in self._state.phases_completed:
            self._state.phases_completed.append("mgmt_anchor")

        for host_name, yaml_content in anchor_files.items():
            client = self._clients[host_name]
            remote_path = naming.mgmt_anchor_topology_file(topo.name, host_name)

            client.upload_text(yaml_content, remote_path)
            try:
                client.deploy_clab(remote_path, reconfigure=True)
            except Exception as e:
                raise DeployError(
                    f"[{host_name}] management anchor deploy failed "
                    f"({remote_path}): {e}"
                ) from e

            self._state.mgmt_anchors[host_name] = MgmtAnchorState(
                host=host_name,
                container=naming.mgmt_anchor_container_name(topo.name, host_name),
                topology_file=remote_path,
                state="running",
            )

    @staticmethod
    def _runtime_assets_for_host(topo, vd_names: list[str]) -> dict[str, str]:
        """Return remote path → content for runtime assets on this host."""
        out: dict[str, str] = {}
        for vd_name in vd_names:
            state = (topo.node_overrides or {}).get(vd_name) or {}
            content = generator.render_node_asset(state, "vswitch.xml")
            if content is not None:
                out[generator.node_asset_path(topo.name, vd_name, "vswitch.xml")] = content
            out.update(generator.render_node_feature_files(topo, vd_name))
        return out

    # ── Phase 3b: Health check VDs ─────────────────────────────────────

    # How long to wait for containers to settle after clab deploy.
    # vrnetlab launch.py crashes are near-instant (import/syntax errors
    # cause Exited(1) within seconds), so 60s is generous. We do NOT
    # wait for the VM inside the container to fully boot — that takes
    # minutes and is out of scope for this check.
    _HEALTH_TIMEOUT = 60
    _HEALTH_POLL_INTERVAL = 5
    _DOCKER_LOG_TAIL = 50

    def _health_check_vds(self, topo, plan):
        """Poll container status on each host; fail fast on Exited/dead."""
        log.info("Phase 3b: Health-checking VD containers")

        # Build {host_name: [container_name, ...]} from plan
        host_containers: dict[str, list[tuple[str, str]]] = {}
        for host_name, assignment in plan.assignments.items():
            if not assignment.vd_names:
                continue
            containers = [
                (vd, micro_vd_container_name(topo.name, vd))
                for vd in assignment.vd_names
            ]
            host_containers[host_name] = containers

        if not host_containers:
            return

        deadline = time.monotonic() + self._HEALTH_TIMEOUT
        settled: set[str] = set()

        while time.monotonic() < deadline:
            all_ok = True

            for host_name, containers in host_containers.items():
                if host_name in settled:
                    continue

                client = self._clients[host_name]
                cnames = [c for _, c in containers]
                statuses = self._query_container_statuses(client, cnames)

                failed = []
                running = 0
                for vd_name, cname in containers:
                    status = statuses.get(cname, "missing")
                    if status in ("exited", "dead"):
                        failed.append((vd_name, cname, status))
                    elif status == "running":
                        running += 1

                if failed:
                    self._raise_health_failure(client, host_name, failed)

                if running == len(containers):
                    settled.add(host_name)
                    for vd_name, _ in containers:
                        if vd_name in self._state.node_runtime:
                            self._state.node_runtime[vd_name].state = "running"
                            self._state.node_runtime[vd_name].started_at = datetime.now().isoformat(timespec="seconds")
                    self._progress.emit(
                        "health-check", "info", host=host_name,
                        detail=f"{running}/{len(containers)} VDs running",
                    )
                else:
                    all_ok = False

            if all_ok:
                log.info("All VD containers healthy across %d host(s)", len(host_containers))
                return

            time.sleep(self._HEALTH_POLL_INTERVAL)

        # Timeout: report which containers never reached running
        pending_detail = []
        for host_name, containers in host_containers.items():
            if host_name in settled:
                continue
            client = self._clients[host_name]
            cnames = [c for _, c in containers]
            statuses = self._query_container_statuses(client, cnames)
            for vd_name, cname in containers:
                st = statuses.get(cname, "missing")
                if st != "running":
                    pending_detail.append(f"{vd_name}@{host_name}={st}")
        raise DeployError(
            f"Health-check timeout ({self._HEALTH_TIMEOUT}s): "
            f"containers not running: {', '.join(pending_detail)}"
        )

    def _query_container_statuses(
        self, client: SSHClient, container_names: list[str],
    ) -> dict[str, str]:
        """Return {container_name: status} via docker inspect on one host."""
        names = " ".join(container_names)
        # docker inspect outputs one status per line, matching input order.
        rc, out, _ = client.run_no_check(
            f"docker inspect --format '{{{{.State.Status}}}}' {names}",
            timeout=15,
        )
        result: dict[str, str] = {}
        if rc != 0:
            # All missing / docker not responding
            for cn in container_names:
                result[cn] = "missing"
            return result
        lines = out.strip().splitlines()
        for i, cn in enumerate(container_names):
            result[cn] = lines[i].strip() if i < len(lines) else "missing"
        return result

    def _raise_health_failure(
        self, client: SSHClient, host_name: str,
        failed: list[tuple[str, str, str]],
    ) -> None:
        """Collect docker logs for failed containers and raise DeployError."""
        details = []
        for vd_name, cname, status in failed:
            rc, logs, _ = client.run_no_check(
                f"docker logs --tail {self._DOCKER_LOG_TAIL} {cname} 2>&1",
                timeout=10,
            )
            log_snippet = logs.strip() if rc == 0 else "(logs unavailable)"
            details.append(
                f"[{host_name}] {vd_name} ({cname}): {status}\n{log_snippet}"
            )
            self._progress.emit(
                "health-check", "error", host=host_name,
                detail=f"{vd_name}: container {status}",
                data={"container": cname, "logs": log_snippet[:2000]},
            )
        raise DeployError(
            f"VD container(s) failed on {host_name}:\n"
            + "\n---\n".join(details)
        )

    # ── Phase 5: Runtime dataplane links ─────────────────────────────

    def _deploy_runtime_links(self, topo, plan):
        links = runtime_links_svc.build_runtime_links(topo, plan)
        if not links:
            log.info("Phase 5: No runtime dataplane links")
            return

        log.info("Phase 5: Reconciling %d runtime dataplane links", len(links))
        running_nodes = {
            name
            for name, runtime in self._state.node_runtime.items()
            if runtime.state == "running"
        }
        self._state.runtime_links = runtime_links_svc.reconcile_all_links(
            links, self._clients, self._underlay_ips, running_nodes,
            defer_warm_carriers=True,
        )
        self._state.vxlan_dataplane = [
            VxlanLinkState(
                id=link.vxlan_id,
                link=(
                    f"{link.endpoint_a.get('node')}:{link.endpoint_a.get('iface')} "
                    f"<-> {link.endpoint_b.get('node')}:{link.endpoint_b.get('iface')}"
                ),
                side_a={"node": link.host_a, "iface": link.host_endpoint_a},
                side_b={"node": link.host_b, "iface": link.host_endpoint_b},
                status=link.state,
            )
            for link in self._state.runtime_links
            if link.link_type == "cross_host"
        ]

        self._state.phases_completed.append("runtime_links")

    # ── Phase 5b: Runtime relay sidecars ────────────────────────────

    def _deploy_runtime_relays(self, topo, plan):
        log.info("Phase 5b: Deploying runtime relay sidecars")
        api_key = runtime_relay_svc.generate_api_key()
        results = runtime_relay_svc.deploy_runtime_relays(
            topo, plan, self._clients, self._underlay_ips, api_key,
        )
        for host_name, info in results.items():
            self._state.runtime_relays[host_name] = RuntimeRelayState(
                host=host_name,
                container=info["container"],
                bind_ip=info["bind_ip"],
                port=info["port"],
                api_key=info["api_key"],
                allowed=info["allowed"],
            )
        self._state.phases_completed.append("runtime_relay")

    # ── Phase 6: Centralized DNS container ──────────────────────────

    def _deploy_dns(self, topo, plan):
        log.info("Phase 6: Deploying centralized DNS on master")

        master = self._clients["master"]
        container, mgmt_ip, upstream, entries = dns_svc.deploy_dns(
            topo, master, self._clients,
            extra_entries=self._runtime_dns_entries(),
        )

        self._state.dns = DnsState(
            node="master",
            container=container,
            mgmt_ip=mgmt_ip,
            upstream=upstream,
            hosts_file=dns_svc.hosts_file_path(topo.name),
            entries=entries,
        )
        self._state.phases_completed.append("dns")

    def _runtime_dns_entries(self) -> list[HostEntry]:
        """DNS aliases for per-VD runtime containers and logical VD names."""
        entries: list[HostEntry] = []
        for runtime in (self._state.node_runtime or {}).values():
            if not runtime.mgmt_ipv4:
                continue
            entries.append(HostEntry(runtime.container, runtime.mgmt_ipv4, "A"))
            entries.append(HostEntry(runtime.node, runtime.mgmt_ipv4, "A"))
        return entries

    # ── Phase 7: Jump host ───────────────────────────────────────────

    def _deploy_jumphost(self, topo, plan):
        log.info("Phase 7: Deploying jump host on master")

        mgmt_ip = topo.mgmt.ipv4_gw or jumphost._compute_jumphost_mgmt_ip(topo.mgmt.ipv4_subnet)
        resolver_ip = self._state.dns.mgmt_ip if self._state.dns else None

        # Collect container names of every VD in the lab (all hosts) so the
        # jumphost login banner shows the full picture, not just what lives
        # on the master.
        vd_names = [
            vd
            for host_assign in plan.assignments.values()
            for vd in host_assign.vd_names
        ]
        vd_map = {
            vd: micro_vd_container_name(topo.name, vd)
            for vd in vd_names
        }

        # Build the authorized_keys for labuser@jumphost: always the
        # master's orchestrator pubkey (generated on-the-fly if missing)
        # plus the dnlab-gui pubkey when present, so the GUI process can
        # hop through with its own audit-distinct key.
        authorized_keys = jumphost.collect_authorized_pubkeys(self._clients["master"])

        # Register the jumphost in state BEFORE deploying so a mid-way crash
        # still gets cleaned up by rollback. host_ip/ext_network are filled
        # in after deploy_jumphost() returns the auto-assigned IP.
        self._state.jumphost = JumphostState(
            node="master",
            container=naming.jumphost_container_name(topo.name),
            mgmt_ip=mgmt_ip,
            host_ip="",
            ext_network=topo.jumphost_net.network,
            password="",
            resolver=resolver_ip or "",
        )
        self._state.phases_completed.append("jumphost")

        container, password, ext_network, jh_ip_cidr, ssh_port = jumphost.deploy_jumphost(
            topo, self._clients["master"], mgmt_ip,
            resolver_ip=resolver_ip,
            vd_names=vd_names,
            vd_map=vd_map,
            authorized_keys=authorized_keys,
            relay_map=self._relay_map_for_jumphost(),
            ssh_bind_ip=topo.jumphost_net.ssh_bind_ip,
            ssh_port_range=topo.jumphost_net.ssh_port_range,
        )

        self._state.jumphost.container = container
        self._state.jumphost.password = password
        self._state.jumphost.ext_network = ext_network
        self._state.jumphost.host_ip = jh_ip_cidr
        self._state.jumphost.ssh_port = ssh_port
        self._state.jumphost.ssh_bind_ip = topo.jumphost_net.ssh_bind_ip

        # Pre-seed the jumphost host key into master:~root/.ssh/known_hosts
        # so the first `ssh labuser@<jumphost>` is non-interactive.
        jh_addr = jh_ip_cidr.split("/")[0]
        jumphost.trust_jumphost_hostkey(
            self._clients["master"], jh_addr, naming.jumphost_container_name(topo.name),
        )

        # Add a /etc/hosts entry on the master so the container name resolves
        # to the jumphost IP from a plain shell (no DNS hop needed).
        jumphost.add_master_hosts_entry(
            self._clients["master"], topo.name,
            naming.jumphost_container_name(topo.name), jh_addr,
        )

    def _set_vd_default_routes(self, topo):
        gw = topo.mgmt.ipv4_gw
        if not gw:
            return
        for runtime in self._state.node_runtime.values():
            if runtime.state != "running":
                continue
            client = self._clients.get(runtime.host)
            if client is None:
                continue
            cmd = (
                f"docker exec {runtime.container} "
                f"sh -lc 'ip route replace default via {gw}'"
            )
            rc, _, err = client.run_no_check(cmd, timeout=15)
            if rc != 0:
                log.warning(
                    "[%s] Could not set VD %s default route via %s: %s",
                    runtime.host, runtime.node, gw, (err or "").strip(),
                )
                continue
            log.info(
                "[%s] VD %s default route set via jumphost %s",
                runtime.host, runtime.node, gw,
            )

    # ── Phase 8: Verify ──────────────────────────────────────────────

    def _verify(self, topo, plan):
        log.info("Phase 8: Verifying tunnels")

        if plan.cross_host_links:
            results = vxlan.verify_tunnels(plan.cross_host_links, self._clients)
            for r in results:
                log.info("  VxLAN %d: %s → %s", r["vxlan_id"], r["link"], r["status"])

        self._state.phases_completed.append("verify")

    # ── Rollback ─────────────────────────────────────────────────────

    def _rollback(self, topo):
        """Rollback completed phases in reverse order."""
        if not self._state:
            return

        log.warning("Rolling back phases: %s", self._state.phases_completed)

        phases = list(reversed(self._state.phases_completed))
        for phase in phases:
            try:
                if phase == "jumphost":
                    jumphost.destroy_jumphost(topo.name, self._clients["master"])
                elif phase == "dns":
                    dns_svc.destroy_dns(topo.name, self._clients["master"])
                elif phase == "runtime_relay":
                    runtime_relay_svc.destroy_runtime_relays(topo.name, self._clients)
                elif phase == "runtime_links":
                    for link in self._state.runtime_links:
                        runtime_links_svc.delete_link(link, self._clients)
                elif phase == "realnet":
                    realnet_svc.destroy_realnets(
                        topo.name, self._clients, self._state.realnets,
                    )
                elif phase == "dnlab":
                    for runtime in self._state.node_runtime.values():
                        if runtime.host in self._clients and runtime.topology_file:
                            self._clients[runtime.host].run(
                                f"containerlab destroy -t {runtime.topology_file} --cleanup --keep-mgmt-net",
                                check=False,
                            )
                elif phase == "mgmt_anchor":
                    for anchor in self._state.mgmt_anchors.values():
                        if anchor.host in self._clients and anchor.topology_file:
                            self._clients[anchor.host].run(
                                f"containerlab destroy -t {anchor.topology_file} --cleanup --keep-mgmt-net",
                                check=False,
                            )
                elif phase == "mgmt_network":
                    for client in self._clients.values():
                        mgmt_network_svc.destroy_mgmt_network(topo, client)
                elif phase == "mgmt":
                    for host_name in self._clients:
                        netsetup.teardown_mgmt_infra(
                            topo.name, topo.mgmt.bridge,
                            self._clients[host_name], host_name,
                        )
            except Exception as e:
                log.error("Rollback phase '%s' failed: %s", phase, e)
                log.error("Manual cleanup may be needed for phase '%s'", phase)

    def _relay_map_for_jumphost(self) -> dict[str, dict]:
        relay_by_container: dict[str, dict] = {}
        for relay in (self._state.runtime_relays or {}).values():
            for container in relay.allowed:
                relay_by_container[container] = {
                    "host": relay.bind_ip,
                    "port": relay.port,
                    "api_key": relay.api_key,
                }
        return relay_by_container
