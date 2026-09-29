"""Single VD runtime lifecycle controller."""

from __future__ import annotations

import time
import re
import shlex
import threading
from pathlib import Path
from typing import Callable

from dnlab_multinode.models.schedule import HostAssignment, SchedulePlan
from dnlab_multinode.models.state import (
    DeploymentState, HostScheduleState, MgmtAnchorState, NodeRuntimeState,
    RuntimeRelayState, VxlanLinkState, WebUIAllocation,
)
from dnlab_multinode.services import (
    generator, runtime_links as runtime_links_svc, scheduler,
    dns as dns_svc, persistence as persistence_svc, resources,
    jumphost as jumphost_svc,
    runtime_relay as runtime_relay_svc, warm_links as warm_links_svc,
    webui_ports as webui_ports_svc,
    mgmt_network as mgmt_network_svc,
)
from dnlab_multinode.services.hostsfile import HostEntry
from dnlab_multinode.services.config import assign_sticky_mgmt_identities, assign_sticky_mgmt_ipv4, parse_topology
from dnlab_multinode.services.ssh import create_clients
from dnlab_multinode.services.state import load_state, save_state
from dnlab_multinode.utils import naming


class NodeLifecycleError(Exception):
    pass


class NodeLifecycleCancelled(NodeLifecycleError):
    pass


class NodeLifecycleController:
    def __init__(
        self,
        topology_file: str,
        *,
        hosts_file: str | None = None,
        cancel_event: threading.Event | None = None,
        phase_callback: Callable[[str], None] | None = None,
    ):
        self.topology_file = topology_file
        self.hosts_file = hosts_file
        self.topo = parse_topology(topology_file, hosts_file=hosts_file)
        self.state_dir = Path(topology_file).parent
        self.state = load_state(self.topo.name, self.state_dir)
        self.cancel_event = cancel_event
        self.phase_callback = phase_callback
        self._active_clients = {}
        if not self.state:
            raise NodeLifecycleError(f"Lab '{self.topo.name}' is not deployed")
        # Capability inspection is persisted in node runtime state.  Rehydrate
        # the parsed topology so later stop/start/reconcile does not fall back
        # to trusting a mutable image tag.
        for name, runtime in self.state.node_runtime.items():
            if name not in self.topo.nodes:
                continue
            if runtime.hot_links_status == "validated":
                self.topo.nodes[name].env[warm_links_svc.IMAGE_STATUS_ENV] = "validated"
            elif runtime.hot_links_status in {"experimental", "experimental-enabled"}:
                self.topo.nodes[name].env[warm_links_svc.IMAGE_STATUS_ENV] = "experimental"

    def list_nodes(self) -> dict:
        return self.state.node_runtime

    def _cancelled(self) -> bool:
        event = getattr(self, "cancel_event", None)
        return bool(event and event.is_set())

    def _check_cancelled(self) -> None:
        if self._cancelled():
            raise NodeLifecycleCancelled("Node start cancelled")

    def request_cancel(self) -> None:
        """Cancel the operation and unblock any in-flight remote command."""
        event = getattr(self, "cancel_event", None)
        already_cancelled = bool(event and event.is_set())
        if event:
            event.set()
        if already_cancelled:
            return
        for client in list(getattr(self, "_active_clients", {}).values()):
            client.cancel_active_commands()

    def _set_active_clients(self, clients) -> None:
        self._active_clients = clients

    def _clear_active_clients(self, clients) -> None:
        if getattr(self, "_active_clients", None) is clients:
            self._active_clients = {}

    def _set_phase(self, runtime: NodeRuntimeState, phase: str, *, save: bool = True) -> None:
        runtime.state = phase
        callback = getattr(self, "phase_callback", None)
        if callback:
            callback(phase)
        if save:
            save_state(self.state, self.state_dir)

    def stop(self, node: str, *, force: bool = False) -> DeploymentState:
        runtime = self.state.node_runtime.get(node)
        if runtime is None:
            if force and node in self.topo.nodes:
                return self.state
            runtime = self._runtime(node)
        self._ensure_deployed()
        self._ensure_per_vd_runtime(runtime)
        if runtime.state == "stopped":
            return self.state

        clients = create_clients(self.topo.all_hosts)
        self._set_active_clients(clients)
        try:
            self._connect(clients)
            self._set_phase(
                runtime,
                "cancelling" if force and runtime.state in {
                    "queued", "starting", "reconciling", "cancelling",
                } else "stopping",
            )

            if force:
                clients[runtime.host].destroy_clab(runtime.topology_file)
                runtime_links_svc.delete_node_links(node, self.state.runtime_links, clients)
            else:
                runtime_links_svc.delete_node_links(node, self.state.runtime_links, clients)
                clients[runtime.host].destroy_clab(runtime.topology_file)

            self._set_phase(runtime, "stopped", save=False)
            runtime.last_error = ""
            for link in self.state.runtime_links:
                if node in self._link_nodes(link):
                    link.state = "partial"
            self._sync_vxlan_state()
            save_state(self.state, self.state_dir)
            return self.state
        except Exception as exc:
            runtime.state = "error"
            runtime.last_error = str(exc)
            save_state(self.state, self.state_dir)
            raise
        finally:
            self._clear_active_clients(clients)
            for client in clients.values():
                client.close()

    def start(self, node: str) -> DeploymentState:
        self._check_cancelled()
        if node not in self.state.node_runtime:
            return self.add(node)
        runtime = self._runtime(node)
        self._ensure_deployed()
        self._ensure_per_vd_runtime(runtime)
        if runtime.state == "running":
            return self.state

        clients = create_clients(self.topo.all_hosts)
        self._set_active_clients(clients)
        try:
            self._connect(clients)
            self._check_cancelled()
            self._set_phase(runtime, "starting")
            mgmt_network_svc.ensure_mgmt_network(
                self.topo, clients[runtime.host],
            )

            clients[runtime.host].deploy_clab(
                runtime.topology_file, cancel_event=getattr(self, "cancel_event", None),
            )
            self._check_cancelled()
            self._wait_container_running(
                clients[runtime.host], runtime.container, timeout=60,
            )
            self._check_cancelled()
            self._set_default_route(clients[runtime.host], runtime.container)

            self._set_phase(runtime, "reconciling")
            runtime.started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
            runtime.last_error = ""
            running = self._running_nodes()
            self._refresh_runtime_links(clients)
            self._check_cancelled()
            runtime_links_svc.reconcile_node_links(
                node, self.state.runtime_links, clients, self._underlay_ips(), running,
            )
            self._check_cancelled()
            self._sync_vxlan_state()
            self._set_phase(runtime, "running", save=False)
            save_state(self.state, self.state_dir)
            return self.state
        except NodeLifecycleCancelled:
            self._cancel_started_node(node, runtime, clients)
            return self.state
        except Exception as exc:
            if self._cancelled():
                self._cancel_started_node(node, runtime, clients)
                return self.state
            runtime.state = "error"
            runtime.last_error = str(exc)
            save_state(self.state, self.state_dir)
            raise
        finally:
            self._clear_active_clients(clients)
            for client in clients.values():
                client.close()

    def add(self, node: str) -> DeploymentState:
        """Deploy a node added to the topology while the lab is running."""
        self._check_cancelled()
        self._ensure_deployed()
        self._ensure_hot_add_supported()
        if node in self.state.node_runtime:
            return self.start(node)
        if node not in self.topo.nodes:
            raise NodeLifecycleError(f"Unknown topology VD '{node}'")

        reservations = assign_sticky_mgmt_ipv4(
            self.topo.nodes, self.topo.mgmt, self.state.mgmt_ip_reservations,
        )
        identities = assign_sticky_mgmt_identities(
            self.topo.nodes, self.topo.mgmt, lab_name=self.topo.name,
            ipv6_reservations=self.state.mgmt_ipv6_reservations,
            mac_reservations=self.state.mgmt_mac_reservations,
            duid_reservations=self.state.mgmt_duid_reservations,
            iaid_reservations=self.state.mgmt_iaid_reservations,
        )
        clients = create_clients(self.topo.all_hosts)
        self._set_active_clients(clients)
        runtime: NodeRuntimeState | None = None
        remote_path = ""
        host = ""
        previous_links = list(self.state.runtime_links)
        previous_reservations = dict(self.state.mgmt_ip_reservations)
        previous_scheduling = {
            name: HostScheduleState(
                host=item.host,
                topology_file=item.topology_file,
                vd=list(item.vd),
                resources_used=dict(item.resources_used),
            )
            for name, item in self.state.scheduling.items()
        }
        previous_webui = {
            name: list(items) for name, items in self.state.webui_allocations.items()
        }
        created_mgmt_anchor = False
        try:
            self._connect(clients)
            self._check_cancelled()
            underlay_ips = self._resolve_underlay_ips(clients)
            host, requirement = self._select_add_host(node, clients)
            self._check_cancelled()
            vd = self.topo.nodes[node]
            warm_links_svc.inspect_image_on_host(vd, clients[host])
            plan = self._plan_with_added_node(node, host, requirement)
            mgmt_network_svc.ensure_mgmt_network(self.topo, clients[host])
            created_mgmt_anchor = self._ensure_mgmt_anchor(host, plan, clients)
            self._allocate_node_webui(node, clients)
            webui_allocations = {
                name: [
                    {
                        "container_port": item.container_port,
                        "host_port": item.host_port,
                        "bind_ip": item.bind_ip,
                        "proto": item.proto,
                    }
                    for item in allocs
                ]
                for name, allocs in self.state.webui_allocations.items()
            }
            host_files = generator.generate_micro_topology_files(
                self.topo, plan, webui_allocations=webui_allocations,
            )
            remote_path = naming.micro_topology_file(self.topo.name, node, host)
            yaml_content = host_files[host][node]
            client = clients[host]
            container = naming.micro_vd_container_name(self.topo.name, node)
            runtime = NodeRuntimeState(
                node=node,
                state="starting",
                host=host,
                container=container,
                topology_file=remote_path,
                kind=vd.kind,
                image=vd.image,
                mgmt_ipv4=vd.mgmt_ipv4,
                warm_ports=warm_links_svc.capacity_for_node(self.topo, node),
                hot_links_status=warm_links_svc.status_for_node(vd),
            )
            self.state.node_runtime[node] = runtime
            self.state.mgmt_ip_reservations = reservations
            (self.state.mgmt_ipv6_reservations, self.state.mgmt_mac_reservations,
             self.state.mgmt_duid_reservations, self.state.mgmt_iaid_reservations) = identities
            self._update_scheduling(plan, underlay_ips)
            self._set_phase(runtime, "starting")
            self._check_cancelled()

            if generator._needs_persist_bind(vd.image):
                persist_dir = generator.persist_dir_for_node(
                    self.topo.name, node, vd.persist_id, self.topo.persistence.root,
                )
                client.run(f"mkdir -p '{persist_dir}'")
            for path, content in generator.render_node_feature_files(self.topo, node).items():
                client.run(f"mkdir -p '{Path(path).parent}'")
                client.upload_text(content, path)
            for path, asset in generator.render_node_override_files(self.topo, node).items():
                client.run(f"mkdir -p '{Path(path).parent}'")
                client.upload_text(asset, path)

            client.upload_text(yaml_content, remote_path)
            self._check_cancelled()
            client.deploy_clab(
                remote_path, cancel_event=getattr(self, "cancel_event", None),
            )
            self._check_cancelled()
            self._wait_container_running(client, container, timeout=60)
            self._check_cancelled()
            self._set_default_route(client, container)
            runtime.started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
            runtime.last_error = ""
            self._set_phase(runtime, "reconciling")

            old_links = {
                self._link_key(link): link for link in self.state.runtime_links
            }
            rebuilt = runtime_links_svc.build_runtime_links(self.topo, plan)
            rebuilt.extend(runtime_links_svc.pending_runtime_links(
                self.topo, set(self.state.node_runtime),
            ))
            rebuilt = runtime_links_svc.merge_runtime_links(rebuilt, self.state.runtime_links)
            for link in rebuilt:
                previous = old_links.get(self._link_key(link))
                if previous and previous.link_type == link.link_type:
                    if link.validation_error:
                        self._mark_link_validation(link, clients)
                    continue
                elif node in self._link_nodes(link):
                    self._mark_link_validation(link, clients)
            self.state.runtime_links = rebuilt
            self._check_cancelled()
            runtime_links_svc.reconcile_node_links(
                node, rebuilt, clients, underlay_ips, self._running_nodes(),
            )
            self._check_cancelled()
            self._sync_vxlan_state()
            self._reconcile_shared_services(plan, clients, underlay_ips)
            self._check_cancelled()
            self._set_phase(runtime, "running", save=False)
            save_state(self.state, self.state_dir)
            persistence_svc.save_placement_history(self.topo, plan, self.state_dir)
            return self.state
        except NodeLifecycleCancelled:
            if runtime is not None:
                self._cancel_started_node(node, runtime, clients)
                persistence_svc.save_placement_history(
                    self.topo, self._runtime_plan(), self.state_dir,
                )
            return self.state
        except Exception as exc:
            if self._cancelled() and runtime is not None:
                self._cancel_started_node(node, runtime, clients)
                persistence_svc.save_placement_history(
                    self.topo, self._runtime_plan(), self.state_dir,
                )
                return self.state
            if runtime is not None:
                runtime_links_svc.delete_node_links(
                    node, self.state.runtime_links, clients,
                )
                self.state.node_runtime.pop(node, None)
            self.state.runtime_links = previous_links
            self._sync_vxlan_state()
            self.state.mgmt_ip_reservations = previous_reservations
            self.state.scheduling = previous_scheduling
            self.state.webui_allocations = previous_webui
            if remote_path and host:
                clients[host].run_no_check(
                    f"containerlab destroy -t '{remote_path}' --cleanup --keep-mgmt-net", timeout=120,
                )
            if created_mgmt_anchor and host:
                anchor = self.state.mgmt_anchors.pop(host, None)
                if anchor:
                    clients[host].run_no_check(
                        f"containerlab destroy -t {shlex.quote(anchor.topology_file)} --cleanup --keep-mgmt-net",
                        timeout=120,
                    )
            try:
                self._reconcile_shared_services(self._runtime_plan(), clients)
            except Exception:
                # Preserve the original hot-add failure. A later explicit
                # reconcile/deploy can repair shared services if rollback was
                # itself interrupted by an unreachable host.
                pass
            save_state(self.state, self.state_dir)
            raise NodeLifecycleError(f"Failed to add node '{node}': {exc}") from exc
        finally:
            self._clear_active_clients(clients)
            for client in clients.values():
                client.close()

    def _ensure_mgmt_anchor(self, host: str, plan: SchedulePlan, clients) -> bool:
        """Create the per-host management network before the first hot-added VD."""
        if host in self.state.mgmt_anchors:
            return False
        files = generator.generate_mgmt_anchor_topology_files(self.topo, plan)
        content = files.get(host)
        if not content:
            raise NodeLifecycleError(
                f"Cannot generate management anchor for newly active host '{host}'"
            )
        remote_path = naming.mgmt_anchor_topology_file(self.topo.name, host)
        client = clients[host]
        client.upload_text(content, remote_path)
        client.deploy_clab(remote_path, reconfigure=True)
        self.state.mgmt_anchors[host] = MgmtAnchorState(
            host=host,
            container=naming.mgmt_anchor_container_name(self.topo.name, host),
            topology_file=remote_path,
            state="running",
        )
        save_state(self.state, self.state_dir)
        return True

    def restart(self, node: str) -> DeploymentState:
        """Restart one VD using the established per-VD stop/start paths."""
        self.stop(node)
        return self.start(node)

    def remove(self, node: str) -> DeploymentState:
        """Stop a VD and remove its runtime bookkeeping from a live lab."""
        runtime = self._runtime(node)
        self._ensure_deployed()
        self._ensure_per_vd_runtime(runtime)
        if runtime.state != "stopped":
            self.stop(node, force=True)

        clients = create_clients(self.topo.all_hosts)
        try:
            self._connect(clients)
            self.state.runtime_links = [
                link for link in self.state.runtime_links
                if node not in self._link_nodes(link)
            ]
            self.state.node_runtime.pop(node, None)
            self.state.webui_allocations.pop(node, None)
            schedule = self.state.scheduling.get(runtime.host)
            if schedule:
                schedule.vd = [name for name in schedule.vd if name != node]
                if not schedule.vd:
                    self.state.scheduling.pop(runtime.host, None)
            self._sync_vxlan_state()

            if not any(item.host == runtime.host for item in self.state.node_runtime.values()):
                anchor = self.state.mgmt_anchors.pop(runtime.host, None)
                if anchor:
                    clients[runtime.host].run_no_check(
                        f"containerlab destroy -t {shlex.quote(anchor.topology_file)} --cleanup --keep-mgmt-net",
                        timeout=120,
                    )

            plan = self._runtime_plan()
            self._reconcile_shared_services(plan, clients)
            save_state(self.state, self.state_dir)
            persistence_svc.save_placement_history(self.topo, plan, self.state_dir)
            return self.state
        finally:
            for client in clients.values():
                client.close()

    def reconcile(self, node: str | None = None) -> DeploymentState:
        self._ensure_deployed()
        clients = create_clients(self.topo.all_hosts)
        try:
            self._connect(clients)
            self._refresh_runtime_links(clients)
            running = self._running_nodes()
            if node:
                self._ensure_per_vd_runtime(self._runtime(node))
                runtime_links_svc.reconcile_node_links(
                    node, self.state.runtime_links, clients, self._underlay_ips(), running,
                )
            else:
                runtime_links_svc.reconcile_all_links(
                    self.state.runtime_links, clients, self._underlay_ips(), running,
                )
            self._sync_vxlan_state()
            self._reconcile_shared_services(self._runtime_plan(), clients)
            save_state(self.state, self.state_dir)
            return self.state
        finally:
            for client in clients.values():
                client.close()

    def reconcile_link(
        self,
        node_a: str,
        iface_a: str,
        node_b: str = "",
        iface_b: str = "",
        real_net: str = "",
    ):
        """Reconcile exactly one desired link and persist its live status."""
        self._ensure_deployed()
        clients = create_clients(self.topo.all_hosts)
        try:
            self._connect(clients)
            self._refresh_runtime_links(clients)
            wanted = self._endpoint_key(
                {"node": node_a, "iface": iface_a},
                {"node": node_b, "iface": iface_b} if node_b else {"real_net": real_net},
            )
            link = next(
                (item for item in self.state.runtime_links
                 if self._endpoint_key(item.endpoint_a, item.endpoint_b) == wanted),
                None,
            )
            if link is None:
                raise NodeLifecycleError("Desired link not found in topology")
            if not link.validation_error and link.link_type != "pending":
                try:
                    runtime_links_svc.create_link(
                        link, clients, self._underlay_ips(), self._running_nodes(),
                    )
                except Exception as exc:
                    link.state = "error"
                    link.last_error = str(exc)
            self._sync_vxlan_state()
            save_state(self.state, self.state_dir)
            return link
        finally:
            for client in clients.values():
                client.close()

    def _runtime(self, node: str):
        if node not in self.state.node_runtime:
            raise NodeLifecycleError(f"Unknown runtime VD '{node}'")
        return self.state.node_runtime[node]

    def _select_add_host(self, node: str, clients):
        vd = self.topo.nodes[node]
        requirement = resources.extract_resources(
            {node: vd.image},
            cache_dir=self.state_dir,
            nodes={node: vd},
            resource_specs=self.topo.resource_specs,
        )[node]
        available = scheduler.gather_host_resources(clients)
        candidates = []
        for host, capacity in available.items():
            rc, _, _ = clients[host].run_no_check(
                f"docker image inspect {shlex.quote(vd.image)} --format '{{{{.Id}}}}'",
                timeout=30,
            )
            if rc != 0:
                continue
            if capacity.cpu_available < requirement.cpu or capacity.ram_mb_available < requirement.ram_mb:
                continue
            running_count = sum(1 for item in self.state.node_runtime.values() if item.host == host)
            candidates.append((capacity.is_master, running_count, -capacity.ram_mb_available, host))
        if not candidates:
            raise NodeLifecycleError(
                f"No host has image {vd.image!r} and enough resources for '{node}'"
            )
        return min(candidates)[-1], requirement

    def _plan_with_added_node(self, node: str, host: str, requirement=None) -> SchedulePlan:
        assignments = self._runtime_plan().assignments
        assignments[host].vd_names.append(node)
        if requirement is not None:
            assignments[host].cpu_used += requirement.cpu
            assignments[host].ram_mb_used += requirement.ram_mb
        return scheduler.classify_links(
            self.topo,
            SchedulePlan(lab_name=self.topo.name, assignments=assignments),
            allow_unscheduled=True,
        )

    def _runtime_plan(self) -> SchedulePlan:
        assignments = {
            name: HostAssignment(name, infra.host, vd_names=[])
            for name, infra in self.topo.all_hosts.items()
        }
        for name, runtime in self.state.node_runtime.items():
            if runtime.host in assignments:
                assignments[runtime.host].vd_names.append(name)
        for host_name, schedule in self.state.scheduling.items():
            if host_name in assignments:
                assignments[host_name].cpu_used = schedule.resources_used.get("cpu", 0)
                assignments[host_name].ram_mb_used = schedule.resources_used.get("ram_mb", 0)
        return SchedulePlan(lab_name=self.topo.name, assignments=assignments)

    def _refresh_runtime_links(self, clients) -> None:
        """Rebuild link state from the current topology and clean removed links."""
        assignments = {
            name: HostAssignment(name, infra.host, vd_names=[])
            for name, infra in self.topo.all_hosts.items()
        }
        for name, runtime in self.state.node_runtime.items():
            if name in self.topo.nodes and runtime.host in assignments:
                assignments[runtime.host].vd_names.append(name)
        plan = scheduler.classify_links(
            self.topo,
            SchedulePlan(lab_name=self.topo.name, assignments=assignments),
            allow_unscheduled=True,
        )
        rebuilt = runtime_links_svc.build_runtime_links(self.topo, plan)
        rebuilt.extend(runtime_links_svc.pending_runtime_links(
            self.topo, set(self.state.node_runtime),
        ))
        old = {self._link_key(link): link for link in self.state.runtime_links}
        rebuilt = runtime_links_svc.merge_runtime_links(rebuilt, self.state.runtime_links)
        new_keys = {self._link_key(link) for link in rebuilt}
        for key, link in old.items():
            if key not in new_keys:
                runtime_links_svc.delete_link(link, clients)
        for link in rebuilt:
            previous = old.get(self._link_key(link))
            if link.link_type != "pending" and (
                not previous
                or previous.link_type != link.link_type
                or link.validation_error
            ):
                self._mark_link_validation(link, clients)
        self.state.runtime_links = rebuilt

    def _mark_link_validation(self, link, clients=None) -> None:
        try:
            self._validate_new_hot_link(link, clients)
        except NodeLifecycleError as exc:
            link.state = "error"
            link.last_error = str(exc)
            link.validation_error = True
        else:
            if link.validation_error:
                link.state = "down"
                link.last_error = ""
            link.validation_error = False

    def _validate_new_hot_link(self, link, clients=None) -> None:
        sides = (
            (link.endpoint_a, link.host_a, link.host_endpoint_a, link.warm_a),
            (link.endpoint_b, link.host_b, link.host_endpoint_b, link.warm_b),
        )
        for endpoint, host, host_endpoint, warm_enabled in sides:
            node = endpoint.get("node")
            if not node:
                continue
            runtime = self.state.node_runtime.get(node)
            if not runtime:
                raise NodeLifecycleError(f"link endpoint '{node}' is not running")
            # A node added with this link already owns its host-side veth in
            # the freshly deployed micro-topology. It does not need the
            # warm-link capability; only peers whose endpoint must be exposed
            # after boot do. Probe runtime truth instead of inferring this from
            # image labels alone.
            if not warm_enabled and clients and host and host_endpoint:
                client = clients.get(host)
                if client:
                    rc, _, _ = client.run_no_check(
                        f"ip link show {shlex.quote(host_endpoint)}", timeout=10,
                    )
                    if rc == 0:
                        continue
            if runtime.hot_links_status not in {
                "validated", "experimental", "experimental-enabled",
            }:
                raise NodeLifecycleError(
                    f"node '{node}' image is not enabled for hot links"
                )
            match = re.fullmatch(r"eth([1-9][0-9]*)", endpoint.get("iface", ""))
            if not match:
                raise NodeLifecycleError(
                    f"node '{node}' hot-link interface must use ethN naming"
                )
            if int(match.group(1)) > runtime.warm_ports:
                raise NodeLifecycleError(
                    f"node '{node}' only has {runtime.warm_ports} warm ports; "
                    "restart the node with a larger DNLAB_WARM_PORTS value"
                )

    @staticmethod
    def _link_key(link):
        return runtime_links_svc.canonical_key(link)

    @staticmethod
    def _endpoint_key(endpoint_a, endpoint_b):
        return tuple(sorted(
            tuple(sorted(endpoint.items()))
            for endpoint in (endpoint_a, endpoint_b)
        ))

    def _ensure_deployed(self) -> None:
        if not self.state.dnlab_deployed:
            raise NodeLifecycleError(f"Lab '{self.topo.name}' infrastructure is not deployed")

    def _ensure_hot_add_supported(self) -> None:
        if self.state.runtime_mode != "per-vd":
            raise NodeLifecycleError(
                "Live node addition requires a per-VD runtime deployment; "
                "stop and redeploy this legacy lab first"
            )

    def _allocate_node_webui(self, node: str, clients) -> None:
        wishlist = (self.topo.webui_wishlist or {}).get(node) or []
        if not wishlist:
            return
        existing = {
            item.host_port
            for allocs in self.state.webui_allocations.values()
            for item in allocs
        }
        previous = {
            item.container_port: item.host_port
            for item in self.state.webui_allocations.get(node, [])
        }
        allocated: list[WebUIAllocation] = []
        for spec in wishlist:
            container_port = int(spec.get("container_port") or 0)
            if container_port <= 0:
                continue
            host_port = webui_ports_svc.allocate_webui_port(
                clients["master"],
                self.topo.webui_ports.bind_ip,
                self.topo.webui_ports.port_range,
                used_extra=existing,
                preferred=previous.get(container_port),
            )
            existing.add(host_port)
            allocated.append(WebUIAllocation(
                container_port=container_port,
                host_port=host_port,
                bind_ip=self.topo.webui_ports.bind_ip,
                proto="tcp",
            ))
        if allocated:
            self.state.webui_allocations[node] = allocated

    def _update_scheduling(
        self, plan: SchedulePlan, underlay: dict[str, str] | None = None,
    ) -> None:
        underlay = underlay or self._underlay_ips()
        for host_name, assignment in plan.assignments.items():
            if not assignment.vd_names:
                self.state.scheduling.pop(host_name, None)
                continue
            self.state.scheduling[host_name] = HostScheduleState(
                host=underlay.get(host_name, assignment.host_ip),
                topology_file="",
                vd=list(assignment.vd_names),
                resources_used={
                    "cpu": assignment.cpu_used,
                    "ram_mb": assignment.ram_mb_used,
                },
            )

    def _sync_vxlan_state(self) -> None:
        self.state.vxlan_dataplane = [
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
            for link in self.state.runtime_links
            if link.link_type == "cross_host"
        ]

    def _reconcile_shared_services(
        self, plan: SchedulePlan, clients,
        underlay_ips: dict[str, str] | None = None,
    ) -> None:
        """Refresh services whose allowlists/records depend on active VDs."""
        underlay_ips = underlay_ips or self._underlay_ips()
        if self.state.runtime_relays:
            api_key = next(iter(self.state.runtime_relays.values())).api_key
        else:
            api_key = runtime_relay_svc.generate_api_key()
        relays = runtime_relay_svc.reconcile_runtime_relays(
            self.topo, plan, clients, underlay_ips, api_key,
            self.state.runtime_relays,
        )
        self.state.runtime_relays = {
            host: RuntimeRelayState(
                host=host,
                container=info["container"],
                bind_ip=info["bind_ip"],
                port=info["port"],
                api_key=info["api_key"],
                allowed=info["allowed"],
            )
            for host, info in relays.items()
        }
        if self.state.dns:
            entries: list[HostEntry] = []
            for runtime in self.state.node_runtime.values():
                if not runtime.mgmt_ipv4:
                    continue
                entries.append(HostEntry(runtime.container, runtime.mgmt_ipv4, "A"))
                entries.append(HostEntry(runtime.node, runtime.mgmt_ipv4, "A"))
            count, _ = dns_svc.refresh_dns(
                self.topo.name, clients["master"], clients, extra_entries=entries,
            )
            self.state.dns.entries = count

        if self.state.jumphost:
            vd_map = {
                runtime.node: runtime.container
                for runtime in self.state.node_runtime.values()
            }
            relay_map: dict[str, dict] = {}
            for relay in self.state.runtime_relays.values():
                for container in relay.allowed:
                    relay_map[container] = {
                        "host": relay.bind_ip,
                        "port": relay.port,
                        "api_key": relay.api_key,
                    }
            jumphost_svc.refresh_jumphost_inventory(
                self.topo.name, clients["master"], vd_map, relay_map,
            )
            jumphost_svc.refresh_dhcp_config(
                self.topo, clients["master"], self.state.jumphost.container,
                self.state.jumphost.resolver or None,
            )

    def _ensure_per_vd_runtime(self, runtime) -> None:
        expected_prefix = f"clab-dnlab-{self.topo.name}-"
        if not runtime.container.startswith(expected_prefix):
            raise NodeLifecycleError(
                "Single-VD start/stop requires a per-VD runtime deployment. "
                f"Node '{runtime.node}' is part of a legacy per-host Containerlab topology."
            )

    @staticmethod
    def _connect(clients) -> None:
        for client in clients.values():
            client.connect()

    def _wait_container_running(self, client, container: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._check_cancelled()
            rc, out, _ = client.run_no_check(
                f"docker inspect --format '{{{{.State.Status}}}}' {container}",
                timeout=15,
            )
            if rc == 0 and out.strip() == "running":
                return
            if rc == 0 and out.strip() in {"exited", "dead"}:
                raise NodeLifecycleError(f"Container {container} is {out.strip()}")
            cancel_event = getattr(self, "cancel_event", None)
            if cancel_event:
                if cancel_event.wait(timeout=1):
                    self._check_cancelled()
            else:
                time.sleep(1)
        raise NodeLifecycleError(f"Timeout waiting for {container} to run")

    def _cancel_started_node(self, node: str, runtime, clients) -> None:
        """Best-effort cleanup for an explicitly cancelled start."""
        self._set_phase(runtime, "cancelling")
        client = clients.get(runtime.host)
        if client and runtime.topology_file:
            try:
                client.destroy_clab(runtime.topology_file)
            except Exception:
                pass
        try:
            runtime_links_svc.delete_node_links(
                node, self.state.runtime_links, clients,
            )
        except Exception:
            pass
        runtime.last_error = ""
        self._set_phase(runtime, "stopped", save=False)
        try:
            self._refresh_runtime_links(clients)
        except Exception:
            pass
        for link in self.state.runtime_links:
            if node in self._link_nodes(link):
                link.state = "partial"
                link.last_error = ""
        self._sync_vxlan_state()
        try:
            self._reconcile_shared_services(self._runtime_plan(), clients)
        except Exception:
            pass
        save_state(self.state, self.state_dir)

    def _running_nodes(self) -> set[str]:
        return {
            node
            for node, runtime in self.state.node_runtime.items()
            if runtime.state in {"running", "reconciling"}
        }

    def _set_default_route(self, client, container: str) -> None:
        gw = self.topo.mgmt.ipv4_gw
        if not gw:
            return
        client.run_no_check(
            f"docker exec {container} sh -lc 'ip route replace default via {gw}'",
            timeout=15,
        )

    def _underlay_ips(self) -> dict[str, str]:
        values = {
            host: infra.host
            for host, infra in self.topo.all_hosts.items()
        }
        values.update({
            host: schedule.host
            for host, schedule in self.state.scheduling.items()
        })
        return values

    def _resolve_underlay_ips(self, clients) -> dict[str, str]:
        """Resolve literal underlay addresses for hosts activated after deploy."""
        iface = self.topo.underlay_iface
        command = (
            f"ip -4 -o addr show dev {shlex.quote(iface)} "
            "| awk '{print $4}' | cut -d/ -f1 | head -n1"
        )
        values: dict[str, str] = {}
        for host, client in clients.items():
            rc, out, err = client.run_no_check(command, timeout=30)
            ip = (out or "").strip()
            if rc != 0 or not ip:
                raise NodeLifecycleError(
                    f"[{host}] cannot resolve IPv4 for underlay interface "
                    f"'{iface}': rc={rc} err={err!r}"
                )
            values[host] = ip
        return values

    @staticmethod
    def _link_nodes(link) -> set[str]:
        return {
            endpoint.get("node")
            for endpoint in [link.endpoint_a, link.endpoint_b]
            if endpoint.get("node")
        }
