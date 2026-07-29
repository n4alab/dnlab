"""Destroy controller — teardown in reverse order."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import (
    jumphost, dns as dns_svc, netsetup, state as state_svc, vxlan,
    realnet as realnet_svc, runtime_links as runtime_links_svc,
    runtime_relay as runtime_relay_svc, mgmt_network as mgmt_network_svc,
)
from dnlab_multinode.services.progress import ProgressCallback, make_timer
from dnlab_multinode.services.ssh import SSHClient

log = logging.getLogger(__name__)


class DestroyError(Exception):
    pass


class DestroyController:
    """Orchestrates the full teardown sequence from saved state."""

    def __init__(
        self,
        topology_file: str,
        *,
        hosts_file: str | None = None,
        progress: ProgressCallback | None = None,
    ):
        self.topology_file = topology_file
        self.hosts_file = hosts_file
        self._state: DeploymentState | None = None
        self._clients: dict[str, SSHClient] = {}
        self._errors: list[str] = []
        self._progress = make_timer(progress)

    def _phase(self, phase: str, detail: str, fn, *args, **kwargs):
        self._progress.emit(phase, "start", detail=detail)
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            self._progress.emit(phase, "error", detail=str(exc))
            raise
        self._progress.emit(phase, "ok", detail=f"{detail} — done")
        return result

    def run(self) -> None:
        """Execute the full teardown pipeline."""
        self._progress.emit("destroy", "start", detail="Destroying lab")
        state_dir = Path(self.topology_file).parent

        from dnlab_multinode.services.config import parse_topology
        topo = parse_topology(self.topology_file, hosts_file=self.hosts_file)

        self._state = state_svc.load_state(topo.name, state_dir)
        if not self._state:
            log.warning("No deployment state found for '%s' — nothing to destroy", topo.name)
            self._progress.emit(
                "destroy", "ok",
                detail=f"No state for '{topo.name}' — nothing to destroy",
            )
            return

        # Persist the caller's intent before making any remote change. If a
        # host is down, lab-cleanup can safely finish this exact teardown once
        # the host returns instead of losing ownership information.
        self._phase(
            "destroy-intent", "Persisting teardown intent",
            self._mark_teardown_requested, state_dir,
        )

        from dnlab_multinode.services.ssh import create_clients
        self._clients = create_clients(topo.all_hosts)
        try:
            for client in self._clients.values():
                try:
                    client.connect()
                except Exception as e:
                    log.error("Cannot connect to %s: %s", client.name, e)
                    self._errors.append(f"SSH connect failed: {client.name}: {e}")
                    self._progress.emit(
                        "ssh-connect", "error",
                        host=client.name, detail=str(e),
                    )

            self._phase("destroy-jumphost", "Removing jump host", self._destroy_jumphost)
            self._phase("destroy-dns", "Removing DNS container", self._destroy_dns)
            self._phase("destroy-runtime-relay", "Removing runtime relays", self._destroy_runtime_relays)
            self._phase("destroy-legacy-logging", "Removing legacy logging containers", self._destroy_legacy_logging)
            self._phase("destroy-runtime-links", "Removing runtime dataplane links", self._destroy_runtime_links)
            self._phase("destroy-dnlab", "Destroying containerlab", self._destroy_clab)
            self._phase("destroy-mgmt-anchor", "Destroying management anchors", self._destroy_mgmt_anchors)
            self._phase("destroy-realnet", "Removing real_net infrastructure", self._destroy_realnets)
            self._phase("destroy-vxlan", "Removing dataplane VxLAN", self._destroy_vxlan_dataplane)
            # Docker owns the bridge while the management network exists, so
            # remove the managed network before deleting the bridge/VRF.
            self._phase("destroy-mgmt-network", "Removing mgmt Docker network", self._destroy_mgmt_network, topo)
            self._phase("destroy-mgmt", "Removing mgmt infrastructure", self._destroy_mgmt, topo)
            self._phase("cleanup-hosts", "Cleaning master /etc/hosts", self._destroy_master_hosts_entry, topo)

            if self._errors:
                self._finalize_state(topo.name, state_dir)
                log.warning("Destroy completed with %d errors:", len(self._errors))
                for err in self._errors:
                    log.warning("  %s", err)
                self._progress.emit(
                    "destroy", "ok",
                    detail=(
                        f"Destroyed with {len(self._errors)} non-fatal errors; "
                        "lab-cleanup will reconcile the pending teardown"
                    ),
                    data={"errors": list(self._errors)},
                )
            else:
                self._finalize_state(topo.name, state_dir)
                log.info("Lab '%s' destroyed cleanly", topo.name)
                self._progress.emit("destroy", "ok", detail=f"Lab '{topo.name}' destroyed cleanly")

        except Exception as exc:
            self._progress.emit("destroy", "error", detail=str(exc))
            raise
        finally:
            for client in self._clients.values():
                client.close()

    def _mark_teardown_requested(self, state_dir: Path) -> None:
        assert self._state is not None
        self._state.teardown_requested = True
        state_svc.save_state(self._state, state_dir)

    def _finalize_state(self, lab_name: str, state_dir: Path) -> None:
        assert self._state is not None
        if self._errors:
            state_svc.save_state(self._state, state_dir)
            return
        state_svc.delete_state(lab_name, state_dir)

    # ── Phase 1: Jump host ───────────────────────────────────────────

    def _destroy_jumphost(self):
        if not self._state.jumphost:
            return

        log.info("Teardown: removing jump host")
        jh = self._state.jumphost
        host = jh.node
        if host not in self._clients:
            self._errors.append(f"Cannot remove jumphost: host '{host}' not connected")
            return

        try:
            jumphost.destroy_jumphost(self._state.lab_name, self._clients[host])
        except Exception as e:
            self._errors.append(f"Jumphost removal: {e}")
            log.error("Jumphost removal failed: %s", e)

    # ── Phase 1b: DNS container ─────────────────────────────────────

    def _destroy_dns(self):
        if not self._state.dns:
            return

        log.info("Teardown: removing centralized DNS container")
        host = self._state.dns.node
        if host not in self._clients:
            self._errors.append(f"Cannot remove DNS: host '{host}' not connected")
            return

        try:
            dns_svc.destroy_dns(self._state.lab_name, self._clients[host])
        except Exception as e:
            self._errors.append(f"DNS removal: {e}")
            log.error("DNS removal failed: %s", e)

    def _destroy_runtime_relays(self):
        if not self._state.runtime_relays:
            return
        log.info("Teardown: removing runtime relay sidecars")
        try:
            runtime_relay_svc.destroy_runtime_relays(
                self._state.lab_name, self._clients,
            )
        except Exception as e:
            self._errors.append(f"Runtime relay removal: {e}")
            log.error("Runtime relay removal failed: %s", e)

    def _destroy_legacy_logging(self):
        """Best-effort cleanup for labs deployed before runtime relay logging."""
        lab_name = self._state.lab_name
        log.info("Teardown: removing legacy syslog/log-shipper artifacts")
        for host_name, client in self._clients.items():
            try:
                client.run(f"docker rm -f dnlab-{lab_name}-log-shipper 2>/dev/null", check=False)
            except Exception as e:
                log.debug("[%s] legacy log-shipper cleanup ignored: %s", host_name, e)
        master = self._clients.get("master")
        if master is None:
            return
        try:
            master.run(f"docker rm -f dnlab-{lab_name}-syslog 2>/dev/null", check=False)
        except Exception as e:
            log.debug("legacy syslog cleanup ignored: %s", e)
        try:
            master.run(f"docker volume rm dnlab-{lab_name}-logs 2>/dev/null", check=False)
        except Exception as e:
            log.debug("legacy syslog volume cleanup ignored: %s", e)

    # ── Phase 2: containerlab destroy ────────────────────────────────

    def _destroy_clab(self):
        if not self._state.scheduling and not self._state.node_runtime:
            return

        log.info("Teardown: destroying containerlab on all hosts")

        def _destroy_topology(host_name, topology_file):
            if host_name not in self._clients:
                return f"Host '{host_name}' not connected"
            try:
                self._clients[host_name].destroy_clab(topology_file)
                log.info("[%s] containerlab destroy OK: %s", host_name, topology_file)
                return None
            except Exception as e:
                return f"[{host_name}] clab destroy: {e}"

        targets = []
        if self._state.node_runtime:
            targets = [
                (runtime.host, runtime.topology_file)
                for runtime in self._state.node_runtime.values()
                if runtime.host and runtime.topology_file
            ]
        else:
            targets = [
                (host_name, hs.topology_file)
                for host_name, hs in self._state.scheduling.items()
                if hs.topology_file
            ]

        with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
            futures = {
                pool.submit(_destroy_topology, h, path): (h, path)
                for h, path in targets
            }
            for f in as_completed(futures):
                err = f.result()
                if err:
                    self._errors.append(err)

    def _destroy_mgmt_anchors(self):
        if not self._state.mgmt_anchors:
            return

        log.info("Teardown: destroying management anchors")

        def _destroy_anchor(host_name, topology_file):
            if host_name not in self._clients:
                return f"Host '{host_name}' not connected"
            try:
                self._clients[host_name].destroy_clab(topology_file)
                log.info("[%s] mgmt anchor destroy OK: %s", host_name, topology_file)
                return None
            except Exception as e:
                return f"[{host_name}] mgmt anchor destroy: {e}"

        targets = [
            (anchor.host, anchor.topology_file)
            for anchor in self._state.mgmt_anchors.values()
            if anchor.host and anchor.topology_file
        ]
        with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
            futures = {
                pool.submit(_destroy_anchor, h, path): (h, path)
                for h, path in targets
            }
            for f in as_completed(futures):
                err = f.result()
                if err:
                    self._errors.append(err)

    # ── Phase 3: Runtime links / VxLAN dataplane ─────────────────────

    def _destroy_runtime_links(self):
        if not self._state.runtime_links:
            return
        log.info("Teardown: removing runtime dataplane links")
        for link in self._state.runtime_links:
            try:
                runtime_links_svc.delete_link(link, self._clients)
            except Exception as e:
                self._errors.append(f"runtime link delete {link.id}: {e}")

    def _destroy_realnets(self):
        if not self._state.realnets:
            return
        try:
            realnet_svc.destroy_realnets(
                self._state.lab_name, self._clients, self._state.realnets,
            )
        except Exception as e:
            self._errors.append(f"real_net removal: {e}")
            log.error("real_net removal failed: %s", e)

    def _destroy_vxlan_dataplane(self):
        if not self._state.vxlan_dataplane:
            return

        log.info("Teardown: removing dataplane VxLAN tunnels")
        for vl in self._state.vxlan_dataplane:
            for side_key in ["side_a", "side_b"]:
                side = vl.__dict__.get(side_key, {})
                if not isinstance(side, dict):
                    continue
                node = side.get("node", "")
                iface = side.get("iface", "")
                if not (node and iface and node in self._clients):
                    continue
                try:
                    vxlan._delete_vxlan_iface(self._clients[node], iface, node)
                except Exception as e:
                    self._errors.append(f"VxLAN iface delete vx-{iface}@{node}: {e}")

    # ── Phase 4: Mgmt infrastructure ────────────────────────────────

    def _destroy_mgmt(self, topo):
        if not self._state.mgmt:
            return

        log.info("Teardown: removing mgmt infrastructure")
        bridge = self._state.mgmt.bridge

        for host_name in self._clients:
            try:
                netsetup.teardown_mgmt_infra(
                    self._state.lab_name, bridge,
                    self._clients[host_name], host_name,
                )
            except Exception as e:
                self._errors.append(f"Mgmt teardown {host_name}: {e}")

    # ── Phase 5: Docker network ──────────────────────────────────────

    def _destroy_mgmt_network(self, topo):
        for client in self._clients.values():
            try:
                mgmt_network_svc.destroy_mgmt_network(topo, client)
            except Exception as exc:
                self._errors.append(f"Docker mgmt network cleanup {client.name}: {exc}")

    # ── Phase 6: Master /etc/hosts cleanup ──────────────────────────

    def _destroy_master_hosts_entry(self, topo):
        master = self._clients.get("master")
        if not master:
            return
        try:
            jumphost.remove_master_hosts_entry(master, self._state.lab_name)
        except Exception as e:
            self._errors.append(f"Master /etc/hosts cleanup: {e}")
            log.error("Master /etc/hosts cleanup failed: %s", e)
