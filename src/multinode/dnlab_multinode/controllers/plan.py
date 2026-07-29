"""Plan controller — pre-flight checks and scheduling."""

from __future__ import annotations

import logging
from pathlib import Path

from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.models.schedule import SchedulePlan, VDResources
from dnlab_multinode.services.config import assign_sticky_mgmt_ipv4, parse_topology
from dnlab_multinode.services.persistence import load_placement_preferences
from dnlab_multinode.services.resources import extract_resources, check_images_on_hosts
from dnlab_multinode.services.scheduler import compute_schedule, gather_host_resources
from dnlab_multinode.services import state as state_svc
from dnlab_multinode.services.ssh import SSHClient, create_clients

log = logging.getLogger(__name__)


class PlanError(Exception):
    pass


class PlanController:
    """Orchestrates pre-flight checks and scheduling."""

    def __init__(
        self,
        topology_file: str,
        no_cache: bool = False,
        *,
        hosts_file: str | None = None,
    ):
        self.topology_file = topology_file
        self.no_cache = no_cache
        self.hosts_file = hosts_file
        self.topo: DistributedTopology | None = None
        self.vd_resources: dict[str, VDResources] = {}
        self.plan: SchedulePlan | None = None

    def run(self) -> SchedulePlan:
        """Execute the full planning pipeline.

        1. Parse topology
        2. Extract VD resources
        3. Check image alignment
        4. Gather host resources
        5. Compute schedule
        """
        # Phase 0: Parse
        self.topo = parse_topology(self.topology_file, hosts_file=self.hosts_file)
        previous_state = state_svc.load_state(self.topo.name, Path(self.topology_file).parent)
        if previous_state is not None and previous_state.teardown_requested:
            raise PlanError(
                f"Lab '{self.topo.name}' has a pending teardown. Restore all hosts and "
                "wait for lab-cleanup to finish, or run destroy again before deploying it."
            )
        previous_reservations = (
            previous_state.mgmt_ip_reservations if previous_state is not None else {}
        )
        self.topo.raw["dnlab_mgmt_ip_reservations"] = assign_sticky_mgmt_ipv4(
            self.topo.nodes,
            self.topo.mgmt,
            previous_reservations,
        )

        # Phase 1: Extract VD resources
        images = {name: node.image for name, node in self.topo.nodes.items()}
        self.vd_resources = extract_resources(
            images,
            cache_dir=Path(self.topology_file).parent,
            no_cache=self.no_cache,
            nodes=self.topo.nodes,
            resource_specs=self.topo.resource_specs,
        )

        # Phase 2-5: Need SSH connections
        clients = create_clients(self.topo.all_hosts)
        try:
            for client in clients.values():
                client.connect()

            # Check image alignment
            unique_images = set(images.values())
            missing = check_images_on_hosts(unique_images, clients)
            if missing:
                lines = []
                for img, hosts in missing.items():
                    lines.append(f"  [✗] {img} not found on: {', '.join(hosts)}")
                lines.append(f"  Esegui: dnlab-multinode sync-images -t {self.topology_file}")
                raise PlanError(
                    "Images not aligned across nodes:\n" + "\n".join(lines)
                )

            # Gather host resources
            host_resources = gather_host_resources(clients)

            # Compute schedule
            placement_preferences = {}
            if self.topo.persistence.backend == "local-sticky":
                placement_preferences = load_placement_preferences(
                    self.topo, Path(self.topology_file).parent,
                )
            self.plan = compute_schedule(
                self.topo,
                self.vd_resources,
                host_resources,
                placement_preferences=placement_preferences,
            )
            return self.plan

        finally:
            for client in clients.values():
                client.close()
