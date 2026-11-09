"""Lab lifecycle controller (deploy / destroy / inspect).

Deploy/destroy are routed through the multinode orchestrator
(:class:`~app.services.multinode_service.MultinodeService`): the GUI
topology may contain ``jumphost:`` / ``mgmt:`` blocks the bare
``containerlab`` CLI rejects. Inspect-all still runs locally — the
master's view is enough to list "running" labs on the home page.

All lab-scoped methods take a :class:`~app.services.lab_resolver.ResolvedLab`
rather than a raw string: the route handler has already verified the
caller's read/write permission and produced the UUID→netname mapping,
so this layer never re-derives names or re-checks authz.

The status report coming back from multinode speaks netname (that's
the ``name:`` field in the YAML on disk). Before returning to the API
we swap it with ``lab.display_name`` so the user always sees the name
they picked.
"""

import logging

from app.models.lab import ContainerInfo, Lab
from app.services.containerlab_service import ContainerLabService
from app.services.lab_resolver import ResolvedLab
from app.services.multinode_service import MultinodeServiceError, multinode
from app.services.webui_service import webui_service

log = logging.getLogger(__name__)


class LabController:
    def __init__(self) -> None:
        self._clab = ContainerLabService()

    async def list_running_labs(self) -> list[Lab]:
        """All labs currently reported as running by ``clab inspect``.

        Home-page widget. Returns raw netnames in ``Lab.name``; the
        route annotates them with display names before shipping to the
        frontend (one DB round-trip, done once for list call).
        """
        labs = await self._clab.inspect_all()
        log.debug("list_running_labs: found %d labs", len(labs))
        return labs

    async def get_lab_status(self, lab: ResolvedLab) -> Lab | None:
        """Return the lab snapshot using the multinode status probe.

        ``containerlab inspect`` on the master only sees master-local
        containers; the orchestrator's ``StatusController`` probes
        every host, which is what the GUI needs to enable / disable
        console / log / stop actions for node. We overwrite the
        report's internal netname with the user-facing display name
        before handing it to the route.
        """
        try:
            report = await multinode.status(lab, emit_events=False)
        except MultinodeServiceError as exc:
            log.debug("status(%s): %s", lab.netname, exc)
            return None

        nodes = report.get("nodes") or {}
        containers: list[ContainerInfo] = []
        for node_name, n in nodes.items():
            state = n.get("state") or ""
            if state == "missing":
                continue
            containers.append(ContainerInfo(
                name=n.get("container") or f"clab-{lab.netname}-{node_name}",
                container_id="",
                image=n.get("image", ""),
                kind=n.get("kind", ""),
                state=state,
                ipv4_address=n.get("mgmt_ipv4", ""),
                ipv6_address=(
                    n.get("mgmt_ipv6")
                    or n.get("ipv6_address")
                    or n.get("ipv6")
                    or ""
                ),
                lab_name=lab.display_name,
                node_name=node_name,
            ))

        if not containers:
            status = "stopped"
        elif all(c.state == "running" for c in containers):
            status = "running"
        else:
            status = "partial"

        log.debug("get_lab_status(%s): %s (%d containers)",
                  lab.netname, status, len(containers))
        return Lab(name=lab.display_name, status=status, containers=containers)

    async def deploy(self, lab: ResolvedLab) -> dict:
        log.info("API deploy: %s (%s)", lab.display_name, lab.netname)
        try:
            closed = webui_service.close_lab(str(lab.id))
            if closed:
                log.info("API deploy: closed %d stale WebUI tunnel(s) for %s", closed, lab.netname)
            state = await multinode.deploy(lab)
            return {"success": True, "output": "", "state": state}
        except MultinodeServiceError as exc:
            log.error("Deploy failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Deploy crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def destroy(self, lab: ResolvedLab) -> dict:
        log.info("API destroy: %s (%s)", lab.display_name, lab.netname)
        try:
            closed = webui_service.close_lab(str(lab.id))
            if closed:
                log.info("API destroy: closed %d WebUI tunnel(s) for %s", closed, lab.netname)
            result = await multinode.destroy(lab)
            return {"success": True, "output": "", "result": result}
        except MultinodeServiceError as exc:
            log.error("Destroy failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Destroy crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def node_start(self, lab: ResolvedLab, node_name: str) -> dict:
        log.info("API node_start: %s/%s (%s)", lab.display_name, node_name, lab.netname)
        try:
            state = await multinode.node_start(lab, node_name)
            cancelled = state.get("_operation_outcome") == "cancelled"
            return {
                "success": True, "cancelled": cancelled,
                "output": "", "state": state,
            }
        except MultinodeServiceError as exc:
            log.error("Node start failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Node start crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def node_stop(self, lab: ResolvedLab, node_name: str, *, force: bool = False) -> dict:
        log.info("API node_stop: %s/%s (%s)", lab.display_name, node_name, lab.netname)
        try:
            state = await multinode.node_stop(lab, node_name, force=force)
            return {
                "success": True, "cancelled": bool(state.get("cancelled")),
                "output": "", "state": state,
            }
        except MultinodeServiceError as exc:
            log.error("Node stop failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Node stop crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def node_restart(self, lab: ResolvedLab, node_name: str) -> dict:
        log.info("API node_restart: %s/%s (%s)", lab.display_name, node_name, lab.netname)
        try:
            state = await multinode.node_restart(lab, node_name)
            return {"success": True, "output": "", "state": state}
        except MultinodeServiceError as exc:
            log.error("Node restart failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Node restart crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def node_reconcile(self, lab: ResolvedLab, node_name: str) -> dict:
        log.info("API node_reconcile: %s/%s (%s)", lab.display_name, node_name, lab.netname)
        try:
            state = await multinode.node_reconcile(lab, node_name)
            return {"success": True, "output": "", "state": state}
        except MultinodeServiceError as exc:
            log.error("Node reconcile failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Node reconcile crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def link_reconcile(self, lab: ResolvedLab, link: dict) -> dict:
        log.info("API link_reconcile: %s (%s): %s", lab.display_name, lab.netname, link)
        try:
            state = await multinode.link_reconcile(lab, link)
            return {"success": True, "output": "", "link": state}
        except MultinodeServiceError as exc:
            log.error("Link reconcile failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Link reconcile crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def realnet_reconcile(self, lab: ResolvedLab, realnet_name: str) -> dict:
        log.info("API realnet_reconcile: %s/%s (%s)", lab.display_name, realnet_name, lab.netname)
        try:
            state = await multinode.realnet_reconcile(lab, realnet_name)
            return {"success": True, "output": "", "state": state}
        except MultinodeServiceError as exc:
            log.error("RealNet reconcile failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("RealNet reconcile crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def wipe_node_disk(self, lab: ResolvedLab, node_name: str) -> dict:
        """Wipe one node persistent overlay, if the node is not running."""
        log.info(
            "API wipe_node_disk: %s/%s (%s)",
            lab.display_name, node_name, lab.netname,
        )
        try:
            topo = self._clab.load_topology_from_file(lab.yaml_path)
            node = topo.get_node(node_name)
            if node is None:
                return {"success": False, "output": f"Node '{node_name}' not found"}

            status_lab = await self.get_lab_status(lab)
            for container in (status_lab.containers if status_lab else []):
                if container.node_name == node_name and container.state == "running":
                    return {
                        "success": False,
                        "code": "node_running",
                        "output": f"Node '{node_name}' is running. Stop the lab before wiping disk.",
                    }

            wiped = await multinode.wipe_node_persist_dir(lab, node_name)
            results = wiped.get("results") or {}
            warnings = []
            errors = []
            if not any(st == "ok" for st in results.values()) and any(
                st == "missing" for st in results.values()
            ):
                warnings.append(f"Image {node.image} is not persistent")
            for host, st in results.items():
                if isinstance(st, str) and st.startswith("error:"):
                    errors.append(f"{host}: {st}")

            return {
                "success": not errors,
                "output": "; ".join(errors),
                "node": node_name,
                "image": node.image,
                "path": wiped.get("path", ""),
                "results": results,
                "warnings": warnings,
            }
        except MultinodeServiceError as exc:
            log.error("Wipe disk failed: %s", exc)
            return {"success": False, "output": str(exc)}
        except Exception as exc:
            log.exception("Wipe disk crashed")
            return {"success": False, "output": f"{type(exc).__name__}: {exc}"}

    async def delete_lab(self, lab: ResolvedLab) -> dict:
        """Full delete: destroy if running → clean persist → drop YAML.

        Three scenarios:
        1. Lab deployed → destroy, clean persist, delete YAML file.
        2. Lab not deployed but has persist dirs → clean persist, delete YAML.
        3. Lab never deployed → delete YAML only.

        The DB row deletion is the route's responsibility — this
        controller only owns the on-disk artifacts and the running
        containers.
        """
        log.info("API delete_lab: %s (%s)", lab.display_name, lab.netname)
        errors: list[str] = []

        try:
            status_lab = await self.get_lab_status(lab)
        except Exception:
            status_lab = None
        if status_lab and status_lab.status in ("running", "partial"):
            log.info("delete_lab: lab is %s — destroying first", status_lab.status)
            result = await self.destroy(lab)
            if not result.get("success"):
                return {
                    "success": False,
                    "output": f"Destroy failed: {result.get('output', '')}",
                }

        try:
            persist_results = await multinode.clean_persist_dirs(lab)
            for host, st in persist_results.items():
                if st != "ok":
                    errors.append(f"persist cleanup {host}: {st}")
        except MultinodeServiceError as exc:
            errors.append(f"persist cleanup: {exc}")
            log.warning("delete_lab: persist cleanup failed: %s", exc)

        try:
            lab.yaml_path.unlink(missing_ok=True)
        except Exception as exc:
            return {
                "success": False,
                "output": f"Deletion topology failed: {exc}",
            }

        if errors:
            log.warning("delete_lab(%s): completed with warnings: %s",
                        lab.netname, errors)

        return {"success": True, "output": "", "warnings": errors}
