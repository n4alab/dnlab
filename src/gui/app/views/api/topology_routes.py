"""Topology CRUD + graph-edit API, keyed by lab UUID.

Prefix changed from ``/api/topologies`` (name-keyed) to
``/api/labs/<uuid>/topology`` so topology editing and lab lifecycle
share one URL space — the UI only ever knows about lab UUIDs.
Createtion and listing live on the parent ``/api/labs`` namespace.

Authz uses :func:`app.services.lab_resolver.resolve_for_write` for
every mutation (add/delete/update node, add/remove link, import). The
GET endpoints use :func:`resolve_for_read`.
"""

from __future__ import annotations

import logging
import uuid as uuidlib
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import audit
from app.auth.db import get_session
from app.auth.deps import get_current_user
from app.auth.labs import can_create_lab, create_lab, derive_network_name, list_all_labs
from app.auth.models import Role, User
from app.controllers.topology_controller import TopologyController, TopologyValidationError
from app.models.node import Node
from app.models.link import Link
from app.models.topology import Topology
from app.services.lab_resolver import resolve_for_read, resolve_for_write
from app.services import realnet_bgp
from app.services.multinode_service import MultinodeServiceError, multinode

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/labs", tags=["topologies"])
_ctrl = TopologyController()


def _can_view_realnet_password(lab, user: User) -> bool:
    return user.role == Role.admin or bool(lab.owner and lab.owner.id == user.id)


def _dump_topology_for_user(topo: Topology, lab, user: User) -> dict:
    dumped = topo.model_dump()
    dumped["name"] = lab.display_name
    return realnet_bgp.scrub_realnet_passwords(
        dumped,
        can_view_password=_can_view_realnet_password(lab, user),
    )


class NewTopologyRequest(BaseModel):
    name: str


class WebUIPortSpec(BaseModel):
    container_port: int
    scheme: str = "https"
    path: str = "/"
    label: str = ""
    source: str = "user"   # "user" | "catalog"


class NodeUpdateRequest(BaseModel):
    kind: str | None = None
    image: str | None = None
    position: dict | None = None
    extra: dict | None = None
    new_name: str | None = None
    # List of Web UIs for the node. If ``None``, it is left untouched;
    # if provided (even empty), it is written to
    # ``topology.gui_webui_state[<node>]``.
    webui_ports: list[WebUIPortSpec] | None = None
    # GUI state for per-kind special overrides. The controller saves it
    # in the sidecar and translates it into native clab config.
    node_overrides: dict | None = None
    # Data-driven GUI state for features declared in the device catalog.
    node_features: dict | None = None
    # Free-form YAML for Containerlab node-level fields managed per node.
    # Parsed on the backend side and merged into node.extra.
    advanced_extra_yaml: str | None = None


class MgmtConfigRequest(BaseModel):
    ipv4_subnet: str = ""
    ipv4_gw: str = ""
    ipv6_subnet: str = ""
    ipv6_gw: str = ""
    dhcp: bool = False
    # Position of the "mgmt cloud" on the canvas. Stored in topology extra,
    # but has no effect on deployment: it is only used by the GUI to remember
    # where the user placed the dummy mgmt network node.
    canvas_pos: dict | None = None


class NodeMgmtIpRequest(BaseModel):
    mgmt_ipv4: str = ""


class NodeMgmtIpv6Request(BaseModel):
    mgmt_ipv6: str = ""


class LinkStyleRequest(BaseModel):
    source: str
    source_iface: str = ""
    target: str
    target_iface: str = ""
    style: dict = Field(default_factory=dict)


class CanvasAnnotationsRequest(BaseModel):
    annotations: list[dict] = Field(default_factory=list)


# ── Createte ────────────────────────────────────────────────────────

@router.post("/")
async def create_lab_route(
    req: NewTopologyRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Createte an empty lab owned by the caller.

    Rookies are rejected. The (owner_id, name) unique constraint
    prevents one user from having two labs with the same display name;
    collisions across users are fine — each gets a different UUID and
    therefore a different netname.
    """
    if not can_create_lab(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "lab creation not allowed")

    display = req.name.strip()
    if not display:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "name cannot be empty")

    owner = None if user.id is None else user
    try:
        lab_row = await create_lab(db, name=display, owner=owner)
    except Exception as exc:
        log.warning("create_lab(%s) failed: %s", display, exc)
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cannot create lab '{display}': {exc}",
        )

    # Persist an empty topology under <uuid>.yml with name=<netname>.
    netname = derive_network_name(lab_row.id)
    topo = Topology(name=netname)
    path = _ctrl.save_by_uuid(lab_row.id, topo)

    await audit.record(
        db, event="lab.create", user=user, request=request,
        resource=str(lab_row.id),
        detail={"display_name": display},
    )
    await db.commit()

    return {
        "id": str(lab_row.id),
        "name": display,
        "netname": netname,
        "file": str(path),
    }


# ── Per-lab topology CRUD ─────────────────────────────────────────

@router.get("/{lab_id}/topology")
async def get_topology(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_read(db, lab_id, user)
    topo = _ctrl.get_by_path(lab.yaml_path)
    if not topo:
        raise HTTPException(404, "topology file missing")
    dumped = _dump_topology_for_user(topo, lab, user)
    # Expose the display name rather than the internal netname.
    dumped["id"] = str(lab.id)
    dumped["netname"] = lab.netname
    return dumped


@router.put("/{lab_id}/topology")
async def save_topology(
    lab_id: UUID,
    topology: Topology,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    # Force internal name to the netname regardless of what the client
    # sent — the display name lives in the DB row.
    topology.name = lab.netname
    path = _ctrl.save_by_uuid(lab.id, topology)
    return {"id": str(lab.id), "name": lab.display_name, "file": str(path)}


@router.get("/{lab_id}/realnet/importable-routers")
async def importable_realnet_routers(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    await resolve_for_read(db, lab_id, user)
    labs = list(await list_all_labs(db))
    return realnet_bgp.importable_realnet_routers(str(lab_id), labs)


@router.get("/{lab_id}/realnet/config")
async def realnet_public_config(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    await resolve_for_read(db, lab_id, user)
    try:
        remote_as = realnet_bgp.rr_as_from_hosts()
    except realnet_bgp.RealNetBgpError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"remote_as": remote_as}


# ── Node operations ───────────────────────────────────────────────

@router.post("/{lab_id}/topology/nodes")
async def add_node(
    lab_id: UUID,
    node: Node,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.add_node_by_path(lab.yaml_path, lab.netname, node)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.patch("/{lab_id}/topology/nodes/{node_name}")
async def update_node(
    lab_id: UUID,
    node_name: str,
    updates: NodeUpdateRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.update_node_by_path(
            lab.yaml_path, lab.netname, node_name,
            updates.model_dump(exclude_none=True),
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.delete("/{lab_id}/topology/nodes/{node_name}")
async def remove_node(
    lab_id: UUID,
    node_name: str,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        runtime_nodes = await multinode.node_list(lab)
    except MultinodeServiceError as exc:
        if "not deployed" not in str(exc).lower():
            raise HTTPException(
                409, f"Cannot verify live node state before removal: {exc}",
            ) from exc
        runtime_nodes = {}
    if node_name in runtime_nodes:
        try:
            await multinode.node_remove(lab, node_name)
        except MultinodeServiceError as exc:
            raise HTTPException(
                409, f"Cannot remove live node runtime: {exc}",
            ) from exc
    try:
        topo = _ctrl.remove_node_by_path(lab.yaml_path, lab.netname, node_name)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.put("/{lab_id}/topology/mgmt")
async def set_mgmt_config(
    lab_id: UUID,
    mgmt: MgmtConfigRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Update the top-level ``mgmt:`` block (subnet/gateway only).

    Network and bridge names are derived from the lab UUID (PR4a),
    not from anything the user types here, so they are never
    round-tripped through this endpoint.
    """
    lab = await resolve_for_write(db, lab_id, user)
    try:
        payload = {
            "ipv4-subnet": mgmt.ipv4_subnet,
            "ipv4-gw":     mgmt.ipv4_gw,
            "ipv6-subnet": mgmt.ipv6_subnet,
            "ipv6-gw":     mgmt.ipv6_gw,
            "dhcp":        mgmt.dhcp,
        }
        if mgmt.canvas_pos is not None:
            payload["canvas_pos"] = mgmt.canvas_pos
        topo = _ctrl.set_mgmt_config_by_path(lab.yaml_path, lab.netname, payload)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except TopologyValidationError as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.put("/{lab_id}/topology/nodes/{node_name}/mgmt-ipv4")
async def set_node_mgmt_ipv4(
    lab_id: UUID,
    node_name: str,
    req: NodeMgmtIpRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Set (or clear) per-node ``mgmt-ipv4``."""
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.set_node_mgmt_ipv4_by_path(
            lab.yaml_path, lab.netname, node_name, req.mgmt_ipv4,
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.put("/{lab_id}/topology/nodes/{node_name}/mgmt-ipv6")
async def set_node_mgmt_ipv6(
    lab_id: UUID,
    node_name: str,
    req: NodeMgmtIpv6Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Set (or clear) per-node ``mgmt-ipv6``."""
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.set_node_mgmt_ipv6_by_path(
            lab.yaml_path, lab.netname, node_name, req.mgmt_ipv6,
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


# ── Link operations ───────────────────────────────────────────────

@router.post("/{lab_id}/topology/links")
async def add_link(
    lab_id: UUID,
    link: Link,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.add_link_by_path(lab.yaml_path, lab.netname, link)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.delete("/{lab_id}/topology/links")
async def remove_link(
    lab_id: UUID,
    source: str,
    target: str,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
    source_iface: str | None = None,
    target_iface: str | None = None,
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.remove_link_by_path(
            lab.yaml_path, lab.netname,
            source, target, source_iface, target_iface,
        )
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.patch("/{lab_id}/topology/links/style")
async def set_link_style(
    lab_id: UUID,
    req: LinkStyleRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.set_link_style_by_path(
            lab.yaml_path, lab.netname,
            req.source, req.source_iface, req.target, req.target_iface,
            req.style,
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


@router.put("/{lab_id}/topology/canvas-annotations")
async def set_canvas_annotations(
    lab_id: UUID,
    req: CanvasAnnotationsRequest,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_write(db, lab_id, user)
    try:
        topo = _ctrl.set_canvas_annotations_by_path(
            lab.yaml_path, lab.netname,
            req.annotations,
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return _dump_topology_for_user(topo, lab, user)


# ── draw.io import / export ───────────────────────────────────────

@router.post("/{lab_id}/topology/import-drawio")
async def import_drawio(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
    file: UploadFile = File(...),
):
    lab = await resolve_for_write(db, lab_id, user)
    xml = (await file.read()).decode()
    try:
        topo = _ctrl.import_drawio_by_path(lab.yaml_path, lab.netname, xml)
    except Exception as exc:
        raise HTTPException(400, f"Import failed: {exc}")
    return _dump_topology_for_user(topo, lab, user)


@router.get("/{lab_id}/topology/export-drawio")
async def export_drawio(
    lab_id: UUID,
    db: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user)],
):
    lab = await resolve_for_read(db, lab_id, user)
    try:
        xml = _ctrl.export_drawio_by_path(lab.yaml_path)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Content-Disposition":
                f'attachment; filename="{lab.display_name}.drawio"',
        },
    )
