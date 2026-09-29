"""Topology edit controller — path-based.

Every operation takes an explicit :class:`Path` to the YAML and a
``netname`` to write into the ``name:`` field on save. The netname is
derived from the lab UUID by the route handler (via
:mod:`app.services.lab_resolver`), so this layer never computes it on
its own and never risks writing a display-name-collision-prone string.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid as uuidlib
from pathlib import Path
from uuid import UUID

import yaml

from app.auth.labs import derive_network_name
from app.config import settings
from app.models.topology import Topology
from app.models.node import Node, NodePosition
from app.models.link import Link
from app.services.containerlab_service import ContainerLabService
from app.services.drawio_service import DrawioService
from app.services import node_overrides
from app.services import realnet_bgp

log = logging.getLogger(__name__)

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _link_style_key(source: str, source_iface: str, target: str, target_iface: str) -> str:
    endpoints = [f"{source}:{source_iface or ''}", f"{target}:{target_iface or ''}"]
    return "|".join(sorted(endpoints))


def _link_style_key_for_link(link: Link) -> str:
    return _link_style_key(link.source, link.source_iface, link.target, link.target_iface)


class TopologyValidationError(ValueError):
    pass


class TopologyController:
    def __init__(self) -> None:
        self._clab = ContainerLabService()
        self._drawio = DrawioService()

    # ── Path helpers ──────────────────────────────────────────────

    @staticmethod
    def _yaml_path_for(lab_id: UUID) -> Path:
        return settings.TOPOLOGIES_DIR / f"{lab_id}.yml"

    # ── Save / Load ───────────────────────────────────────────────

    def save_by_uuid(self, lab_id: UUID, topology: Topology) -> Path:
        """Persist ``topology`` to ``<uuid>.yml`` with ``name:`` forced
        to the UUID-derived netname.
        """
        topology.name = derive_network_name(lab_id)
        path = self._yaml_path_for(lab_id)
        self._prepare_realnet_bgp(topology, path)
        return self._clab.save_topology_to(path, topology)

    def get_by_path(self, path: Path) -> Topology | None:
        if not path.exists():
            return None
        return self._clab.load_topology_from_file(path)

    # ── Node operations (path-based) ──────────────────────────────

    def add_node_by_path(
        self, path: Path, netname: str, node: Node,
    ) -> Topology:
        log.info("add_node: %s/%s (kind=%s)", netname, node.name, node.kind)
        topo = self._require_path(path)
        if node.kind == "_real_net":
            realnet_bgp.ensure_single_realnet(topo, new_node=node.name)
        # Wire-format compat: se il frontend inietta ``webui_ports``
        # dentro ``node.extra`` (versione vecchia o transitoria), lo
        # intercettiamo e lo posizioniamo nel sidecar
        # ``gui_webui_state``. Il client nuovo usa il campo dedicato
        # in NodeUpdateRequest dopo la creazione.
        legacy_extra = node.extra or {}
        legacy_webui = legacy_extra.pop("webui_ports", None)
        if legacy_webui:
            # Stessa normalizzazione di update_node_by_path. La
            # forma extra-side era ``{port, scheme, path, label}``.
            normalized = []
            for e in legacy_webui:
                if not isinstance(e, dict):
                    continue
                cport = e.get("port") or e.get("container_port")
                if not cport:
                    continue
                normalized.append({
                    "container_port": int(cport),
                    "scheme": e.get("scheme", "https"),
                    "path":   e.get("path", "/"),
                    "label":  e.get("label", ""),
                    "source": e.get("source") or "user",
                })
            self._apply_webui_ports(topo, node.name, normalized)
        if node.kind == "_real_net":
            node.extra = self._normalize_realnet_extra(node.extra, path)
        topo.add_node(node)
        if node.kind != "_real_net":
            topo.gui_node_ids_state.setdefault(node.name, str(uuidlib.uuid4()))
        default_override = node_overrides.default_state(node.kind, node.image)
        if default_override:
            applied = node_overrides.apply_state(node, default_override)
            if applied:
                topo.gui_node_overrides_state[node.name] = applied
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def update_node_by_path(
        self, path: Path, netname: str, node_name: str, updates: dict,
    ) -> Topology:
        topo = self._require_path(path)
        node = topo.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")

        new_name = updates.pop("new_name", None)
        # Web UI ports: list opzionale dal frontend. Se passata (anche
        # vuota), sostituisce ``topology.gui_webui_state[node_name]``.
        # It lives in the sidecar, not in node.extra or in the clab YAML body.
        webui_ports = updates.pop("webui_ports", None)
        node_override_state = updates.pop("node_overrides", None)
        node_features_state = updates.pop("node_features", None)
        advanced_extra_yaml = updates.pop("advanced_extra_yaml", None)

        if advanced_extra_yaml is not None:
            node.extra = self._merge_advanced_extra_yaml(node.extra or {}, advanced_extra_yaml)

        for key, val in updates.items():
            if key == "position":
                node.position = NodePosition(**val)
            elif key == "extra":
                # Merge non-destructivo: setattr(node, "extra", val)
                # it would delete other existing keys (es. mgmt-ipv4)
                # che questa PATCH non tocca. Aggiorniamo solo le chiavi
                # inviate; una chiave con valore None viene rimossa.
                current = dict(node.extra or {})
                for k, v in (val or {}).items():
                    if v is None:
                        current.pop(k, None)
                    elif k == "env" and isinstance(v, dict):
                        env = dict(current.get("env") or {})
                        for env_key, env_val in v.items():
                            if env_val is None:
                                env.pop(env_key, None)
                            else:
                                env[env_key] = env_val
                        if env:
                            current["env"] = env
                        else:
                            current.pop("env", None)
                    else:
                        current[k] = v
                node.extra = current
            elif hasattr(node, key):
                setattr(node, key, val)

        if webui_ports is not None:
            self._apply_webui_ports(topo, node_name, webui_ports)

        if node.kind == "_real_net":
            node.extra = self._normalize_realnet_extra(node.extra, path)

        if node_override_state is not None:
            applied = node_overrides.apply_state(node, node_override_state)
            if applied:
                topo.gui_node_overrides_state[node_name] = applied
            else:
                topo.gui_node_overrides_state.pop(node_name, None)

        if node_features_state is not None:
            applied = self._clean_node_features_state(node.kind, node_features_state)
            if applied:
                topo.gui_node_features_state[node_name] = applied
            else:
                topo.gui_node_features_state.pop(node_name, None)

        if new_name and new_name != node_name:
            if topo.get_node(new_name):
                raise ValueError(f"Node '{new_name}' already exists")
            # Riallinea anche la chiave del sidecar se cambia il nome.
            if node_name in topo.gui_webui_state:
                topo.gui_webui_state[new_name] = topo.gui_webui_state.pop(node_name)
            if node_name in topo.gui_node_ids_state:
                topo.gui_node_ids_state[new_name] = topo.gui_node_ids_state.pop(node_name)
            node_overrides.rename_state(topo.gui_node_overrides_state, node_name, new_name)
            if node_name in topo.gui_node_features_state:
                topo.gui_node_features_state[new_name] = topo.gui_node_features_state.pop(node_name)
            old_link_styles = dict(topo.gui_link_styles_state or {})
            old_link_keys = {
                id(link): _link_style_key_for_link(link)
                for link in topo.links
                if link.source == node_name or link.target == node_name
            }
            node.name = new_name
            for link in topo.links:
                if link.source == node_name:
                    link.source = new_name
                if link.target == node_name:
                    link.target = new_name
            for link in topo.links:
                old_key = old_link_keys.get(id(link))
                if old_key and old_key in old_link_styles:
                    topo.gui_link_styles_state[_link_style_key_for_link(link)] = old_link_styles[old_key]
                    topo.gui_link_styles_state.pop(old_key, None)
            renamed_override = topo.gui_node_overrides_state.get(new_name)
            if renamed_override:
                applied = node_overrides.apply_state(node, renamed_override)
                if applied:
                    topo.gui_node_overrides_state[new_name] = applied
            renamed_features = topo.gui_node_features_state.get(new_name)
            if renamed_features:
                applied = self._clean_node_features_state(node.kind, renamed_features)
                if applied:
                    topo.gui_node_features_state[new_name] = applied
                else:
                    topo.gui_node_features_state.pop(new_name, None)

        topo.name = netname
        self._prepare_realnet_bgp(topo, path)
        self._clab.save_topology_to(path, topo)
        return topo

    @staticmethod
    def _normalize_realnet_extra(extra: dict, path: Path) -> dict:
        current = dict(extra or {})
        if current.get("ospf") and "bgp" not in current:
            current["bgp"] = True
            current["nat"] = False
        bgp_enabled = bool(current.get("bgp"))
        current["bgp"] = bgp_enabled
        current["nat"] = not bgp_enabled
        current.pop("ospf", None)
        current = realnet_bgp.normalize_realnet_lan(current, current_path=path)
        if bgp_enabled:
            current = realnet_bgp.allocate_for_realnet_node(current, current_path=path)
        return current

    def _prepare_realnet_bgp(self, topo: Topology, path: Path) -> None:
        realnet_bgp.ensure_single_realnet(topo)
        for node in topo.nodes:
            if node.kind == "_real_net":
                node.extra = self._normalize_realnet_extra(node.extra, path)

    @staticmethod
    def _merge_advanced_extra_yaml(current_extra: dict, raw_yaml: str) -> dict:
        """Replace user-authored Containerlab extras while preserving GUI fields."""
        reserved = {"kind", "image", "name", "mgmt-ipv4", "mgmt-ipv6", "webui_ports", "node_overrides"}
        try:
            parsed = yaml.safe_load(raw_yaml or "") or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid advanced YAML: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Advanced YAML must be a mapping of Containerlab node fields")

        blocked = sorted(k for k in parsed if k in reserved)
        if blocked:
            raise ValueError(
                "Advanced YAML cannot set GUI-managed field(s): " + ", ".join(blocked)
            )
        env = parsed.get("env")
        if env is not None and (not isinstance(env, dict) or isinstance(env, list)):
            raise ValueError("Advanced YAML field 'env' must be a mapping")

        next_extra: dict = {}
        if "mgmt-ipv4" in current_extra:
            next_extra["mgmt-ipv4"] = current_extra["mgmt-ipv4"]
        if "mgmt-ipv6" in current_extra:
            next_extra["mgmt-ipv6"] = current_extra["mgmt-ipv6"]

        current_env = current_extra.get("env") if isinstance(current_extra.get("env"), dict) else {}
        preserved_env = {
            k: current_env[k]
            for k in ("VCPU", "RAM", "CLAB_MGMT_PASSTHROUGH")
            if k in current_env
        }

        next_extra.update(parsed)
        parsed_env = parsed.get("env") if isinstance(parsed.get("env"), dict) else {}
        merged_env = {**parsed_env, **preserved_env}
        if merged_env:
            next_extra["env"] = merged_env
        else:
            next_extra.pop("env", None)
        return next_extra

    @staticmethod
    def _clean_node_features_state(kind: str | None, state: dict | None) -> dict:
        from app.services import device_catalog
        return device_catalog.clean_node_features_state(kind, state)

    @staticmethod
    def _apply_webui_ports(topo: Topology, node_name: str, ports: list) -> None:
        """Sostituisce le entry Web UI for il node nel sidecar.

        Lista vuota → rimuove l'entry. Ogni voce viene normalizzata e
        deduplicata for (scheme, container_port).
        """
        if not ports:
            topo.gui_webui_state.pop(node_name, None)
            return
        seen: set[tuple[str, int]] = set()
        cleaned: list[dict] = []
        for p in ports:
            if not isinstance(p, dict):
                continue
            try:
                cport = int(p.get("container_port") or 0)
            except (TypeError, ValueError):
                continue
            if not (1 <= cport <= 65535):
                continue
            scheme = (p.get("scheme") or "https").lower()
            key = (scheme, cport)
            if key in seen:
                continue
            seen.add(key)
            cleaned.append({
                "container_port": cport,
                "scheme":         scheme,
                "path":           p.get("path") or "/",
                "label":          p.get("label") or "",
                "source":         p.get("source") or "user",
            })
        if cleaned:
            topo.gui_webui_state[node_name] = cleaned
        else:
            topo.gui_webui_state.pop(node_name, None)

    def remove_node_by_path(
        self, path: Path, netname: str, node_name: str,
    ) -> Topology:
        topo = self._require_path(path)
        topo.remove_node(node_name)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def set_mgmt_config_by_path(
        self, path: Path, netname: str, mgmt: dict,
    ) -> Topology:
        """Update the top-level ``mgmt:`` block.

        Strips any legacy ``network``/``bridge`` keys — those are
        derived from the lab UUID and must not come from user input.
        Gateway fields are derived from the subnets and are never trusted
        from the client.
        """
        topo = self._require_path(path)
        current = dict(topo.extra.get("mgmt") or {})
        current.pop("network", None)
        current.pop("bridge", None)
        current["dhcp"] = bool(mgmt.get("dhcp", False))
        v4_raw = (mgmt.get("ipv4-subnet") or "").strip()
        if v4_raw:
            v4_net = self._validate_mgmt_ipv4_subnet(v4_raw)
            current["ipv4-subnet"] = str(v4_net)
            current["ipv4-gw"] = str(v4_net.broadcast_address - 1)

            v6_raw = (mgmt.get("ipv6-subnet") or "").strip()
            if v6_raw:
                v6_net = self._validate_mgmt_ipv6_subnet(v6_raw)
                if v6_net.network_address.ipv4_mapped is not None:
                    v6_net = self._derive_mgmt_ipv6_from_ipv4(v4_net)
            else:
                v6_net = self._derive_mgmt_ipv6_from_ipv4(v4_net)
            current["ipv6-subnet"] = str(v6_net)
            current["ipv6-gw"] = str(v6_net.network_address + (v6_net.num_addresses - 1))
        else:
            for key in ("ipv4-subnet", "ipv4-gw", "ipv6-subnet", "ipv6-gw"):
                current.pop(key, None)
        # canvas_pos (opzionale): solo la GUI lo usa for ricordare dove
        # l'user ha piazzato il "cloud" della mgmt network. Non
        # does not affect deployment; it is cosmetic metadata.
        if "canvas_pos" in mgmt:
            pos = mgmt.get("canvas_pos") or None
            if pos and isinstance(pos, dict) and "x" in pos and "y" in pos:
                current["canvas_pos"] = {"x": float(pos["x"]), "y": float(pos["y"])}
            else:
                current.pop("canvas_pos", None)
        if current:
            topo.extra["mgmt"] = current
        else:
            topo.extra.pop("mgmt", None)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    @staticmethod
    def _validate_mgmt_ipv4_subnet(value: str) -> ipaddress.IPv4Network:
        try:
            net = ipaddress.IPv4Network(value, strict=False)
        except ValueError as exc:
            raise TopologyValidationError(f"Invalid IPv4 mgmt subnet {value!r}: {exc}") from exc
        if net.prefixlen > 29:
            raise TopologyValidationError(
                f"IPv4 mgmt subnet {net} is too small: need at least /29 "
                "for Docker gateway, DNS, jumphost, and VD addresses"
            )
        return net

    @staticmethod
    def _validate_mgmt_ipv6_subnet(value: str) -> ipaddress.IPv6Network:
        try:
            net = ipaddress.IPv6Network(value, strict=False)
        except ValueError as exc:
            raise TopologyValidationError(f"Invalid IPv6 mgmt subnet {value!r}: {exc}") from exc
        if net.num_addresses < 2:
            raise TopologyValidationError(f"IPv6 mgmt subnet {net} is too small")
        return net

    @staticmethod
    def _derive_mgmt_ipv6_from_ipv4(v4_net: ipaddress.IPv4Network) -> ipaddress.IPv6Network:
        octets = str(v4_net.network_address).split(".")
        return ipaddress.IPv6Network(
            f"3fff:{octets[0]}:{octets[1]}:{octets[2]}::/64",
            strict=False,
        )

    def set_node_mgmt_ipv4_by_path(
        self, path: Path, netname: str, node_name: str, mgmt_ipv4: str,
    ) -> Topology:
        topo = self._require_path(path)
        node = topo.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")
        val = (mgmt_ipv4 or "").strip()
        if val:
            node.extra["mgmt-ipv4"] = val
        else:
            node.extra.pop("mgmt-ipv4", None)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def set_node_mgmt_ipv6_by_path(
        self, path: Path, netname: str, node_name: str, mgmt_ipv6: str,
    ) -> Topology:
        topo = self._require_path(path)
        node = topo.get_node(node_name)
        if not node:
            raise ValueError(f"Node '{node_name}' not found")
        val = (mgmt_ipv6 or "").strip()
        if val:
            node.extra["mgmt-ipv6"] = val
        else:
            node.extra.pop("mgmt-ipv6", None)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    # ── Link operations (path-based) ──────────────────────────────

    def add_link_by_path(
        self, path: Path, netname: str, link: Link,
    ) -> Topology:
        log.info("add_link: %s  %s:%s → %s:%s",
                 netname, link.source, link.source_iface,
                 link.target, link.target_iface)
        topo = self._require_path(path)
        topo.add_link(link)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def remove_link_by_path(
        self,
        path: Path,
        netname: str,
        source: str,
        target: str,
        source_iface: str | None = None,
        target_iface: str | None = None,
    ) -> Topology:
        log.info("remove_link: %s  %s:%s → %s:%s",
                 netname, source, source_iface or '*', target, target_iface or '*')
        topo = self._require_path(path)
        if source_iface and target_iface:
            removed_keys = {
                _link_style_key_for_link(lk)
                for lk in topo.links
                if (
                    lk.source == source and lk.target == target
                    and lk.source_iface == source_iface and lk.target_iface == target_iface
                ) or (
                    lk.source == target and lk.target == source
                    and lk.source_iface == target_iface and lk.target_iface == source_iface
                )
            }
            topo.links = [
                lk for lk in topo.links
                if not (
                    lk.source == source and lk.target == target
                    and lk.source_iface == source_iface and lk.target_iface == target_iface
                ) and not (
                    lk.source == target and lk.target == source
                    and lk.source_iface == target_iface and lk.target_iface == source_iface
                )
            ]
        else:
            removed_keys = {
                _link_style_key_for_link(lk)
                for lk in topo.links
                if (lk.source == source and lk.target == target)
                or (lk.source == target and lk.target == source)
            }
            topo.links = [
                lk for lk in topo.links
                if not (lk.source == source and lk.target == target)
                and not (lk.source == target and lk.target == source)
            ]
        for key in removed_keys:
            topo.gui_link_styles_state.pop(key, None)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def set_link_style_by_path(
        self,
        path: Path,
        netname: str,
        source: str,
        source_iface: str,
        target: str,
        target_iface: str,
        style: dict,
    ) -> Topology:
        topo = self._require_path(path)
        key = _link_style_key(source, source_iface, target, target_iface)
        if not any(_link_style_key_for_link(lk) == key for lk in topo.links):
            raise ValueError("Link not found")
        clean = self._clean_link_style(style)
        if clean:
            topo.gui_link_styles_state[key] = clean
        else:
            topo.gui_link_styles_state.pop(key, None)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def set_canvas_annotations_by_path(
        self,
        path: Path,
        netname: str,
        annotations: list[dict],
    ) -> Topology:
        topo = self._require_path(path)
        topo.gui_canvas_annotations_state = self._clean_annotations(annotations)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    @staticmethod
    def _clean_link_style(style: dict) -> dict:
        clean = {}
        for key in ("color", "label_color"):
            value = (style or {}).get(key)
            if isinstance(value, str) and _HEX_COLOR_RE.match(value):
                clean[key] = value.lower()
        return clean

    @classmethod
    def _clean_annotations(cls, annotations: list[dict]) -> list[dict]:
        # Reuse the Pydantic model's permissive JSON path by importing the
        # persistence sanitizer locally, keeping one canonical schema filter.
        from app.services.containerlab_service import _clean_canvas_annotations

        return _clean_canvas_annotations(annotations)

    # ── draw.io import/export (path-based) ────────────────────────

    def import_drawio_by_path(
        self, path: Path, netname: str, xml: str,
    ) -> Topology:
        topo = self._drawio.from_xml(xml, netname)
        topo.name = netname
        self._clab.save_topology_to(path, topo)
        return topo

    def export_drawio_by_path(self, path: Path) -> str:
        topo = self._require_path(path)
        return self._drawio.to_xml(topo)

    # ── helpers ───────────────────────────────────────────────────

    def _require_path(self, path: Path) -> Topology:
        if not path.exists():
            raise FileNotFoundError(f"Topology file missing: {path}")
        return self._clab.load_topology_from_file(path)
