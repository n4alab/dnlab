"""Warm-link image profiles and validation metadata."""

from __future__ import annotations

import json
from pathlib import Path


PROFILES: dict[str, dict[str, int | bool]] = {
    "dnlab_frr": {"default_ports": 8, "max_ports": 8, "vm_index": 0},
    "openwrt": {"default_ports": 8, "max_ports": 64, "vm_index": 0},
    "dnlab_opnsense": {"default_ports": 8, "max_ports": 64, "vm_index": 0},
    "nvidia_cumulusvx": {"default_ports": 64, "max_ports": 64, "vm_index": 0},
    "mikrotik_ros": {"default_ports": 16, "max_ports": 31, "vm_index": 0},
    "cisco_vios": {"default_ports": 15, "max_ports": 15, "vm_index": 0},
    "juniper_vjunosrouter": {"default_ports": 16, "max_ports": 97, "vm_index": 0},
    "juniper_vjunosswitch": {"default_ports": 16, "max_ports": 57, "vm_index": 0},
    "juniper_vjunosevolved": {"default_ports": 16, "max_ports": 17, "vm_index": 0},
    "cisco_n9kv": {"default_ports": 16, "max_ports": 129, "vm_index": 0},
    "cisco_nxos": {"default_ports": 16, "max_ports": 32, "vm_index": 0},
    "cisco_cat9kv": {"default_ports": 9, "max_ports": 9, "vm_index": 0},
    "cisco_c9800cl": {"default_ports": 3, "max_ports": 3, "vm_index": 0},
    "cisco_xrv9k": {"default_ports": 16, "max_ports": 128, "vm_index": 0},
}


REGISTRY_PATH = Path(__file__).with_name("warm_link_registry.json")
REGISTRY = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

VALIDATED_BASE_IMAGES: dict[str, str] = {
    item["image"]: item["digest"]
    for item in REGISTRY["images"]
    if item["certification"] == "validated"
}

CLUSTER4_CANDIDATE_BASE_IMAGES: dict[str, str] = {
    item["image"]: item["digest"]
    for item in REGISTRY["images"]
    if item["cluster"] == 4
}


def profile_for(kind: str, image: str = "") -> dict[str, int | bool] | None:
    if kind == "cisco_cat9kv" and "c9800" in image.lower():
        return PROFILES["cisco_c9800cl"]
    return PROFILES.get(kind)


def validation_status(image: str, identity: str) -> str:
    expected = VALIDATED_BASE_IMAGES.get(image)
    digest = identity.rsplit("@", 1)[-1]
    return "validated" if expected and expected == digest else "experimental"
