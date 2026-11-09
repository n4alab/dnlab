"""Network node model."""

from typing import Any
from pydantic import BaseModel, Field
from app.services import device_catalog


class NodePosition(BaseModel):
    x: float = 100.0
    y: float = 100.0


class Node(BaseModel):
    name: str
    kind: str
    image: str
    position: NodePosition = Field(default_factory=NodePosition)
    mgmt_ipv4: str | None = None
    mgmt_ipv6: str | None = None
    # Extra ContainerLab node parameters (env, binds, ports, etc.)
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_vrnetlab(self) -> bool:
        return self.image.startswith("vrnetlab/")

    # Default env vars injected into every node.
    # Management passthrough is also enforced after merging legacy node env.
    _DEFAULT_ENV: dict[str, str] = {"CLAB_MGMT_PASSTHROUGH": "false"}

    def to_clab_dict(self) -> dict[str, Any]:
        clab_kind = device_catalog.deploy_kind(self.kind)
        d: dict[str, Any] = {"kind": clab_kind, "image": self.image}
        # Filtro chiavi GUI-private da non scrivere nel YAML clab:
        #  * ``webui_ports`` — wart legacy del primo round Web UI; oggi
        #    the source of truth is the ``# dnlab-gui-webui:`` sidecar and
        #    l'esposizione fisica passa for ``ports:`` (clab-native)
        #    iniettata da multinode al deploy time.
        clean_extra = {
            k: v for k, v in self.extra.items()
            if k not in ("webui_ports", "node_overrides")
        }
        if self.kind == "_real_net":
            d["extra"] = clean_extra
            return d
        d.update(clean_extra)
        # Merge user env, then enforce the global management policy.
        env = {**self._DEFAULT_ENV, **device_catalog.default_env(self.kind), **(d.get("env") or {})}
        env["CLAB_MGMT_PASSTHROUGH"] = "false"
        if env:
            d["env"] = env
        else:
            d.pop("env", None)
        return d
