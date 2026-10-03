"""Application configuration.

Filesystem paths are loaded from the shared file at
``/etc/dnlab/paths.yml`` via a GUI-local loader. Environment variables remain
supported as per-deployment overrides.
"""

import logging
import os
from pathlib import Path

from app.services.paths import PATHS

_log = logging.getLogger(__name__)


def _resolve_gui_ssh_key() -> str:
    """Return the SSH key dnlab-gui should use, with fallback.

    Preference: the dedicated GUI key (``PATHS.gui_ssh_key``). If absent
    (operator has not run ``scripts/setup-gui-ssh-key.sh``) we fall
    back to the orchestrator key so the GUI keeps working — with a
    WARNING so the next startup surfaces the missing setup step.
    """
    gui_key = PATHS.gui_ssh_key
    if Path(gui_key).exists():
        return gui_key
    _log.warning(
        "GUI SSH key %s not found; falling back to orchestrator key %s. "
        "Run scripts/setup-gui-ssh-key.sh to generate the dedicated GUI key "
        "and distribute its public key to workers and running jumphosts.",
        gui_key, PATHS.ssh_key,
    )
    return PATHS.ssh_key


class Settings:
    # ── Network binding ──────────────────────────────────────────────
    # Default: bind to loopback only. For remote access put a reverse
    # proxy (nginx/traefik/caddy) or an SSH tunnel in front, and set
    # DNLABGUI_HOST=0.0.0.0 explicitly.
    HOST: str = os.getenv("DNLABGUI_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("DNLABGUI_PORT", "8080"))
    DEBUG: bool = os.getenv("DNLABGUI_DEBUG", "false").lower() == "true"

    # ── Hardening (M6) ───────────────────────────────────────────────
    # Comma-separated list of allowed browser origins for CORS and
    # WebSocket `Origin` validation. If unset the allowlist is derived
    # from HOST/PORT (loopback variants). Never use "*" here.
    ALLOWED_ORIGINS: str | None = os.getenv("DNLABGUI_ALLOWED_ORIGINS")

    CONTAINERLAB_BIN: str = os.getenv("CONTAINERLAB_BIN", PATHS.containerlab_bin)
    DOCKER_SOCKET: str = os.getenv("DOCKER_SOCKET", PATHS.docker_socket)

    TOPOLOGIES_DIR: Path = Path(os.getenv("TOPOLOGIES_DIR", PATHS.topologies_dir))
    STATIC_DIR: Path = Path(__file__).parent / "views" / "static"
    # Writable host-mounted state for the administrator-managed device catalog.
    # The built-in catalog remains part of the immutable application image.
    DEVICE_CATALOG_DIR: Path = Path(os.getenv(
        "DNLAB_DEVICE_CATALOG_DIR", "/var/lib/dnlab-device-catalog",
    ))

    # ── Multinode backend (dnlab-multinode) ──────────────────────────
    # Path to the site-wide host inventory. If unset here, the
    # orchestrator falls back to PATHS.hosts_file internally.
    DNLAB_MULTINODE_HOSTS: str | None = os.getenv("DNLAB_MULTINODE_HOSTS")
    # Base Compose intentionally permits administrator-managed hosts.yml and
    # paths.yml updates. compose.hardened.yml sets this false and remounts the
    # directory read-only, so the API can return a clear error before writing.
    CONFIG_WRITABLE: bool = os.getenv("DNLABGUI_CONFIG_WRITABLE", "true").lower() == "true"

    # Optional HTTP API for the dockerized multinode backend. Empty keeps the
    # current local Python adapter, which is the safe transition fallback.
    DNLAB_MULTINODE_API_URL: str = os.getenv("DNLAB_MULTINODE_API_URL", "").rstrip("/")

    # Optional HTTP API for the dockerized image-build backend. Empty keeps the
    # current in-process admin image-build job runner as a transition fallback.
    DNLAB_IMAGE_BUILD_API_URL: str = os.getenv("DNLAB_IMAGE_BUILD_API_URL", "").rstrip("/")

    # Image-sync daemon state file (read-only from the GUI).
    IMAGE_SYNC_STATE_FILE: Path = Path(os.getenv(
        "IMAGE_SYNC_STATE_FILE",
        PATHS.image_sync_state,
    ))

    # GUI log directory.
    LOG_DIR: Path = Path(os.getenv("DNLABGUI_LOG_DIR", str(Path(PATHS.log_root) / "gui")))

    # Ring-buffer size (events for lab) for the in-process event bus
    # that powers /ws/events/{lab}.
    EVENTS_BUFFER_SIZE: int = int(os.getenv("DNLABGUI_EVENTS_BUFFER", "500"))

    # SSH private key used by the GUI for interactive user-facing hops
    # (console to jumphost, vd log, docker exec on workers). Kept
    # distinct from the orchestrator key so destination hosts can audit
    # GUI vs. orchestrator actions separately. The default path comes
    # from /etc/dnlab/paths.yml and can be provisioned with
    # scripts/setup-gui-ssh-key.sh.
    # If the dedicated key does not exist yet, silently fall back to
    # the orchestrator key with a WARNING — maintains backwards
    # compatibility during upgrade.
    GUI_SSH_KEY: str = os.getenv("DNLABGUI_SSH_KEY", _resolve_gui_ssh_key())

    # Jumphost SSH user inside the per-lab jumphost container.
    JUMPHOST_USER: str = os.getenv("DNLABGUI_JUMPHOST_USER", "labuser")

    # Host through which the dockerized GUI reaches a jumphost's SSH.
    # Each per-lab jumphost publishes SSH on the master host
    # (``-p <bind>:<ssh_port>:22``); the GUI connects to that published
    # port on the master rather than to the jumphost container by name
    # (the GUI lives on its own compose network and shares no network
    # with the per-lab jumphost). ``host.docker.internal`` resolves to the
    # master via the ``host-gateway`` extra_hosts entry in compose. When
    # the GUI runs directly on the master (legacy), set this to
    # ``127.0.0.1`` or leave the per-name fallback to kick in.
    JUMPHOST_HOST: str = os.getenv("DNLABGUI_JUMPHOST_HOST", "host.docker.internal")

    # ── Auth / RBAC (M7 fase 2) ──────────────────────────────────────
    # SQLAlchemy connection URL for the auth DB. The Postgres service
    # lives in `deploy/auth/docker-compose.yml` and binds to 127.0.0.1.
    # Driver must be asyncpg (`+asyncpg`) because the auth stack runs
    # under FastAPI's async event loop.
    AUTH_DATABASE_URL: str = os.getenv(
        "DNLABGUI_AUTH_DATABASE_URL",
        "postgresql+asyncpg://dnlab_gui:dnlab_gui@127.0.0.1:5432/dnlab_auth",
    )

    # Which backend authenticates requests. One of:
    #   basic_auth — trust `X-Remote-User` header set by an upstream
    #                reverse proxy (e.g. Apache mod_auth_basic). Zero
    #                DB / cookies, minimal setup for dev & test.
    #   local_db   — argon2id check against the users table (default)
    #   ldap       — bind to an LDAP/AD directory (stub)
    #   oidc       — OpenID Connect redirect flow (stub)
    AUTH_BACKEND: str = os.getenv("DNLABGUI_AUTH_BACKEND", "local_db")

    # basic_auth: name of the header carrying the authenticated
    # username from the reverse proxy. Apache mod_headers convention
    # is `X-Remote-User`. NGINX uses `X-Auth-Request-User`. Override
    # as needed.
    BASIC_AUTH_REMOTE_USER_HEADER: str = os.getenv(
        "DNLABGUI_BASIC_AUTH_HEADER", "X-Remote-User",
    )

    # basic_auth: role assigned to every authenticated user. Keep it
    # permissive by default — dev/test environments use basic_auth for
    # convenience, not for fine-grained RBAC. Use local_db/ldap/oidc
    # when per-user role matters.
    BASIC_AUTH_DEFAULT_ROLE: str = os.getenv(
        "DNLABGUI_BASIC_AUTH_DEFAULT_ROLE", "admin",
    )

    # Cookie name & TTL for server-side sessions. The cookie carries an
    # opaque 32-byte token; the session row lives in the DB so we can
    # revoke immediately on logout / password change.
    SESSION_COOKIE_NAME: str = os.getenv("DNLABGUI_SESSION_COOKIE", "dnlab_session")
    SESSION_TTL_SECONDS: int = int(os.getenv("DNLABGUI_SESSION_TTL", str(12 * 3600)))

    # Host suffix used by the WebUI reverse proxy. With the default
    # empty value, the GUI derives it from the request host:
    #   https://dnlab.example.com -> https://<token>.webui.dnlab.example.com
    # Set DNLABGUI_WEBUI_HOST_SUFFIX to pin a production wildcard such as
    # "dnlab.example.com" when using a cert for *.dnlab.example.com.
    WEBUI_HOST_SUFFIX: str = os.getenv("DNLABGUI_WEBUI_HOST_SUFFIX", "").strip().strip(".")

    # Public GUI base URL used when minting absolute capability URLs for
    # local desktop handlers, such as Wireshark capture launchers. Leave empty
    # to derive it from reverse-proxy X-Forwarded-* headers.
    PUBLIC_BASE_URL: str = os.getenv("DNLABGUI_PUBLIC_BASE_URL", "").strip().rstrip("/")

    # Signing key used by itsdangerous to sign short-lived artifacts
    # (CSRF, password-reset links). NOT used for the session cookie
    # itself — that's an opaque DB-backed token. Override in production.
    SESSION_SECRET: str = os.getenv(
        "DNLABGUI_SESSION_SECRET",
        "dev-insecure-change-me",
    )

    # Map Docker image name fragments → ContainerLab node kind
    # Kind names must match exactly what `containerlab deploy` accepts.
    IMAGE_KIND_MAP: dict[str, str] = {
        "cisco_xrv9k":           "cisco_xrv9k",
        "cisco_xrv":             "cisco_xrv",
        "cisco_n9kv":            "cisco_n9kv",
        "cisco_nxos":            "cisco_n9kv",
        "cisco_csr1000v":        "cisco_csr1000v",
        "cisco_csr":             "cisco_csr1000v",
        "cisco_cat9kv":          "cisco_cat9kv",
        "cisco_iol":             "cisco_iol",
        "cisco_iosv":            "cisco_vios",       # clab kind: cisco_vios
        "cisco_vios":            "cisco_vios",
        "juniper_vmx":           "juniper_vmx",
        "juniper_vjunos-router": "juniper_vjunosrouter",   # no hyphen in clab 0.74
        "juniper_vjunosrouter":  "juniper_vjunosrouter",
        "juniper_vjunosevolved": "juniper_vjunosevolved",
        "juniper_vjunos-switch": "juniper_vjunosswitch",   # no hyphen in clab 0.74
        "juniper_vjunosswitch":  "juniper_vjunosswitch",
        "juniper_vqfx":          "juniper_vqfx",
        "juniper_vsrx":          "juniper_vsrx",
        "arista_veos":           "arista_veos",
        "arista_ceos":           "arista_ceos",
        "ceos":                  "arista_ceos",
        "nokia_sros":            "nokia_sros",
        "nokia_srlinux":         "nokia_srlinux",
        "srlinux":               "nokia_srlinux",
        "huawei_vrp":            "huawei_vrp",
        "openwrt":               "openwrt",
        "mikrotik":              "mikrotik_ros",
        "mikrotik_ros":          "mikrotik_ros",
        "routeros":              "mikrotik_ros",
        "paloalto_panos":        "paloalto_panos",
        "fortinet_fortigate":    "fortinet_fortigate",
        "linux":                 "linux",
    }

    # Map kind → vendor for icons and display. Allineato alla lista completa
    # dei kind supportati da containerlab (https://containerlab.dev/manual/kinds/).
    # The client-side source of truth for labels/colors is
    # app/views/static/config/devices.json — questa mappa serve al backend
    # for taggare le images Docker col vendor in list_images().
    KIND_VENDOR_MAP: dict[str, str] = {
        # Nokia
        "nokia_srlinux":         "nokia",
        "nokia_sros":            "nokia",
        "nokia_srsim":           "nokia",
        # Arista
        "arista_ceos":           "arista",
        "arista_veos":           "arista",
        # Juniper
        "juniper_crpd":          "juniper",
        "juniper_vmx":           "juniper",
        "juniper_vqfx":          "juniper",
        "juniper_vsrx":          "juniper",
        "juniper_vjunosrouter":  "juniper",
        "juniper_vjunosswitch":  "juniper",
        "juniper_vjunosevolved": "juniper",
        "juniper_cjunosevolved": "juniper",
        # Cisco
        "cisco_xrd":             "cisco",
        "cisco_xrv":             "cisco",
        "cisco_xrv9k":           "cisco",
        "cisco_csr1000v":        "cisco",
        "cisco_n9kv":            "cisco",
        "cisco_c8000":           "cisco",
        "cisco_c8000v":          "cisco",
        "cisco_cat9kv":          "cisco",
        "cisco_iol":             "cisco",
        "cisco_vios":            "cisco",
        "cisco_ftdv":            "cisco",
        # Altri NOS
        "cumulus_cvx":           "cumulus",
        "cumulus_vx":            "cumulus",
        "aruba_aoscx":           "aruba",
        "sonic-vs":              "sonic",
        "sonic-vm":              "sonic",
        "dell_ftosv":            "dell",
        "dell_sonic":            "dell",
        "mikrotik_ros":          "mikrotik",
        "huawei_vrp":            "huawei",
        "ipinfusion_ocnos":      "ipinfusion",
        "paloalto_panos":        "paloalto",
        "fortinet_fortigate":    "fortinet",
        "checkpoint_cloudguard": "checkpoint",
        "6wind_vsr":             "6wind",
        "keysight_ixia-c-one":   "keysight",
        "spirent_stc":           "spirent",
        "arrcus_arcos":          "arrcus",
        "vyosnetworks_vyos":     "vyos",
        "veesix_osvbng":         "veesix",
        "fdio_vpp":              "linux",
        "rare":                  "linux",
        # Linux generici / bridge / host
        "linux":                 "linux",
        "freebsd":               "linux",
        "openbsd":               "linux",
        "openwrt":               "linux",
        "k8s-kind":              "linux",
        "bridge":                "linux",
        "ovs-bridge":            "ovs",
        "ext-container":         "linux",
        "host":                  "linux",
        "generic_vm":            "generic",
        "flinos":                "n4alab",
    }

    # Fallback minimale for l'endpoint /api/docker/interfaces quando il catalogo
    # device is not readable. Configurable mappings live in
    # app/views/static/config/devices.json, campo kinds.<kind>.interfaces:
    # { "linux_fmt": "eth{n}", "vendor_fmt": "Ethernet{n}", "count": 8 }.
    KIND_INTERFACES: dict[str, dict] = {
        "linux": {
            "linux_fmt": "eth{n}",
            "vendor_fmt": "eth{n}",
            "count": 8,
        },
        "generic_vm": {
            "linux_fmt": "eth{n}",
            "vendor_fmt": "eth{n}",
            "count": 8,
        },
        "flinos": {
            "linux_fmt": "eth{n-1}",
            "vendor_fmt": "eth{n-1}",
            "vendor_names": {"1": "mgmt"},
            "count": 9,
        },
    }

    # NOTA storica: qui viveva ``VRNETLAB_CONSOLE_PORT``, una mappa
    # kind→5000 usata come set di "kind che vanno via jumphost". È stata
    # removed: console dispatch is now entirely runtime-driven
    # (vedi ``app/services/console_service.py`` + ``vd connect`` sul
    # jumphost). Adding a new kind no longer requires touching config.


settings = Settings()
settings.TOPOLOGIES_DIR.mkdir(parents=True, exist_ok=True)
