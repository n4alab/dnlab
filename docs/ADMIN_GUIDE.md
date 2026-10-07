# dNLab Admin Guide

This guide is for administrators who deploy and operate the dNLab Docker
distribution stack. It is the authoritative guide for installation, TLS,
validation, hardening, upgrade, backup and release operations.

For end-user workflows in the browser, see [USER_GUIDE.md](USER_GUIDE.md).

## Architecture

dNLab exposes one public Compose service, `proxy`, on the host. The GUI and
backend services stay on the internal Compose network.

Main Compose services:

- `proxy`: Apache reverse proxy for HTTP, TLS, WebSocket and per-device
  Web UI access.
- `gui`: FastAPI GUI and browser application.
- `multinode`: internal orchestration API for Containerlab, workers and
  runtime state.
- `image-sync`: internal image synchronization helper.
- `lab-cleanup`: periodic reconciler for stale runtime artifacts.
- `image-build`: internal API for image-build jobs and logs.
- `auth-db`: PostgreSQL database for local authentication.

Images, binaries, log directories, TLS files and source artifacts keep their
`dnlab-*` product names.

The GUI container does not mount `/var/run/docker.sock`; Docker discovery and
orchestration flow through the internal services.

## Host Prerequisites

Use Linux hosts suitable for nested container, network and virtual-device
workloads. The reference baseline is Debian 13 on bare metal with Docker Engine
from Docker's official repository, Docker Compose plugin, Containerlab, cgroup
v2 and root or sudo access for host networking operations.

Expose only proxy ports to users, normally 80 and 443 in production.

## Bare-Metal First Start

Use this ordered path for a new installation with published GHCR images. Run
the master-host commands from `/opt/dnlab`; repeat the Docker and Containerlab
prerequisites on every worker before it is added to the inventory.

1. Obtain the matching release checkout:

   ```bash
   git clone --branch v0.2.5 https://github.com/n4alab/dnlab.git /opt/dnlab
   cd /opt/dnlab
   ```

2. Install and verify Docker, the Compose plugin and Containerlab on each
   host with [Install Docker And Containerlab Prerequisites](#install-docker-and-containerlab-prerequisites).
3. On the master, create `/etc/dnlab/hosts.yml` and `/etc/dnlab/paths.yml`
   from the repository templates, prepare the directories and keys described
   below, configure TLS and complete `.env`.
4. Download both the Compose-service images and the runtime images used later
   for lab deployment:

   ```bash
   docker compose -f compose.yml --profile release-images pull
   ```

5. Bootstrap only the proxy dependency chain. This creates the deterministic
   `dnlab_internal` network without starting `image-sync` or `lab-cleanup`:

   ```bash
   docker compose -f compose.yml up -d proxy
   docker network inspect dnlab_internal \
     --format '{{(index .IPAM.Config 0).Gateway}}'
   ```

   Set the printed gateway as `infrastructure.master.host` in `hosts.yml` for
   a single-node site. Set every worker address and the shared
   `infrastructure.underlay_iface`, then authorize and verify SSH from the
   master before continuing.
6. Start the normal stack, including `image-sync` and `lab-cleanup`, then seed
   the first administrator and sign in through the proxy:

   ```bash
   docker compose -f compose.yml up -d
   docker compose -f compose.yml ps
   ```

   `smoke.sh` is an extended diagnostic for troubleshooting, stack changes and
   upgrades; it is not required for a normal first start.

## Site Configuration Reference

dNLab expects shared host configuration under `/etc/dnlab`. The following
sections are a reference for the files prepared by the first-start procedure.

### Site inventory (`hosts.yml`)

The site inventory is a YAML file named `/etc/dnlab/hosts.yml` by default
(`DNLAB_MULTINODE_HOSTS` can select another YAML path). It is not XML. The
complete canonical examples are shipped with the distribution as
`hosts.yml.example` and `paths.yml.example`.

`infrastructure.master.host` is the SSH-reachable master target and each
`workers.<name>` entry has `host`, optional `ssh_user` (default `root`) and
optional `ssh_key` (default `~/.ssh/id_ed25519`). For a single-node install,
use the host address reachable from containers and set `workers: {}`; do not
use `localhost` because it identifies the calling container.

`infrastructure.underlay_iface` is one site-wide Linux interface name. dNLab
uses it on every declared host to discover the IPv4 address used for VXLAN and
RealNet dataplane traffic. Do not configure `interface:` below `master` or a
worker: it has never been consumed and is rejected. Hosts requiring distinct
underlay interfaces are not supported by this inventory schema.

The supported sections are `infrastructure.jumphost_net` (including SSH bind
address and inclusive port range), `webui_ports`, `realnet`, and `persistence`;
plus top-level `defaults.mgmt`, `image_sync`, `lab_cleanup`, and
`follow_the_rabbit`. Unknown keys and incorrect value types are rejected so a
misspelled setting cannot silently fall back to a default. Ranges such as
`2200-2299` must be quoted YAML strings; image-sync patterns use `fnmatch`
syntax and an image must match an `include` pattern and no `exclude` pattern.
`image_sync.interval_seconds` and `lab_cleanup.interval_seconds` must be at
least 30; cleanup grace must be non-negative.

For compatibility, the legacy RealNet names `bgp_as` and `lab_as_pool`, and
`plus.follow_the_rabbit`, are read once but Admin saves rewrite them as
`rr_as`, `router_as_pool`, and top-level `follow_the_rabbit`.

Create the two installation files from the repository templates before starting
the stack:

```bash
sudo install -d -m 0755 /etc/dnlab
sudo install -m 0640 hosts.yml.example /etc/dnlab/hosts.yml
sudo install -m 0640 paths.yml.example /etc/dnlab/paths.yml
```

`/etc/dnlab/paths.yml` uses top-level keys only; do not wrap values in `paths:`
or `persistence:`. The template contains every supported key, including
`hosts_file`, daemon state paths, storage paths, SSH keys, `containerlab_bin`
and `docker_socket`.

`ssh_key` is the master-to-worker orchestration key used by backend services.
`gui_ssh_key` is the GUI-to-jumphost key used for Web UI, console and log
tunnels.

Common host directories:

```bash
sudo mkdir -p /etc/dnlab /root/dnlab-topologies \
  /var/lib/docker/dnlab-backups /var/log/dnlab \
  /var/lib/dnlab-image-build /opt/vrnetlab
```

`/opt/vrnetlab` is the persistent host mount used by the `image-build`
service. Prepare an empty directory on a fresh host:

```bash
sudo mkdir -p /opt/vrnetlab
```

Each dNLab release records the compatible immutable vrnetlab commit in
`vrnetlab.lock.json`. The `image-build` service automatically creates or
aligns `/opt/vrnetlab` to that commit when it starts. Do not use `git pull` in
`/opt/vrnetlab`: a dirty checkout is deliberately left unchanged and is
reported as a degraded binding through the admin API.

The base Compose stack mounts `/etc/dnlab` read/write only into the GUI so administrators can save supported configuration. Runtime services mount it read-only. Add `compose.hardened.yml` to make the GUI mount read-only too and disable Admin configuration writes.

Prepare SSH from the same point of view used by the containers. For manual
installs, create the dedicated keypair on the master and keep the private key
there:

```bash
install -d -m 0700 /root/.ssh
test -f /root/.ssh/id_ed25519_dnlab || \
  ssh-keygen -t ed25519 -N '' \
    -f /root/.ssh/id_ed25519_dnlab \
    -C "dnlab@$(hostname)"
chmod 0600 /root/.ssh/id_ed25519_dnlab
```

Install `/root/.ssh/id_ed25519_dnlab.pub` in
`/root/.ssh/authorized_keys` on every host declared in `hosts.yml`, including
the configured master target for master-to-master access. For remote workers,
`ssh-copy-id -i /root/.ssh/id_ed25519_dnlab.pub root@<worker-host>` is
acceptable when available. For single-node installs, `master.host` should be
reachable from the `multinode` service over SSH. Because `/root/.ssh` is mounted
read-only inside the containers, add the configured master and worker host keys
to `/root/.ssh/known_hosts` on the host before starting the complete normal
stack. Some RealNet
paths may still look for
`/root/.ssh/id_ed25519`; if you use a dedicated key in `paths.yml`, provide a
controlled alias, symlink or copy at the default key path with the same
permissions as the source key.

Create the dedicated keypair declared as `gui_ssh_key` in `paths.yml`. The GUI
uses it to reach per-lab jumphost containers for Web UI, console and log
tunnels:

```bash
test -f /root/.ssh/dnlab-gui.key || \
  ssh-keygen -t ed25519 -N '' \
    -f /root/.ssh/dnlab-gui.key \
    -C "dnlab@$(hostname)"
chmod 0600 /root/.ssh/dnlab-gui.key
```

### Environment File

Create `.env` from `.env.example` and set a strong database password before
starting the stack. At minimum, set:

```text
DNLAB_VERSION=0.2.5
POSTGRES_PASSWORD=<long random value>
DNLAB_PROXY_SERVER_NAME=<gui-hostname-or-ip>
DNLAB_PROXY_HTTPS_PORT=<https-port>
DNLAB_PROXY_TLS_DIR=<host TLS directory>
DNLABGUI_ALLOWED_ORIGINS=https://<gui-origin>
```

TLS is always enabled by the base Compose file. The GUI, login, consoles and
logs work when this setting is an FQDN, IPv4/IPv6 address or `localhost`.
Device Web UI access alone requires an FQDN because dNLab creates a dynamic
token subdomain for each browser tunnel. Use a site hostname such as:

```text
DNLAB_PROXY_SERVER_NAME=dnlab.example.test
DNLAB_PROXY_HTTPS_PORT=8443
DNLAB_PROXY_TLS_DIR=/etc/ssl/dnlab
DNLABGUI_ALLOWED_ORIGINS=https://dnlab.example.test:8443
```

Important settings:

- `DNLAB_VERSION`: image tag. For the current published release, use `DNLAB_VERSION=0.2.5`.
- `DNLAB_IMAGE_PREFIX`: image registry prefix, normally `ghcr.io/n4alab/`.
- `DNLAB_RUNTIME_IMAGE_PREFIX`: runtime image prefix, normally
  `ghcr.io/n4alab/dnlab-`.
- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`: auth DB settings.
- `DNLAB_PROXY_HTTP_PORT`: public HTTP port used for ACME challenge and HTTP-to-HTTPS redirect.
- `DNLAB_PROXY_SERVER_NAME`: public GUI hostname or IP address. When it is a
  valid FQDN, it also drives Apache wildcard aliases and the GUI Web UI suffix.
  IP addresses and `localhost` support the GUI but not device Web UI proxying.
- `DNLABGUI_ALLOWED_ORIGINS`: browser-facing origin for CORS and WebSocket
  origin checks.
- `DNLAB_TOPOLOGIES_DIR`, `DNLAB_PERSIST_ROOT`, `DNLAB_DEVICE_CATALOG_DIR`,
  `DNLAB_LOG_ROOT`, `DNLAB_IMAGE_BUILD_WORKSPACE`: host-side storage and log
  directories.

Do not keep real bootstrap admin passwords in `.env`; export them only for the
single seed command.

## Host Runtime Prerequisites

### Install Docker And Containerlab Prerequisites

Use this prerequisite path for manual bare-metal installations and for worker
hosts prepared outside the Proxmox LXC template. The published Proxmox LXC
template already preinstalls these packages.

The reference package baseline matches the dNLab template builder: Debian
13/Trixie on `amd64`, Docker Engine from Docker's official Debian repository,
the Docker Compose plugin from the Docker packages, and Containerlab from the
NetDevOps Fury APT repository.

Install the base APT tools first:

```bash
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg
```

Add Docker's official Debian repository and install Docker Engine, containerd,
Buildx and the Compose plugin:

```bash
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
cat >/etc/apt/sources.list.d/docker.list <<'EOF'
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable
EOF

apt-get update
apt-get install -y --no-install-recommends \
  containerd.io \
  docker-buildx-plugin \
  docker-ce \
  docker-ce-cli \
  docker-compose-plugin
```

Add the Containerlab APT repository and install Containerlab:

```bash
cat >/etc/apt/sources.list.d/netdevops.list <<'EOF'
deb [trusted=yes] https://netdevops.fury.site/apt/ /
EOF

apt-get update
apt-get install -y --no-install-recommends containerlab
```

Enable and verify Docker, then record the installed tool versions before
deploying the dNLab stack:

```bash
systemctl enable --now docker
systemctl status docker
docker version
docker compose version
containerlab version
```

### Bare Metal Setup Reference

The ordered first-start procedure above is authoritative. The details here
expand its configuration and release-image steps; do not use the old smoke
check as a required setup step.

1. Copy `hosts.yml.example` and `paths.yml.example` to `/etc/dnlab` as shown
   above, then prepare the host directories. For a single-node install, set
   `master.host` to the Docker-network gateway address reachable from
   containers, such as `172.18.0.1` in an installation where that is the dNLab
   internal-network gateway, and leave `workers` empty. For a multi-node
   install, set the single shared dataplane interface in
   `infrastructure.underlay_iface`.
2. Install or verify the dNLab vrnetlab tree at `/opt/vrnetlab`; it is used by
   the `image-build` service, which automatically aligns it with the exact
   commit recorded by the installed dNLab release.
3. Configure SSH key-based access from the master to every host in
   `hosts.yml`. Generate `/root/.ssh/id_ed25519_dnlab` if needed,
   install its public key in `/root/.ssh/authorized_keys` on the configured
   master target and every worker, and keep the private key only on the master.
   Validate access with a non-interactive command such as
   `ssh -o BatchMode=yes root@<master.host> true` and repeat for every worker
   before starting installation. Also ensure the configured master and worker
   host keys are already present in `/root/.ssh/known_hosts`.
4. Generate `/root/.ssh/dnlab-gui.key` if needed and set
   `gui_ssh_key: /root/.ssh/dnlab-gui.key` in `/etc/dnlab/paths.yml`; the GUI
   uses this key for Web UI, console and log tunnels through jumphost
   containers.
5. If device Web UI access is required, install a wildcard TLS certificate for
   the proxy. For a local test, a
   self-signed certificate under `/etc/ssl/dnlab` is acceptable if clients
   trust its issuer; production should use a publicly trusted or internal-CA
   certificate.

```bash
mkdir -p /etc/ssl/dnlab
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout /etc/ssl/dnlab/dnlab-gui.key \
  -out /etc/ssl/dnlab/dnlab-gui.crt \
  -subj "/CN=dnlab.example.test" \
  -addext "subjectAltName=DNS:dnlab.example.test,DNS:*.dnlab.example.test"
```

6. Copy `.env.example` to `.env`; set `POSTGRES_PASSWORD`,
   `DNLAB_PROXY_SERVER_NAME`, `DNLAB_PROXY_HTTPS_PORT`,
   `DNLAB_PROXY_TLS_DIR` and `DNLABGUI_ALLOWED_ORIGINS`.
7. Public release images are readable without registry login. If the deployment
   uses a private mirror, authenticate Docker to that registry first; Git SSH
   access to the repository is separate from Docker registry access.
8. Pull the full published GHCR image set, then start the proxy dependency
   chain:

```bash
docker compose -f compose.yml --profile release-images pull
docker compose -f compose.yml up -d proxy
```

Use `--profile release-images` only for `pull`. It includes runtime images
such as jumphost, DNS, RealNet and management-anchor helpers that are created
later by lab orchestration; it is not part of the normal `up` command.

9. Seed the first administrator after the complete stack is running:

```bash
DNLABGUI_BOOTSTRAP_ADMIN_USERNAME=admin \
DNLABGUI_BOOTSTRAP_ADMIN_PASSWORD='<one-time-password>' \
docker compose -f compose.yml --profile seed-admin run --rm auth-seed
```

For extended troubleshooting, including `smoke.sh` use, see
[Validation and Troubleshooting](#validation-and-troubleshooting).

### Bare Metal Install From Local Sources

Use this path when the host should build the dNLab Docker images from the
monorepo sources instead of pulling the published GHCR images. Keep the same
host preparation, SSH, TLS, `.env`, vrnetlab and validation steps from the
bare-metal install above.

Application sources live under `/opt/dnlab/src`:

- GUI: `/opt/dnlab/src/gui`
- proxy: `/opt/dnlab/src/gui/deploy/apache/Dockerfile`
- multinode API and image-sync: `/opt/dnlab/src/multinode`
- lab-cleanup: `/opt/dnlab/src/multinode/Dockerfile.cleanup`
- image-build: `/opt/dnlab/src/image-build`
- runtime helper images:
  `/opt/dnlab/src/multinode/{jumphost,dns,runtime-relay,realnet-router,realnet-rr,mgmt-anchor}`

Use a local tag and prefixes that still match `compose.yml` image names:

```text
DNLAB_VERSION=local
DNLAB_IMAGE_PREFIX=dnlab-local/
DNLAB_RUNTIME_IMAGE_PREFIX=dnlab-local/dnlab-
```

Build the application and runtime helper images through the local-build Compose
override. The final image names still come from `compose.yml` and the `.env`
prefix/version variables above; `--profile release-images` only includes the
runtime helper build targets and is not used for the normal `up` command.

```bash
cd /opt/dnlab
docker compose -f compose.yml -f compose.local-build.yml --profile release-images build
```

After the images exist locally, follow the bootstrap and complete-stack steps
in [Bare-Metal First Start](#bare-metal-first-start), without the release-image
pull step:

```bash
docker compose -f compose.yml up -d proxy
# Set infrastructure.master.host after inspecting dnlab_internal, then:
docker compose -f compose.yml up -d
docker compose -f compose.yml ps
```

When a dedicated local-build Compose override is present, use it only as a
shorter way to build the same image names and tags; `compose.yml` remains the
runtime source of truth.

### Proxmox LXC Template Install

Use this path when deploying from the published template documented in
[dNLab Proxmox LXC Template](PROXMOX_LXC_TEMPLATE.md). The template is
pulled from GitHub Container Registry, preinstalls host prerequisites and runs
an idempotent first-boot configurator.

1. Prepare the Proxmox host and CT config as described in the template guide:
   boot the Proxmox node with `loop.max_loop=64`, create a Proxmox LXC CT, and
   apply the dNLab raw-device tuning to `/etc/pve/lxc/<CTID>.conf` with
   `apply-proxmox-ct-tuning.sh <CTID>` or the documented manual block.
2. Let `dnlab-firstboot.service` complete. It creates `.env`, generates a
   local database password, writes `/etc/dnlab/hosts.yml` and
   `/etc/dnlab/paths.yml`, generates the orchestration and GUI-jumphost SSH
   keys, creates a local self-signed TLS certificate and starts the proxy.
3. Run `dnlab-configure-env` inside the CT, or update `/opt/dnlab/.env`
   manually, for the public GUI hostname or IP address, public HTTPS port, certificate directory
   and browser origin:
   `DNLAB_PROXY_SERVER_NAME`, `DNLAB_PROXY_HTTPS_PORT`,
   `DNLAB_PROXY_TLS_DIR` and `DNLABGUI_ALLOWED_ORIGINS`.
4. Replace the generated self-signed certificate with a site certificate before
   production use. Keep the certificate and key names aligned with
   `DNLAB_PROXY_CERT_FILE` and `DNLAB_PROXY_CERT_KEY_FILE`; the guided
   configurator can generate a new local self-signed certificate for test
   deployments.
5. Verify `/etc/dnlab/hosts.yml` and `/etc/dnlab/paths.yml`. The generated
   `paths.yml` should include `ssh_key: /root/.ssh/id_ed25519_dnlab`,
   `gui_ssh_key: /root/.ssh/dnlab-gui.key` and
   `log_root: /var/log/dnlab`.
6. Optionally preload runtime helper images with
   `docker compose -f compose.yml --profile release-images pull`; use that
   profile for pulls only.
7. Start the complete stack with `docker compose -f compose.yml up -d`, seed
   the first administrator and sign in through the CT HTTPS URL. Use
   `smoke.sh` only for troubleshooting as described in
   [Validation and Troubleshooting](#validation-and-troubleshooting).

No additional Proxmox LXC step is required for the `dnlab-vrf` management
network driver when the CT template already includes `v0.2.0` or later.
dNLab installs or refreshes `dnlab-vrf-plugin.service` automatically through
the normal control plane during the first lab management-network deployment or
reconciliation.

## TLS And Wildcard Web UI

TLS is built into `compose.yml`; `compose.tls.yml` remains only as a no-op
compatibility file for older commands and should not be treated as an active
override.

```bash
DNLAB_PROXY_SERVER_NAME=dnlab.example.com \
DNLABGUI_ALLOWED_ORIGINS=https://dnlab.example.com \
DNLAB_PROXY_TLS_DIR=/etc/ssl/dnlab \
docker compose -f compose.yml up -d --force-recreate gui proxy
```

`DNLAB_PROXY_SERVER_NAME` is the single public-host setting for the proxy and
GUI. It may be an FQDN or IP address: in either case the normal GUI proxy,
login, consoles and logs remain available. Compose derives Apache wildcard
aliases and the GUI Web UI suffix only when it is a valid FQDN.
The TLS directory is mounted inside the proxy container as `/etc/ssl/dnlab`.
It must contain the certificate and key referenced by `DNLAB_PROXY_CERT_FILE`
and `DNLAB_PROXY_CERT_KEY_FILE`.

Verify the proxy after TLS changes:

```bash
docker compose -f compose.yml exec -T proxy apache2ctl configtest
curl -kI https://dnlab.example.com/
```

For GUI-only access through an IP address, use a certificate with that address
as an IP subject alternative name instead; it does not enable device Web UIs:

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout /etc/ssl/dnlab/dnlab-gui.key \
  -out /etc/ssl/dnlab/dnlab-gui.crt \
  -subj "/CN=192.0.2.10" \
  -addext "subjectAltName=IP:192.0.2.10"
```

When the setting is an IP address, selecting a device Web UI opens an
explanatory browser page and does not create a tunnel. Device Web UI access is
supported only through wildcard hostnames. Configure
client-facing DNS and certificate coverage for:

- `DNLAB_PROXY_SERVER_NAME`, such as `dnlab.example.com`;
- `*.${DNLAB_PROXY_SERVER_NAME}`, such as `*.dnlab.example.com`.

The proxy receives browser requests for per-device Web UI hostnames and routes
them to the matching Web UI tunnel created by dNLab.

The internal `dnlab-<lab>-dns` containers are per-lab management resolvers.
They are not exposed to browser clients and do not provide this public wildcard
zone. DNS remains site infrastructure managed by the administrator.

`/etc/hosts` cannot define wildcard records. Since dNLab token subdomains are
created dynamically, static hosts-file entries cannot support device Web UI
access. Configure the wildcard in a resolver used by every browser client.

For dnsmasq, add a site-local configuration file such as
`/etc/dnsmasq.d/dnlab-webui.conf`, then reload dnsmasq:

```ini
# Resolve dnlab.example.test and every subdomain to the dNLab proxy.
address=/dnlab.example.test/192.0.2.10
```

For BIND 9, add this zone declaration to `named.conf.local`:

```conf
zone "dnlab.example.test" {
    type master;
    file "/etc/bind/db.dnlab.example.test";
};
```

and create `/etc/bind/db.dnlab.example.test`:

```zone
$TTL 300
@   IN SOA ns1.dnlab.example.test. hostmaster.dnlab.example.test. (1 3600 600 86400 300)
    IN NS  ns1.dnlab.example.test.
ns1 IN A   192.0.2.10
@   IN A   192.0.2.10
*   IN A   192.0.2.10
```

Replace `dnlab.example.test` and `192.0.2.10` with the site FQDN and proxy IP.
For a self-signed lab certificate, generate an apex-plus-wildcard certificate
and install its issuing certificate authority in each browser client trust
store:

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout /etc/ssl/dnlab/dnlab-gui.key \
  -out /etc/ssl/dnlab/dnlab-gui.crt \
  -subj "/CN=dnlab.example.test" \
  -addext "subjectAltName=DNS:dnlab.example.test,DNS:*.dnlab.example.test"
```

Validate DNS, certificate names and proxy configuration before exposing Web UI:

```bash
dig +short dnlab.example.test
dig +short test-token.dnlab.example.test
openssl x509 -in /etc/ssl/dnlab/dnlab-gui.crt -noout -text | grep -A1 'Subject Alternative Name'
docker compose -f compose.yml exec -T proxy apache2ctl configtest
curl --resolve dnlab.example.test:443:192.0.2.10 -kI https://dnlab.example.test/
```

## Authentication And RBAC

The default authentication backend is `local_db`, with Argon2id password hashes
stored in PostgreSQL. Other backends may be configured for reverse-proxy basic
auth, LDAP or OIDC depending on deployment policy.

![Users and roles](images/admin-users-roles.png)

Roles:

- `admin`: full access to all labs and administrator areas.
- `graduate`: can manage own labs and student labs; read-only elsewhere.
- `assistant`: API-only automation role with graduate-like API permissions; it
  cannot use the browser GUI or browser Web UI access.
- `student`: can manage own labs; read-only elsewhere.
- `rookie`: read-only everywhere; cannot create or own labs.

Operational rules:

- New local users default to `rookie` unless an administrator assigns another
  role.
- Only one local-db `assistant` user may exist.
- Keep at least one active local administrator.
- Avoid changing your own role or active state in a way that locks you out.

Administrators can edit the email address, role, active state and password of
local-db accounts from the Users tab. Usernames are immutable; replace an
account if its username must change. LDAP and OIDC accounts retain their
upstream email address, while dNLab administrators can still change their
role or active state because those fields govern dNLab RBAC. Password reset,
role changes and deactivation revoke the account's existing browser sessions.

## Admin Configuration

Administrators can manage shared configuration for hosts, paths and device
catalog metadata from the Admin area.

![Hosts and paths configuration](images/admin-config-hosts-paths.png)

The device catalog controls how the GUI displays device kinds, recognizes
Docker images, chooses icons, maps GUI kinds to Containerlab kinds, injects
defaults and exposes known Web UI metadata.

When an administrator saves the catalog, dNLab stores the complete effective
catalog under `${DNLAB_DEVICE_CATALOG_DIR:-/var/lib/dnlab-device-catalog}` on
the Docker host instead of changing the image asset. On a later image upgrade,
dNLab merges release additions into that saved catalog; if both sides changed
the same value, the administrator's value is retained and the conflict is
logged. Delete this directory only when intentionally resetting all catalog
customizations.

![Device catalog admin](images/admin-device-catalog.png)

Treat catalog changes as platform changes: validate them with a small lab before
making them broadly available.

## VD Disk Persistence

dNLab can preserve disk state for virtual devices whose images support the
dNLab `/persist` overlay model. Persistent data is stored below the configured
persistence root, normally `/var/lib/docker/dnlab-backups`, using stable
per-device identifiers so renaming a node does not by itself orphan its disk
state.

The default backend is `local-sticky`. It keeps a small placement history and
prefers scheduling a persistent virtual device on the same worker that last ran
it. If the scheduler remaps a stopped persistent device, dNLab can migrate the
overlay before deploy.

The Admin hosts/paths configuration exposes persistence settings:

- `backend`: `local-sticky` or `cephfs`;
- `root`: host path used for persistent VD data;
- `migration fallback`: whether dNLab may fall back to local-sticky handling if
  a shared backend preflight fails;
- `CephFS mountpoint`, `CephFS fstype` and shared marker settings.

CephFS-backed persistence is experimental and has not been production-tested.
Do not rely on it for important labs until you have validated mount behavior,
shared marker checks, failure handling, performance and recovery in your own
environment. Keep `local-sticky` as the default operational choice.

## RealNet BGP

RealNet models connectivity from labs to external networks. NAT mode is simple
egress; BGP mode integrates with administrator-managed route reflector
configuration.

![RealNet BGP admin](images/admin-realnet-bgp.png)

These global settings also back the user-facing RealNet BGP lab-to-lab
communication feature. Users can select allowed peer labs from the RealNet node
properties, subject to RBAC, but the route-reflector parameters are configured
centrally here by administrators.

Configure the route-reflector AS and address (`RR AS`, `RR IP`), the host-side
network used for RealNet infrastructure (`Host network`), the pools assigned to
lab routers (`Router AS pool`, `Router IP pool`), the RealNet node network pool,
the route-reflector image and the shared `RR BGP password`. Keep these ranges
large enough for the expected number of RealNet-connected labs and avoid
overlap with physical networks and the data-plane prefixes used inside labs.
Management subnets are isolated per lab and may overlap across different labs
starting with `v0.2.0`; avoid overlap only when the same lab explicitly
connects management and RealNet routing domains.

Use the Admin page to update global RealNet BGP settings, regenerate the route
reflector password when needed and reconcile the route reflector service.
Device-side BGP configuration remains explicit inside each virtual device.

The global `dnlab-realnet-rr` container is BGP-only infrastructure. It is not
created for NAT-only RealNet labs; those labs only create their per-lab
`dnlab-<lab>-<realnet>-realnet` router.

In the base Docker distribution, administrators can update `hosts.yml` from the
Admin area. When using `compose.hardened.yml`, configuration writes are
intentionally disabled; update the host-side YAML during a controlled
maintenance window instead. A minimal BGP block looks like this:

```yaml
infrastructure:
  realnet:
    rr_as: 64512
    rr_ip: 10.0.0.10
    host_net: 10.0.0.0/24
    router_as_pool: 64513-65534
    router_ip_pool: 10.0.0.20-10.0.0.250
    realnet_network_pool: 100.64.0.0/10
    rr_password: change-me
```

## Image Build And Image Sync

`image-build` provides an internal API for virtual-device image uploads,
vrnetlab build jobs and job log streaming. It is separate from building the
dNLab application images from the monorepo sources under `/opt/dnlab/src`.
Build metadata and logs are stored under
`${DNLAB_IMAGE_BUILD_WORKSPACE:-/var/lib/dnlab-image-build}`.
Build contexts are read from `${DNLAB_VRNETLAB_DIR:-/opt/vrnetlab}`, which
is automatically cloned or aligned by `image-build` to the immutable commit
recorded in the release's `vrnetlab.lock.json`.

FLINOS accepts signed production release bundles and development bundles in
the Admin image-build area. Development bundles must be created as the single
`flinos-<release>.zip` output of `make -f build/Makefile qcow-dev`; upload no
loose QCOW2, JSON, version, or launcher files. A development import displays
`Unsigned FLINOS development bundle — not for production` and produces the
separate `vrnetlab/n4alab_flinos-dev:<release>-dnlab` image. It is for testing
only and is not a Secure Boot release image.

![Image build admin](images/admin-image-build.png)

`image-sync` tracks image availability across nodes. After adding or
importing virtual device images, verify image discovery and image sync before
asking users to start labs that depend on those images. dNLab release helper
images are not built locally during installation; preload them with:

```bash
docker compose -f compose.yml --profile release-images pull
```

### Generic persistent VMs

The **Generic VM** entry in Admin → Devices & Images imports an x86 QCOW2 as a
locally built persistent appliance. The wizard creates an image named
`vrnetlab/dnlab_<id>:<version>-dnlab` and, after the image build succeeds,
adds or updates the corresponding device kind in the persistent catalog.

Choose the BIOS/UEFI, NIC model, vCPU, RAM and number of data ports required
by the appliance. Runtime port order is fixed: the first QEMU NIC is
management and each later NIC is a data port. The wizard lets you name every
guest-facing port, including management; dNLab keeps its internal Containerlab
names (`eth0`, `eth1`, …) only as the stable transport mapping. Management is
not offered as a topology link endpoint.

The generated image stores its QCOW2 overlay under `/persist`; UEFI images
also retain their mutable firmware variables there. This preserves disk state
through stop/start, recreate and supported worker migration, but it does not
replace an appliance-specific "save configuration" command inside the guest.

Configure the minimal image-sync filter in `/etc/dnlab/hosts.yml` so workers
receive all `vrnetlab/*` virtual-device images plus the runtime helper images
needed by lab orchestration. Helper names without an explicit tag match all
tags, for example `dnlab-runtime-relay` matches `dnlab-runtime-relay:latest`.

```yaml
image_sync:
  enabled: true
  include:
    - "vrnetlab/*"
    - "dnlab-runtime-relay"
    - "dnlab-mgmt-anchor"
  exclude:
    - "dnlab-jumphost"
    - "dnlab-dns"
    - "dnlab-realnet-router"
    - "dnlab-realnet-rr"
    - "postgres"
    - "<none>:<none>"
  interval_seconds: 300
```

## Lab Cleanup Reconciler

`lab-cleanup` periodically reconciles stale lab artifacts. During first
rollout, keep cleanup in dry-run mode in `/etc/dnlab/hosts.yml`:

```yaml
lab_cleanup:
  enabled: true
  interval_seconds: 300
  grace_seconds: 600
  dry_run: true
```

After validating reports, switch `dry_run` to `false` when the environment is
ready for automatic cleanup.

Manual checks:

```bash
docker compose -f compose.yml exec lab-cleanup \
  dnlab-lab-cleanup sync --dry-run --json

docker compose -f compose.yml exec lab-cleanup \
  dnlab-lab-cleanup sync --execute --json
```

Se un `destroy` trova un host indisponibile, dNLab conserva lo state del lab
con `teardown_requested: true`. Dopo il ritorno dell'host, eseguire il comando
`sync --execute` (possono servire due passaggi: endpoint/container, poi rete e
infrastruttura) invece di cancellare lo state a mano. Un deploy dello stesso
lab resta intenzionalmente bloccato finche il cleanup non ha verificato che gli
artefatti posseduti sono assenti.

## Management Network Driver

Management IPv4 and IPv6 CIDRs need only be valid within one lab: separate labs
may reuse the same CIDR because dNLab isolates their management networks in
separate VRFs. Docker retains native `eth0` for Containerlab nodes, vrnetlab
images, consoles and Web UI tunnels.

When a lab management network is deployed or reconciled, the control plane
automatically installs or refreshes the external `dnlab-vrf` Docker network and
IPAM driver on every required master and worker. It is not a Compose service or
a Docker-managed plugin image. It writes the service unit, socket spec and
state below without patching or restarting `dockerd`:

- `/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py`
- `dnlab-vrf-plugin.service`
- `/etc/docker/plugins/dnlab-vrf.spec`
- `/var/lib/dnlab-vrf-plugin/state.json`

Keep the systemd service, its socket spec and its state while a dNLab
management network exists. For an operational check on a host, use:

```bash
sudo systemctl status dnlab-vrf-plugin.service
sudo journalctl -u dnlab-vrf-plugin.service -n 100 --no-pager
docker network inspect <lab-management-network>
```

## Production Hardening

Use `compose.hardened.yml` after the base Compose file when validating a
production-like stack:

```bash
docker compose \
  -f compose.yml \
  -f compose.hardened.yml \
  up -d --force-recreate gui proxy
```

The hardening override makes the GUI filesystem and `/etc/dnlab` configuration
mount read-only, disables Admin configuration writes, drops GUI Linux
capabilities, adds tmpfs mounts for transient paths, and applies
`no-new-privileges` to GUI, proxy, auth DB and image-build. `multinode`
remains the privileged orchestration boundary for Docker, Containerlab and host
operations. `image-build` keeps the Docker socket because image builds
require Docker and the service remains internal-only.

Run smoke with the same Compose file set:

```bash
COMPOSE_FILES=compose.yml:compose.hardened.yml ./smoke.sh
```

## Validation And Troubleshooting

Use `./smoke.sh` for troubleshooting or after Docker distribution changes. It
is an extended diagnostic, not a required first-start step: it checks proxy
reachability, GUI isolation, internal API boundaries, image discovery, lab
cleanup state and key Docker-stack invariants.

Specifically, smoke verifies that:

- the proxy is reachable;
- the GUI container has no Docker socket;
- the GUI image does not install or import `dnlab-multinode`;
- RealNet RR status, `hosts.yml` validation and image discovery go through
  `multinode`;
- `lab-cleanup` is running and has published a state snapshot;

Run `./preflight.sh` for a fresh-install validation in an isolated Compose
project with an empty database, first-admin bootstrap and login through the
TLS proxy. It starts HTTPS on `18443` and HTTP redirect/ACME on `18080`, runs
Alembic migrations through GUI startup, checks GUI isolation, checks that the
GUI image does not install `dnlab-multinode`, and verifies the image-build API.
The project is removed automatically unless `DNLAB_PREFLIGHT_KEEP=1` is set.

## Upgrade

When upgrading a deployment created before `v0.2.0`, destroy and redeploy its
labs: the former management-network implementation has no in-place migration
to the `dnlab-vrf` driver. Do not remove the driver service, socket spec or
state until the old Docker management networks no longer exist.

Before upgrading, back up the auth DB:

```bash
sudo install -d -m 0700 /var/backups/dnlab/auth-db
docker compose -f compose.yml exec -T auth-db sh -lc \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges' \
  | sudo sh -c 'umask 077; cat > /var/backups/dnlab/auth-db/dnlab_auth_before_upgrade.sql'
```

Pull the full release image set selected by `.env`, then recreate the internal
services and proxy:

```bash
grep '^DNLAB_VERSION=0.2.5$' .env
docker compose -f compose.yml --profile release-images pull
docker compose -f compose.yml up -d --force-recreate multinode image-sync lab-cleanup image-build gui proxy auth-db
```

For the `0.1.2` logging migration, replace any old per-service logging entries
with `log_root: /var/log/dnlab`. Use `DNLAB_LOG_ROOT` only if the host-side log
root must differ from `/var/log/dnlab`. See
`CHANGELOG.md` for the legacy key names and one-time migration
checklist.

Run guardrails:

```bash
./smoke.sh
```

After validating cleanup dry-run reports, either keep scheduled dry-runs or
switch the reconciler to execution mode in `/etc/dnlab/hosts.yml`:

```yaml
lab_cleanup:
  enabled: true
  interval_seconds: 300
  grace_seconds: 600
  dry_run: false
```

## Backup And Restore

Use `pg_dump` and `psql` for the auth database. Keep dumps outside images and
outside git. Store local operator backups under `/var/backups/dnlab/auth-db`
or another protected path outside the source checkout.

Restore is an operator action, not a Docker build step. Stop the GUI before
restoring, reset the target schema, load the dump, restart through the proxy and
run smoke checks.

```bash
docker compose -f compose.yml stop gui
docker compose -f compose.yml exec -T auth-db sh -lc \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "drop schema public cascade; create schema public;"'
docker compose -f compose.yml exec -T auth-db sh -lc \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' \
  < /var/backups/dnlab/auth-db/dnlab_auth_restore.sql
docker compose -f compose.yml up -d proxy
COMPOSE_FILES=compose.yml \
DNLAB_SMOKE_PROXY_URL=https://dnlab.example.test:8443/ \
DNLAB_SMOKE_CURL_RESOLVE=dnlab.example.test:8443:127.0.0.1 \
DNLAB_SMOKE_CURL_INSECURE=1 \
./smoke.sh
```
