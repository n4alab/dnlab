# dNLab Proxmox LXC Template

This guide is for administrators who want to run dNLab from the ready-made
Proxmox LXC template published on GitHub Container Registry.

This artifact is built and supported for Proxmox LXC. Generic LXC runtimes are
not a supported target for this template.

You do not need to build the template yourself for a normal installation.

## Download From GHCR

The primary distribution channel for the LXC template is GHCR:

```text
ghcr.io/n4alab/dnlab-lxc-proxmox:0.2.5
```

Install `oras` on your workstation or Proxmox host then pull the artifact:

```bash
mkdir -p dnlab-lxc-0.2.5
cd dnlab-lxc-0.2.5
oras pull ghcr.io/n4alab/dnlab-lxc-proxmox:0.2.5
sha256sum -c SHA256SUMS
```

The artifact contains:

```text
dnlab-lxc-proxmox-0.2.5-amd64.tar.zst
LXC-RELEASE-NOTES-0.2.5.md
proxmox-dnlab-ct.conf
apply-proxmox-ct-tuning.sh
prepare-proxmox-ct.sh
SHA256SUMS
```

The same files may also be attached to the GitHub Release as a browser-friendly
mirror, but GHCR is the canonical registry location.

The template does not contain production secrets, admin bootstrap credentials,
site TLS certificates or a fixed hostname. Those are generated or configured
inside each CT.

The template redistributes Debian packages, Docker Engine packages,
Containerlab and dNLab files. License and package evidence is included inside
the CT at `/usr/share/doc/dnlab/third-party/`, alongside the dNLab source tree
under `/opt/dnlab`.

## Prepare The Proxmox Host

dNLab LXC deployments need enough loop devices for nested lab workloads. On the
Proxmox host, add `loop.max_loop=64` to the kernel command line. With the
default GRUB flow, edit `/etc/default/grub` and include it in
`GRUB_CMDLINE_LINUX_DEFAULT`, for example:

```text
GRUB_CMDLINE_LINUX_DEFAULT="quiet loop.max_loop=64"
```

Then update GRUB and reboot the Proxmox node:

```bash
update-grub
reboot
```

After reboot, verify the host command line:

```bash
grep -w loop.max_loop=64 /proc/cmdline
```

## Create The CT

dNLab needs Docker, Containerlab, nested containers and host-like networking.
Bare metal remains the reference deployment model; Proxmox LXC is usable only
when the CT exposes the required privileges and kernel features.

Copy `dnlab-lxc-proxmox-0.2.5-amd64.tar.zst` to a Proxmox storage that accepts
CT templates, normally:

```bash
cp dnlab-lxc-proxmox-0.2.5-amd64.tar.zst /var/lib/vz/template/cache/
```

Then create a CT from it.

Recommended starting point:

```text
ostype: debian
arch: amd64
cores: 4
memory: 8192
swap: 2048
rootfs: local-lvm:64
net0: name=eth0,bridge=vmbr0,ip=dhcp
features: nesting=1,keyctl=1
unprivileged: 1
```

If the CT must live on a tagged VLAN, set the site-specific VLAN tag on `net0`.
This is optional and depends on your Proxmox host and switch design. In the
Proxmox GUI this is the **VLAN Tag** field; in `/etc/pve/lxc/<CTID>.conf` it is
stored as `tag=<vlan-id>`, for example:

```text
net0: name=eth0,bridge=vmbr0,tag=10,ip=dhcp
```

The bridge and physical switch path must carry the configured tagged VLAN. If
no VLAN tag is configured, the CT uses the untagged network on the selected
bridge.

Use reliable local ext4 or xfs-backed storage for Docker data. Increase CPU,
memory and disk for larger network labs or image-build workloads.

### Prepare The CT Config

Before first boot, run the dNLab Proxmox preparation helper on the Proxmox
host. It validates the CT network, host loop-device setting and LXC features,
then applies the raw-device tuning idempotently to
`/etc/pve/lxc/<CTID>.conf`:

```bash
chmod +x prepare-proxmox-ct.sh apply-proxmox-ct-tuning.sh
./prepare-proxmox-ct.sh <CTID>
```

The helper creates a timestamped backup of the CT config and appends only
missing raw-device tuning lines. It does not change `net0`, bridge, VLAN, MAC,
firewall or IP settings.

If you prefer to edit the CT config manually, add this block:

```text
lxc.cgroup2.devices.allow: c 10:232 rwm
lxc.mount.entry: /dev/kvm dev/kvm none bind,optional,create=file

lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,optional,create=file

lxc.cgroup2.devices.allow: b 7:* rwm
lxc.mount.entry: /dev/loop-control dev/loop-control none bind,optional,create=file

lxc.cgroup2.devices.allow: c 10:229 rwm
lxc.mount.entry: /dev/fuse dev/fuse none bind,optional,create=file

lxc.autodev: 1
```

Restart the CT after changing `/etc/pve/lxc/<CTID>.conf`.

### DHCP And VLAN Troubleshooting

New templates configure `systemd-networkd` to bring `eth0` up with IPv4 DHCP.
If a CT was created from an older template and `eth0` stays down or never gets
an address, configure it inside the CT:

```bash
mkdir -p /etc/systemd/network
cat >/etc/systemd/network/20-eth0.network <<'EOF'
[Match]
Name=eth0

[Network]
DHCP=ipv4
IPv6AcceptRA=no

[DHCPv4]
UseDNS=true
UseDomains=true
EOF

systemctl enable --now systemd-networkd
ip link set eth0 up
systemctl restart systemd-networkd
```

Then verify the link, address and DNS:

```bash
ip addr show eth0
networkctl status eth0
journalctl -u systemd-networkd -n 50 --no-pager
resolvectl status || cat /etc/resolv.conf
ping -c 3 1.1.1.1
getent hosts ghcr.io
```

If `networkctl` reports `Failed to connect to system bus` when used through
`pct enter`, rely on `ip addr show eth0`, `systemctl status systemd-networkd`
and `journalctl -u systemd-networkd` instead.

On the Proxmox host, verify the CT network line and VLAN-aware bridge state:

```bash
pct config <CTID>
grep -A20 -n 'iface vmbr0' /etc/network/interfaces
bridge vlan show
```

For a CT on a tagged VLAN, `pct config <CTID>` should include a network line
like:

```text
net0: name=eth0,bridge=vmbr0,tag=10,ip=dhcp
```

To see whether DHCP requests leave the host bridge on a tagged VLAN, replace
`10` with the configured VLAN ID and run this on the Proxmox host while
rebooting the CT:

```bash
tcpdump -eni vmbr0 'vlan 10 and (port 67 or port 68)'
pct reboot <CTID>
```

If DHCP discovers appear but no offers return, fix the upstream VLAN/DHCP path.
If no discovers appear, fix the CT network configuration or `systemd-networkd`
inside the CT.

## First Boot

Start the CT and wait for `dnlab-firstboot.service` to finish:

```bash
systemctl status dnlab-firstboot
```

The first-boot service runs `/usr/local/sbin/dnlab-firstboot`, which:

- creates `/opt/dnlab/.env` from `.env.example`;
- generates `POSTGRES_PASSWORD`;
- creates a local self-signed certificate under `/etc/ssl/dnlab` for the
  detected FQDN, or with an IP SAN for the CT address when no FQDN is available;
- writes `/etc/dnlab/paths.yml`;
- creates a local root SSH key and authorizes it for root-to-root access;
- creates the GUI-to-jumphost SSH key used for Web UI, console and log
  tunnels;
- creates the Compose network, discovers its gateway and writes
  `/etc/dnlab/hosts.yml`;
- starts `docker compose -f compose.yml up -d proxy`;
- preloads the full release image set best-effort;
- creates the first `admin` user with a generated password and stores it in
  `/root/dnlab-first-admin.txt`.

The release image preload is best-effort: a temporary GHCR or network failure
does not fail first boot. To retry the image preload manually, run this inside
the CT:

```bash
cd /opt/dnlab
docker compose -f compose.yml --profile release-images pull
```

No extra LXC installation step is required for the dNLab `dnlab-vrf`
management network driver. When the template already includes a release at or
after `v0.2.0`, the normal dNLab control plane installs or refreshes
`dnlab-vrf-plugin.service` automatically on the CT during the first lab
management-network deployment or reconciliation. The driver is not a patched
Docker Engine and does not require a separate package, Compose service or
Proxmox CT setting.

The GUI can be reached through the detected CT IP address. To enable device
Web UI proxying as well, configure an FQDN, wildcard DNS and a certificate
covering both the FQDN and its wildcard subdomain from the CT console.

After configuration, the HTTPS URL defaults to port `8443`:

```text
https://<ct-address>:8443/
```

Because a self-signed certificate is not trusted by default, install its CA in
each browser client or replace it with a site certificate before production use.

Read the generated first-admin credentials as root:

```bash
cat /root/dnlab-first-admin.txt
```

The file is created with mode `0600` and is not stored in `.env`.

## Configure Site Settings

The LXC template is already installed, but the generated instance still needs
site-specific settings in `/opt/dnlab/.env`. This corresponds to the bare metal
environment-file step in [ADMIN_GUIDE.md](ADMIN_GUIDE.md), with the host
prerequisites and first config files already prepared by first boot.

Run the guided configurator inside the CT:

```bash
sudo dnlab-configure-env
```

Run this before attempting to sign in through the browser. It accepts a public
GUI FQDN, IP address or `localhost`. An FQDN must have client-reachable
wildcard DNS, or be ready for the DNS configuration in the administrator guide,
when device Web UI access is required.

It prompts for:

- `DNLAB_PROXY_SERVER_NAME`: public GUI FQDN, IP address or `localhost`.
  IP addresses and `localhost` support the GUI but not device Web UI proxying;
- `DNLAB_PROXY_HTTP_PORT` and `DNLAB_PROXY_HTTPS_PORT`: public proxy ports;
- `DNLAB_PROXY_TLS_DIR`: host directory mounted into the proxy as
  `/etc/ssl/dnlab`;
- `DNLABGUI_ALLOWED_ORIGINS`: browser-facing HTTPS origin;
- `DNLAB_PROXY_CERT_FILE` and `DNLAB_PROXY_CERT_KEY_FILE`: certificate and key
  paths as seen inside the proxy container.

The TLS directory is a host path mounted into the proxy container as
`/etc/ssl/dnlab`. Therefore `DNLAB_PROXY_CERT_FILE` and
`DNLAB_PROXY_CERT_KEY_FILE` must be paths under `/etc/ssl/dnlab` as seen inside
the proxy container. If the configured certificate or key is missing under the
host TLS directory, the script can generate a new local self-signed certificate
with the selected IP as an IP SAN, or covering the selected FQDN and
`*.${DNLAB_PROXY_SERVER_NAME}`.

For device Web UI access, install a certificate that covers both the GUI FQDN
and `*.${DNLAB_PROXY_SERVER_NAME}`. Configure a client-reachable wildcard DNS
zone for the same names; see [TLS and Wildcard Web UI](ADMIN_GUIDE.md#tls-and-wildcard-web-ui)
for dnsmasq and BIND examples. For GUI-only IP access, use a certificate with
the address as an IP SAN. A self-signed certificate must be trusted by each
browser client.

The generated `/etc/dnlab/paths.yml` should match the bare metal shape and
include both SSH keys plus the shared log root:

```yaml
ssh_key: /root/.ssh/id_ed25519_dnlab
gui_ssh_key: /root/.ssh/dnlab-gui.key
log_root: /var/log/dnlab
```

The corresponding public keys are:

```bash
cat /root/.ssh/id_ed25519_dnlab.pub
cat /root/.ssh/dnlab-gui.key.pub
```

`ssh_key` is the master-to-worker orchestration key. On the generated
single-node CT, its public key is added to `/root/.ssh/authorized_keys` for
root-to-root access. `gui_ssh_key` is used by the GUI for per-lab jumphost Web
UI, console and log tunnels.

If you edit `.env` manually instead of using the guided script, recreate the GUI
and proxy after changing hostname, origin, ports or TLS settings:

```bash
cd /opt/dnlab
docker compose -f compose.yml up -d --force-recreate gui proxy
```

## Sign In

After first boot, read the generated admin credentials:

```bash
cat /root/dnlab-first-admin.txt
```

Then open:

```text
https://<ct-address-or-fqdn>:8443/
```

## Validate

Useful checks inside the CT:

```bash
docker version
docker compose version
containerlab version
docker compose -f /opt/dnlab/compose.yml ps
```

Run the HTTPS smoke check:

```bash
cd /opt/dnlab
COMPOSE_FILES=compose.yml \
DNLAB_SMOKE_PROXY_URL=https://dnlab.example.test:8443/ \
DNLAB_SMOKE_CURL_RESOLVE=dnlab.example.test:8443:192.0.2.10 \
DNLAB_SMOKE_CURL_INSECURE=1 \
./smoke.sh
```

Replace `dnlab.example.test` and `192.0.2.10` with the configured FQDN and CT
address when the client resolver does not already provide the wildcard record.

To rerun the first-boot configurator safely:

```bash
sudo dnlab-firstboot
```

Existing `hosts.yml` and `paths.yml` are preserved by default. To regenerate
them:

```bash
sudo DNLAB_FIRSTBOOT_REWRITE_HOSTS=1 DNLAB_FIRSTBOOT_REWRITE_PATHS=1 dnlab-firstboot
```

To rerun only the hostname, port and TLS prompts, use:

```bash
sudo dnlab-configure-env
```
