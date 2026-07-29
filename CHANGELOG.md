# Changelog

All notable public changes to dNLab are recorded in this file.

This changelog is generated from the structured release sources in
`docs/releases/`. Internal bug-tracking references stay in the private
operational repository and are not published here.

## 0.2.0 - 2026-07-29

Feature release for live topology changes, overlapping management subnets,
canvas annotations and shared VD consoles.

### Added

- Add warm links and live topology changes: Compatible per-VD images can add or
  remove dataplane links and nodes while a lab is running, with capability
  validation, deterministic host networking, persisted runtime state and
  rollback on partial failure.
- Allow overlapping management subnets across labs: dNLab now provisions lab
  management networks through the custom dnlab-vrf Docker NetworkDriver and
  IpamDriver, preserving Docker-native eth0 for Containerlab, vrnetlab consoles
  and Web UIs while allowing different labs to reuse the same IPv4 or IPv6
  management subnet in separate VRFs.
- Annotate canvas topology diagrams: The GUI can color individual links, add
  editable text, rectangle and circle annotations with ordered layers around VD
  icons, and preserve those visual aids through draw.io export and import.
- Build managed images without an uploaded source: Image-build metadata and the
  administration UI can start managed source-free builds while retaining upload
  validation for device images that require a vendor artifact.
- Restart individual per-VD nodes: The GUI and multinode API can restart an
  individual node in a per-VD lab by performing a controlled stop and start
  without redeploying the entire lab.
- Share VD consoles across concurrent sessions: VD consoles can be shared
  concurrently by GUI and SSH sessions through one runtime connection, and the
  GUI can open every live VD console in one tabbed window.

### Changed

- Document GUI API operations for agents: The GUI OpenAPI schema now explains
  each HTTP operation's purpose, relevant constraints, side effects, and result
  so API agents can select calls safely.
- Expose live runtime operation state: The topology UI now reports actionable
  start and stop capabilities, displays active node operations and partial link
  failures, and safely removes live runtime nodes before deleting their topology
  definitions.

### Fixed

- Persist custom dNLab images: Per-lab topology generation now preserves
  configured custom dNLab image references instead of replacing them during
  multinode generation.
- Preserve RouterOS overlays across rebuilds: RouterOS image rebuilds now retain
  their writable overlay state instead of losing persisted device data during
  the rebuild workflow.
- Quote per-VD topology paths over SSH: Remote per-VD operations now safely
  quote topology paths, including paths containing characters that the remote
  shell would otherwise interpret.
- Reclaim running lab containers without deployment state: The lab cleanup
  reconciler now reclaims running VD and per-lab infrastructure containers when
  no valid multinode deployment state exists and the grace window has expired,
  preventing incomplete destroy operations from leaving permanently protected
  artifacts.
- Refresh host and device image metadata: Image synchronization now refreshes
  host inventory and device catalog metadata so newly available or updated
  images are shown consistently.
- Select the declared XRv9k console port: Console discovery now prefers the
  launcher-declared interactive serial port and limits fallback selection to the
  supported console range, avoiding attachment to an unrelated XRv9k serial
  socket.

### Breaking Changes

- Allow overlapping management subnets across labs: dNLab now provisions lab
  management networks through the custom dnlab-vrf Docker NetworkDriver and
  IpamDriver, preserving Docker-native eth0 for Containerlab, vrnetlab consoles
  and Web UIs while allowing different labs to reuse the same IPv4 or IPv6
  management subnet in separate VRFs.

### Upgrade Notes

- Starting with v0.2.0, destroy and redeploy labs created with the former
  management-network implementation; deployed management networks are not
  migrated in place.
- Ensure each master and worker can run the automatically installed
  dnlab-vrf-plugin.service; no patched Docker Engine is required.

### Artifacts

- Source archives: *-0.2.0-source.tar.gz (GitHub Release)
- Source checksums: SHA256SUMS (GitHub Release)
- Proxmox LXC template: dnlab-lxc-proxmox-0.2.0-amd64.tar.zst (GHCR and GitHub
  Release mirror)
- Proxmox LXC release notes: LXC-RELEASE-NOTES-0.2.0.md (GHCR and GitHub Release
  mirror)

## 0.1.2 - 2026-07-08

Logging release that standardizes runtime infrastructure logs under a single
/var/log/dnlab root across the Docker stack.

### Changed

- Runtime log layout: Persistent service logs now live under /var/log/dnlab with
  dedicated subdirectories for proxy, gui, auth-db, multinode, image-sync,
  lab-cleanup, and image-build.
- Image-build job logs remain application data: Image-build job logs stay under
  /var/lib/dnlab-image-build/logs because they are job history data used by the
  GUI, not service infrastructure logs.

### Breaking

- Unified runtime log root: /etc/dnlab/paths.yml now uses log_root:
  /var/log/dnlab. The previous public keys log_dir_gui and log_dir_multinode are
  removed, and the Compose environment variables DNLAB_LOG_DIR_GUI and
  DNLAB_LOG_DIR_MULTINODE are replaced by DNLAB_LOG_ROOT.

### Upgrade Notes

- Create the log root before recreating services: sudo mkdir -p /var/log/dnlab
- Replace old logging keys in /etc/dnlab/paths.yml with log_root: /var/log/dnlab
- Replace DNLAB_LOG_DIR_GUI and DNLAB_LOG_DIR_MULTINODE with DNLAB_LOG_ROOT in
  .env customizations.
- Recreate runtime services with docker compose -f compose.yml up -d
  --force-recreate proxy gui auth-db multinode image-sync lab-cleanup
  image-build.
- Run ./smoke.sh after the upgrade to verify service health and log files.

### Artifacts

- Source archives: *-0.1.2-source.tar.gz (GitHub Release)
- Source checksums: SHA256SUMS (GitHub Release)
- Proxmox LXC template: dnlab-lxc-proxmox-0.1.2-amd64.tar.zst (GHCR and GitHub
  Release mirror)
- Proxmox LXC release notes: LXC-RELEASE-NOTES-0.1.2.md (GHCR and GitHub Release
  mirror)

## 0.1.1 - 2026-07-07

Bugfix release for stale per-lab service cleanup and Docker Compose naming, plus
runtime helper image prefix consistency.

### Fixed

- Orphan per-lab service containers were not always cleaned up: The cleanup
  reconciler now protects a lab only when actual VD runtime containers are
  running. Per-lab service containers such as runtime relay, DNS, jumphost,
  legacy logging services, and mgmt-anchor no longer keep an inactive lab from
  being cleaned up by themselves.
- Duplicated Docker Compose service prefixes: Compose service keys were
  normalized so the Compose project name no longer produces duplicated
  dnlab-dnlab-* container names. Documentation now uses the clean service names
  such as proxy, gui, multinode, image-sync, lab-cleanup, image-build, and
  auth-db.
- Runtime helper image prefix mismatch: Runtime helper image naming is now
  driven by configuration instead of duplicated Compose defaults, keeping local
  flat image names and GHCR release image names consistent across multinode
  services and release image preload placeholders.

### Artifacts

- Source archives: *-0.1.1-source.tar.gz (GitHub Release)
- Source checksums: SHA256SUMS (GitHub Release)

## 0.1.0 - 2026-06-18

Initial public dNLab release with the Docker Compose distribution, GHCR image
publication, corresponding source archives, and the first Proxmox LXC template
artifact.

### Added

- Public Compose distribution: Added the public dNLab distribution repository
  with Compose files, install documentation, source availability policy, and
  administrator guides for the first published release.
- GHCR release images: Published the dNLab service image family under
  ghcr.io/scaci/dnlab-* for versioned installations.
- Proxmox LXC template: Published the first ready-made Proxmox LXC template for
  dNLab with the required Proxmox helper assets and first-boot setup flow.

### Artifacts

- Source archives: *-0.1.0-source.tar.gz (GitHub Release)
- Source checksums: SHA256SUMS (GitHub Release)
- Proxmox LXC template: dnlab-lxc-proxmox-0.1.0-amd64.tar.zst (GHCR and GitHub
  Release mirror)
- Proxmox LXC release notes: LXC-RELEASE-NOTES-0.1.0.md (GHCR and GitHub Release
  mirror)
