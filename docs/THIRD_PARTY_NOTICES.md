# Third-Party Notices

dNLab is licensed under `AGPL-3.0-or-later`. It also uses, invokes, packages
or helps build software distributed under other licenses. This file is the
project-level notice index; release artifacts must include artifact-specific
notice bundles as described below.

This document is informational and is not legal advice.

## Notice Bundle Format

Each public binary artifact should have a generated notice bundle:

```text
dist/notices/<artifact>/
  SBOM.spdx.json
  THIRD_PARTY_NOTICES.md
  package-metadata/
  license-files/
```

For container images, copy the bundle into the image at:

```text
/usr/share/doc/dnlab/third-party/
```

For the Proxmox LXC template, include the same path inside the rootfs. The
bundle records the exact packages present in that artifact; this top-level file
does not try to replace per-image SBOMs.

## Host Prerequisites

The standard bare-metal deployment expects administrators to install these
host tools:

- Debian GNU/Linux or another supported Linux distribution.
- Docker Engine, containerd, Docker Buildx and the Docker Compose plugin.
- Containerlab.

These tools are not distributed by the dNLab Docker Compose stack when they are
installed directly on the host. Administrators are responsible for complying
with the licenses of the packages they install. dNLab services may bind-mount
the host `containerlab` binary into containers so the service can invoke it as
an external runtime tool.

The Proxmox LXC template is different: it bundles Docker packages,
Containerlab, Debian packages and dNLab files in one redistributable rootfs.
See the template section below.

## Distributed dNLab Images

Public dNLab images are published as `ghcr.io/n4alab/dnlab-*` images. Each image
must carry an embedded notice bundle under
`/usr/share/doc/dnlab/third-party/`.

Current release image families:

- `ghcr.io/n4alab/dnlab-gui`
- `ghcr.io/n4alab/dnlab-proxy`
- `ghcr.io/n4alab/dnlab-multinode`
- `ghcr.io/n4alab/dnlab-lab-cleanup`
- `ghcr.io/n4alab/dnlab-image-build`
- `ghcr.io/n4alab/dnlab-jumphost`
- `ghcr.io/n4alab/dnlab-dns`
- `ghcr.io/n4alab/dnlab-runtime-relay`
- `ghcr.io/n4alab/dnlab-realnet-router`
- `ghcr.io/n4alab/dnlab-realnet-rr`
- `ghcr.io/n4alab/dnlab-mgmt-anchor`

The images include combinations of Debian, Alpine Linux, Python packages, APT
or APK packages and dNLab application code. Examples include Apache HTTP
Server, OpenSSH, Docker CLI packages, FRRouting, dnsmasq, tcpdump, qemu-utils,
FastAPI, Pydantic, Docker SDK for Python and Paramiko. Image-specific SBOMs
and package metadata are the release source of truth for exact versions and
licenses.

Known direct Python license flags to verify in generated image bundles:

- `paramiko==4.0.0` declares `LGPL-2.1` in PyPI metadata.
- Docker SDK for Python declares Apache Software License classifiers in PyPI
  metadata.
- FastAPI and Pydantic declare MIT License classifiers in PyPI metadata.

## Proxmox LXC Template

The Proxmox LXC template is a redistributed binary artifact. It includes a
Debian rootfs, Docker Engine packages, Containerlab, dNLab source files and the
Compose stack that pulls the runtime images.

The template build must capture:

- `dpkg-query` package inventory.
- `/var/lib/dpkg/status`.
- Debian package copyright files under `/usr/share/doc/*/copyright`.
- Docker package metadata and documentation present in the rootfs.
- Containerlab version, package metadata, package file list and any installed
  license or notice files.
- This repository's `LICENSE`, `docs/LICENSE_FAQ.md`,
  `docs/THIRD_PARTY_NOTICES.md` and `docs/SOURCE.md`.

Containerlab license metadata can differ by installed package version or
distribution channel. For example, a previously sampled LXC artifact contained
`containerlab 0.76.1` package metadata declaring `License: GNU GPLv3`, while
the current upstream GitHub repository presents a `BSD-3-Clause` project
license. dNLab release validation must preserve the exact package evidence for
the shipped artifact and must not replace it with an assumed license.

## Generated Or Patched Images

`src/image-build` can build or patch images derived from upstream images such
as `vrnetlab/*`, `quay.io/frrouting/frr`, or user-provided vendor/NOS images.
When dNLab builds a `-dnlab` image it applies dNLab persistence or startup
patches to files extracted from the upstream image.

If dNLab distributes such an image, the distributed image must:

- preserve applicable upstream license and copyright notices;
- include a dNLab derived-image notice describing the upstream image, upstream
  digest, patch kind and dNLab version;
- mark modified files or otherwise make the modification provenance clear;
- comply with the license terms of the upstream image and any included vendor
  software.

dNLab does not distribute proprietary network operating system images. Users
who build private images from vendor media are responsible for complying with
the relevant vendor license terms.

## Stock External Images

The Compose stack references `postgres:16-alpine` as a stock external image.
dNLab does not mirror or redistribute that image by default. If dNLab mirrors,
vendors, republishes or modifies it, the relevant PostgreSQL, Alpine Linux and
package notices must be preserved in the redistributed artifact.

## Non-Endorsement

The names Docker, Debian, Alpine Linux, PostgreSQL, Containerlab, Nokia,
srl-labs, FRRouting and vendor NOS names identify third-party projects or
products. Their use in dNLab documentation and metadata does not imply
endorsement, sponsorship or affiliation unless explicitly stated by the
respective rights holder.
