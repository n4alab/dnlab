# Source Availability

dNLab container images are distributed through GitHub Container Registry
(`GHCR`) under the `ghcr.io/n4alab/dnlab-*` image names. Public release packages
are linked to the public `n4alab/dnlab` repository, even when the operational
repositories used to build those images remain private.

For each public dNLab image tag, the corresponding source code will be
published as a source archive attached to the matching dNLab release. The
archive for a release tag must match the container images published with that
same tag.

For example:

- Image: `ghcr.io/n4alab/dnlab-gui:0.1.2`
- Source: release `v0.1.2`, artifact `dnlab-gui-0.1.2-source.tar.gz`

The corresponding source archive must include the application source,
Dockerfiles, build scripts, release metadata and configuration needed to build,
install, run and modify the distributed image.

## Release assets

Source archives are published as assets on the matching `n4alab/dnlab` GitHub
Release. They are not committed as binary files in this repository.

For a release `vX.Y.Z`, the expected source asset names are:

- `dnlab-gui-X.Y.Z-source.tar.gz`
- `dnlab-proxy-X.Y.Z-source.tar.gz`
- `dnlab-multinode-X.Y.Z-source.tar.gz`
- `dnlab-lab-cleanup-X.Y.Z-source.tar.gz`
- `dnlab-jumphost-X.Y.Z-source.tar.gz`
- `dnlab-dns-X.Y.Z-source.tar.gz`
- `dnlab-runtime-relay-X.Y.Z-source.tar.gz`
- `dnlab-realnet-router-X.Y.Z-source.tar.gz`
- `dnlab-realnet-rr-X.Y.Z-source.tar.gz`
- `dnlab-mgmt-anchor-X.Y.Z-source.tar.gz`
- `dnlab-image-build-X.Y.Z-source.tar.gz`
- `CHANGELOG-X.Y.Z.md`
- `RELEASE_NOTES-X.Y.Z.md`
- `RELEASE-MANIFEST-X.Y.Z.json`
- `SHA256SUMS`

Each source archive includes a `SOURCE-MANIFEST.json` file that identifies the
image, version, source repository, release tag, commit SHA, Dockerfile and build
context used for the corresponding image.

The changelog, release notes and release manifest assets are generated from the
structured release source in `docs/releases/X.Y.Z.yml`. `CHANGELOG.md` remains
the version-controlled aggregate changelog, while the generated assets are the
immutable release snapshot attached to the GitHub Release.

During development, each logical modification is recorded in
`changes/pending/*.yml`. `scripts/changes.py release` validates and archives
those fragments, creates the versioned release source, regenerates the
aggregate changelog, and writes the release snapshot assets. Public output only
contains fragments marked `visibility: public`; internal records remain
traceable in the versioned archive but are not release notes.

Each public image should also carry a generated third-party notice bundle inside
the image at `/usr/share/doc/dnlab/third-party/`. The bundle records the image
SBOM, package metadata and license files for base-image packages, Python
dependencies and other included third-party components. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the bundle layout and
validation expectations.

After downloading the assets for a release, verify them with:

```bash
sha256sum -c SHA256SUMS
```

The source archive generation and publication workflow is maintained as a
release engineering process in the private operational documentation. This
document records the public source availability policy; it does not require
private operational repositories to be made public.

## Proxmox LXC Template

Some releases also include a ready-made Proxmox LXC template published as an
OCI artifact on GitHub Container Registry, for example
`ghcr.io/n4alab/dnlab-lxc-proxmox:0.1.2`. The template is a distribution binary;
it is not committed to this repository.

The LXC template build and first-boot helper code is internal release
orchestration and is not committed to this public repository. The template
includes the public dNLab distribution tree copied into `/opt/dnlab`; the
per-image AGPL source archives listed above remain the corresponding source for
the GHCR images used by the stack. The Proxmox helper assets needed to install
the template are attached to the GitHub Release as a browser-friendly mirror,
while GHCR is the canonical registry location.

The template is also expected to include
`/usr/share/doc/dnlab/third-party/`, containing the Debian package inventory,
Docker package metadata, Containerlab metadata, copied package license files
and the generated template third-party notice.
