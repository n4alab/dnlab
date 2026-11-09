# Initial direct-VM template inventory

This is source analysis for the experimental libvirt backend, not a bootable
bundle or a qualification of the guest. Only `_V2` launchers are considered.
No launcher or image-build recipe was executed to obtain these facts.

## Source profiles

| Property | n9kv `_V2` | vIOS `_V2` |
|---|---|---|
| Launcher | `cisco/n9kv_V2/docker/launch.py` | `cisco/vios_V2/docker/launch.py` |
| Components | One QEMU VM | One QEMU VM, router or switch variant |
| Launcher RAM default | 10,240 MiB | Router 512 MiB; switch 768 MiB |
| Launcher vCPU default | 4 | 1 |
| CPU default from common launcher | `host` | `host` |
| Disk attachment | AHCI controller and SATA disk on `ahci0.0` | virtio disk |
| Firmware | Explicit `OVMF.fd` supplied with the V2 source | No explicit firmware asset; QEMU default |
| NIC model default | `e1000` | `e1000` |
| NIC capacity configured by launcher | `num_nics=129`, plus common first NIC | `num_nics=15`, plus common first NIC |
| Management in direct-VM model | One OOB NIC | One selected and reserved data NIC |
| Initial guest automation | Manual bootstrap/readiness; shutdown unqualified | Manual bootstrap/readiness; shutdown unqualified |

Common hardware and NIC generation are in `common/vrnetlab.py`. Image-build
patches also contribute behavior: `src/image-build/patches/cisco_n9kv.py` and
`cisco_vios.py`, together with `_common.py`, must remain part of source provenance.
The container Dockerfile's base QEMU version is not a host-libvirt capability
claim. Image tags, launcher defaults and GUI catalog defaults are distinct inputs.

The first source disk candidates found under `/opt/img_dnlab` are
`n9kv-9500-10.5.5.M.qcow2` and
`iosvl2-2020/vios_l2-adventerprisek9-m.ssa.high_iron_20200929.qcow2`.
This records their location only: content hashes, backing chains, licensing and
bundle readiness have not been validated here. Do not substitute a similarly
named disk automatically. The n9kv V2 firmware source is
`/opt/vrnetlab/cisco/n9kv_V2/docker/OVMF.fd`; it must become a hashed bundle asset.

## NIC mapping and capacity

The common launcher creates a first guest NIC with backend `p00`, without an
explicit PCI address. Its name in the launcher does not establish whether the
guest has OOB management. For vIOS, the existing mapping qualification tool
compares `p00` with `GigabitEthernet0/0`, `p01` with `GigabitEthernet0/1`, and so on,
using guest MAC addresses. That tool and its historical container results do not
qualify this mapping for a new direct-VM hardware definition.

For ordinary data NICs numbered `i` from one, common code assigns
`bus = floor(i / 26) + 1` and `slot = (i % 26) + 1`. For example, NIC 1 is on
bus 1, slot 2; NIC 25 on bus 1, slot 26; NIC 26 on bus 2, slot 1.
The bridges themselves are created without explicit root PCI addresses.
The first NIC and the n9kv AHCI controller also rely on automatic root placement.
These missing addresses must not be guessed by the template generator.

`num_nics` is launcher capacity, not a qualified count of guest-visible ports.
The common code can omit NICs after the highest provisioned port and insert
dummy NICs for holes. Catalog data-port counts are yet another limit: currently
10 for n9kv and 8 for the vIOS kinds. The template must fix a qualified NIC
inventory and keep its PCI order and MACs stable across stop/start, wipe and
later link attachment. Attaching an existing spare port is distinct from adding
a new guest NIC. No capacity or scale claim follows from the launcher constant.

All vIOS guest NICs are data ports in the direct-VM model. A selected management
port is exclusively reserved and excluded from data links. A different eligible
port may be selected only after its mapping is qualified. For n9kv, management
uses the OOB NIC; no data NIC is repurposed by this source analysis.

## Resource and lifecycle translation

Use the existing resolved per-node resource values rather than replacing them
with launcher defaults. For example, the catalog currently requests 2,048 MiB
for vIOS L2 while its launcher default is 768 MiB. The common launcher supports
`QEMU_MEMORY`, `QEMU_SMP`, `QEMU_CPU` and `QEMU_NIC_TYPE`; these are container
implementation inputs, not a second VM configuration authority. Any supported
override must become an explicit validated field in the VM hardware intent.
Arbitrary `QEMU_ADDITIONAL_ARGS` cannot silently bypass that contract.

The common source uses the unversioned machine alias `pc`. The direct-VM
contract requires an explicit versioned i440fx machine. The first libvirt host
qualification must identify an available machine version and the resulting
PCI/firmware behavior before producing an executable sample template.
The current template validator supports ROM firmware and SATA/virtio disks,
but this does not prove equivalence with either launcher.

Container-specific overlay path rewrites, user-mode networking, forwarded ports,
TC shell scripts and console TCP ports do not belong in the VM bundle. Native
overlay ownership, qualified TAP attachment and a per-instance Unix console
replace those mechanisms. Guest MAC identity comes from the dNLab ledger;
there is no Docker uplink MAC to preserve for a direct VM.

Both V2 boot loops may stop/start their QEMU process after an extended bootstrap
timeout. That behavior is intentionally not transferred: the agreed runtime
contract preserves guest-requested reboot but never infers authorization for
restart from readiness failure. n9kv loader/ROMMON counts as domain startup,
not NOS readiness or successful management traffic. No verified ordinary guest
shutdown capability is established by these launchers' SIGTERM handlers.

## Remaining work for the first bundles

1. Pin the source repository/branch/commit and record launchers, common code,
   build patches and firmware by hash; keep the V2 source choice explicit.
2. Qualify the selected host machine, emulator/firmware and complete PCI layout.
   Compare guest port names and MACs for both samples, including holes/spares.
3. Verify and hash the chosen immutable source disks and their backing chains;
   package firmware and other required assets without executing launcher hooks.
4. Emit canonical manifests accepted by `vm_template`, verify the filesystem
   bundles and bind per-instance overlays, TAPs, console and original generation.
5. Perform the separately authorized VM gates for lifecycle, persistence, guest
   traffic, management move, recovery and interoperability with native containers.

No build, disk conversion, libvirt connection, service change or operational
test is authorized or implied by this inventory. The public backend remains
Containerlab until the explicit qualified cutover.
