# Generic VM resource overrides

The launcher resolves each resource independently before constructing the VM:

| Resource | First choice | Compatibility alias | Profile default | Range |
| --- | --- | --- | --- | --- |
| vCPU | `VCPU` | `QEMU_SMP` | `vcpu` | 1–64 |
| RAM MiB | `RAM` | `QEMU_MEMORY` | `ram_mb` | 256–1048576 |

Only an absent variable permits fallback. Present empty, non-integer or
out-of-range values fail before VM allocation. The selected values normalize
the QEMU aliases before the vrnetlab constructor, so a conflicting old alias
cannot override a dNLab per-node setting. Startup logs contain the resolved
values and their source names, without dumping the container environment.

Existing images require a rebuild from the same QCOW2 and a new image version.
Recreate the affected containers from the new image while preserving `/persist`;
restarting an old container does not install a new launcher. This fix does not
require a wipe, overlay deletion or regeneration of the guest disk.

The portable validation tests run without vendor files. Final QEMU command
qualification additionally requires an explicit copy of the exact upstream
source pinned by this Dockerfile; its hash is checked before executing it.
For example, with an existing vrnetlab checkout containing that commit:

```sh
git -C /path/to/vrnetlab show 3e8578d2e946d38a3176480e80f8510bdb2ee53a:common/vrnetlab.py > /tmp/dnlab-generic-vrnetlab-pinned.py
```

Then, from `src/image-build`:

```sh
DNLAB_TEST_VRNETLAB_SOURCE=/tmp/dnlab-generic-vrnetlab-pinned.py ../../.venv/bin/python -m pytest -q tests/test_generic_vm_resources.py tests/test_generic_vm_recipe.py
```

The pinned constructor, resource properties and QEMU command assembly run with
external disk, NIC, process and telnet I/O mocked. No QEMU process or guest boots
in these tests. Without that explicit source, only the integration cases skip;
input-validation tests remain active. Image and guest qualification are separate.
