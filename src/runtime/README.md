# Experimental local runtime spike

This package implements the first local primitives of the custom runtime. It
does not replace the distribution's Containerlab backend. Multinode, its API,
GUI, scheduler, network plugin and existing labs are not switched to this runtime.

Current direction: retain Docker for native container workloads and infrastructure
services; use host-managed libvirt/KVM for devices previously wrapped by vrnetlab.
VM templates will be immutable filesystem bundles, with per-device writable
overlays. The complete libvirt execution adapter, template distribution and
direct-VM qualification are not implemented yet. Expansion of vrnetlab-as-container qualification is
suspended; existing results apply only to their original backend and version.
The first packaging target remains a runtime image accessing a supervised host
libvirt service. The chosen host target is a supervised session under a dedicated
non-root dNLab account, with private socket/state and the runtime as its only
ordinary writer. KVM/TAP/storage access and packaging still need qualification.
This is an implementation target, not an operational claim.

Offline VM preparation now consists of `vm_template.py`, `vm_bundle.py` and
`libvirt_xml.py`. The first contract describes one x86_64 VM with an explicitly
versioned i440fx machine, CPU/RAM, disk assets, ROM/pflash firmware when supplied,
PCI layout and NIC/guest-port mapping. Management selects one eligible OOB or
data NIC. Bootstrap/readiness remain manual and NOS shutdown unqualified.
Multi-VM, Q35 and automated guest profiles are not supported by this first
contract; they must not fall back to an approximate hardware profile.

The [V2 template inventory](VM_V2_TEMPLATE_INVENTORY.md) records the initial
n9kv/vIOS source profiles, asset candidates and unresolved machine/PCI details.
It separates source facts from guest and host qualification; it is not a
bootable bundle and does not transfer previous container qualifications.

`vm_sample_template.py` now translates those two V2 profiles into candidate
manifests. Resources, NIC count, versioned machine and root PCI addresses are
explicit inputs; automatic placement from the launcher is never inferred.
`vm_bundle_prepare.py` copies pinned source FDs into a new content-addressed
directory, verifies hashes and sizes, synchronizes files/directories and
publishes the manifest last with an exclusive rename. Existing or interrupted
attempts are preserved and refused. This is offline packaging, without disk
conversion, overlays or guest execution. A matching filesystem bundle is still
not a host/guest qualification or permission to boot it.

Current master milestone: the dedicated non-root libvirt session has completed
its original activation and returned an empty all-domain inventory. The three
daemon generations and private sockets were qualified; no VM has been created.
Earlier package/installation milestones below describe their original scope.

VM definition admission now reserves writable disk/NVRAM paths atomically with
TAP names in the common journal. `vm_storage.py` binds each local overlay to
the original definition, template, nonce and inode. Creation is requested once;
uncertain completion needs the original filesystem adapter's recovery. A ready
file cannot be recreated when missing or replaced. The whole disk set is checked
before the next allocation, with original QEMU writer/fence checks. Storage
intents also veto container admission and cleanup if a definition disappears.
CephFS and writable NVRAM require separate qualification; wipe and storage
retirement are not implemented yet.

The formatter in `vm_overlay_worker.py` / `vm_overlay_runner.py` reuses the
original-process observer and blocked-worker protocol. It can execute only
`qemu-img create` for an inherited, already recorded, empty single-link inode
with the expected marker. It verifies that inode both before readiness and at
release, then replaces the same tracked PID. The fixed command uses an explicit
backing format, without shell commands or arbitrary output paths. A native
canary formatted a synthetic 1 MiB raw base into an overlay owned by UID1001 /
GID1002, retaining inode/marker and reopening its durable exit-0 receipt. No VM
was started. This proves that formatter path only; native VM writer admission,
stop/start, wipe and CephFS still need their own qualification.

`vm_overlay_files.py` now connects those intents to the formatter for the first
local ext4 profile. It requires an original parent identity and explicit
preflight/runner providers, creates no directories, records file birth before
initialization, synchronizes file and parent, and resumes only the original
formatter. Unknown birth identity or an unverified release stays pending until
qualified original evidence is available.
Readonly mode requires the original tables and never creates or recovers files.
Immutable base hashes are reused only while complete file metadata is unchanged.
The bounded [qcow2 header reader](https://www.qemu.org/docs/master/interop/qcow2.html)
verifies backing path, explicit backing format and virtual size through the
original inode, without opening backing files or using `qemu-img --force-share`.
It does not acquire a QEMU writer lease or check allocation tables.
Dirty headers require a qualified original writer; snapshots, encryption,
external data and unqualified feature flags are refused in this first profile.

A native synthetic-SDK canary exercised `VMStorage`, this filesystem adapter and
real QEMU formatting for normal, lost-arm-response and lost-release-response
cases. Each used one original worker and reopened the same proof. A separate
query-only observation verified all three histories without journal writes.
No libvirt connection, domain or guest was used by this canary: it does not
qualify NOS lifecycle, actual VM writers, CephFS or runtime-image packaging.
The response-loss cases retain the original supervisor/waiter. Losing it before
a durable exit receipt remains pending; runtime-crash recovery is not qualified
by these cases and cannot adopt a PID or repeat an uncertain command.
Filesystem integration tests need a fresh exclusive basetemp on ext4 and mapped
UID1001/GID1002; the formatter remains simulated in those tests. The ordinary
`/tmp` mount can be tmpfs and is correctly rejected by the native ext4 profile.

`tools/vm_host_inventory.py` prepares the first host prerequisite collection.
It requires explicit `--collect-host --host-id HOST`, or `--fixture-root` for
synthetic input. It reports bounded hashes/metadata for fixed QEMU/libvirt and
configuration paths, device metadata without opening devices, candidate socket
presence without connections, boot ID and the requested local account projection
(default proposed name `dnlab-libvirt`, never created). It does not execute
binaries, version commands or NSS helpers; symlinks are reported without being
followed. Reports contain no raw config/passwd contents, go to stdout and must
be captured privately by the caller. Eight synthetic tests cover no execution,
device access, outside symlinks, FIFOs, ambiguous accounts, size bounds, changed
boot and isolated CLI bootstrap. One explicitly authorized master collection
completed: QEMU/qemu-img and KVM/TUN character devices were present; virsh,
libvirt daemon/configuration/socket paths and the candidate local account were
absent at the fixed inventoried locations. This does not exclude an installation
at other paths or prove device access. No binary execution, connection or
installation occurred. The result always has `qualified: false`: capabilities, permissions, machine/PCI
layout, service ownership, PID namespace and packaging still need qualification.

The [dedicated-session procedure](VM_LIBVIRT_SESSION_PROCEDURE.md) specifies the
proposed account/paths, supervision and staged package/account/service rollout.
It records the completed package-only step and experimental installation primitives.
New preparations require explicit service layout version2, with separate root-owned
qemu.conf parents and a private writable driver subtree. Version1 remains readonly
history; no old intent is migrated. The master now has the dedicated account and
version2 files installed with original birth proofs, in `installed_not_started`.
No dedicated daemon or VM has been started; operational session qualification is
still pending and the document does not authorize daemon start. Logging/locking dependencies must remain available
until all dependent VMs have verified exits; client autostart is disabled.

`tools/vm_package_inventory.py` prepares the next package metadata preflight,
bound to the original prerequisite report's boot and distribution-file hash.
It reads the distribution and a bounded dpkg status snapshot, then permits one
fixed `apt-cache policy` query for the declared libvirt/QEMU package names with
`Dir::Cache::pkgcache=` and `Dir::Cache::srcpkgcache=`. Both persistent cache
files are disabled per the [APT configuration manual](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html).
There is no apt-get, update, download, dependency simulation, install or service
operation. Inputs and apt-cache binary are rechecked after the query; raw query
errors remain in the private report without fallback or retries. Unsupported
distributions stop without trying another package manager. Candidate data may
be stale and is not an approved transaction. Host mode needs explicit opt-in;
synthetic mode requires policy fixture data and never executes apt-cache.
Nineteen tests of both inventory tools pass with synthetic files and transports.
One authorized master package collection then completed: Debian 13, QEMU
10.0.13 installed, queried libvirt packages absent and cached libvirt candidate
11.3.0-3+deb13u3. No package state changed. The examined Debian packages supply
libvirtd rather than the draft's virtqemud target. The user selected preparation
of a dedicated non-root monolithic profile. The 16 reviewed packages have now
been installed; no libvirt daemon or dedicated session has been started.

`libvirt_service_profile.py` now renders three private libvirtd/virtlogd/virtlockd
units and four config files from explicit session UID/GID, KVM group, daemon
paths/hashes and a pinned libvirt version. It performs no host IO or package,
account, file or service operations. Units use numeric non-root credentials,
private XDG paths, no force/restart or automatic boot enablement, and no implicit
directory creation. The renderer returns ownership, package and forbidden vendor
activation requirements for a later installer; its result is always unqualified.
Eighteen profile tests and 31 related definition/fence tests pass synthetically.
The user authorized installation. The dependency simulation and archive/hook
review are complete for the package-only transaction: exact archive hashes and
versions were verified, vendor services/sockets and libvirt-guests remain masked,
and the nonce-bound temporary policy-rc.d was removed with original identity
checks. All packages are configured; the three installed daemon hashes match
the archives. The dedicated account/config/units and live session qualification
are still pending. Privileged LXC (the current
master environment) and bare metal require separate qualification. Running the
daemon as root would not remove outer LXC capability/device/confinement limits;
the selected first profile retains unprivileged QEMU and pre-created owned TAPs.

Bundles contain `manifest.json` and declared immutable assets with SHA256 and
size. The read-only verifier checks the expected canonical manifest digest,
asset contents, duplicate keys, symlinks and stable path/file metadata. It
rechecks earlier members after reading later files. The result is a read-time
proof; it does not lock files or verify actual qcow2 format/backing chains.
No launcher, hook, qemu-img command or libvirt connection is executed.

The offline XML planner binds the original VM UUID/generation/nonce/template,
explicit overlays outside the immutable bundle, unmanaged pre-created TAPs,
MAC/PCI/MTU/carrier and a Unix serial socket. It creates no libvirt NAT/DHCP
network or interface script. Guest reboot is preserved (`on_reboot=restart`),
while crashes do not trigger restart. Execution remains disabled until the
adapter journals guest reboot events and requalifies the original domain and
process incarnation, refusing ambiguous exits. Asset/overlay/TAP ownership and
host capabilities must be verified before any eventual execution. Synthetic
XML parsing does not qualify libvirt's schema or behavior on an installed host.
The XML follows the [official libvirt domain format](https://libvirt.org/formatdomain.html),
including generic Ethernet interfaces and event policies.

`vm_events.py` adds durable event reduction in the same runtime journal, with an
injected ownership/configuration/process observer and no hypervisor commands.
An original source token and a fresh collector token identify the observation
stream. A reboot notification preserves its birth only while configuration and
the original QEMU incarnation agree; it never asserts NOS readiness. Sequence
gaps, connection loss, changed incarnations and other lifecycle notifications
require recovery, without restart or inferred graceful shutdown. Repeated event
delivery returns the original historical receipt; callers must inspect current
stream state separately. A new collector can read history but cannot resume an
old stream or replace its token implicitly. Libvirt callback wiring, proof of
continuous observation and explicit recovery remain unimplemented.

The event callback itself does not identify the human or CLI that requested a
reboot; the trusted adapter must bind notifications to the original connection,
domain and process ([libvirt event API](https://libvirt.org/html/libvirt-libvirt-domain.html#virConnectDomainEventGenericCallback)).
The local cleanup inventory vetoes finalization for a lab with VM stream records;
corrupt records cause a refusal rather than disappearing from inventory. No VM
retirement operation is available yet, so such records remain protected. This
veto does not qualify deployed cleanup actors or inspect actual libvirt domains.

`libvirt_observer.py` supplies SDK-shaped read-only domain observation for an
injected original connection. Its pinned reference must come from the durable
qualified creation acknowledgement, including persistent/live XML and original
QEMU process proof. It never obtains a reference by discovering a matching name.
UUID, original ownership metadata, both full XML descriptions and the process
fingerprint are rechecked around a mandatory process-capture context. XML
comparison tolerates attribute ordering and indentation while preserving
elements, values and child order; DTDs are refused. Domain IDs are not PIDs.
The creation-acknowledgement producer, event callback wiring and connection
lifecycle remain to be implemented/qualified. Synthetic
SDK objects do not qualify installed libvirt. See the [domain API](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainGetXMLDesc)
for the distinction between persistent and live XML.

`qemu_process.py` implements read-only capture of an already recorded original
QEMU process. The caller supplies the complete durable birth/process/credential/
command/namespace record; the provider cannot discover a PID or adopt one from a
pidfile or libvirt domain ID. It holds a pidfd while checking bounded procfs reads,
boot ID, process start ticks, executable content, dedicated credentials, command
UUID/hash and namespaces before and after the domain observer. The pidfd caller
must share the recorded QEMU PID namespace; merely mounting host procfs into a
different PID namespace is insufficient. Exit, invalid or error poll events
refuse admission without signals or fallback. All acquired descriptors close on
failure. This follows the [pidfd interface](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
and [proc stat layout](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html).
Thirty-one tests use synthetic files and mocked pidfd/poll/namespace providers,
including integration with the domain observer. Original creation-record
acquisition/persistence, the trusted host procfs view, permissions and runtime
packaging remain to be connected and qualified; no host observation was run.

`libvirt_session.py` validates a dedicated session profile and injected evidence
of its daemon, private socket and directories. `vm_definition.py` adds a one-shot
definition driver in the existing runtime journal: durable intent, qualified
UUID/name absence and asset/overlay/endpoint preflight before the only define.
It uses XML validation, not a create-only libvirt flag. Existing domains are
refused; uncertain outcomes remain held without a second define or cleanup.
An already committed acknowledgement survives a lost commit response and is
verified on retry. Unexpected XML normalization leaves the inactive definition
in recovery. This primitive does not boot a VM, install the session, implement
uncertain-definition recovery/retirement or enable public VM requests. Real
session and preflight providers remain mandatory and unqualified.

VM definition admission now reserves host TAP names in the common `resources`
table, atomically with the definition intent. Container and VM admission share
these keys. Retry and preflight require the exact original interface inventory
and creator; missing or altered reservations require recovery, without backfill.
Reservations remain held through uncertain definitions; qualified VM retirement
and release are not implemented. Public VM admission stays disabled.
Synthetic TAP conflicts, retry, two-connection concurrency, VM boot and recovery
tests pass. The cleanup expectation now includes both `resources` and the VM
intent blocker, preserving its read-only assertions. The extended combined run
passed 182 tests before the native-container Unix transport test failed at
socket bind with sandbox EPERM. A separately authorized repetition of that exact
Unix transport test outside the sandbox passed (1 test, 0.61s, exit 0), without
changing the test or guard. The original combined run remains recorded as failed;
no complete rerun or real TAP/libvirt operation was performed.

`backend_reservations.py` shares logical-node exclusion through existing native
operation/resource/birth records and VM definition/stream records. Both native
submit and VM prepare check under the same SQLite admission transaction; native
planning also checks without mutations and detects VM reservation changes during
its snapshot. No separate ownership ledger or scheduler is introduced. Recovery
and incomplete cleanup retain the reservation, and force does not bypass a
conflicting backend. Verified native stop permits an explicit VM preparation;
VM retirement is not implemented, so VM records cannot yet release their node.
Corrupt or mixed reservations refuse mutation, including before compensation.

VM definition intents also pin `lab_generation` (default 1 only for the initial
lab epoch), independently of the VM's own birth generation. The existing lab
closure and management fences are checked before admission, inside its SQL
transaction, on apply/retry, around preflight and after checkpoints, and before
acknowledgement commit. Reopened labs require their explicit new epoch; an old
intent is never rewritten to the current one. Stored intents without an epoch
are refused for qualified recovery. Read-only history remains accessible while
mutations are fenced. A late conflict retains the original intent and any
already defined inactive domain, without retrying define or deleting resources.

Implemented: native Linux start/stop, immutable image identities, local veth
endpoints, attachment to a pre-existing lab-owned `dnlab-vrf` management network,
Docker published ports, durable operations, request deduplication, revisions,
resource reservations, cancellation, compensation and restart replay.

The original primitive-spike exclusions were: vrnetlab adapters, safe guest shutdown, `/persist`
mounts, management network creation/routing/services, VXLAN/stitch, warm carrier
control, live management moves, guest readiness and distributed reconciliation.
Later experimental work and its specific qualification limits are described
below; this original list is not a current feature inventory. Unsupported
kinds/actions fail explicitly. `kind: linux` means a native process,
not a VM image deployed with a Containerlab Linux kind.

## Local tests

From the repository root:

```sh
.venv/bin/python -m pytest -q src/runtime/tests
```

Tests use stateful fake Docker and kernel backends. Unix transport tests open a
socket in the pytest temporary directory. They never contact Docker, start labs,
change host interfaces or qualify a guest image. No additional package is needed
to run the prototype from source:

```sh
PYTHONPATH=src/runtime .venv/bin/python -m dnlab_runtime.cli --help
```

## Protocol and lifecycle

The service uses HTTP/JSON on a root-only Unix socket. The client sends requests
over that socket; it can be invoked via the existing SSH transport later without
putting the request or credentials in command-line arguments.

| Method and path | Purpose |
|---|---|
| GET `/v1/capabilities` | Explicit implemented and unqualified features |
| POST `/v1/plan` | Static validation and affected steps; no Docker/kernel mutation |
| POST `/v1/operations` | Persist and queue a versioned start/stop request |
| GET `/v1/operations/{id}` | Durable status without spec/env payload |
| POST `/v1/operations/{id}/cancel` | Persist cancellation intent; does not imply cleanup completed |
| POST `/v1/operations/{id}/reconcile` | Explicitly retry an operation requiring recovery |
| GET `/v1/nodes/{lab}/{node}` | Committed revision plus observed container state |

Node inspection additionally exposes `workload_ref` (`backend`, `kind`, `id`)
and `workload_state`. Current execution produces only Docker/container references
or null when absent, retaining `container_id`, `container_state` and all original
birth checks. The client accepts older responses without these additive fields,
but rejects partial or contradictory references. The identity type distinguishes
libvirt domain UUIDs from container references; it does not authorize VM requests
or substitute for an ownership proof. Committed state, operation state and NOS
readiness remain separate.

Requests have `schema_version: 1`, `request_id`, `lab_id`, `node_id`,
`expected_revision`, and `action`. Start includes `spec`; stop uses the committed
spec. `force` defaults to false and is only accepted on stop.

Same request ID and content return the same operation, including after daemon
restart. Different content with the same ID, stale revisions, active mutations,
resource collisions and implicit changes to a running spec are conflicts.
Container names are supplied by the control plane so existing internal naming
can be preserved. Only one worker mutates locally, with a bounded pending queue;
cancellation and status do not wait on its execution lock.

Journal intent/reservations precede side effects. Created containers carry lab,
node, spec and creator-operation labels. Veth cleanup verifies its ownership
alias and never infers ownership from a prefix. A namespace file descriptor is
held while operating, and the Docker ID/PID is rechecked before mutations.

Safe native process stop sends SIGTERM and observes process exit. Timeout never
escalates to SIGKILL or forced removal. It leaves `recovery_required`; explicit
recovery with `{"force": true}` may send SIGKILL. This is process lifecycle,
not a guest shutdown guarantee. Native application signal handling is the
application's responsibility. Stop retains the committed manifest/revision;
the next start uses that revision and a new request ID.

Cancelled spawn is terminal only after observed cleanup. If a repeated start
was acting on an already committed running node, cancellation preserves that
node. Stop cancellation arriving after process exit records completion and
the late cancellation; it does not silently recreate the process.

Crash recovery replays only nonterminal recorded operations. `recovery_required`
requires explicit reconcile and retains reservations. Host veth creation includes
a deterministic locally administered MAC on both peers in the same netlink
request; its full ownership alias is then set and verified before transfer.
Recovery in that gap requires the exact recorded MAC pair and reciprocal peer
identity. A foreign or unproven interface is never adopted or deleted.

## Preparing an isolated live probe

The management/service and relay console runners currently stop before creating
their output directory or allocating resources. Their cleanup compatibility
preflight is deliberately blocking: no deployed cleanup policy has been
qualified for them. Local Docker discovery supplies diagnostics only. An absent
or stopped daemon, a capability label, and updated checkout sources do not
authorize a gate. There is no bypass flag and the check never pauses cleanup.
Separately qualify the deployed cleanup protection before enabling these runners
again. This check does not cover the other experimental tools in this directory;
it is not permission to execute them or replay an older frozen recipe.

The following commands are for a separately authorized isolated host probe.
They create a privileged service, containers and host veth interfaces; they are
not part of the local unit checks. Do not run this against existing lab names.

Build the image from `src/runtime`, then choose empty, dedicated absolute paths
for `DNLAB_RUNTIME_SPIKE_STATE` and `DNLAB_RUNTIME_SPIKE_RUN`. The opt-in
`compose.spike.yml` shares host PID/network and the local Engine socket. State
and socket paths must also be reachable by a host-installed client. No TCP
service or Docker-in-Docker is used. The service needs root and privileges for
namespace/network operations; those privileges have not yet been minimized.

```sh
docker compose -f src/runtime/compose.spike.yml build
docker compose -f src/runtime/compose.spike.yml up -d
```

The image accepts the same CLI commands as the native package. To compare host
and image execution, stop one daemon before starting the other with the same
state and socket paths; do not run two owners of the journal. The instance lock
refuses concurrent daemons and will not replace an active or non-socket path.

For a first probe, copy `examples/linux-start.json` outside the source tree and
replace its placeholder image ID with the immutable ID of an already available
native Linux image containing Python 3. Its explicit SIGTERM handler also works
when the command is PID 1. The prototype does not pull images. Do not use a vrnetlab
image. Begin with `management` omitted: ports then remain unavailable, but the
container/veth lifecycle can be tested without management infrastructure.

```sh
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" capabilities
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" plan < /tmp/linux-start.json
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" submit < /tmp/linux-start.json
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" status OPERATION_ID
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" inspect runtime-spike linux1
```

After a completed start, submit this stop request and verify both container and
endpoint absence, plus committed revision 2:

```json
{"schema_version":1,"request_id":"stop-1","lab_id":"runtime-spike","node_id":"linux1","expected_revision":1,"action":"stop"}
```

For cancellation or recovery:

```sh
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" cancel OPERATION_ID
dnlab-runtime --socket "$DNLAB_RUNTIME_SPIKE_RUN/runtime.sock" reconcile OPERATION_ID
```

`reconcile --force` is a separate explicit choice, retained in operation status.
To test management/ports later, supply `management: {network, ipv4?, ipv6?}` and
`ports: [{container_port, host_port, host_ip, protocol}]`. The network must
already use driver/IPAM `dnlab-vrf` with `io.dnlab.managed=mgmt-vrf` and
`io.dnlab.lab` matching `lab_id`. The prototype never creates/removes that network
or rewrites the plugin's state.

## Gates before integration

`tools/smoke.py` provides the isolated probe for both service packaging modes.
Without `--execute` it only prints the proposed actions and performs no Docker
or host network calls. It uses existing images, pins their immutable IDs, creates
unique test names, stores evidence under `/tmp`, and checks exact ownership during
cleanup. It does not automatically pull images or build the runtime image.

```sh
.venv/bin/python src/runtime/tools/smoke.py
# Only on an explicitly authorized local host, after building the runtime image:
.venv/bin/python src/runtime/tools/smoke.py --execute
```

The native/image lifecycle probe passed on Docker Engine 29.8.1 and kernel
6.17.13-1-pve. It covered real veth/netns operations, deduplication, safe process
stop, timeout without implicit kill, explicit forced recovery, journal replay
after staged creation/restart, persisted queued cancellation, and cleanup.
This lifecycle probe used network mode `none`; a separate datapath probe is
described below. Production management/IPAM and cross-host behavior remain
unqualified.

Record actual Engine/kernel/tool versions, pinned image identities, operations,
and before/after resource inventories. Run native/image parity, interruption
between each side effect, safe-stop timeout, explicit-force recovery, and foreign
resource tests in isolation. Local doubles are not qualification evidence for
namespace permissions, Docker network/IPAM or port publication.

The stable datapath has local Linux and vIOS legacy-slot evidence on stock
Docker bridge networks. OOB n9kv, arbitrary data-port selection, dnlab-vrf, IPv6
and distributed isolation still require qualification before the distribution's
network services, GUI and lifecycle APIs adopt this backend. No current lab is implicitly migrated.


## Experimental stable management probe

For a node already committed in the same runtime journal, handoff also records
its current management assignment separately from the immutable birth spec.
Container labels and data endpoint ownership continue to use that birth spec.
Verified completion or rollback commits the assignment and increments the node
revision atomically; callers must use the updated revision for subsequent data
links and lifecycle requests. `GET /v1/nodes/{lab}/{node}` includes an optional
`management` observation when this assignment exists. A move needing completion
or recovery reserves the node and blocks new lifecycle and link operations.

Handoff idempotency keys are scoped to the lab, matching lifecycle requests.
`submit(request_id, ...)` returns a unique opaque operation `id`; pass that ID
to `get`, `execute` and `rollback`. `by_request(request_id)` explicitly resolves
a key within the caller's lab and VD context. Keys and operation IDs have no
implicit fallback between them. Reusing a key with different content or another
VD inside one lab is rejected. Every operation read, phase change and recovery
checks lab, VD, immutable birth fingerprint and stable-port owner, including
terminal operations. Completed rollback is read-only. Request mapping, move
intent and node reservation commit together. Unscoped older probe records are
preserved and never implicitly adopted; outstanding legacy moves still block
new moves for their container. This is a probe interface, not a change to the
production management API.

Handoff, lifecycle and link execution share a reentrant per-journal thread/file
lock. A daemon encountering another executing process retains queued requests
and retries after the gate is free. Replaying a completed move never increments
its revision again. Stop/start retains the current management network; a new
container generation is bound only to its explicit start operation. Failed
starts preserve the previous desired assignment. Explicit management changes
in a new stopped-node birth spec take effect only after verified start commit.

`tools/management_link_authority_smoke.py` qualifies native Linux interoperability
on dedicated stock Docker bridges: process death before, during and after commit, fresh
replay, bridge creation via Unix API after handoff, data traffic across a second
move with that bridge active, and unchanged VD/data/stable-port identities.
Two labs share one journal and the same request key, with separate opaque IDs;
foreign operation access/recovery is refused, and crashing the first move
preserves the second lab's queued move and stable port. The stock bridge gate
uses distinct subnets; permitted overlap between labs is covered by unit tests
with simulated network drivers, pending native dnlab-vrf qualification.
Cleanup writes `cleanup-events.jsonl` with per-phase snapshots and exact primitive
argv, exit code, stdout and stderr. The tracing is fixture-only. After a failed
endpoint deletion the runtime now verifies absence of the previously qualified
port; only confirmed absence completes cleanup. Present or replaced ports and
failed verification remain errors, with no additional destructive attempt.
Endpoint deletion uses a bounded namespace-local helper and an index-only
`RTM_DELLINK` request, without a name attribute. The helper checks host boot and
network-namespace identity and revalidates name, index, alias, MAC, peer index
and veth kind before sending on a socket bound to that namespace. A different
resource reusing the name is preserved; its presence keeps cleanup in conflict
and the lifecycle journal in `recovery_required`. Identity/namespace conflicts
are never converted to success by a later absence observation.
`--endpoint-delete-race` holds the fixture VD namespace open across stop, then
releases it after the owned read and before deletion. Verified absence of the
original index completes cleanup without targeting a newly resolved name.
This qualifies the asynchronous disappearance case. The cause of the earlier
intermittent host failure remains unproven.
`tools/endpoint_identity_smoke.py --execute` verifies actual netlink deletion,
name replacement preservation across retry, disappearance and namespace refusal
inside one newly created private namespace, removed after inode verification.
`--runtime-image sha256:<local-image-id>` runs the Unix API daemon in the dedicated
image with host PID/network, a Docker socket mount, the dedicated fixture journal
and explicit host boot identity. Installed module paths and hashes are verified.
The gate restarts that daemon with a data link active and confirms that a queued
native spawn waits for a host process holding the shared execution lock, then
completes after release. It also stops that VD through the image API while a
fixture FD keeps its namespace alive, exercising real indexed endpoint deletion
inside the image before container removal. Daemon cleanup checks its exact ID, image and fixture
labels before killing/removing it. Management handoffs and the endpoint race
remain native fixture operations; this qualifies the image's consumption of the
shared management authority through link and lifecycle APIs, rather than full
image-based handoff or production management API exposure.
Adding `--image-handoff` runs submit, execute, crash/replay and a post-connect
failure/rollback inside that image through bounded, tracked Docker exec calls.
The fixture program uses only installed runtime modules and records process,
host network identity, module hashes and phase receipts in
`image-handoff-events.jsonl`. Fresh image workers recover a move killed before,
during or after commit. Two labs reuse the same key; foreign get/execute/rollback
are refused inside the image as well. A second move and a rollback preserve the
active data link and the stable management port. This is still a local native
Linux gate on stock bridges, with fixture-created networks/workloads and native
endpoint cleanup; it does not expose a production move API or qualify NOS,
dnlab-vrf overlap, remote hosts or the full catalog.
This is not production move API exposure or NOS/dnlab-vrf qualification.


`tools/management_smoke.py` tests a stable `mgmt0` veth and its `dmu0` peer,
with an internal `dnlab-mgmt` bridge connecting the peer to the replaceable Docker uplink. The runtime resolves
that uplink through endpoint membership and reciprocal kernel peer identity,
independently of its `ethN` name. Addresses and bootstrap discovery use `mgmt0`; vrnetlab-style `tc`
redirects keep their original ingress interface across endpoint replacement.
The journal records detach/connect/verify and rollback. The old stable address
and connected route must be cleared before Docker reconnects the same subnet.

```sh
.venv/bin/python src/runtime/tools/management_smoke.py
# Only on the authorized isolated local host:
.venv/bin/python src/runtime/tools/management_smoke.py --execute
```

The IPv4 Linux guest analogue probe passed for TCP traffic, console exceptions,
fixed published ports, unchanged interface/MAC/process identity, and injected
failure rollback. It creates two uniquely labelled stock bridge networks and
two native containers, verifies owned cleanup, and writes its report under
`/tmp`. No vendor NOS, IPv6, dnlab-vrf routing/IPAM, subnet overlap between labs,
VXLAN or guest shutdown has been qualified by this probe. Handoff is not exposed
through the operation API and does not enable the live-move capability.

The image builder has an explicit candidate option, requiring an unpatched
upstream image and a separate output tag:

```sh
python3 src/image-build/apply.py cisco_n9kv UPSTREAM_IMAGE \
  --runtime-management --runtime-management-python=uv \
  --tag-suffix=-runtime-spike --dry-run
```

This dry run extracts files using a stopped throwaway container; it requires
Docker access. Remove `--dry-run` only when a candidate build is authorized.
The candidate ABI accepts `DNLAB_RUNTIME_MGMT_INTF=mgmt0` and
`DNLAB_RUNTIME_BOOT_WAIT=true`, waiting for
`/run/dnlab-runtime/management-ready` before guest initialization. Timeout is
bounded and fails before guest boot. The experimental `Bootstrap.release` primitive verifies the stable interface
and address, requires candidate image labels/environment, then writes a
readiness marker through a tracked Docker exec. The marker identifies the
current PID-namespace init start; a stale marker cannot release a restarted
container. The normal operation API does not call this primitive yet. Default builds
and legacy startup retain their existing behavior. The `runtime-management-v1`
label describes the ABI; `experimental-unqualified` explicitly records that
NOS traffic/mapping and persistence still require per-digest qualification.


`tools/bootstrap_smoke.py` validates the patched constructor on a temporary
native Python candidate: guest initialization is blocked before preparation,
released after verification, and blocked again on restart despite a persisted
marker. It creates one isolated bridge/container and removes its temporary
image after owned cleanup. Without `--execute` it only prints the actions.

```sh
.venv/bin/python src/runtime/tools/bootstrap_smoke.py
# On the authorized isolated local host:
.venv/bin/python src/runtime/tools/bootstrap_smoke.py --execute
```

`tools/prepare_nos_candidate.py KIND DISK` prepares raw source contexts and patch
previews under `/tmp` from the repository's `vrnetlab.lock.json` commit. It
preserves Git executable modes and records source hashes. Supported preparation
kinds are `cisco_n9kv` and `cisco_vios`; preparation copies no guest disks and
calls no Docker operations. `candidate.json` records the subsequent disk-copy,
raw-build and explicit experimental-patch commands for review. Base image
identity, disk digest and built candidate identity still need recording during
an authorized build. Preparing the shared management ABI does not qualify vIOS
arbitrary data-port selection; that adapter still has to preserve the complete
NIC mapping and isolate the legacy vrnetlab management port.


## Real NOS probe status

`tools/nos_smoke.py IMAGE --execute` is an explicitly authorized vIOS probe
using two labelled bridge networks, all 15 warm data NICs, a dedicated guest
overlay and container-side serial console. It performs manual IP configuration,
checks host-to-guest ICMP, and tests endpoint handoff plus fixed port publication.
It checks exact ownership during forced fixture teardown. Forced teardown is
an explicit probe action, and does not qualify safe guest shutdown.

The first real boot exposed a release-source ABI mismatch: n9kv/vIOS launchers
pass the retired `use_scrapli=True` keyword to an unconditional Scrapli common
constructor. The image builder now adapts that argument for these normal builds
as well as experimental candidates, preserving it on constructors that accept it.
The vIOS probe subsequently passed initial KVM boot, all 16 guest NICs, manual
configuration and initial ICMP traffic. Passive capture traced a live handoff
failure to host ARP resolution using the replaceable Docker endpoint MAC. The
handoff now requests the stable guest MAC on connect/rollback and verifies both
Docker metadata and the kernel interface. A static FDB entry directs that MAC
to the permanent peer instead of the bridge-local endpoint path. A subsequent
vIOS probe passed move, console publication and injected-failure rollback, with
unchanged guest/NIC identity and no host ARP override. The initial evidence covers only
the tested candidate's legacy p00 slot on IPv4 stock bridge networks; the normal
operation API remains Linux-only. Diagnostics and overlays are retained only under `/tmp`.

The first n9kv V2 boot-only attempt with `--kind cisco_n9kv --boot-only`
stopped before bootstrap release: its base uses uv and a virtual environment,
while the initial helper assumed system Python. Candidate builds now require
`--runtime-management-python=system` or `uv`; the latter uses
`uv run --offline python3` for helpers. Missing or unsupported profiles fail
before release. The NOS probe runs the image’s configured exec-form healthcheck,
and rejects missing or shell-form checks before resource creation. Candidates
without the profile must be rebuilt from their source recipe; the runtime
never modifies a built image to add this contract. n9kv NOS boot remains
unqualified. The corrected V2 probe observed one KVM guest, 17 NICs and
17 matching backends. The launcher reported loader/ROMMON and released the
serial console. The user accepts that outcome for process boot; the original
failed NOS-output report remains preserved. Boot-only checks now record the
observed stage separately and accept ROMMON without claiming NOS readiness.
Persistence of NOS boot and configuration requires manual guest boot settings
and saved configuration, followed by a dedicated test. Future n9kv interface
tests must spawn a new V2 fixture. The V2 fixture explicitly passes
`--connection-mode tc` because n9kv does not read the environment setting.
The probe verifies a unique matching netdev backend for every guest NIC. It cannot
qualify OOB traffic or arbitrary vIOS data-port management. Raw console
publication is tested after guest IP configuration; the existing GUI uses
container-side loopback and remains independent of guest management IP.


To repeat the corrected vIOS move and rollback probe on the authorized isolated
host, use `tools/nos_smoke.py IMAGE --execute --diagnose-passive --test-rollback`.
Passive capture starts before guest reconfiguration. Rollback injects a failure
only after target connect, restores the previous endpoint with the same MAC,
and checks traffic without changing guest IP again. The runtime refuses a
network driver that ignores the requested MAC and rejects an FDB collision with
another bridge resource. Owned internal bridges currently require untagged
forwarding; guest MAC behavior still needs per-digest qualification.

## Native dnlab-vrf probe

`tools/management_vrf_smoke.py` exercises the installed driver/IPAM without
reinstalling or restarting the plugin. It creates dedicated host VRFs, bridges,
networks and native Python workloads, then checks same-lab management routing,
addition of a segment to running workloads, overlapping subnet isolation,
stable management handoff and post-connect failure rollback. It is separate
from NOS traffic, Docker port publishing, DNS/jumphost and distributed tests.

```sh
.venv/bin/python src/runtime/tools/management_vrf_smoke.py
# Only on the already authorized isolated local host:
.venv/bin/python src/runtime/tools/management_vrf_smoke.py --execute
```

Host links use unique names, atomic MAC markers, explicit ownership aliases and
recorded VRF table IDs/ifindices. The probe checks the installed plugin against
the checkout and requires existing forwarding; it changes no global sysctls.
It reproduces the management bridge firewall prerequisite from multinode
`netsetup` with exact dedicated bridge matches and unique comments. VRF default
routes prevent fallback to host routing outside the probe. Cleanup refuses
foreign/occupied resources and removes only the recorded rules/default routes;
it checks plugin state and the firewall against their pre-probe snapshots.

The first real-driver rounds exposed the runtime's fixed `eth0` assumption.
The resolver now checks endpoint/network membership, matching IP/gateway,
reciprocal host/container veth indices and the expected bridge/VRF, records
observed identities before binding, and keeps `mgmt0` fixed. The native control
without a reserved data slot passed move, rollback and replay through a fresh
journal without replacing the already connected endpoint. The stock bridge
Linux guest analogue also passed traffic/console/port-publication regressions.

The default VRF probe reserves a native `eth1` data slot, with the same MAC as
management, to verify that MAC alone cannot select or mutate a data interface.
This is a native namespace fixture, not an n9kv or guest OOB mapping test.
Its management IP remains on stable `mgmt0`. Earlier rounds failed because the
remote driver returned an `eth` destination prefix, colliding with the data slot
on target connect and rollback. The corrected plugin preserves an optional
endpoint name from `CreateEndpoint.Options` and returns `DstName` in `Join`.
Endpoints without the option retain the existing `eth` prefix. The runtime
requests `dnmu0` through endpoint `DriverOpts`, requires Engine API >= 1.49,
checks namespace occupancy before detach and verifies the actual endpoint
name/MAC through kernel peer identity before binding. The naming policy is
persisted for move, rollback and replay. Legacy unfinished experimental
handoffs without that policy require explicit recovery.

On Engine 29.8.1/API 1.56, the updated plugin passed the default native probe:
move, post-connect rollback, replay through a fresh journal without another
connect, inter-management routing and overlapping-lab isolation. The same-MAC
`eth1` fixture remained intact. The installed plugin was replaced only for this
isolated qualification and restored afterward; running the probe requires an
installed plugin matching this checkout. Cleanup restored plugin state and
firewall rules. The standard Docker bridge also passed traffic, console and
published-port regression checks with the reserved name.

`--without-data-slot` remains a diagnostic control, not a qualification of warm
port coexistence. API version alone does not qualify remote endpoint naming;
remote handoff preflight now requires a fresh native canary on both source and
target. `EndpointNameProbe` validates a pinned Linux image without an entrypoint,
records create/connect/cleanup intents in its separate journal, verifies the
actual endpoint through kernel peer identity and waits for native SIGTERM exit
before removing the canary. Failed verification or cleanup forbids handoff.
A persistent process lock prevents recovery from deleting a checker that is
still alive; subsequent checks recover only owned unfinished canaries. Evidence
is recorded in the handoff payload and repeated before execution and rollback;
capabilities are not cached across operations. This experimental gate requires
an available IPAM address in each segment and a locally available pinned native
image. Production integration and scale costs remain to be qualified. Neither the handoff primitive nor NOS adapters are
enabled in the production operation API. Guest OOB/data mapping, guest
shutdown, DNS/jumphost, port publishing on dnlab-vrf, IPv6 and distributed
VXLAN still require their own gates.

The naming gate distinguishes initial endpoint creation from reconnect. The
initial-create check requests `dnmu0` in `NetworkingConfig.EndpointsConfig`
and verifies the reciprocal kernel peer without disconnecting the canary.
Native canaries publish an atomic nonce and init-boot marker only after their
SIGTERM handler is installed. A bounded Docker exec checks that marker before
verification and cleanup; recovery repeats the check for a running canary.
Readiness timeout never triggers implicit force. The private journal preserves
the original probe/cleanup errors, failing cleanup step and observed process
state, including when a later recovery succeeds.

The native probe supports `--reject-name-probe` as an explicit negative control:
it omits the naming option only on its owned canaries and verifies that the
original VD attachment, stable/data ports, traffic and overlapping lab remain
unchanged. It does not simulate failure by moving or renaming a VD data port.


## vIOS V2 on dnlab-vrf

`management_vrf_smoke.py --execute --nos-image IMMUTABLE_CANDIDATE_ID` optionally
spawns one new vIOS V2 guest after the native gate checks. The NOS fixture borrows
the dedicated source/target networks, verifies the immutable candidate ID and
kind, and uses fresh native endpoint-name checks before handoff. It removes only
its own container; the outer fixture owns network/VRF/firewall teardown. The
installed plugin must match the checkout; the qualification wrapper temporarily
used the candidate plugin and restored the original service afterward.

The tested candidate passed manual IPv4 and default-gateway configuration on
GigabitEthernet0/0 (`p00`), ICMP from the same-lab native client (including routed
traffic after move), post-connect failure rollback without another guest IP
change, unchanged QEMU PID/start time and every NIC/MAC/backend, and console
reconnect through container loopback. No host ARP override was used. Passive
captures resolve the current uplink by endpoint peer identity and use the
explicit dnlab-vrf bridge. Native workloads and the overlapping lab stayed
unchanged; owned containers, networks, VRFs and firewall rules were cleaned up.

This qualifies only that candidate's legacy p00 slot and IPv4 local-host path.
The fresh vIOS V2 mapping probe also correlates all 16 guest hardware MACs with
QEMU backends: `GigabitEthernet0/N` maps to `pNN` (data slots `ethN`, management
slot zero `mgmt0`). It queries each interface separately with a bounded timeout
and checkpoints responses, including partial output on failure, in a private
`interface-mac-queries.json` artifact. This mapping evidence does not qualify
management traffic through an arbitrarily selected data slot.
Other guest data ports, n9kv OOB guest traffic, safe shutdown, disk persistence,
host port publishing/management services on dnlab-vrf, IPv6 and distributed
VXLAN remain unqualified. The production operation API still supports Linux
only. Logs, packet headers and guest overlays remain private under `/tmp`.


## n9kv V2 structural OOB probe

`management_vrf_smoke.py --execute --nos-image IMMUTABLE_N9KV_CANDIDATE_ID
--nos-kind cisco_n9kv` spawns a new n9kv V2 fixture and performs boot-only
structural interface checks. The tested candidate reported loader/ROMMON via
its launcher; that counts as process boot under the agreed criterion. NX-OS
readiness and guest OOB traffic remain unqualified.

The probe verifies the QEMU `p00` management NIC/MAC and `tap0` management
backend, only `mgmt0 <-> tap0` for management TC redirects, the console exception,
and 16 separate `ethN <-> tapN` data paths. It compares 52 permanent kernel link
identities and 34 TC device signatures before/after move and injected rollback,
as well as QEMU PID/start time and all 17 NIC/backend/MAC values. The replaceable
Docker uplink is resolved separately and becomes `dnmu0`; no data interface is
renamed, repurposed or used for management. Console reconnect uses container
loopback. Dynamic packet counters are excluded from configuration comparison.

The local probe passed on Engine 29.8.1/API 1.56 with the candidate plugin,
including fresh naming checks, unchanged native/overlapping-lab workloads,
owned cleanup and restoration of the original installed plugin. This is a
structural gate only. It does not certify actual NX-OS management traffic,
carrier behavior under data links, guest shutdown, boot/config persistence,
management services, published ports, IPv6, distributed operation or the full
catalog. The normal runtime API continues to reject unqualified NOS kinds.

## vIOS V2 selected management slot

Source-built candidates accept a separate image-build option
`--runtime-selected-management` together with `--runtime-management`, an
explicit helper interpreter and a separate experimental tag suffix. The option
is restricted to `cisco_vios`; it installs the selected-slot source helper and
keeps the capability labelled `experimental-unqualified`.

`management_vrf_smoke.py --execute --nos-image IMMUTABLE_CANDIDATE_ID
--nos-selected-slot N` requests this ABI on a fresh fixture. The initial endpoint
is created directly with reserved name `dnmu0`, after a native create-path
canary; no management uplink occupies an `ethN` slot. For nonzero selections the
fixture prepares `eth0` as an independent data endpoint. QEMU PCI/backend slots
are preserved, the selected NIC receives the stable management MAC and TC
script, and p00 receives the independent eth0 MAC/data script. The selected
slot is excluded from warm carrier control; all other slots start as data ports.
Guest IP/default-route configuration remains manual.

The local gates for slots 1, 8 and 15 passed with separate fresh vIOS V2 fixtures
of the same immutable candidate: exclusive `mgmt0 <-> tapN`, distinct p00/eth0
data path, all 16 hardware MAC-to-slot correlations, rejection of `ethN down`
on the reserved slot by the warm controller, source and routed
target guest ICMP, live move and injected post-connect rollback. QEMU, stable
interfaces, all data links and TC configurations stayed unchanged. The native
canary with a two-second startup delay reached readiness and exited normally;
all owned resources were cleaned and the original plugin/firewall restored.

This qualifies slots 1, 8 and 15 for that immutable candidate and local IPv4 path.
Other selected slots, further data traffic cases, snapshot/boot
persistence, safe guest shutdown, production API/GUI adoption and distributed
operation remain separate gates.

`--nos-data-traffic` additionally qualifies local native-peer ICMP on data
slots 0, 1 and 15 with management on slot8. The fresh V2 fixture passed carrier
down/up, removal and restoration of the peer's IP address after carrier down,
and positive data traffic checks after management move and rollback. Final
carrier down preceded peer address removal; management remained reachable.
QEMU and kernel link/TC identities stayed unchanged. The peer interfaces remain
in the fixture namespace: this does not qualify physical link deletion,
VD-to-VD bridges, RealNet, cross-host VXLAN, TCP/UDP or continuous packet loss
during a management move.

## Journalled local VXLAN API and opt-in client

The local service exposes `link-plan`, `link-submit`, `link-status`,
`link-cancel` and `link-inspect`. Requests reference a committed native Linux
node revision and one of its recorded host endpoints. The runtime verifies
the exact node ownership alias and kernel identity; placement, underlay and
VNI remain caller inputs. Link execution shares the node operation lock.
An active or unfinished local link prevents stopping its node until teardown.

Each operation response contains `id`, `phase` and `error`, including an empty
error on success. Submission acknowledges a journalled operation, not guest
readiness. Interrupted creation compensates owned resources; interrupted
deletion completes cleanup. Explicit recovery is required after incomplete
cleanup. Inspection keeps committed state, kernel observation and unknown
guest readiness separate.

The standalone multinode `services.custom_runtime.RuntimeClient` invokes this
CLI through existing SSH, optionally with `docker exec -i`. It qualifies the
ownership protocol, quotes requests, validates operation envelopes and retains
the accepted ID on polling timeout. It does not retry mutations or fall back
to Containerlab. Existing controllers do not call this client yet.

The optional native Linux lifecycle adapter adds `plan_node`, `submit_node`,
`wait_node` and `node_operation(..., action='status'|'cancel'|'reconcile')`.
It requires the advertised revision/container/index-bound ownership contract,
persistent operations and cancellation. Submission checks the returned lab,
node and request identity. Plans and node manifests use `SSHClient.run_input`:
request bytes go over channel stdin, never a shell argument; there is no
command-payload fallback. The bounded SSH transport drains stdout and stderr
before collecting exit status, tracks cancellation channels and omits payload
and remote stderr from errors/logging. Waiting is bounded and does not resubmit,
cancel, reconcile or force on timeout. Recovery/force are explicit actions.

Optional request controls address a lost submit acknowledgement before the
coordinator knows the operation ID. `request-status <lab> <node> <request>` reads
`GET /v1/operation-requests/...`; its `operation` is null when missing and never
includes the private manifest. `cancel-request` reads the exact original request
on stdin and posts `/v1/cancel-requests`. If submission has not arrived, one
atomic cancelled record seals that lab-scoped key, without node/resource changes.
A matching delayed submission returns the same cancelled ID; different content
or another node is a conflict. If already accepted, cancellation retains its ID
and existing policy; completed/failed/recovery outcomes are not rewritten into
successful cancellation. The coordinator must persist the original request and
key before sending and must inspect the returned phase.

`services.runtime_operations.OperationStore` and `OperationDriver` provide that
private coordinator intent/receipt layer. A service-owned directory (0700) and
SQLite file (0600) retain the exact request, immutable host/socket/container
target and remote journal UUID before sending. The configured parent directory
must already exist. Public summaries exclude request bodies, targets,
fingerprints and extra receipt payload fields. SQLite full sync and directory
sync precede remote mutation. Per-request file locking serializes execution
while cancellation intent remains independently writable. This is an operation
ledger, not a scheduler or another distributed topology model.

The runtime advertises a persistent `journal_id`. Bound clients send the expected
identity in `X-Dnlab-Journal` (CLI `--expected-journal-id`); the service checks it
before handling the request. Recovery uses the saved target and checks the
original request through read-only `request-status --match-input`
(`POST /v1/operation-requests`). The original manifest and hash are not returned.
A missing known operation or changed journal/target/content retains pending
state; the driver does not resubmit, re-place or force it. Completed receipts
describe historical operations, not current container or NOS readiness.

`prepare` performs read-only qualification/plan before persisting the intent;
`advance` submits or observes that exact intent. After a crash it can resume
from the private journal; `request_cancel` persists the flag before dispatching
request cancellation on the next advance. Recovery-required remote operations
remain pending without implicit reconcile. The isolated SSH gate reopens this
journal after a lost acknowledgement, cancels a queued request and executes
native start/stop with persisted receipts. Production controllers do not adopt
the driver yet; its intents/results must still be integrated with their
existing topology state and lifecycle policy.

`RuntimeClient.find_node_request` and `cancel_node_request` require the explicit
request-controls capability. They do not submit a replacement request to discover
an ID, nor retry/force recovery implicitly. Cancelled records do not hide earlier
active or recovery-required operations. The SSH gate can drop a successful submit
response, recover the ID after reconnect, seal another key before submission,
restart the daemon and verify a delayed submit creates no VD or endpoint.

The isolated `management_link_authority_smoke.py --runtime-image ...` gate uses
the actual adapter, installed image CLI, Unix API and kernel for node plan,
duplicate submit, queued spawn, pinned-namespace stop and queued cancellation.
It verifies a fixture input value is absent from command lines. The command
transport defaults to a local stdin shim. `--ssh-transport` uses a temporary
key-only loopback SSH server restricted to this exact runtime CLI; the adapter
then uses production `SSHClient.run`/`run_input` over an actual SSH connection.
It reconnects after an accepted queued submit, preserving the operation ID and
completing without another creation. Server logs contain command and byte-count
metadata, with no request body or private key material. The listener, channels,
transports and CLI subprocesses are closed during verified fixture cleanup.
This qualifies SSH protocol on one host; connection setup uses in-memory fixture
keys and an ephemeral port, so production connection provisioning and remote
workers remain unqualified.
Deploy/node controllers do not adopt this adapter yet, and guest NOS shutdown,
persistence, production integration and cross-host placement remain unqualified.

Unit tests cover cancellation, replay, revision and ownership rejection. A
contract test exercises the adapter, actual CLI, Unix socket and journal with
a simulated kernel backend. This does not qualify production controller
integration, real SSH, the API on live VD endpoints, or the new API in the
previously built runtime image; those require separate gates.

`tools/link_api_smoke.py` adds a live local gate through the installed CLI in
a pinned runtime image. It creates dedicated Linux workloads and an isolated
namespace peer over a dedicated host underlay veth. It checks real API link
creation, ICMP, durable deduplication across daemon restart, rejection of node
stop with an active link, teardown/recreation and safe native shutdown. A
second VD is spawned and stopped while the first VD's link remains active,
checking that its workload identity, endpoint and traffic remain unchanged.
Cleanup validates ownership before removing the fixture's resources; reports
and journals stay under a private temporary directory.

```sh
.venv/bin/python src/runtime/tools/link_api_smoke.py
# Only on the already authorized isolated local host:
.venv/bin/python src/runtime/tools/link_api_smoke.py --execute \
  --runtime-image dnlab-runtime-spike:link-api-20261012 --image python:3.13-slim
```

The tool requires both images to be locally available and resolves immutable
IDs before creating resources. It does not pull them implicitly. The peer is
on the same host; the adapter executes commands locally rather than over SSH.
The gate does not qualify API crash at mutation boundaries, NOS, management
services, RealNet, production controller integration or cross-host placement.

With `--replay-cancel` and a rebuilt runtime image, the gate uses dedicated
image workers to SIGKILL their own process after partial create/delete or
during an active-link retry. A separate image process then persists cancellation
while the daemon is stopped. Restarted API replay cleans the cancelled partial
create, completes an already started delete, and verifies/preserves the link
that existed before the interrupted retry. Workloads and the remote peer are
kept alive. These three live cases complement unit coverage at all nine create
and three delete mutation boundaries; they do not qualify every API crash point.

## Local bridge and TC ownership gate

`tools/local_bridge_smoke.py --execute` exercises the corrected multinode
local bridge path inside five dedicated network namespaces. Two lab bridges
carry the same guest IPv4 subnet while retaining separate complete lab identities.
The probe checks ICMP and raw LLDP/LACP frames, idempotent TC retry, teardown of
one lab while the other keeps traffic, preservation of preexisting and newly
shared clsact qdiscs, and rejection of a foreign rule at a reserved priority.
All interfaces, filters, firewall rules and peers remain inside fixture
namespaces, which are removed after ownership checks.

Local link state now records source identities, host context, TC targets and
which clsact qdiscs the operation created. Existing rules at the reserved
priorities require matching state and exact classifier/action proof. Cleanup
removes only qualified LLDP/LACP rules; preexisting qdiscs remain, and a newly
shared qdisc is relinquished rather than deleted. This gate qualifies the legacy
local bridge path and does not qualify a custom bridge primitive/API, real SSH,
NOS, RealNet, cross-host traffic or crash durability of bridge state.

## Custom bridge primitive gate

`tools/bridge_smoke.py --execute` exercises the journalled custom bridge primitive
inside five dedicated namespaces. It verifies ICMP and raw LLDP/LACP traffic,
read-only active retry, independent teardown of two labs with equal subnets,
preservation of foreign TC/firewall resources, compensation after a lost TC
response, recreation and unchanged source identities. Both journals end cleaned
and all fixture namespaces are removed.

Linux resets the bridge MTU to 1500 after its last port is detached. Recovery
accepts that reset only when the final detach intent is persisted, the journal
is deleting or recovery_required, and the bridge has no members. Creator, MAC,
ifindex, namespace and source checks remain mandatory. Unit tests model crashes
after every create/delete mutation, including reset before acknowledgement.
Add `--crash-recovery` for real SIGKILL before and after all 13 create and 11
delete mutations. A separate worker reopens the persisted WAL and resource lock
and completes owned cleanup while the other lab remains active. Add
`--worker-image sha256:<immutable-local-ID>` to run those workers from the
runtime image. Workers verify core source hashes and reject host core imports;
only the harness, dedicated state, namespace handles and host boot ID are mounted.
No Docker socket is mounted in workers. Container identity, label and image are
checked before removal. The image-created bridge also carries ICMP and LLDP/LACP
test frames. Build with `--build-arg RUNTIME_BASE=python@sha256:<digest>` to fix
the base used for the comparison.

These gates do not qualify a bridge operations API, NOS, RealNet or distributed
placement. Image mode qualifies fixture workers; production daemon integration
still needs its own gate.

Bridge and VXLAN creation share source reservations from their durable primitive
journals under the same resource lock. Any phase other than verified `cleaned`
keeps the source reserved, including partial create, delete and recovery_required.
Conflicting create or retry fails before kernel mutation; it never replaces an
existing transport. Changing transport requires explicit delete then create.
A preexisting clsact by itself is not a reservation and remains preserved.
The bridge gate verifies both conflict directions, the original link and another
lab, and reuse after cleanup. Image mode also submits the conflicting bridge
creation from an image worker against a native active VXLAN journal.

## Bridge operations through the local API

The existing `link-plan`, `link-submit`, `link-status`, `link-cancel` and
`link-inspect` commands also accept native Linux bridges. VXLAN requests keep
their existing format. A bridge create uses:

```json
{
  "schema_version": 1,
  "kind": "bridge",
  "lab_id": "lab1",
  "link_id": "l0",
  "request_id": "create-l0",
  "action": "create",
  "endpoints": [
    {"node_id": "vd1", "host_interface": "rt-left", "expected_node_revision": 1},
    {"node_id": "vd2", "host_interface": "rt-right", "expected_node_revision": 1}
  ],
  "spec": {"mtu": 1450}
}
```

Delete/recover retain both endpoint owners and omit `spec`. Each owner must
match a committed node revision and declared endpoint. Creation verifies both
workloads and reciprocal kernel peers before the primitive mutates resources.
The journal commits both endpoint states atomically; queued/recovery operations
and active links block stop on either node. Status includes both affected nodes.
Repeated requests deduplicate, active retry is read-only, and replay compensates
interrupted creation without implicitly recreating the link. Cancelled partial
delete completes cleanup; interrupted active retry preserves the existing link.

`tools/bridge_api_smoke.py --execute --runtime-image <local-image>` exercises
the image daemon and two native Docker VDs in an isolated anchor namespace,
with actual CLI/Unix HTTP, IPv4 traffic, retry, daemon restart, both stop guards,
spawn/stop of a third VD, deletion, recreation and safe native shutdown.
`--replay-cancel` adds three real image SIGKILL cases followed by cancellation
persisted in a separate worker: partial create, partial delete and active retry.
This covers representative API replay cases, not every API crash boundary.
The adapter remains opt-in; this gate does not qualify real SSH, cross-host
placement, NOS, RealNet or production controllers.

### Isolated RealNet infrastructure cleanup gate

RealNet is infrastructure attached to VD data ports; it has no VD management
endpoint or guest NOS lifecycle. The cleanup prototype in multinode refuses
unqualified legacy resources and requires a complete read-only preflight on
every participating host before any deletion. A root-owned per-host journal
records intent and completion, and cleanup verifies absence before success.

`tools/realnet_cleanup_smoke.py --execute --image <immutable-helper-image>`
creates owned bridge, VXLAN, veth and helper resources in two private network
namespaces. It qualifies fourteen real SIGKILL boundaries, recovery and retry,
preservation of foreign firewall rules and control-infrastructure invariants.
Raw snapshots remain intact. Only numeric drift in bridge
`linkinfo.info_data.gc_timer` and a VXLAN bridge port's
`linkinfo.info_slave_data.forward_delay_timer` is excluded from the invariance
comparison; identity, configuration, port state, helper ID/start time and
firewall comparisons remain strict. Bridge creation supplies an explicit MAC.

`--daemon-recovery` adds two real crashes followed by the daemon's execution
and finalization paths: state remains after incomplete cleanup and is removed
only after guarded recovery, resource absence and durable journal verification.
The daemon inventories every persisted RealNet VXLAN and router veth; those
names never authorize generic deletion. Unqualified legacy resources remain
protected, including when the name-based inventory is already empty.

This gate does not qualify VD data traffic, cross-host RealNet deployment,
provisioning of persistent ownership proofs, remote SSH or the continuously
running daemon service in a production stack.

The opt-in native request `stop_mode: coordinated` separates verified process
exit from link cleanup and finalization. The ordinary legacy stop request keeps
its link-free guard. A coordinated stop reserves the local link footprint,
checks its workload and kernel owners before signaling, and parks at
`awaiting_link_cleanup` without advancing the node revision. Only the existing
coordinator may request the next step with `stop-stage OPERATION_ID` and a JSON
stdin body containing `lab_id`, `node_id`, and `stage` (`cleanup` or `finalize`).
Cleanup runs persisted child link requests; successful cleanup parks at
`awaiting_finalization`. Finalization removes the stopped workload/endpoints and
atomically commits the node revision and releases the footprint reservations.
Stage requests are idempotent and journal-bound. Timeout never escalates force,
and cancellation after exit never restarts a workload. The private coordinator
store records the requested stage before sending it, including retries after a
lost response. These are local primitives, not a second distributed scheduler.

TC actions now carry a random 128-bit cookie persisted before installation.
Kernel readback records the action index and binds the proof to the original
source and target identities in the recorded namespace/host boot. Cleanup
accepts `to_dev: "*"` only when that complete proof matches and both the target
name and original ifindex are absent. Replacements, renamed endpoints, changed
cookies/indices and shared actions are refused. An interrupted installation
without successful readback cannot authorize an unbound action; legacy rules
have no implicit wildcard adoption. Stop sessions bind the TC proof generation.
Both bridge and VXLAN cleanup perform the complete ownership preflight.

The local native `bridge_api_smoke.py --coordinated-stop` gate passes, including
traffic during shutdown timeout, process/daemon/coordinator crashes, lost stage
acknowledgements, explicit finalization and complete fixture cleanup. The local
VXLAN namespace gate also passes traffic, retry and lost-response cleanup.
These results qualify the local native primitives; production controller
adoption, cross-host coordinated shutdown and NOS shutdown remain pending.

`dnlab_multinode.controllers.runtime_node.RuntimeNodeController` provides the
opt-in coordinator for a native stop whose complete footprint is on one host.
It re-observes the original bound operation before advancing, requires an exact
verified parked receipt, persists each stage intent, and then sends it through
`OperationDriver`. It does not reconcile or force a failed shutdown. The native
gate uses this controller for preparation and finalization, with real SSH,
crash checkpoints and lost acknowledgements; cleanup is verified complete.
The caller must supply the complete participating-host list on every call.
Distributed footprints are refused. This controller is not yet selected by the
existing topology APIs: backend/spec bindings, public state projection and a
tracked distributed cleanup barrier remain integration work.

Every Engine-bound workload now has a durable Docker birth proof, independently
of data ports and management moves. The journal reserves a random birth nonce
before create and binds the Docker ID from the create response before start.
Inspect, lifecycle, link owners and coordinated stop use the same backend guard.
A different ID, creator, nonce or spec refuses mutation and retains recovery and
reservations. Stop removes only the qualified generation; a later tracked start
records a new generation after committed stop and verified resource cleanup.
History is retained. Existing journals do not implicitly qualify old workloads.

A crash before Docker allocation can replay the same durable intent when the
container name is absent. A lost create response with an extant container and
no recorded Docker ID remains `recovery_required`: matching labels cannot prove
that it is still the original generation. Force does not bypass this guard.
The native client requires the corresponding `workload_generation` capability.
The `--coordinated-stop` fixture includes dedicated negative canaries recreated
with the original labels and a new Docker ID; their intentional recovery state
and original birth evidence remain in the fixture journal for diagnosis.

Node `inspect` retains its existing fields and adds `journal_id`,
`committed_spec_fingerprint`, `workload` and `operation`. A start interrupted
before commit can report the old committed revision/state alongside the new
qualified Docker generation and its original pending start operation. A first
start with no node commit yet has revision zero and committed state `absent`.
A pending birth spec is accepted only from its original matching journal request;
foreign replacements still fail the common generation guard. No manifest,
environment or birth nonce is exposed by these inspection fields.

Inspection reads metadata in one SQLite read snapshot, checks Docker twice and
rechecks metadata. It retries up to three times on changes, then returns a
conflict requesting a new observation. It does not take the workload execution
gate, so the coordinator can inspect a workload while an operation owns that
gate. Readiness remains `unknown`. `RuntimeClient.inspect_node` requires a bound
journal, the optional `node_inspection` capability and a consistent typed result.
These are inspection primitives; selecting the custom backend from topology and
projecting it into the existing public VD state remain separate integration work.

The experimental cleanup path now installs a durable per-lab closing fence in
both the private coordinator ledger and each qualified local runtime journal.
It persists the original teardown request identities before sending closure;
only those coordinated stops and their proof-bound link cleanup children may
mutate the closed footprint. New lifecycle, link and management requests are
refused. A lost acknowledgement retries the same closure identity. Execution
and submission locks serialize fence installation against active workers and
concurrent submissions; a process crash releases locks, never the saved fence.

The daemon requires complete qualified teardown intents. It leaves legacy,
unknown or distributed/RealNet native footprints protected. Before removing
dependent infrastructure or deployment state it verifies workload absence,
clean journal resources, final stop receipts and closed runtime acknowledgements.
The closed tombstone remains after deployment-state removal. Existing completed
request lookups remain idempotent and cannot create a workload.

Journal-bound CLI commands `lab-close LAB`, `lab-finish LAB` and
`lab-reopen LAB` accept JSON on stdin through the optional closure protocol.
Close requires `closure_id`, `generation` and the exact original `stops` list;
finish requires that closure identity and generation. Reopen additionally
requires a stable `request_id`, verifies cleanup again and increments the lab
generation. The private coordinator stays fenced while reopening has an unknown
remote outcome. Reopening is explicit; ordinary start never reopens a lab.
After reopening, new node/link requests must carry the returned `lab_generation`;
management handoff accepts the corresponding keyword. Missing or old generations
are rejected. The implicit generation remains 1 for existing, never-closed labs.
Request history and container birth history are retained across reopening.

Only local coordinated closure/reopening is qualified. The image/SSH gate uses
two linked native VDs, delayed starts, actual daemon SIGKILL, lost closure and
reopening acknowledgements, a new-generation start/stop and an untouched control
VD. Cross-host reopening and production backend selection/public state projection
remain separate qualification and integration work.

Existing, qualified native Linux bindings now select the public node lifecycle
adapter by owner identity. Names never select or adopt a native owner. Public
node start/stop/restart/remove/reconcile and node listing use the original private
intent ledger, immutable target/journal and Docker birth proof. Unknown or mixed
bindings refuse mutation. Initial topology deployment and whole-lab destroy are
not selected automatically; the legacy controllers refuse custom-owned state.

Public native calls accept an optional stable `request_id`. Composite restart
steps are durable and pinned to the original workload generation, so replay
cannot stop or advance an unrelated generation. Remove retains a
verified stopped owner tombstone separately from active nodes; readd uses a new
tracked generation. No guest disk is erased by node removal. Status exposes an
optional `runtime_status` object separating committed state, actual container,
workload generation, pending operation and unknown guest readiness. A foreign
container with the same name remains unqualified. Status reads do not save the
public deployment state. GUI local progress cannot override native inspection.

Native public stop requires the optional exact stop-footprint fingerprint. Every
planned peer binding is checked before shutdown; a changed graph fails before
host mutation. Ordinary shutdown failures retain the workload and evidence.
Explicit forced recovery is persisted before sending it. Cancellation after a
start commit records an ordinary stop instead of claiming cleanup while leaving
the VD running; a shutdown timeout remains visible as recovery required. A
cancellation acknowledgement reports `cancellation_requested`, not completed
cleanup. An exception cannot qualify cleanup using a cached stopped view. A fully
compensated uncommitted attempt keeps its original private proof and the earlier
committed source specification. State finalization and public mutations share a
per-lab lock in addition to the persistent closing fence.

After a local start/restart, the adapter restores the currently declared native
point-to-point bridges from qualified endpoint mappings and immutable link intents.
Cross-host links, RealNet, NOS adapters, persistence binds and initial deployment
still need separate qualification/integration; unsupported paths refuse mutation.

Initial management networks now have durable local proofs shared by the lab's
nodes and scoped to its explicit lab generation. Before Docker allocation, the
runtime saves the network ID, driver, labels, options and IPAM configuration.
Create uses that immutable ID. Stop and start compensation retain the proof;
restart, inspect and recovery reject replacements or configuration drift. A new
VD in the same lab cannot reset the proof. Reopening a verified closed lab keeps
historical proofs and uses a new lab generation.

Docker's inactive endpoint metadata is accepted only for an owned birth in
`created`/`exited` state with PID zero, no sandbox or endpoint ID, matching IPAM,
and the pinned network mode or tracked management assignment. An active endpoint
still requires its exact network ID. Identity conflicts retain recovery evidence
without automatic cleanup or adoption. Existing experimental workloads without
proof are not adopted. The multinode client requires the corresponding capability
for management manifests and qualified management-bound public/cleanup clients.

`tools/initial_management_identity_smoke.py` exercises initial boot, ordinary
stop/restart, replacement rejection, new-node rejection and daemon crash/recovery
against dedicated networks on the existing `dnlab-vrf` service. It pins the
installed plugin hash and does not update that service. Its control lab uses the
same subnet in a separate VRF. `--execute` and immutable image IDs are required;
all fixture mutations and cleanup remain limited to recorded owned resources.

Start planning reads and validates the effective management network, including
ownership, driver and usable IPAM pools, without creating pins or operation
intents. Its optional `management_preflight` result contains the observed network
proof bound to the runtime journal and original request. A management start must
submit that same proof. Apply and recovery compare it again before pinning and
allocation; a replaced or changed network requires recovery rather than a fresh
observation. Addresses outside the configured pools, reserved addresses, invalid
gateways, overlapping pools and disabled requested IPv6 are rejected in planning.

The coordinator binds the proof automatically when preparing a new private
intent. Retries, lost acknowledgements and public lifecycle replay retain the
original bound request and never refresh its observation. Management clients
require the request-bound preflight capability. This local Linux qualification
does not enable production deployment or qualify the full NOS catalog.


Initial data-port plans now inspect permanent host names, temporary peer names,
resource reservations and any existing workload namespace without mutation. An
occupied name is accepted only as a qualified veth pair belonging to the verified
Docker birth. MACs, both kernel indices, type, alias, peer relation and namespace
must agree; names and labels alone cannot authorize reuse. Permanent/staging name
overlaps inside a manifest are rejected, and temporary names are reserved too.

Before allocating a workload, apply durably records its original endpoint
observation and host boot/network namespace. It rechecks immediately before
Docker create and before endpoint changes. Created-pair identities and guest
namespace are checkpointed as allocation advances. Retry/recovery retain the
original observation and reject replacement pairs, including with a new request
ID on an existing workload. The atomic MAC pair qualifies the crash gap between
veth creation and its first index checkpoint. An endpoint conflict retains
recovery evidence and never triggers generic cleanup of the foreign interface.
The coordinator requires the data-preflight capability for data-port starts.
The bridge API smoke gate includes isolated host/staging conflicts and verifies
that no workload was allocated, foreign pairs survived and control traffic kept
working. This remains a local Linux qualification.

Planning also checks existing journal reservations for container names, permanent
and staging endpoint names and exact published-port keys. It uses the same
ownership check as submission, without reserving or changing anything itself.
Submission retains its atomic admission transaction, so a successful plan never
promises resources against later contenders. Execution rechecks the plan before
mutation. Start clients require the reservation-preflight capability. The initial
management smoke gate holds the execution gate, submits an owner, verifies both
plan and admission reject a contender, and cancels the owner before allocation;
resource release and the management crash/recovery checks are then verified.

The opt-in NOS smoke fixture records its complete privileged Docker creation
configuration separately from production manifests. `tools/nos_fixture.py`
persists the original intent, reserves a birth nonce, records Docker's immutable
response ID and binds that generation before start/bootstrap. Replay keeps the
same intent and generation. A lost create response cannot authorize adoption by
name, even with matching labels; a recorded response can be rebound after a
crash. Cleanup verifies the original identity, records its intent and requires an
explicit force option for the fixture. Conflicts or incomplete cleanup retain
the journal and dependent infrastructure. Reports are saved even on cleanup
failure. These fixtures do not enable production NOS lifecycle support.

`RuntimeInitialDeployment` is an opt-in initial **Linux workload** batch in the
existing multinode operation ledger. The caller supplies every manifest and
host assignment; network/service/link generation and production backend
selection remain separate. Read-only plans include a coherent, request-bound
`node_preflight` view for absent/stopped nodes without changing the existing
inspect contract. Every member must pass preflight before one local transaction
records the batch and all immutable child intents. Resource conflicts within
that batch and unfinished coordinator intents are rejected before submission;
remote atomic admission and execution checks still apply to later contenders.

Batch advancement re-observes all original children before sending the next
start, binds receipts to their original runtime journal and publishes only
verified native bindings. A lost acknowledgment can be recovered by reopening
the coordinator ledger and observing the original request; it never creates a
replacement implicitly. An error retains the complete batch and requires
explicit recovery. Cancellation seals unsubmitted requests and uses durable,
ordinary stop intents for completed children. A shutdown timeout retains the
workload and recovery state; batch cancellation never adds force. This is not
an atomic distributed transaction: partially committed workloads remain recorded
until completed or explicitly cancelled. Reopening a failed child as a new
attempt and production whole-lab deployment remain outside this prototype.

The opt-in `tools/initial_batch_smoke.py --execute --runtime-image <immutable-id>
--workload-image <immutable-id>` gate runs two dedicated runtime namespaces on
one host over key-only loopback SSH. It tests the all-member admission barrier,
pre-spawn cancellation, a lost submit response followed by ledger reopening,
verified generation bindings, and ordinary cancellation. It retains state and
dependent daemons if qualified cleanup cannot finish. It does not qualify
physical cross-host operation, NOS lifecycle, network services or link traffic.

Native Linux manifests may include `management.mac`: a lowercase, nonzero
unicast MAC. It is sent as the Docker management endpoint MAC and included in
the immutable request/spec fingerprint. Existing manifests without this field
retain their previous behavior. A node with an explicit MAC cannot drop or
change it on restart; the identity belongs to the VD, independently of its disk.
Disk wipe must preserve that identity. Guest-generated DUID/IAID may change after
wipe unless the image can explicitly restore them; this extension does not
configure DHCP clients or qualify guest DHCP behavior.

The runtime verifies the requested MAC against Docker and the reciprocal kernel
veth in the pinned workload namespace, without assuming a guest interface name.
Conflicts preserve state and require recovery; inspection and lifecycle do not
silently repair a changed endpoint. Detached original generations may expose an
empty MAC after exit only with verified birth/spec, no sandbox/endpoint, the
original network mode and matching IPAM configuration. MAC claims are reserved
locally and checked across an initial batch; visible foreign endpoint conflicts
are refused before allocation. A later external contender is not excluded by a
successful read-only plan.

This contract applies to native Linux endpoints. A vrnetlab guest NIC identity
remains separate from its Docker uplink, and no production NOS adapter or safe
NOS shutdown capability follows from it. The management identity smoke gate's
`--management-mac` mode checks Docker/kernel equality, stable MAC across ordinary
stop/start with a new Docker generation, changed-MAC rejection and isolation of
a control lab with the same subnet/MAC.

`tools/port_publication_comparison.py --execute --image <immutable-id>
--plugin-sha256 <installed-plugin-hash> --output <new-durable-directory>` runs a
diagnostic comparison of equal Docker port requests on stock bridge and
`dnlab-vrf`. It uses the fixture birth ledger directly, with the complete Docker
config recorded before create and immutable response ID bound before start.
These are non-privileged Linux diagnostic containers; reusing the fixture helper
does not enable NOS or production lifecycle capabilities. Readiness verifies the
signal handler/process marker and HTTP inside the container before host probes.
IPv4/IPv6 host TCP results and binding inventories are observations, including
negative results, rather than a reason to preempt the diagnostic with runtime
compensation. The container service itself uses IPv4; host IPv6 success is not a
qualification of guest IPv6. Ordinary stop and ownership-checked cleanup retain
proofs on failure. The output directory contains the durable journal, intents,
reports and cleanup audit; use a persistent private location instead of `/tmp`.
This tool implements neither a runtime publisher nor plugin port publication.

The opt-in initial batch can now be prepared with
`RuntimeInitialDeployment.prepare_topology(topology, schedule, batch_id, ...)`.
`services/runtime_manifest.py` compiles the existing complete placement without
SSH, pulling images, changing the topology or allocating resources. It retains
current container/host endpoint names and classifies local, cross-host and
RealNet data attachments through the existing link builder. Plans with missing
or duplicate placement, inconsistent link footprints or reserved data ports are
refused before remote preflight. Linux members require resolved IPv4/stable MAC
and an immutable image; explicit source-reference-to-image resolutions are kept
in the operation provenance. Native command arrays/timeouts can be supplied
explicitly. Unqualified NOS kinds, assets, persistence, warm ports and arbitrary
Containerlab attributes are refused rather than silently translated.

Compilation, link footprint, image resolutions and WebUI metadata are persisted
atomically with all original child intents in the existing coordinator ledger.
The batch remains a workload phase; it does not execute link/service phases or
become a topology store. Replay retains the original compilation and rejects a
changed footprint/metadata without re-planning remote management proofs.

GUI WebUI declarations and existing allocation records remain private access
metadata for the existing GUI -> jumphost -> management-IP/guest-port path. They
do not implicitly add Docker publications to native workloads. Explicit topology
`ports:` requests are rejected until native publication on `dnlab-vrf` is
qualified. This keeps the outstanding host-publication requirement visible;
it is not dropped or replaced by a silent fallback. Production backend selection,
multiple-segment topology integration and end-to-end GUI/jumphost qualification
remain open.

### Jumphost birth and management attachment

The multinode jumphost service now uses a standalone root-local worker over the
existing SSH boundary. Requests travel on stdin, using `SSHClient.run_input`,
so login credentials do not appear in the SSH command. The master-side
`jumphost_journal_dir` defaults to `/var/lib/dnlab/jumphost` and contains
root-only, atomically replaced records with file and directory fsync. Keep
these records while any associated resource or recovery remains pending.

The coordinator saves a jumphost generation before requesting allocation. The
worker records the complete intended configuration and a birth nonce before
`docker create`, then binds the immutable Docker ID before start. It pins the
image, external network, lab-owned management network/VRF/bridge and workload
namespace. Management uses a manual veth: the external Docker bridge remains
the endpoint for published SSH. Host veth names hash the full lab and segment
identity rather than truncating the lab name.

The veth peer is born directly in the pinned namespace. Partial creation is
qualified only against the pending durable intent, expected MACs, reciprocal
peer indices, container generation and namespace. Alias assignment, bridge
binding, address assignment and link-up use namespace-local netlink messages
addressed by qualified ifindex. The creation command's alias option is not
assumed sufficient. A nonce alias and both endpoint identities must be verified
before the attachment becomes active. The unaddressed host end uses the current
bridge MAC, preserving a bridge which inherits its MAC from its members.

Ordinary retries verify an active generation; pending operations require the
explicit `recover_jumphost` service operation. A lost create response may bind
only the original nonce/configuration-qualified container. A renamed, replaced,
ambiguous or missing attempted birth is not recreated. A later explicit deploy
can provision a new coordinator generation after verified cleanup; the previous
record is archived and historical generations cannot be reused.

Teardown preflights the container, namespace, pair and infrastructure before
sending TERM, verifies exit before unlink, and removes the stopped container
by ID without force. If the namespace remains open, residual veth deletion uses
its qualified kernel index. A timeout preserves the attachment and journal.
Destroy and the cleanup daemon delegate to this guard, preserve dependencies
on failure, reject stale coordinator generations and retain lab state until
the jumphost journal is verified cleaned. Legacy resources without coordinator
and birth proof are retained for explicit operator resolution; no automatic
adoption or migration is provided.

`tools/jumphost_identity_smoke.py` is an opt-in local gate using a pinned existing
jumphost image and the installed `dnlab-vrf` plugin. It checks common-prefix lab
names, equal management addresses in separate VRFs, SSH publication, management
ICMP, lost create/veth responses, stable generations, a control lab and cleanup
with a pinned namespace. This qualifies the current single-segment attachment
primitive, not full GUI WebUI, multiple-management services, NOS or physical
cross-host operation. The production initial workload backend remains unchanged.

### Sticky management identity admission

Multinode resolves IPv4, IPv6, MAC, DUID and IAID together on a private copy of
the topology nodes. Plan and hot-add publish the five resulting ledgers only
after the entire preflight succeeds, before resource probes or SSH clients.
The existing standalone IPv4 and identity allocator signatures remain available
and also validate their complete inputs before updating node fields.

Reservations have a node owner. A node can reuse its own reservation; explicit
addresses and MACs cannot take another owner's reservation, including a removed
node's retained identity. A recorded VD MAC cannot be replaced by an allocator
retry. Invalid or conflicting existing ledger entries require explicit
resolution rather than silent discard or reassignment. Generated MAC/DUID/IAID
values retain their previous derivation. IPv6 allocation stays inside its prefix
and reports exhaustion without partial updates, including on small subnets.
DUID/IAID strings retain their existing representation; uniqueness checks use the
client pair, allowing IAID reuse with different DUIDs. This is coordinator
identity allocation, not qualification of guest DHCP traffic or a NOS adapter.

Status does not invoke an allocator. It displays the committed runtime address
or the existing reservation and preserves legacy display aliases without
transferring ownership between their names. Planning and mutations continue to
use strict ownership checks. Ledgers remain local to a lab; equal addresses and
MACs in distinct labs are allowed. Management segment-scoped state and the
multiple-network service orchestration remain separate integration work.

### Opt-in management segment planning

`parse_topology(..., native_management=True)` and
`PlanController(..., native_management=True)` accept the experimental segment
schema. The ordinary parser rejects these declarations before host operations,
so the current Containerlab path cannot silently use only the default network.
No public backend selection or HTTP/GUI control is enabled by this option.

```yaml
name: example
management_networks:
  default:
    ipv4-subnet: 198.18.1.0/24
    ipv6-subnet: 2001:db8:1::/64
    dhcp: true
  blue:
    ipv4-subnet: 198.18.2.0/24
    ipv6-subnet: 2001:db8:2::/64
    dhcp: false
topology:
  nodes:
    r1:
      kind: linux
      image: example/linux@sha256:<resolved-digest>
      management_network: blue
      management_port: eth0
```

Explicit segment maps require a `default` entry. Each segment requires an IPv4
subnet; optional `ipv4-gw` and `ipv6-gw` select guest gateways, and DHCP is a
boolean. IPv6 defaults use the existing IPv4-derived prefix if omitted.
Network/bridge names are internal and derived from the full lab/segment identity;
users cannot supply them. Single-network input retains its current network names
as the default segment view. Combining `mgmt` and `management_networks` requires
the default views to agree. Subnets must not overlap within one lab or with the
jumphost external IPv4 network; distinct labs may use equal addresses. A selected
management port cannot also occur in a data or RealNet link. RealNet remains
infrastructure with no VD management assignment.

The pure resolver returns a topology copy and an immutable management plan:
segment definitions, each VD's network/port assignment, per-segment IPv4/IPv6
ledgers and VD-owned MAC/DUID/IAID ledgers. Adding a segment or new VD preserves
prior reservations; removed VDs keep their reservations. An existing segment or
assignment cannot be changed or removed by preparing another initial deployment.
Those changes require their explicit lifecycle operations. Legacy deployment
state is not implicitly converted to the new ledger. The optional
`DeploymentState.management_plan` persists this model for the native coordinator;
initial batches also store the complete model in their compilation provenance.

The native compiler resolves each member against its selected segment and keeps
the existing placement and data-link footprint. Batch admission checks that the
model matches every member, then compares the runtime's request-bound network
proof against desired names, driver, lab ownership, bridge/VRF, tenant and IPAM
subnets/gateways before recording any child intent. Retry retains the original
model and proofs; a recomputed hash alone cannot legitimize inconsistent metadata.
Only native Linux on its default management port is currently executable through
this producer. NOS and other selected ports still require adapter qualification.

Tests cover the parser/resolver, persistent state, native compiler and actual
Engine/Journal with simulated Docker/kernel. The 100-VD/five-host case validates
compilation from existing placement, not physical scale. No segment network,
management VNI, VXLAN, jumphost interface, route, DHCP/DNS service or firewall is
created by this resolver/compiler. Their coordinated materialization, explicit
move/state update and teardown remain required before production selection and
end-to-end GUI qualification.

### Management infrastructure ownership and recovery

`services/netsetup.py` now coordinates the management host worker through the
existing SSH stdin transport. Deployment persists a generation and complete
host/segment intent in `MgmtState.infrastructure` before remote allocation.
Every host completes a read-only ownership preflight before any host starts
setup. The host worker repeats the checks under a root-only lock and writes and
fsyncs its journal before each mutation. Worker journals use the configured
`management_journal_dir` (default `/var/lib/dnlab/management`).

A lab shares one VRF; each segment owns a bridge, a multipoint VXLAN and explicit
flood FDB destinations. Segment VNIs use the existing coordinator registry,
separate tagged identities and the same reservation pool as RealNet. This does
not change the RealNet per-master/worker tunnel contract. Reservation retries
keep their VNI/token. Adding a participating host extends the multipoint peer
inventory without replacing the existing tunnels; incompatible endpoint changes
are refused. Reservations are released only after every host's authoritative
cleanup journal and resource absence have been verified. Coordinator and daemon
retain state on unavailable hosts, generation conflicts or incomplete cleanup.

Birth intent includes an unpredictable generation-derived MAC, fixed at kernel
creation, and the complete link configuration. Some kernels omit an alias
requested at creation; the worker verifies the pending birth MAC/configuration
before assigning the alias by qualified kernel index. Subsequent operations
verify boot/namespace, ifindex, MAC, alias, kind, table, underlay, VNI, master and
technical gateway. Mutations and deletions use kernel indices. Legacy or
replaced resources are rejected; names, matching labels or matching
configuration alone do not authorize adoption or deletion.

FDB flood rows must match their journaled destination, permanent state and self
flag. Firewall selectors include the generation token, are checked before
changes, and are removed individually. IPv4 and IPv6 FORWARD rules put a VRF
input DROP before bridge ACCEPTs: routed traffic enters FORWARD through the VRF,
so bridge-pair selectors alone do not block a host gateway shortcut. Layer-two
traffic toward a jumphost interface remains permitted. A shared VRF and its
routing guard survive individual-segment cleanup; the final segment may remove
them only after all segment resources are gone and no unqualified children or
attached ports remain. Setup failures require explicit recovery; cleanup
failures resume cleanup. Provisioning a new generation is explicit, requires a
verified cleaned predecessor and preserves its archived proof.

The existing deploy, destroy, rollback and cleanup daemon delegate this host
infrastructure lifecycle to the guard. Generic daemon interface deletion is not
an authority for management resources. The segment planner/compiler still does
not materialize Docker networks or multi-interface service configuration itself;
Provider bootstrap/upgrade and full native service orchestration,
DNS/DHCP/RA, management move/state integration, GUI and catalog qualification
remain separate work. Scheduler, placement and public API shapes are preserved.

`tools/management_identity_smoke.py` runs **only in a disposable network
namespace**, with its output under a new private directory in `/tmp`. It exercises
the actual standalone worker/stdin boundary, two labs with equal management
subnets, birth/delete response loss, retry, shared-VRF cleanup, foreign bridge
refusal and unchanged control-lab identities. Disposable guest and jumphost
namespaces verify IPv4 traffic: a technical-gateway shortcut fails, removing
only the fixture's qualified DROP rules proves that route viable, restoring them
blocks it again, and bidirectional traffic succeeds via the jumphost. Full
snapshots are retained; only bridge `info_data.gc_timer` and VXLAN
`info_slave_data.forward_delay_timer` are omitted from equality checks. Address
readiness has a finite wait; address or identity changes are not normalized.

This gate does not install or change the plugin, create Docker VD images, test
NOS readiness, exercise remote hosts or qualify physical scale. IPv6 firewall
creation/ownership/cleanup is exercised, while IPv6 guest routing and complete
Docker/plugin service integration remain unqualified by this particular gate.

### Docker management-network generations

The kernel journal now also owns each segment's Docker network lifecycle.
`management_network_host.py` uses the Docker Unix HTTP API and observes the
installed `dnlab-vrf` provider's network, endpoint and IPAM pool records. A
coordinator-supplied definition must agree with the qualified lab, VRF, bridge
and technical gateway. Full host preflight runs before network allocation;
preflight does not install, update or restart the shared plugin. The provider
must already be provisioned and operational on participating hosts. Provider
bootstrap/upgrade remains a separate infrastructure operation.

Before POST create, the host persists the full definition and a random birth
nonce. The returned immutable network ID is saved before any endpoint is
admitted. Network and IPAM drivers/options, IPv4/IPv6 pools and gateways, host
partition, reservations, lab ownership, nonce and plugin/kernel dependencies are
verified on reuse. Names and matching configuration never authorize adoption of
an existing object. Only structured Docker HTTP 404 is absence; HTTP/transport
errors, malformed responses, stale plugin pools and endpoint records retain
recovery state. A lost create response can bind only the recorded nonce and
complete original definition.

Deploy marks network use before DNS, jumphost, anchors or VDs may attach. Both
legacy start/hot-add wrappers and the native public start/restart dispatcher
require network admission before workload mutation. Failed hot-add admission
does not trigger shared-service reconciliation as rollback. Initial native
batch orchestration must likewise call `network_action(..., 'mark-used')` after
materialization and before admitting the batch; full native services/backend
selection remains experimental integration work.

Once an ID was observed or use was reserved, a missing network cannot be
recreated by ordinary ensure, VD start or ordinary recovery. The logical segment
and its address/identity reservations stay unchanged. Explicit repair is exposed
internally as:

```python
restore_mgmt_networks(
    state, clients, checkpoint=save,
    request_id=uuid.uuid4().hex,
    targets={"worker1": ["default"]},
)
```

All hosts and unaffected segments are checked, but only the requested missing
generations are restored. An intact peer network is not replaced. The previous
ID must be absent, with no unqualified bridge attachments or plugin residues.
The coordinator saves the immutable target set and operation ID before the
first host mutation; host journals bind that ID to the original definition and
new nonce. Retry/recovery keeps the operation, nonce and completed host's ID,
including after a crash between hosts or loss of the restore-create response.
Historical attempts cannot overwrite newer generations. Previous birth proofs
are archived in the host record. Replacement networks are preserved and refused;
they must not be adopted as an infrastructure repair.

Cleanup verifies every target host before its first delete, requires empty
Docker/plugin endpoint inventories, and deletes only the qualified network ID.
Delete response loss resumes cleanup rather than creation. Kernel teardown,
VNI release and daemon finalization require authoritative network cleanup too;
the daemon does not emit a generic management `docker network rm` by name.
Missing/legacy coordinator or birth proof fails before plugin or Docker mutation.
The internal repair entrypoint does not add a GUI or enable a production backend.

`tools/management_network_identity_smoke.py` validates this path against the
unchanged installed provider on the local host. It uses two token-scoped VRFs,
bridges, VXLANs and Docker networks with equal IPv4/IPv6 subnets plus an existing
Python image pinned by ID. It exercises the actual standalone source/stdin
transport, lost birth/restore responses, attached-endpoint cleanup refusal,
explicit restoration, replacement refusal and control-lab preservation. Fixture
container birth is journaled before creation; signal-handler readiness precedes
ordinary verified SIGTERM and ID-bound removal. Final checks require fixture
IDs/links absent, plugin state equal to its baseline and installed plugin source
unchanged. No vendor image, plugin installation or remote-host mutation is part
of this gate. Multi-host repair is covered with real journals and simulated
Docker/plugin hosts, not physical distributed qualification.

### Shared provider ledger durability

The source VRF provider now acknowledges ledger changes only after syncing the
JSON file, atomically replacing it and syncing its directory entries (including
ancestors for a newly created state directory). Failures return the Docker
plugin protocol error field; HTTP 200 alone does not mean success.

Before another ledger operation, the provider validates the observed JSON and
re-establishes file/directory durability. An uncertain commit in the running
process admits only its previous or intended bytes, narrowed to the intended
bytes once replacement is confirmed. Unexpected content remains blocked and is
preserved. The same barrier applies when reopening a ledger after a process
restart and to no-op pool/network/endpoint and release retries. Duplicate IP
allocation remains a conflict; it is not adopted as an idempotent request.

A persistence failure blocks ledger-dependent mutations across labs until a
subsequent request can complete verified recovery. This does not provide a
transaction over existing kernel endpoint operations or establish protection
against arbitrary external writers. The uncertainty proof is in memory; after
process restart the provider validates and synchronizes the observed ledger,
then applies each request's existing identity/configuration checks. This gate
qualifies syscall failures and process restart, not actual power loss.

`tools/vrf_provider_durability_smoke.py --directory /tmp/UNUSED_PRIVATE_DIRECTORY`
starts a separate provider on its own Unix socket and state file, injects a
failed directory sync, verifies cross-lab fencing, restarts that process under
the fault, then verifies automatic recovery and address conflict semantics.
It stops the child, removes the socket and preserves state/report evidence.
It never registers a Docker plugin, mutates network interfaces or updates or
restarts the installed provider. Installing this source remains a separate
shared-infrastructure operation.

### DNS service generation and reload journal

DNS deploy, refresh and destroy now delegate to the root-local `dns_host.py`
worker using the existing SSH stdin boundary. `dns_journal_dir` defaults to
`/var/lib/dnlab/dns`. The coordinator persists its generation before deploy;
the host records the complete configuration, nonce, pinned image/network IDs
and intended hosts content before container creation, and the Docker ID before
start. Existing names without original birth proof are refused and preserved.
An explicit provision after verified cleanup archives the previous generation.

Hosts assets live in a generation-specific directory under the root-only
journal. The mounted directory is root-owned mode 0755, with hosts mode 0644,
so dnsmasq can read it after dropping privileges. It is mounted read-only.
The worker verifies directory/file inode, ownership and content; tracked atomic
replace followed by ID-qualified SIGHUP updates DNS without recreating it.
Lost create/reload/remove responses require `recover_dns` with the original
journal. Conflicting or unqualified resources remain untouched and require
operator recovery; they are never adopted merely by matching names.

Ordinary cleanup sends SIGTERM to the qualified Docker ID, waits for exit,
removes that ID, then removes only verified hosts assets. Partial asset cleanup
is journaled and recoverable. The cleanup daemon delegates DNS ownership checks
and retains dependent infrastructure and lab state on error. Legacy DNS without
a coordinator generation is protected. This qualifies DNS lifecycle, not the
remaining integration of multi-segment DHCP, routing or jumphost attachments.

`tools/dns_identity_smoke.py --execute --image IMMUTABLE_LOCAL_DNS_ID --output
/tmp/UNUSED_DIRECTORY` creates a token-scoped bridge and two DNS instances,
checks UDP/TCP responses, lost create/HUP recovery, atomic hosts updates,
standalone worker invocation and cleanup while preserving the control instance.
It uses no vendor VD, production network, plugin installation or remote host.

### Experimental dynamic jumphost DHCP assets

New DHCP-enabled jumphost generations use a fixed `main` file and separate
`hosts`/`options` files under their journal-owned `.dhcp` directory. The main
file references `dhcp-hostsfile` and `dhcp-optsfile`. Assets are root-owned,
readable by dnsmasq after privilege drop and mounted read-only. Birth config
and container labels stay immutable while the journal tracks dynamic contents.
Legacy single-file generations are preserved and refuse dynamic refresh;
creating a new layout requires an explicit new generation after cleanup.

`refresh_dhcp_config` now requires the coordinator generation, accepts an
optional request ID and delegates to `dhcp-refresh` through the jumphost worker.
It qualifies infrastructure, namespace, container and file identities before
writing, journals temp identities and replace progress, rejects structural
changes, and supports explicit recovery of partial writes/lost responses.
The host service proof binds Docker generation and host boot context, PID/net/
mount namespaces, host PID/starttime, image account credentials, PID-file inode
and executable inode/content. PID-file GID is recorded separately from process
GID. Inspection uses pinned proc/root descriptors and signalling uses pidfd.
Mounted hashes, syntax and matching reload log acknowledgements are required.

The DHCP log profile is explicit for the qualified helper image digest and
its dnsmasq binary hash (`DHCP_LOG_PROFILES` in `jumphost_host.py`). It requires
the configured log path, service UID, GID0, mode0660, one regular file link,
protected root-owned parent directories and an actual writable descriptor in
the qualified service process. File/parent identities and configuration hash
join the durable operation service proof. Replacements are rejected before
HUP and checked again after reload. Unknown image digests require qualification;
group-writable logs are not accepted through a generic permission exception.

`tools/jumphost_dhcp_smoke.py` uses the complete management worker with owned
firewall rules, fixture VNIs/tables and journaled cleanup. Earlier raw-bridge
fixtures dropped DHCP packets in FORWARD; the complete provisioning corrected
that fixture omission. Host-side qualification handles the helper's non-root
PID file; the observed log mode0660 is now qualified by the explicit profile.

On 2026-10-19 the full isolated DHCPv4 gate passed with the pinned helper image
`sha256:de63a0cd8f1083ecab8d81ffcc3446227271b9677ad8dd2e08547704b57850da`:
initial offer .11/DNS .53, update .12/DNS .54 after lost-response recovery,
and .13/DNS .55 through standalone invocation. Process/container generation
and the control lab remained unchanged. HUP used pidfd and log acknowledgement;
cleanup was independently verified and the installed plugin source/state stayed
unchanged. The multinode suite passed1362 tests (59 focused). This qualifies
the isolated IPv4 refresh path, not a complete DHCP lease lifecycle or release.

Pending management qualification (user request, 2026-10-19): audit the actual
DHCPv6 server/version and deployed configuration against the applicable RFCs,
then verify protocol behavior on the wire, DUID/IAID handling, lease lifetimes,
renew/rebind and interaction with RA and overlapping lab networks. A running
dnsmasq process or IPv4 DHCP gate does not establish DHCPv6 compliance. This is
part of the remaining management gates; Containerlab replacement retains priority.

Shared jumphost external-network provisioning now uses the standalone
`jumphost_network_host.py` guard through bounded SSH stdin. This is the shared
external Docker bridge used by jumphost/DNS, distinct from VD management networks.
The deploy performs a read-only preflight before resource phases; jumphost and
DNS creation/replay qualify the shared generation again. Docker HTTP errors are
structured: only a valid404 inspection establishes absence. Existing resources
without the original intent are refused even when their names/configuration
match. There is no per-lab delete or implicit network replacement.

The root-local journal defaults to `/var/lib/dnlab/jumphost-network`, configurable
with `jumphost_network_journal_dir`. It persists the complete configuration,
host namespace/boot identity and nonce before create, then Docker ID before
attachments, plus the bridge identity before success. File and directory fsync
failures propagate; pending births require explicit `recover` through
`ensure_jumphost_network(..., action="recover")`. Recovery binds a lost response
only with matching ownership/configuration and never recreates a bound missing
network. Unknown legacy shared networks require a separate infrastructure
qualification decision; they are not adopted by a lab deploy.

`tools/jumphost_network_smoke.py --execute --output <new-directory>` passed on
2026-10-19 with eight SIGKILL points around intent/create/ID/active commits,
actual standalone stdin recovery, stable retry IDs, preserved control network,
and rejection of incompatible/unqualified reuse and per-lab deletion. Independent
cleanup verified all nine fixture networks/bridges absent, original Docker
inventory restored and installed VRF plugin source/state unchanged. The suite
passed1405 multinode tests (90 focused). This gate creates no VD and does not
qualify multi-management services, DHCPv6, full deployment or release cutover.

The opt-in native compilation now carries a `management_services` intent inside
its fingerprint and durable initial-batch payload. It describes one existing
jumphost/DNS access model, external infrastructure, stable per-segment host and
peer interface names, gateway addresses, DHCP selection and routing via the
jumphost. The default peer remains eth1; additional peers derive from complete
lab/segment identity, so adding an earlier-sorting segment cannot renumber them.
Address ledgers remain in `management_plan`; this metadata does not allocate
services or claim readiness. Inconsistent service metadata is rejected before
remote preflight, even with a recomputed outer hash. Retry/store reopening keeps
the original plan; older batches without service metadata retain that contract.
The 2026-10-20 suite passed1439 tests with73 focused checks at this stage.

The jumphost management guard now reads the network creator's protected local
journal and qualifies the original network ID/nonce, expected driver/IPAM,
subnets/gateways/tenant, bridge and VRF identity before birth and during
lifecycle/recovery. `management_intent` is an optional compatible config field;
when supplied it must match the creator intent. Missing creator proof cannot
be replaced by adopting a matching name or labels. The service wrapper supplies
the intended master configuration and creator-journal directory.

The bind comparison accepts Docker reordering only for the same exact read-only
mappings and multiplicities, with unique normalized destinations. Duplicate,
malformed or changed mappings are refused; ambiguous desired destinations are
rejected before container/asset creation. Docker/container generation, labels,
network and other configuration checks remain required.

On 2026-10-20 the multinode suite passed1483 tests, including17 bind comparison/
recovery regressions. The full isolated jumphost DHCP gate passed using network
creator journals: wrong subnet, incompatible IPAM intent and absent origin were
refused before birth; lost create/veth/reload acknowledgements recovered the same
generation. SSH/ICMP, DHCP offer and DNS-option updates (.11/.53, .12/.54 after
recovery, .13/.55 through standalone worker) passed with control unchanged.
Ordinary guard cleanup completed; a separate check verified all fixture
containers/networks/interfaces/assets absent, journals cleaned, and installed
VRF plugin source/state unchanged. No exceptional container removal was needed.
This gate does not qualify DHCPv6, multiple service attachments or full deployment.

Current v1 decision: each management network retains a separate L2 domain and
belongs to its lab. Networks may remain empty and be added only with the lab
verified stopped and concurrent starts excluded. Live VD spawn/move uses already
prepared networks. The shared-L2 alternative is not adopted. Enforcing this
whole-lab offline barrier and materializing multiple service attachments remain
implementation work; this network-proof change does not claim those complete.

The experimental offline-management fence core now persists immutable intents
and host/runtime identities in the coordinator, and stopped workload inventory
in each local runtime. Bound CLI/HTTP acquire/release controls serialize against
submission and execution; active fences reject lifecycle and direct bridge/VXLAN
creation. Lost replies retain the fence, and release records the coordinator's
readiness attestation. This is not yet wired to segment/service provisioning.

The admission/recovery diagnostic from 2026-10-20 is now resolved for the
qualified fence path. Protocol v2 adds a read-only `management-plan` before
coordinator admission. Its workload fingerprint binds each subsequent acquire;
changed or running workloads are refused before allocation. Planning does not
reserve or persist a barrier. The coordinator still checks its operation ledger
atomically when committing admission, so a concurrent coordinated start cannot
also be admitted.

`management-cancel` retires the exact token on every original runtime, including
those without an acquire acknowledgement. It can create a cancellation tombstone
without touching a workload if acquisition never happened. Held fences require
the original stopped inventory to match before cancellation. The coordinator
stays fenced through missing hosts, lost replies or process crashes until all
cancellation receipts are durable. A late acquire for a cancelled token fails.
Cancellation cannot be used after `begin_provisioning`: that phase durably
activates every local fence before the caller may allocate infrastructure.
Partial activation requires recovery; it cannot be cancelled as mere acquisition.
Actual service provisioning and its readiness observer remain integration work.

On 2026-10-20, 1509 multinode tests and893 runtime/root tests passed. The isolated
`tools/management_barrier_smoke.py` gate passed with two native runtime processes
on one local host, one native Python VD and an empty worker. It covered running
admission rejection followed by ordinary stop, lost acquire/cancel/activate/
release replies, unavailable worker, coordinator reopen, actual runtime kill and
restart, cancellation tombstones, provisioning seal, retained stopped workload
state and explicit generation2 restart. Ordinary final stop reached revision4.
An independent read-only check verified workload IDs/name, daemon processes and
sockets absent; local journals released with cancelled-token history and no
pending operations; coordinator release and complete cancellation history.
This gate does not provision management segments, validate service readiness or
qualify physical multihost operation. The overall replacement remains incomplete.

The opt-in `controllers.management_prepare.ManagementPreparation` now applies
infrastructure under that fence. It freezes host/segment/VRF inputs, seals every
runtime before VNI reservation or host allocation, checkpoints management state
in the existing operation ledger, and refuses unrelated state replacements.
Retry may restore only an original journaled checkpoint. Cross-process locking
excludes release during host mutations; the original local runtime is requalified
before each mutating worker call. Explicit provisioning recovery preflights partial
kernel and Docker births on every host before resuming allocation. Kernel and
network birth nonces/IDs are retained through lost replies. The operation stops
at `infrastructure-ready`, with the workload fence still active for service work.

`verify-ready` is a strictly read-only observation, separate from admission.
It requires the complete active desired generation, all original resource
identities, UP/master relationships, technical gateways, FDB entries and firewall
rules. Network verification also requires completed network operations and every
original active Docker ID/nonce/configuration/plugin proof. Preflight alone can
accept absent resources; it never substitutes for readiness.

On 2026-10-20, 1537 multinode and893 runtime/root tests passed, including64 focused
management preparation/readiness/barrier/netsetup checks. The real local
`tools/management_prepare_smoke.py` gate passed for an empty single-host lab:
initial management and an added second L2 segment, lost network reply and journal
reopen, unchanged original kernel identities and network ID/nonce, and denied VD
start while fenced. Its readiness release was explicitly infrastructure-only for
the empty fixture. It does not qualify services, GUI/API integration or physical
multihost deployment. Independent cleanup verified both network IDs/names and all
owned links absent, management journals cleaned, VNIs released, coordinator
released, runtime/socket absent and installed plugin source/state unchanged.

The planned multi-network GUI/API flow must warn and reject additions while a lab
is running: stop all VDs and wait for pending operations first. The GUI may warn
early; authoritative admission and concurrency protection remain in the backend.
No confirmation can bypass that restriction. The existing single-network editor
already has a running-lab warning; the new multi-network controls are not yet
materialized. Service attachments/readiness and public flow integration remain.

Additional jumphost management L2 attachments now have separate immutable intents
inside the protected parent journal. Each binds its request to the original
container ID/generation/namespace, management network origin and index-bound veth
pair. The birth config and Docker labels remain unchanged. The internal
`segment-add` / `segment-recover` operations refuse occupied or reserved endpoints,
subnet overlap, changed requests and substituted identities. Explicit recovery
can finish a lost pair/alias reply without recreating the container or pair.
Default and additional ports are qualified before parent shutdown; cleanup then
removes all original pairs by identity, including when a held namespace keeps
interfaces alive after the process exits. Cleaned/provisioned generations also
check the additional attachment journals and refuse replacements.

On 2026-10-21, the multinode suite passed1555 tests and runtime/root893, including
18 new multi-attachment regressions (74 targeted jumphost checks). The real local
`tools/jumphost_segments_smoke.py` gate passed with the same parent container ID,
start time and original attachment. A lost additional veth reply recovered through
the standalone stdin worker; both management ports passed ICMP. An experimental
EtherType broadcast sent on blue was observed on its bridge and not on default
within the probe window. The control lab remained unchanged. Shutdown/cleanup
passed with a pinned namespace, and a separate check verified both jumphost
IDs/names, all registered network IDs/names and default/additional host veths absent,
management/attachment journals cleaned, and installed plugin source/state unchanged.

This qualifies the internal attachment primitive only. The new operations are
not yet exposed through public API/GUI or integrated into full service preparation
under the offline barrier. DHCP/RA structural configuration and routing/service
readiness for multiple segments remain incomplete. The helper image was not
modified by this step; its existing DHCP bootstrap still targets eth1. The L2
broadcast probe does not qualify DHCPv6/RFC compliance or all multicast behavior.
# Retiring networks from an interrupted local gate after reboot

`tools/postboot_network_retirement.py` provides an explicit, deletion-only
operation for the original networks of a local management service gate. It is
separate from ordinary worker recovery and does not relax its boot/namespace
checks. It does not resume the gate or make its original result successful.

The operation requires the original released coordinator intent, an offline
dedicated native runtime with no workload footprint, complete helper/probe birth
journals and verified probe cleanup. Original helper IDs and names must be
absent. All original management kernel names/aliases and firewall rules must be
absent in the current boot. The external Docker bridge may remain only with
its original Docker network ID, creator nonce, exact configuration and no
kernel or Docker attachments. Management IPAM may retain only its configured
gateway allocations. Other allocations or conflicting identities block cleanup.

Use an existing private output directory and a stable request ID:

```sh
python3 tools/postboot_network_retirement.py \
  --gate-root /path/to/original-gate \
  --output /path/to/private-retirement/operation.json \
  --request-id retire-original-networks \
  --plugin-sha256 QUALIFIED_INSTALLED_PLUGIN_SHA256
```

The default command is a preflight. Add `--apply` to the same invocation for
retirement. The separate journal records the current boot, source fingerprints,
Docker IDs and current bridge witness before deletion. It reserves the request
in the original gate directory; changing the output path does not create a new
owner. A failed or uncertain response stays recoverable with that same request.
Absence must be reverified before a lost response can count as success; no
automatic blind resend occurs. Repeated apply after verified cleanup only
rechecks absence.

A stale private Unix socket can remain on disk: the runtime daemon lock,
socket identity and `ECONNREFUSED` must jointly establish that it is offline.
The socket is not removed. Birth journals, coordinator state and VNI reservations
are retained; a retirement receipt qualifies network deletion only, not complete
lab teardown. No VM recovery, distributed retirement, legacy adoption or
automatic service recreation is implemented by this tool.

# Managed initial workload handoff

`RuntimeInitialDeployment.prepare_managed_topology(topo, schedule, request_id,
management_request_id, targets=...)` consumes the existing coordinator's
completed network-service release. It uses that operation's ledger and lab
generation; placement remains the existing scheduler's input. The compiled
service model, runtime targets and journal IDs must match the original parent.

Every target must explicitly include `container_name`: `null` selects the host
runtime and a valid nonempty name selects the runtime container. Compilation
preserves this selection in its fingerprint and every child intent. Missing or
invalid names are refused; they never select an implicit host fallback. Replay
and recovery continue to use the original target and runtime journal identity.

The parent fingerprint is stored atomically with the initial batch and its child
intents in the existing private coordinator ledger. A changed parent during the
last read-only preflight prevents admission of every child. Apply, recovery,
cancellation and binding publication revalidate the same saved parent; replay
cannot drop the binding or refresh it to a newer preparation implicitly. A
partial commit remains recoverable under its original intent, without restarting
already-qualified children.

Loading custom public state preserves its saved reservation maps, including
empty maps, and its original management ledger. Publishing a VD does not cause
the loader to synthesize an IPv4 reservation map from that VD's address. The
older reservation backfill remains limited to compatible Containerlab states.

Read-only runtime qualification covers every host in the original management
intent, including hosts with no workload in this batch. An unavailable host or
changed runtime journal prevents admission. The final local transaction checks
the original parent again; it does not perform remote calls while holding the
SQLite write transaction.

This is an opt-in initial Linux workload path. Lower-level experimental batches
remain available for primitive tests; they are not automatically promoted to
managed deployment. The handoff does not publish workload bindings itself,
attach links, create relay inventory, declare NOS readiness or finalize a lab.
Those phases and the ordinary public deploy/API selector still require their
own integration and qualification.

The optional `management_services_smoke.py --managed-initial-batch` fixture
connects this handoff to HTTP workload admission and durable VD binding
publication before the existing GUI HTTP probe. It requires pinned HTTP/GUI
images and implies service inventory publication. This extension has inert
integration coverage and a passed single-host native Linux gate covering the
original management release, compiled batch, binding publication/replay and
actual GUI HTTP proxy through SSH. Independent cleanup verification includes
the original workload/helper generations and unchanged pre-existing resources.
This does not qualify physical multihost operation, NOS devices or the ordinary
public deploy selector.
The managed fixture saves placement from the existing schedule in its first
public checkpoint. This does not construct running nodes: VD bindings stay
empty until the original completed batch passes qualified publication. Changes
to the original placement are rejected by that publication path.

If the fixture cancels a batch before any VD exists, it verifies the original
cancelled member and a complete read-only plan of its original request instead
of inspecting a nonexistent node. Journal, request, lab/node, revision, absence
of container, workload birth and pending operation must all match. Conflicts or
incomplete observations retain `cleanup_pending`; cleanup does not create a VD
or weaken runtime inspection. Started workloads retain their generation guards.

# Relay container ownership

Relay deploy/reconcile now use a host-local private journal under
`PATHS.relay_journal_dir`, structured Docker HTTP calls and the existing stdin
worker transport. The first intent is durable before create. Nonce, immutable
image ID, configuration and Docker ID qualify reuse, recovery and deletion.
All hosts pass read-only preflight before any relay allocation. Adding VDs uses
the original prefix capability without restarting the relay or changing its
frozen environment; incompatible images/configuration are refused.
Ensure preflight also refuses active relays that are absent or stopped and
journals requiring recovery, before the first host can allocate. Inventory and
qualified cleanup retain their separate contract: an original container already
absent can still complete tracked deletion without restarting or recreating it.

An uncertain create is never repeated. Recovery may bind only the unique
original nonce/name/configuration; absence with no recorded ID remains pending.
Cleanup stops the original ID without a timed SIGKILL fallback, then removes
that stopped ID and verifies absence. Coordinator state records generation and
ID. Destroy, rollback and lab-cleanup delegate to the same guard and retain
state on missing ownership or incomplete recovery. Legacy relays without proof
are preserved and require an explicit qualification/replacement procedure.

Before the workload-ID protocol extension, the opt-in
`tools/relay_console_smoke.py` gate passed on one local host
with two native Linux workloads. It qualifies the original loopback listener,
console output and logs using workload-specific nonces, rejects unauthorized
requests, and admits a second workload without replacing the relay process or
listener. `CONNECT` streams the console directly; only `LOG` has an `OK`
acknowledgement. The console probe distinguishes command output from terminal
echo. Independent checks verify original workload stops, terminal journals,
process exit, Docker absence and unchanged protected resources and plugin.
This does not qualify distributed hosts, NOS consoles or GUI console routing;
a running container alone does not prove console reachability.

Native GUI/API console and log resolution now shares a read-only resolver. It
checks the original coordinator intent, runtime journal, committed running
workload binding and active relay generation. Missing bindings, pending
operations, replaced containers and relay images without
`qualified-container-id-v1` are rejected. The response adds
`runtime_backend: custom` and the full original `container_id`. Legacy
Containerlab responses retain their existing fields and protocol.

For custom targets the GUI sends `CONNECT_ID key name id` or
`LOG_ID key name id tail follow`. The relay checks the current name against
that full ID before opening the stream, then uses the ID for Docker commands,
console brokers and their history, console discovery, cleanup and logs. A
replacement under the same name cannot become the target. Requests by name
alone are refused for containers bearing native runtime labels. There is no
automatic retry using the legacy protocol.

Relay request parsing consumes only the first newline-terminated line, bounded
to 8 KiB including the newline. Bytes following that line remain in the socket
for the console broker, even when a client sends its first command together
with `CONNECT` or `CONNECT_ID`. This requires no guest prompt or initial output.
Incomplete and oversized requests are rejected before target inspection.
The early-input correction has inert fake-stream and local Unix socketpair
coverage. A separate candidate containing the parser correction passed one
local native gate with two Linux workloads. The probe sent the request and
first command together for each workload and verified nonce output distinct
from terminal echo. Independent checks confirmed cleanup, original workload
stops, unchanged relay process/listener during late spawn, and unchanged
protected containers, networks and plugin. Installed images were not replaced.

This extension has inert API, GUI and relay coverage. A separate relay candidate
with the ID protocol also passed the local native gate with two Linux workloads,
nonce-bound console/log output and late spawn without relay replacement.
Independent checks confirmed original stops, terminal journals, process exit,
absence of all three original containers and unchanged protected resources and
plugin. The candidate has not replaced installed relay images. Distributed
hosts, NOS consoles, the real GUI console route and jumphost console inventory
still require qualification; cached older images are not adopted automatically.

Native jumphost inventory publication is now part of the public lifecycle
operation. The inventory carries `runtime_backend: custom` and the original
Docker ID, rendered as `name=host:port:key:custom:id`. The `vd` helper and Python
client translate that suffix into `CONNECT_ID` and `LOG_ID`. Malformed native
identities are rejected without trying the name protocol. Legacy rows retain
their three fields. A new jumphost image must advertise
`qualified-relay-inventory-v1`; existing images are not replaced implicitly.

The restart-aware qualification helper `tools/native_lifecycle_fixture.py`
uses the canonical public operation ledger and records every original workload
birth separately. It delegates restart and final stop to the public controller,
requires completed inventory publication, and resumes the same request after
lost acknowledgements. Cleanup remains unverified until every recorded Docker
ID is absent. Its fake-host tests cover multiple generations, publication and
checkpoint loss, stale identities, receipt changes and cleanup retry. This
helper is preparation for the integrated jumphost gate; it has not qualified
the candidate's CLI or lifecycle on a real host.

`management_services_smoke.py --native-lifecycle-relay-image <digest>` adds an
opt-in lifecycle/publication stage after the managed initial HTTP workload and
GUI forwarding checks. It requires `--managed-initial-batch` and uses the
canonical `.runtime-operations` ledger for this new scope; historical fixture
runs retain their `coordinator` directory. Externally configured coordinator
paths are refused. The stage provisions an owned relay on the dedicated
external bridge gateway, publishes inventory through an already-running public
start, runs the original jumphost CLI for console/log, then performs and replays
a public restart and repeats the CLI probes. Cleanup delegates to the
restart-aware helper before deleting the original relay and shared services.
CLI success requires each original exec, output marker and client exit; pending
initialization/execution blocks workload and relay teardown. The combined runner
is still inert-qualified. The independent verifier is implemented; a frozen
operational recipe and a separately authorized window remain necessary before
offering the native gate.

Stage preparation reopens the original relay intent and validates its fixed
inputs before invoking the guard. Retries reuse the original generation, key
and port; they never replace that intent or the original publication record.
Published bindings must match the observed original relay. Reopening after a
restart preserves the full birth history and resumes the original pending step
without replaying the initial inventory. Missing history or incompatible input
is refused before writes or allocation.

A durable CLI plan records each slot and nonce before asset or exec creation.
Cleanup inventories that plan plus all persisted asset/exec/capture records,
including after reopening. It refuses missing, unbound, pending or changed
records before stopping a workload. Original exec and output verification uses
read-only callbacks: no create/start, capture repair or journal rewrite is
allowed. The complete census is checked again after observation. Only qualified
completed execs permit dependent teardown; the resulting cleanup report lists
their original IDs.

`tools/verify_jumphost_lifecycle_gate.py` independently checks the combined
gate after teardown. It cross-checks both SQLite journals, original birth and
public receipts, the stop preflight fingerprint, published VD IDs, the lab's
persistent management-network pin, and complete raw CLI journals. It also
checks helper/process stability and exit, original resource absence, protected
global inventory, source/plugin/boot baselines and VNI release. SQLite reads
require closed checkpointed databases and create no sidecars. This verifier
has inert positive and corruption tests; it has not certified a combined
candidate run yet.

The agreed existing console behavior treats input EOF as disconnect. The
qualification I/O helper `tools/console_input_fixture.py` therefore holds the
owned client's input pipe open until it observes a marker absent from the
command text. It then closes input and requires process exit within the same
deadline. Timeout, output limits, stderr, failed exit and command echo cannot
qualify the probe. The helper never spawns or retries a client: its caller must
own durable execution identity and recovery. Real local CLI/broker tests cover
the open-input path; the EOF diagnostic records the unchanged disconnect
behavior. These tests do not qualify execution inside a jumphost container.

`tools/jumphost_cli_execution.py` supplies fixture-only durable Docker exec
control. It freezes the original jumphost proof, command and nonce before
create, saves the returned exec ID before start, and reobserves ownership after
each checkpoint. Lost replies recover only the original matching exec; uncertain
create/start outcomes never trigger a second attempt. Completion requires both
Docker exit and the original result reader's nonce-bound client exit proof.
The observer and result reader are connected through
`tools/jumphost_cli_assets.py`. They reobserve the original container, PID and
namespace, qualify the candidate CLI files and non-root account, and bind an
output file to a nonce-tagged birth. Live journal growth is accepted only for
the mutable output; source/account reads must remain stable. A complete output
journal is captured privately on the host before container cleanup and its hash
is bound to the exec result. This wiring has not yet run on the candidate.

`tools/jumphost_cli_program.py` builds the frozen in-container program from a
bounded profile and the console I/O helper. It requires the original output
file's device/inode/UID/GID, mode and nonce, records wrapper/client births and
progress, and emits success only after verified client exit. Wrapper and CLI
run with the same credentials; a parent-death signal prevents the direct client
from remaining active if the wrapper is killed. Inert local process tests cover
this boundary, timeout cleanup and output-asset conflicts. Candidate namespace,
account and file qualification are still required before native execution.

The coordinator records the publication phase and frozen desired inventory
before writes. It checks every selected VD binding and relay plus the original
jumphost generation. Publication must complete before the lifecycle operation
is completed. A lost response or checkpoint resumes the same request or its
pending worker journal, while the already-started VD remains running. A pending
publication prevents another public mutation from superseding its snapshot.
Stop retains the original stopped VD identity in the inventory; remove excludes
it. Conflicts retain the operation and proofs for recovery. This integration
has inert lifecycle coverage. A separate jumphost candidate has been built and
its four assets, permissions and interpreters audited. Its exact digest has an
explicit DHCP log profile after an isolated on-host process/log diagnosis;
unknown images and changed metadata remain rejected. This does not qualify
console/log publication or DHCP packet readiness with the new image: the native
jumphost CLI/lifecycle gate remains pending. Installed images are unchanged.

# Shared workload fixture cleanup

The HTTP and relay fixtures requalify the original completed start and immutable
birth identity before cleanup. A stopped retry requires the original tracked
stop request, its matching completed runtime receipt, the expected revision and
cleaned generation, and an independent Docker absence check. It does not submit
a second stop. A lost stop acknowledgement can update only the original local
receipt after a read-only match. Existing request bodies remain unchanged.

Entering cleanup invalidates the previous verification flag. Conflicting births,
revisions, pending operations, missing receipts or unavailable observations keep
`cleanup_pending` with `cleanup_verified=False`. These fixture checks do not
relax runtime ownership guards or qualify a native relay gate by themselves.

# Local fixture transport

The integrated jumphost lifecycle fixture routes `dnlab-runtime` commands to
the checkout's Python module through its existing native CLI adapter. Helper
guard commands keep the diagnostic host transport. This does not require an
installed runtime executable and does not alter production SSH invocation.

Managed initial batches now require a durable management usage handoff in the
existing coordinator before the first workload allocation. The handoff pins
the released parent's all-host kernel and Docker network proofs, preflights
every original host (including hosts without a workload), and records usage
for the selected host/segment pairs. Each attempt is saved before the remote
mark; recovery observes the same network generation and avoids repeating a
mark whose acknowledgement was lost. Publication requires the completed
handoff and current qualified proofs. Original batch/member requests remain
unchanged. Batches already allocated without this handoff require separate
qualified recovery; this path does not backfill their intents or adopt them.
The local service fixture explicitly supplies its original diagnostic host
transports; production runtime clients use their existing SSH transport.

Deletion-only retirement is a separate experimental operation for an original
completed local managed batch that predates the usage handoff. It does not
backfill `used` or admit endpoints. The read-only retirement observer requires
the exact original network ID/nonce/config, kernel proof and runtime-qualified
VD IDs, creator/spec labels, endpoint IDs, addresses and plugin inventory. It
rejects unknown endpoints and changed generations. The ordinary network guard
continues to reject unadmitted endpoints.

The coordinator persists the retirement intent before preparing fingerprinted
ordinary stop requests, closes the existing coordinator/runtime fences, and
requires verified shutdown and absence before ordered owner cleanup: relay,
jumphost, DNS, management and external network. Each owner attempt is recorded
before mutation and verified afterward. Cleanup/retry preserves original IDs
and requests, including uncertain responses after network removal; the closed
fence and shutdown proof remain, and ID/name absence is checked directly.
Deployment state and journals are retained; no implicit reopen or force occurs.

`tools/retirement_infrastructure.py` supplies fixture adapters to the existing
guards, original VNI registry and ordinary teardown. It requires the original
materialization receipt, published relay identity and private journal paths;
fixtures containing CLI journals must first use their own qualified CLI cleanup.
Current retirement qualification is single-host, Linux, complete initial batch,
without data links/RealNet or concurrent pending operations. Tests use real
coordinator/runtime/network journals and in-memory Docker/kernel adapters, plus
an inert Unix HTTP server for the stdin worker. No native retirement gate has
been run, and existing failed-gate resources remain pending separate execution.

Local live-gate cleanup admission remains blocked by default. The experimental
`CleanupAttestation` protocol in `tools/cleanup_compatibility.py` can compare a
pinned local gate context with fresh observations from trusted providers. It
requires executed qualification receipts for daemon, API/CLI and native CLI
ingresses, including both cleanup and sync commands. Matching source hashes
or self-declared labels alone cannot supply these receipts. Artifact identity
includes execution assets and import configuration; current generation identity
includes process/starttime/namespace/configuration, or the excluded native
installation. The context also pins the gate, lab, local host, coordinator,
boot, agreed window and verified image-build hold.

An attestation must be rechecked before allocations and at phase/recovery
boundaries. Inventory, provenance, generation, scope or window changes, missing
receipts, provider errors and expiry invalidate it. It cannot renew itself or
authorize resource deletion; cleanup uses the original resource guards. This
is provenance plus previously qualified execution, not live memory inspection.
`tools/cleanup_execution.py` supplies the execution-receipt provider. Trusted
local configuration pins raw reports and native before/after/process evidence.
It verifies digests, completed entrypoint coverage, images, callback sources,
native startup assets and successful process completion. Its artifact descriptor
must also be reconstructed by the current observer; historical receipt validation
does not observe a running service. Every recheck authenticates the evidence
again, with no acceptance cache or automatic adoption.

`tools/cleanup_container_observer.py` provides read-only observations of the
original cleanup containers. It checks pinned image/configuration, both module
copies, console bootstraps, interpreter, invocation, working directory and import
environment. A readonly pidfd binds process, namespaces and source observations
across the Docker before/after comparison. Source reads reject symlinks and
unsafe ownership/write permissions; raw environment and configuration values
are not retained in the returned evidence. Artifact and generation fingerprints
remain separate.

`tools/cleanup_observation.py` composes the receipt descriptors, container
provenance and trusted native observer into the observation expected by
`CleanupAttestation`. Fresh environment observations bracket the actor reads;
changed context, lost window/hold, unexpected actors or mismatched artifacts
and generation evidence fail admission. Each recheck repeats the providers.
The assembly supplies no census, window or image-build stop implementation:
those must come from separately qualified current observers, never request
booleans or saved successful reports.

`tools/cleanup_census.py` checks the declared single-coordinator process and
scheduled-source scope through trusted readonly readers. Two scans must match
the qualified original process generations and reviewed scheduled descriptor.
Additional recognizable CLI invocations, including status commands, prevent
native CLI exclusion. Commands are classified at their executable/module
position; opaque invocations remain outside the declared scope and cannot be
used as proof of universal absence. The census does not observe Docker actors
or native installation content, attest a window, stop image-build or authorize
a gate. Its concrete reader integration still needs qualification.
The process classifier accepts empty arguments after a nonempty program name.
Malformed or undecodable commands still fail the census; rejection metadata
contains PID, command hash, argument count and empty positions, without raw
argument values. A private collection wrapper must preserve this metadata
before reporting failure.
Script entrypoints use qualified full paths to distinguish cleanup from
`/opt/dnlab-image-build/api.py`. Ambiguous `api.py`/`cli.py` paths remain
unqualified candidates rather than disappearing from the census. Image-build
is retained in a separate process group; collection may record its explicitly
pinned generation, but gate admission rejects a running image-build and still
requires the independent qualified hold observation.
`tools/cleanup_scope_sources.py` handles expected scope transitions without a
global exemption for `/run/systemd/transient`. A trusted provider must freshly
authenticate the same gate context, Docker birth nonce, original journal and
qualified definition profile for each created or removed scope and its drop-ins.
Only those exact rows and corresponding parent-directory entries may be
projected onto the immutable source baseline. The parent directory's identity
and permissions remain fixed; only entry-dependent size/mtime/ctime can change.
All other source changes fail. `CleanupCensus` can use this explicit qualifier
while retaining the actual observed source digest; without it the original
strict comparison remains. No operational proof provider is supplied or
qualified by these synthetic tests, and live runners remain blocked.
`tools/cleanup_scope_definitions.py` verifies the exact scope and two device
drop-ins against a finite set of reviewed Docker configuration profiles. The
full container ID replaces only the explicit description token. File hashes,
types, root ownership, modes, sizes and drop-in inventory must agree; unknown
configurations and directives are refused rather than learned. Profile selection
does not qualify the entire container: the operational scope-proof provider must
still bind its full configuration and current generation to the original birth,
journal and gate, and read the current scope evidence coherently.
`tools/cleanup_native_scope_proof.py` supplies that read-only verification path
for native Linux workload births. It consumes an already-open coordinator and
a pinned durable record from the original gate creation path; it never creates
a journal or discovers/adopts a workload by name. The original completed start,
bound runtime inspection, Docker ID/image/configuration/start and nonce, pidfd
process identity and current scope definitions must agree. Removal requires the
same ordinary completed stop receipt and double Docker/scope absence checks;
later workload generations do not rewrite that historical shutdown proof.
The provider rereads the immutable birth and coordinator operation before
returning. Gate fixture birth-record acquisition and helper-service adapters
still need integration and operational qualification. No host qualification or
live-gate permission follows from the synthetic tests.
`tools/native_scope_registration.py` acquires and registers Linux scope births
in the existing coordinator's `gate_scope_births` operation table. A fixture must
opt in with its complete gate context in the original planned intent, before
creating the VD; existing fixtures cannot acquire that context retroactively.
The HTTP and managed HTTP fixtures accept this optional context without changing
their default path. Initial acquisition uses the original completed start and
current proof checks, then durably inserts an immutable record. Reopening or a
lost commit response rereads and verifies that record without another capture.
Replacement records and changed owners are refused. Proof reads use the same
coordinator metadata without writing; records are retained as operation history.
Actual gate callers and helper-service adapters remain to be connected and
qualified before a live gate can use this registration path.
`tools/cleanup_helper_scope_owner.py` provides read-only ownership adapters for
DNS, jumphost and relay, using workers and fixed birth projections from the
original service materialization receipts. Bound ID/nonce/config/image/host
context must agree. Active observations reuse the existing container, assets and
attachment guards without binding or recovery; cleaned observations reuse the
original cleanup guards. Jumphost exposes the existing cleaned-resource check
as a pure method so the observer does not enter the command/locking path.
These adapters qualify ownership; the separate proof and registration modules
provide scope verification. Operational gate integration is still required.

`tools/cleanup_helper_scope_proof.py` composes those ownership guards with the
original management service receipt or pinned relay intent and birth receipt.
Creation checks the complete Docker configuration and generation, pidfd process
identity and explicit scope definitions. Removal requires the original helper
cleanup guard and repeated Docker/scope absence checks. Reads do not create,
bind, recover or remove helpers. Initial acquisition returns a birth record for
the caller to persist; it does not itself register that record. The relay path
requires gate context already present in its pre-create intent, so existing
fixture intents cannot be adopted retroactively.
`tools/helper_scope_registration.py` persists these records in the existing
coordinator operation ledger. Retry and lost commit responses reuse the saved
birth, with the original ownership and scope proofs checked again; a conflict
never recaptures or overwrites the record. Removal proofs retain the same birth
without writing the ledger. The console workload fixture now preserves its
original intent on reopening, validates immutable inputs and accepts optional
gate context only on initial creation, requiring an exact match on reopen.
Fixture wiring and operational qualification of helper scope profiles remain
pending; none of these changes enables a live gate.

The scope-source qualifier also handles a scope both created and cleaned after
its original baseline. It requires the same durable birth and current qualified
cleanup/absence proof, including on a fresh observer after cleanup. Such a scope
must be absent from both baseline and current inventory. The baseline remains
immutable; only entry-dependent parent size/timestamps can be normalized after
verification, while parent identity, permissions, names and unrelated sources
remain exact checks. Existing baseline-scope removal retains its original
complete-row comparison.

`dnlab_runtime.vm_boot` begins an injected-provider prototype for initial VM
startup: arm the original event source, start with paused CPUs, persist the
original QEMU process reference, activate monitoring and only then resume.
Uncertain start/source responses block retries; an uncertain resume can be
reconciled read-only against the original running instance. Managed saves are
rejected without discarding their state. Existing lab fences and backend
reservations apply to these stages. No live provider or public VM admission is
enabled. Eleven synthetic boot cases pass, together with 78 related definition,
fence, backend ownership, event, observer and identity cases. The monitor-loss
test explicitly expects TemplateError; process replacement still expects
Conflict. The earlier failed run is retained in the experimental evidence.
Actual event capture, process acquisition, libvirt behavior and guest operation
still require provider implementation and operational qualification.

The boot receipt now also requires the complete original QEMU process record,
persisted with the reference before event activation or CPU resume. Observer
factories receive both saved values on replay; activation binds their hashes.
Records with another birth, process or dedicated session credentials are refused;
old prototype boot records lacking this receipt require explicit recovery.
The extended synthetic suite passes 131 cases, including boot and replay using
the procfs provider reconstructed from the durable record. The event-source
fixture dispatches through the same configured observer as boot. Its earlier
failure from retaining the old fake observer remains in historical evidence;
the fix changed only that fixture dispatch, preserving runtime guards. Original
host creation-proof acquisition and operational qualification remain pending.

Live-runner integration still requires operational qualification of this
assembly and current actor inventory, window and image-build hold checks.
Existing live runners supply no attestation and remain blocked. Tests use
synthetic IO and do not attest deployed actors or authorize a gate.


`libvirt_install.py` adds a create-only persistent session installation coordinator
with an injected adapter, complete preflight and nonce-bound recovery. Its
`installed_not_started` result never starts a daemon. The 33 targeted synthetic
tests cover profile rendering and installation failure boundaries. The concrete
host adapter, resource-specific birth checks and post-package host baseline
remain pending; this does not authorize or implement a real session installation.

`libvirt_install_files.py` now records the original file/parent birth in the
existing journal and separates pending from confirmed durability. Readonly
observation rejects pending state; explicit recovery verifies the original file,
syncs file and directory, then commits confirmation. The failed-fsync regression
is fixed and the targeted 52-test run includes coordinator integration on
synthetic resources and temporary files. Directory/account helper execution and actual
session installation remain pending; no real host adapter is enabled.

`libvirt_provisioning.py` prepares the agreed provisioning-window contract and
tracked account helper protocol. Directory births in `libvirt_install_files.py`
now require that window, record intent before mkdir, and refuse recovery if the
original FD identity was never committed. The targeted 68-test run uses only
temporary files/directories and simulated accounts. Actual account-helper
execution, full host-adapter composition and operational provisioning are pending.

`libvirt_install_adapter.py` composes provisioning windows, complete original
prerequisite snapshots, dependencies and account/filesystem primitives. All six
composition cases passed across separate runs: positive/replay (1), preflight
rejections (4), lost-account-response recovery (1). The two ownership cases ran
outside the sandbox on temporary paths; accounts were simulated throughout.
This is not actual account-helper execution or an operational libvirt session.

`libvirt_account_commands.py` prepares fixed account command plans and durable
arm/reference/release tracking. The targeted 43-test run covers original
completion and lost-response integration with simulated workers/accounts only.
No concrete host process runner or account command is enabled; installed-tool
hashes, configuration/NSS and worker launch/exit remain unqualified.

`libvirt_account_worker.py` prepares the blocked child-side protocol: fixed
command/environment, pinned ELF hash/identity and an exact token/hash release
before exec. Its 51-test combined run uses memory streams and mocked exec only.
No process runner or actual account command has been exercised; original
process capture, durable parent outcome and host qualification remain pending.

`libvirt_account_runner.py` prepares concrete parent transport and durable worker
outcomes, with a mandatory original-process observer. The private worker entry
is `tools/libvirt_account_worker_main.py`. The final targeted60-test run uses
fake processes/observers and anonymous pipes only; no real worker/account
process was launched. Real pidfd/process/exit qualification remains pending,
and no operational provisioning entrypoint is enabled.
