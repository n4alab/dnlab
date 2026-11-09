# Dedicated libvirt session: preparation and installation procedure

Status: draft for review, not an installer or authorization to change a host.
The initial target remains a dedicated non-root dNLab session, supervised on
each host, with the runtime as its only ordinary writer. No system libvirt
instance or unrelated domain is adopted. This procedure complements
[the V2 template inventory](VM_V2_TEMPLATE_INVENTORY.md).

## Observed starting point

The authorized master-only inventory found regular QEMU/qemu-img binaries and
KVM/TUN character devices. It did not find virsh, libvirt daemon/config/socket
files at its fixed paths, or the proposed local account `dnlab-libvirt`.
It did not query the package database, execute tools, open devices or connect
to a daemon. Presence does not prove access; absence at fixed paths does not
prove that a package is absent everywhere. Workers have not been inventoried.

A subsequent separately authorized package preflight completed with one local
`apt-cache policy` query and stable input rechecks. It identified Debian 13
(trixie); installed QEMU is `1:10.0.13+ds-0+deb13u1`, OVMF is
`2025.02-8+deb13u1` and systemd is `257.13-1~deb13u1`. The queried libvirt packages
are not installed; the local cache offers `11.3.0-3+deb13u3` for the daemon,
QEMU driver, clients, logging/locking and library. Python bindings have a
separate candidate `11.3.0-1`. This is not a dependency simulation or permission
to install any of them; no package indexes were refreshed.

The public Debian file lists expose a packaging mismatch with the modular draft:
`libvirt-daemon` supplies `/usr/sbin/libvirtd`, while the examined QEMU driver
package supplies the driver module, not `/usr/sbin/virtqemud`.
[Daemon file list](https://packages.debian.org/trixie/amd64/libvirt-daemon/filelist),
[QEMU driver file list](https://packages.debian.org/trixie/amd64/libvirt-daemon-driver-qemu/filelist).
This does not establish absence of every possible external modular package.
The user selected preparation of a dedicated non-root `libvirtd` profile using
the distribution packages. It retains the dedicated account, private state/socket,
sole ordinary writer and lifecycle rules. Upstream documents its non-root XDG
layout. The earlier modular draft remains historical rather than a fallback.
[Libvirtd manual](https://libvirt.org/manpages/libvirtd.html).

## Deployment platforms and privilege boundary

The current master is a privileged LXC container. Privileged LXC and bare metal
are both target deployment platforms, with separate capability and lifecycle
qualification. Do not assume that a positive result on one qualifies the other.
The libvirt service belongs inside the selected dNLab host environment, not to
an unqualified outer LXC host or a shared host libvirt instance.

The selected first profile keeps both the daemon and QEMU non-root. dNLab's
qualified network operations create persistent TAPs and assign their ownership;
libvirt supports pre-created TAPs with `managed='no'` in an unprivileged session.
QEMU must separately have access to KVM, TAPs and its disks. The alternative of
a root daemon with non-root QEMU is distinct from running QEMU as root and needs
an explicit profile decision if a concrete requirement blocks the selected mode.
[Pre-created TAP support](https://libvirt.org/formatdomain.html#generic-ethernet-connection),
[QEMU privilege model](https://libvirt.org/drvqemu.html#security).

Root inside privileged LXC can still be subject to dropped capabilities,
AppArmor/SELinux, seccomp and device/cgroup restrictions set outside it. Changing
the daemon UID does not establish compatibility with these controls. Do not
relax the outer container's controls or redirect operations to the outer host
as an implicit remedy. [LXC deployment model](https://linuxcontainers.org/lxc/getting-started/).

The package-only installation completed before dedicated session provisioning.
At that earlier milestone the dedicated account and profile were absent.
Package-created standard system accounts are distinct from the dedicated dNLab
session account. The current master installation milestone follows below.

## Current layout (version 2, installed but not started)

On 2026-11-08, one separately authorized apply of the original prepared intent
completed in `installed_not_started` on the master. It created the dedicated
`dnlab-libvirt` group/account (UID1001/GID1002, locked and nologin), nine directories
and seven configuration/unit files. `/etc/dnlab` remained an unchanged verified
dependency. Both original account workers exited with code 0. Independent
readonly verification confirmed the journal, birth markers, identities and file
contents. The first verification's sandbox could not read UID1001-owned 0700
directories; the same readonly checks completed with reviewed escalation.

No daemon reload/start, VM, libvirt connection or package operation was performed.
The apply took about 129 seconds and issued 1,580 readonly service queries; that
cost is recorded rather than optimized by weakening preflight. Empty-session,
socket/KVM/TAP/storage and worker qualification remain pending. Installation
success is not operational qualification or permission to activate the daemons.

### Activation journal prototype (synthetic only)

`SessionActivation` records a separate intent bound to the completed installation.
Its steps are manager reload, dedicated logging, dedicated locking and libvirtd,
in that order. Each step is persisted before the action and reobserves the whole
session before proceeding. An uncertain step requires its original completion;
absence never permits another reload/start. Confirmed service generations are
immutable. A failed empty-domain inventory retains the confirmed service proofs
for a readonly retry. Ten targeted synthetic cases pass.

The adapter remains injected: it must qualify the original installed resources,
administrative window, command completion, process generation and private socket
ownership. Opaque synthetic receipts do not qualify these host properties. No
native service adapter, daemon reload/start, libvirt connection or enablement was
executed by this prototype. A separately authorized operational qualification is
still required before declaring the empty session ready.

New activation profiles explicitly select
`activation_policy="requisite-after-v1"` with layout version2. The libvirtd unit
uses `Requisite=` plus `After=` for the dedicated logging/locking units: those
units must already be active rather than being started as dependencies. The
activation prepare/apply paths reject profiles without this policy before
observing or mutating host services. Historical activation intents remain
readable; they are not silently converted or executed.

Rendering a historical request without the policy preserves its exact files and
profile fingerprint, including layouts 1 and 2. The original installed master
profile was compared with the archived observation and remains identical. Its
unit still uses `Requires=`; it therefore needs a separately tracked qualified
configuration update before activation. This code change did not modify any
installed unit or run daemon-reload. The targeted synthetic suite passes 92 tests.

### Configuration revision coordination (synthetic only)

`ConfigurationRevision` records a separate transition from the historical
installed profile to `requisite-after-v1`. Exactly one file may change: the
dedicated libvirtd unit. The original installation, provisioning window, nonce,
staging and backup paths are bound before replacement is requested.
The installation record remains immutable. The effective configuration carries
the new unit's creator and birth proof while preserving all other creators;
`observe_service_files` checks these per-file bindings.

Recovery requires the original replacement completion and backup identity.
An uncertain request without completion stays pending without repeating the
replacement. After completion, effective observation and apply replay make no
journal writes and require no open administrative window; resource identities
and the original transition are still checked.

The replacement adapter is synthetic and injected. Native backup/staging,
durability, atomic replacement and service-state qualification remain pending.
The effective descriptor is a derived view, not a new installation record.
No real revision intent, unit update, reload or service start has occurred.
The targeted configuration, activation, profile and unit-observation suite passes
66 tests. This does not qualify VM operation.

`ConfigurationStaging` now implements candidate creation using the original
filesystem birth/durability primitive, a separate persistent staging request and
mandatory complete inactive-session preflight. It rechecks the source unit,
revision binding and administrative window before and after creation. Existing
foreign candidates are refused. A lost response or failed fsync leaves staging
pending; explicit recovery may synchronize only the original recorded birth,
and never creates a missing candidate. Observation alone cannot complete pending
staging. The installed unit is neither moved nor rewritten by this component.

Nine staging tests use private temporary files and a synthetic session preflight.
The combined staging, revision, filesystem, activation, profile and unit-reader
suite passes 95 tests. This qualifies that filesystem preparation within its
test scope, not a native complete-session preflight or an operational update.
At that checkpoint, backup/switch remained unimplemented; the following
temporary-file milestone adds those primitives. No staging or replacement has
been performed against the master installation.

`ConfigurationSwap` now journals an exchange request before an actual
`renameat2(RENAME_EXCHANGE)` between the qualified unit and candidate. After
syncing both original inodes and their directory, it records a separate backup
request and moves the displaced original with `RENAME_NOREPLACE`. Existing
backup destinations are never overwritten. Unsupported flags have no fallback.
Both operations use a pinned, verified common parent and the agreed exclusive
administrative window; the window is an agreement, not an OS lock against other
root writers. A new marker is not inferred from the destination filename.

The original filesystem birth can be observed at an explicit sibling path using
`InstallationFiles.observe_relocated`. It requires the recorded durable birth,
original marker, content, metadata, inode and parent, returning the original
receipt rather than creating a destination birth. The swap receipt separately
binds the effective target configuration to the qualified candidate inode.

Recovery can finish syncing an already observed original exchange or backup,
and can perform the first backup after a confirmed exchange. It never repeats
an uncertain rename: an unchanged arrangement, substituted inode or ambiguous
outcome remains pending. No automatic rollback, cleanup or service reload is
implemented. Completed observation is readonly after the window closes.

Twelve swap tests use real filesystem syscalls exclusively on temporary files;
the complete-session preflight remains synthetic. The combined suite passes
107 tests. Native session preflight, integration of the effective file observer
with the revision/activation controllers and a separately authorized operational
update are still required. No installed file or daemon was changed.
Rename semantics reference: [Linux renameat2 manual](https://man7.org/linux/man-pages/man2/renameat2.2.html).

`ConfigurationFileAdapter` composes staging and exchange with the outer revision
journal. It normalizes only lifecycle bookkeeping for the same original request;
source, target, nonce, window and paths remain bound. `ConfigurationRevision.recover`
accepts only a previously requested replacement and invokes its original adapter.
It can recover a recorded candidate birth and perform the first exchange, or
recover an already requested exchange/backup. It cannot create a missing birth,
start a prepared revision, repeat an uncertain rename or skip independent final
observation. Lost outer completion commits reuse the completed original swap.

The adapter validates the unchanged installation and inactive services through a
mandatory provider before and after observations and at mutation boundaries.
That provider remains injected; there is no native full-session provider or host
entrypoint yet. A revised unit can be observed through its transition receipt,
while the other six files retain their original creators. The integration test
uses all seven real temporary files with the existing service-file reader;
accounts, directory ownership and service state remain simulated. This is a
pre-activation file view, not qualification of reads after daemon activation.

Ten adapter integration cases and the combined 117-test suite pass, including
lost candidate/rename/outer-commit responses, changed unrelated files and closed
windows. No installed file, service, VM or lab was modified. The native provider,
operational revision and empty-session activation are still pending.

`ConfigurationPreflight` now composes the original installation snapshot with
account, filesystem and explicitly selected dependency readers. It validates
the original complete target inventory and profile binding, observes every
unchanged target twice, and rechecks package/binary/mask/context/service
prerequisites. Only the changing libvirtd unit is delegated to the staging/swap
observer. Inactive services, zero pending jobs and no dedicated-UID processes
are required; this remains a pre-activation contract.

`CompletedAccountObserver` verifies committed original account birth and worker
completion, then the current identity, without reopening the installation's old
administrative window or executing helper completion/recovery. The revision
still requires its separate current window. Observation makes no journal writes;
the temporary-journal test also passes under SQLite query_only. The existing
native identity/completion providers must be explicitly supplied and qualified.

Eighteen new cases cover the unchanged target kinds, dependencies, snapshot
changes, inactive-service restrictions and completed account evidence. One
composition case uses all seven real temporary files through prepare/apply of
the revision; account/directory/service observations remain synthetic. The
combined suite passes 135 tests. A concrete native assembly/recipe, operational
observation and update remain pending. No new master inventory, account command,
installed file change, daemon start or VM was performed.

`ConfigurationSession` assembles the revision from the original completed
`SessionProvisioning` instance and an explicit installed reference. It checks
journal identity, request, context, dependencies and the separate unit-only
revision window. Construction performs no snapshot/NSS/filesystem observation;
explicit prepare records the revision without staging or changing the unit.
Apply and recovery require the original prepared reference, and recheck the
authoritative installation record around every snapshot, including observations
after revision checkpoints. No fallback prepares a new intent on retry.

The assembly reuses the concrete snapshot, account identity/completion,
filesystem and dependency readers through their existing interfaces. It does
not execute the original provisioning adapter's create/recovery paths or require
the old installation window to remain active. Nine targeted assembly cases pass
on a complete temporary filesystem; NSS and worker execution are simulated.
They ran outside the UID-restricted sandbox solely to assign UID1001/GID1002 to
fixture directories. No real account, package, service or master inventory
operation occurred. This is additional evidence alongside the earlier 135-test
run, not a combined full native qualification. The concrete host recipe and its
separately authorized prepare/update remain pending.

The native prepare-only entry is `tools/libvirt_configuration_prepare.py`.
It refuses before loading a recipe without `--prepare-host`; the frozen private
bundle binds all runtime/tool sources, nine original inputs and the entry hash.
It checks the original boot/namespaces, installed journal hash/identity/record,
systemctl/interpreter/worker binaries and prerequisite snapshot. Fixed systemctl
show queries are readonly and have a five-second timeout. Target NSS identity
and the original account lock/completion are observed by the existing readers;
no shadow contents are exported. Worker arm/release and uncommitted outcome
collection are explicitly disabled in the native runner.

Only the revision prepare is reachable: the operation records tables and intent
in the original journal, and writes private intent/report/lock artifacts. It does
not stage, exchange or remove files, create accounts, reload/start services or
connect to libvirt. The installed record stays unchanged; the journal's database
bytes necessarily change when revision metadata is recorded. A second invocation
cannot overwrite the first output directory. Changed context or journal has no
discovery, adoption or retry fallback.

Fourteen bootstrap/transport/temporary-SQLite tests pass. The package was built
from archived inputs and current repo sources and checked without running its
host body. Native prepare has not been executed. It requires separate consent
and the agreed window without changes to accounts, libvirt/runtime configuration,
packages or reboot. Guests can remain stable. This prepares neither a service
activation nor a VM gate; apply/recovery authorization remains separate.

### Native prepare attempt refused before journal/account/service observation

The single authorized prepare attempt stopped at its initial context check:
the observed boot ID differs from the original installation context, while the
namespace observations match. The failed attempt retained its private intent
and error report. It did not open the original journal, perform systemctl/NSS
queries, prepare a revision, stage/replace a file or activate a daemon. No retry
was executed. Historical input and guard criteria remain unchanged. A separate
post-boot qualification contract is needed before another operational attempt;
the mismatch does not authorize adoption or recreation of persistent/volatile
resources or reuse of historical process identities in the new context.

### Separate post-boot qualification prototype (synthetic verification only)

The agreed contract preserves the original installed record and records a new
qualification intent bound to the same host and an explicitly different boot.
`HistoricalAccountCreation` validates the saved original account birth, command,
worker outcome and durable exit chain as historical creation evidence. It does
not inspect the old PID in the current boot or claim current process liveness.
Current account identity remains a separate observation.

`PostBootQualification` reobserves the complete persistent inventory twice with
unchanged original proofs and static prerequisites, plus inactive services and
no dedicated-UID processes. It records `persistent_qualified` separately from
runtime readiness. All `/run` targets remain pending, whether absent or present;
an old name/inode or a caller-supplied ready flag cannot qualify them. This first
component neither recreates volatile resources nor supplies a new effective
installation to the existing revision/activation paths. Those guards remain
unchanged. Current-boot volatile recovery and its integration are still needed.

The initial synthetic run had one pass and one failure before the remaining
tests: the fixture denies all Python `os.open` calls, including acquisition of
its own temporary journal execution lock. The failure precedes historical
reads. The separately authorized test-only correction acquires the original
fixture gate before enabling the no-open mock. All fourteen post-boot tests now
pass, including readonly historical account evidence, immutable replay, rejected
source/context changes, incomplete historical chains and stale volatile proofs.
The history-reader test uses SQLite query_only and denies new Python file/pidfd
opens during the read; it does not claim an OS sandbox. Runtime and lock
validation are unchanged. The initial failed evidence remains preserved.

No new host collection, original host journal access, native prepare, resource
recreation or service operation occurred. Concrete current-boot observation,
volatile recovery and integration remain pending; this persistent-only receipt
cannot bypass the original boot guard or authorize the next operational step.

`VolatileDirectories` prepares a distinct recovery intent for the session's
explicit `/run` directories, bound to the persistent qualification and current
boot/window. It observes all targets before creating any, records a fresh nonce
and create request for each directory, then requires its original filesystem
birth and durability proof. An existing unqualified directory is a conflict;
there is no delete, adoption or recreation of an occupied path. Replaying an
uncertain absent create cannot repeat it. Explicit recovery may only synchronize
an already recorded original birth before continuing the remaining planned steps.

`observe_persistent` rechecks the immutable persistent/account history while
reporting volatile path changes separately. The recovery must explain those
changes with its own new births. It does not rewrite the earlier pending receipt
or reuse the old boot's directory proof. Every checkpoint rechecks context,
window, unchanged resources and the whole target inventory. Conflicts retain
already created resources and the pending journal; no automatic cleanup runs.

The completed result covers session directories only (`daemon_ready=False`).
Revision/activation integration and a qualified current-boot native provider
remain pending; the legacy boot guard is unchanged. Twenty-four synthetic tests
pass, plus one separate test with real private temporary directories. The latter
used reviewed escalation solely for fixture UID1001/GID1002 ownership; account,
service and host context remained simulated. No installed directory, master
inventory, operational prepare, account command, daemon or VM was touched.

`CurrentSessionView` joins the original persistent qualification and completed
current-boot directory recovery into an explicit `postboot-session-view-v1`
descriptor. It preserves the original stored installation and records every
resource's creator; new directory proofs retain the recovery ID and nonce.
The descriptor is journal lineage, with `observation_required=True`, not live
readiness. It cannot be derived from a directory name or an incomplete recovery.

`CurrentSessionPreflight` reuses the complete unchanged-target and inactive-service
checks with fresh context/prerequisite snapshots. Accounts require their original
historical creation evidence plus current identity; filesystem resources are
observed through their explicitly bound per-item creators. Only the unit being
revised is delegated to the existing independent staging/exchange observer.
This lets the historical source descriptor remain stable after a tracked unit
exchange, while all other resources continue to be checked.

`CurrentConfigurationSession` is a separate explicit post-boot assembly. It reuses
the original prepared-reference/apply/recovery protocol without modifying or
falling back from the legacy boot guard. Seven synthetic source/creator/conflict
cases pass. One complete temporary-filesystem case separately passes in32.05s:
initial simulated-account installation, changed fixture boot, fresh runtime
directory births, qualified source view, unit exchange and immutable replay.
Escalation was limited to fixture UID/GID ownership. NSS, worker execution and
historical account evidence were simulated in that integration case; the
historical SQL chain has its separate tests. No daemon or master operation ran.

The evidence covers the initial inactive installation and this one tracked
post-boot revision. Further boot/revision generations, native collection and
operational recipes remain unqualified; this does not qualify a running libvirt
session, VM lifecycle, catalog, distributed recovery or cutover.

### Readonly post-boot collector prototype (synthetic verification only)

`SessionInstaller(readonly=True)` reads only the existing original table and
refuses prepare/apply/save before mutation callbacks. `PostBootObserver` composes
the original readonly file/identity/dependency readers with the current snapshot;
volatile paths are statted without following leaf symlinks and remain unqualified.
It retains stage/target diagnostics. Twenty-four observer/installer tests pass.

`PostBootCollection` compares two complete observations and historical account
reads, returning only a non-qualifying report with prerequisite differences and
pending volatile targets. Its native entry uses a frozen source/input manifest,
explicit expected context, readonly/immutable SQLite and fixed readonly queries;
there is no journal writer or prepare/apply/recovery API in that entry.

The initial collector suite stopped after ten passes and one failure. Its synthetic
native-wiring fixture omits `prerequisites.profile_sha256`, so the existing
profile/context guard rejects it before output creation or native callbacks.
The archived installed manifest contains the correct matching field. The
separately authorized fixture-only correction adds that fingerprint. All36
combined collector/observer/installer tests now pass, including the synthetic
native-entry routing and unchanged readonly SQLite bytes with no WAL/SHM files.
Runtime and guards are unchanged; the first failed evidence remains preserved.
No concrete native collection recipe or master collection has been run by this
prototype. Operational collection and any subsequent qualification/recovery
remain separate steps requiring authorization.

The first readonly collection package is frozen against182 runtime/tool sources
and seven archived inputs. Its expected current context comes explicitly from
the saved failed-prepare observation, not fresh discovery or an updated source
installation. Recipe validation reads only repo/archived files and has passed;
the native body has not been invoked. A different boot/context, source inventory
or original journal is an immediate refusal, without automatic adoption/retry.

The proposed single master collection writes private reports only. Original
SQLite opens readonly/immutable with query_only; no original lock, intent/table
initialization or mutation API is used. Historical creation and current NSS/lock,
filesystem, package/configuration and fixed systemctl-show observations stay
separate. No shadow contents are exported, no old PID is adopted and volatile
paths remain pending. Physical workers are not needed. Native collection requires
separate consent and a brief window without package/account/libvirt/runtime
updates or host reboot; stable guests can continue running. No prepare/apply,
resource recovery/recreation, libvirt connection or daemon start is authorized
by packaging the recipe.

`ServiceGenerationObserver` prepares typed validation of an already acknowledged
daemon generation. It binds the original activation nonce and command completion
to the installed unit/configuration, systemd invocation ID, nonroot process
credentials, groups, argv/environment, namespaces, executable and live pidfd proof.
The private socket must have the original filesystem identity and peer credentials
of that process. Two observations must match the immutable original reference;
an inspect result cannot create or replace the start acknowledgement.

The observer has no default systemd/procfs/socket readers and makes no host calls
at construction. The native provider must establish the process, peer and command
proofs before these checks have operational meaning. Thirty-one targeted synthetic
tests cover this validator together with the activation journal. No service was
observed or activated on the master by this step.

`ServiceUnitReader` prepares the native readonly `systemctl show` transport for
the three dedicated units, with a five-second query timeout and no default
command executor. It retains the original response before parsing and compares
all installed file proofs before and after the query. Missing/foreign/duplicate
units, unqualified fragments/drop-ins and invalid generation fields are rejected;
inactive and transitional observations never imply readiness.

`InstallationFiles(..., readonly=True)` reads existing birth proofs without table
initialization and refuses create, recovery and birth updates. A query-only SQL
test confirms that observation performs no database writes or fsync. The prepared
master collector opens the original closed journal with SQLite readonly/immutable
flags, checks its hash/context before and after, and writes only private reports.
The unit reader and file modes have passed targeted synthetic tests. On
2026-11-09, one separately authorized master observation completed with exit 0:
all three units were loaded from the original fragments, inactive/dead, with no
drop-ins, job, PID or invocation ID and with Restart=no. All seven file proofs,
the installation context and journal hash remained unchanged. It performed one
readonly service query and no reload/start, NSS or libvirt connection. This is a
pre-activation observation, not a daemon readiness or capability qualification.

The installation snapshot also observes the OS directories above the planned
targets, including `/`, `/etc`, `/etc/systemd/system`, `/var/lib` and `/run`.
They must be real root:root directories with mode 0755. Their device, inode and
permissions are checked twice and retained as dependencies; they are never
adopted, created or changed by this check. Child timestamps are excluded so
unrelated directory activity does not change the dependency identity. Planned
session directories retain their separate original-birth and ownership checks.
The parent check was exercised on fixture filesystems and the separately
authorized version2 master collection and apply. Historical version1 observations
remain limited to their original layout.

`InstallationDirectoryDependencies` supplies the injected dependency reader for
an explicitly selected existing root-owned 0755 profile directory, such as
`/etc/dnlab`. It checks the directory and ancestor identities twice without
following symlinks. The resulting receipt is persisted through the installer's
`existing_directories` argument and compared on replay and before mutations.
It grants no ownership, chmod, cleanup or replacement rights over that directory
or its existing children. Temporary-filesystem tests cover this reader together
with prepare/replay and refusal before account creation. The master prepare/apply
used this reader to preserve the original `/etc/dnlab` dependency identity.

`SessionProvisioning` assembles the snapshot, explicit window, account helper,
local/NSS identity reader, file adapter and directory dependency reader around
one journal. All host providers and the original dependency receipts are explicit
inputs. Construction does not observe the host or launch a worker. `prepare()`
only observes and records the intent; `apply()` is separate and ends at
`installed_not_started`. There is no default host launcher/NSS lookup or daemon
activation. Synthetic assembly checks cover preflight conflicts and a complete
temporary-filesystem apply/replay with a simulated account worker. This is not
authorization or operational qualification of real account creation.

Account command preflight also reobserves the original window and every target
after the durable arming/release checkpoints. Account observations avoid recursive
helper preflight: existing accounts require the original birth and an already
committed worker outcome, while the current account may still be absent before
execution. The readonly completion reader neither collects a pending process nor
retires it. A lost response can recover only from the original committed outcome;
another pending account or any changed dependency/target blocks progress without
another release. The targeted synthetic suite passes 103 tests; the unchanged
runtime also passed the separate temporary-filesystem positive apply/replay case.

`tools.libvirt_install_prepare.prepare_only` binds the original successful
collection to the current profile and translates only explicitly selected
occupied directory targets into dependency receipts. It rejects missing ancestor
proofs, modified inventories and unselected occupied targets. Its account runner
refuses arm, verify, release and outcome, so this entry cannot execute account
commands. Tests cover durable intent reopen and equality between the saved
directory receipt and the live temporary-filesystem reader. A real prepare still
requires separate authorization for the repeated readonly host/NSS observations
and its private journal; it does not authorize apply or activate the session.

New installation requests must explicitly set `layout_version=2` and
`driver_config_root=/var/lib/dnlab-libvirt-control`. Version1 remains renderable
only to read historical evidence; prepare/apply and mutating command preflight
refuse it. Stored intents are not migrated or rewritten.

| Resource | Proposed target |
|---|---|
| Account/group | `dnlab-libvirt`, fixed nonzero UID/GID recorded after creation |
| Private state/home | `/var/lib/dnlab-libvirt`, mode 0700 |
| Private runtime root | `/run/dnlab-libvirt`, mode 0700 |
| Client URI | Explicit `qemu:///session` |
| Primary socket | `/run/dnlab-libvirt/libvirt/libvirt-sock` |
| Administrative daemon config | `/etc/dnlab/libvirt/`, root-controlled, readable by the account |
| Driver config parents | `/var/lib/dnlab-libvirt-control` and its `libvirt/`, root:root0755 |
| QEMU driver config | `/var/lib/dnlab-libvirt-control/libvirt/qemu.conf`, root:root0644 |
| Mutable domain/driver tree | `/var/lib/dnlab-libvirt-control/libvirt/qemu/`, dedicated UID/GID0700 |
| XDG runtime/config | `/run/dnlab-libvirt` and `/var/lib/dnlab-libvirt-control` |
| XDG data/cache | `/var/lib/dnlab-libvirt/data` and `/var/lib/dnlab-libvirt/cache` |
| QEMU service | `dnlab-libvirtd.service` |
| Logging/locking | `dnlab-virtlogd.service`, `dnlab-virtlockd.service` |
| Directory ownership | Explicit installer intents before any daemon start; units create no directories |

`libvirtd` supports a foreground process, explicit configuration and pidfile,
and a non-root socket under the XDG runtime directory. Its QEMU driver reads
the session's XDG configuration. These are the basis for the layout above;
availability and syntax still need checking against selected packages.
[Upstream libvirtd manual](https://libvirt.org/manpages/libvirtd.html).

The first reviewed profile uses libvirtd with the QEMU driver and explicit
logging/locking dependencies. There is no automatic daemon switch,
system-session fallback or embedded libvirt mode. Names, IDs and paths remain
proposals until the installation intent pins actual original resources.

The driver tree is separate from the user-owned state/home root. Its root-owned
parents protect qemu.conf from replacement by the dedicated user; only the qemu
subtree is writable for persistent domains and native driver state. Disk assets
and overlays retain their separately qualified storage paths. The native driver
loads qemu.conf from its config base, independently of libvirtd's --config option.
[Libvirt11.3 driver initialization](https://raw.githubusercontent.com/libvirt/libvirt/v11.3.0/src/qemu/qemu_driver.c).
Actual service/configuration and device/storage qualification is still pending.

## Supervision and client behavior

All three daemons run under the dedicated account, in the foreground with
explicit configuration and pidfile paths. The units must be named independently
of vendor units and must not inherit the shared system instance's configuration.
Required unit settings for the first reviewed profile are:

```ini
[Service]
Type=simple
User=dnlab-libvirt
Group=dnlab-libvirt
UMask=0077
Environment=XDG_RUNTIME_DIR=/run/dnlab-libvirt
Environment=XDG_CONFIG_HOME=/var/lib/dnlab-libvirt-control
Environment=XDG_DATA_HOME=/var/lib/dnlab-libvirt/data
Environment=XDG_CACHE_HOME=/var/lib/dnlab-libvirt/cache
KillMode=process
KillSignal=SIGTERM
SendSIGKILL=no
Restart=no
TimeoutStopSec=30s
```

This common section is illustrative. `dnlab_runtime.libvirt_service_profile`
now renders the three complete proposed units and four configuration files
purely from explicit session IDs, daemon paths/hashes and a pinned package
version. It pins numeric UID/GID in the units, disables automatic force/restart,
does not enable daemon boot activation or guest autostart, requests a private socket and lockd, and returns file hashes plus
directory and package requirements. There is no installer or account lookup.
The caller must qualify the supplied values; synthetic example IDs/hashes must
never be treated as observed host facts. The package transaction and native
configuration/unit validity remain unqualified. Do not install the illustrative
section or generated files solely because rendering succeeds.
Guest autostart flags and private session state require separate checks before
starting a daemon; rendering service files does not verify or change them.
The runtime directory has one explicit owner; stopping a sibling daemon must
not remove the shared directory or other sockets. Do not add automatic service
enablement or VM autostart during the first installation.

`KillMode=process` avoids using a daemon stop as a control-group-wide guest
termination. Disabling automatic SIGKILL leaves a timeout for explicit recovery;
it does not establish that a guest shut down. These settings require validation
with the actual supervision and guest process layout.
[systemd kill semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html).

Logging and locking are persistent infrastructure dependencies. Stop or replace
them only after every dependent VM has a verified exit; no rolling restart of
virtlogd is implied. In particular, it holds logging pipe descriptors while
guests run. Domain disk locks supplement, rather than replace, the runtime's
single-writer reservations and overlay ownership.
[Libvirt daemon roles](https://libvirt.org/daemons.html),
[lockd configuration](https://libvirt.org/kbase/locking-lockd.html).

The client must set `LIBVIRT_AUTOSTART=0` before opening libvirt: a missing daemon
is an error, not permission for an untracked launch. Use the explicit session
URI and private socket/configuration context, without URI aliases or probing
the system instance as a fallback. Bindings must verify the daemon, socket and
configuration against the original session proof before and after connection.
Whether the library reports a canonical or transport-specific URI is a fact
to verify, not a reason to rewrite `DedicatedSession` checks speculatively.
[Libvirt connection API](https://libvirt.org/html/libvirt-libvirt-host.html#virConnectOpen),
[connection URIs](https://libvirt.org/uri.html).

## Experimental installation coordinator

`dnlab_runtime.libvirt_install.SessionInstaller` now prepares a durable intent
in the runtime journal and sequences group, account, private directories and
profile files. It rerenders the original profile on reads, reserves one install
intent per host and stores an individual nonce before each create. A complete
adapter observation must cover context, package/service prerequisites and every
target before mutations, including after the durable create checkpoint.

Only explicit pre-existing directory proofs may be dependencies; they are
rechecked and never changed or adopted as installer-created resources. The host
adapter must qualify their ownership/metadata and all parent paths. Existing
accounts or files are conflicts. All created resources retain their original
birth receipt and are independently observed before subsequent use.

A lost create response stays `create_requested`. Recovery may recognize the
same nonce/spec/intent and persist that original birth without repeating create.
Absence in an uncertain phase remains blocked: it is not proof that a delayed
create cannot complete. Committed creates are rechecked on replay. There is no
automatic rollback, removal, service start, package install or enablement.
Completion is explicitly `installed_not_started`.

This is the persistent coordinator, not an executable host installer. The
injected adapter is synthetic in the tests. A concrete adapter still needs
exclusive creation and durable birth evidence for accounts, files/directories
and unit installation, kind-specific identity checks, complete prerequisites
(including vendor masks and no active dependencies), and a fresh post-package
host baseline. Generic receipt validation does not qualify those host checks.
No account, unit, directory or daemon was changed by this implementation.
The first targeted run passed 33 synthetic tests across coordinator and profile.

## File adapter preparation: explicit durability recovery

`libvirt_install_files.InstallationFiles` now requires the existing runtime
journal. Immediately after exclusive file creation it records the original
file and parent kernel identities, intent/nonce/spec binding and
`durability_pending`, before writing the marker/content. Only successful file
and parent fsync followed by a committed proof can produce
`durability_confirmed`. Readonly observation refuses pending durability.

Explicit `recover()` rechecks original file, visible parent path, ownership,
content and marker before synchronizing the original pinned file and parent.
It independently observes them again, then commits the confirmation before
returning a qualified receipt. Failures keep pending state; replacements are
preserved, and no recovery creates, rewrites or deletes a file. Missing original
birth records are conflicts, including a crash before birth was saved. A lost
confirmation response can reuse the original committed proof.

The original failed-fsync regression is fixed. The preceding targeted run passed
52 tests on temporary files, the synthetic coordinator and profile, including
an integration case where coordinator progress is blocked until explicit file
recovery. The earlier failed run remains historical evidence. Directory
creation now requires the provisioning-window contract below. This component
is not a complete host adapter: account/group helper execution,
real host prerequisite qualification and daemon start remain pending. No actual
host account, configuration, service or VM was changed.

## Provisioning window and account/directory preparation

The selected contract requires a short agreed administrative window excluding
concurrent changes to the dedicated accounts and session paths. Stable labs may
remain active. This is an explicit operating condition, not an OS barrier that
prevents another root administrator from violating the agreement.

`libvirt_provisioning.ProvisioningWindow` pins operation, context, target inventory
and window nonce; injected observation rechecks that exact receipt. Directory
creation now requires this window before mkdir and after durable checkpoints.
The journal records mkdir intent before mutation and the original FD identity
before marker/metadata use. A crash before that identity is committed leaves
`birth_pending`: matching path contents do not permit adoption or another mkdir.
Durability recovery requires the same window and original resource identities.

`InstallationAccounts` similarly records create intent before invoking an
injected helper. The requested account is non-root, locked, noninteractive,
with an explicit home and intent/nonce comment. Names and numeric IDs must be
free; the helper must inspect both namespaces. Recovery requires the helper's
original durable successful completion plus a matching current resource, not
just an account/group row. An uncertain command with no completion stays
pending; no create retry, adoption, removal or rewrite is performed.

The current 68-test run uses temporary directory trees and an in-memory account
helper. No useradd/groupadd, host account lookup, system directory provisioning,
service reload/start or VM operation has been performed. A concrete supervised
account helper with qualified durable completion, a complete host preflight and
composition of these components into the real adapter remain to be implemented.
The window agreement authorizes preparation only; real provisioning requires
its own reviewed attempt and actual window confirmation.

## Installation sequence and stopping conditions

1. **Resolve packages without installing.** Identify the actual distribution,
   installed package versions, available daemon/helper packages and candidate
   versions. Inspect the planned transaction and package service/network hooks.
   Package/version facts are collected; full dependency and hook review is open.
   No generic `apt install libvirt-daemon-system` instruction is approved here.
2. **Review a complete package plan.** Pin dependencies, executable paths,
   configuration format and Python/client requirements. Avoid replacement of
   the QEMU already used by existing labs. Reject implicit vendor service,
   default network, DHCP/NAT, bridge or firewall activation. Any required
   package service-inhibition mechanism must be explicit and must preserve
   existing policy and unrelated service administration.
3. **Prepare the installation intent.** Record the host boot/context, package
   plan, original files, empty-target checks and all intended account, unit,
   config and directory identities before mutations. Existing names, accounts,
   state or services require an ownership decision; do not adopt them by name.
4. **Apply only after separate approval.** Track package, account, directory,
   config and unit creation separately. Record birth/identity before subsequent
   use. Stop on a conflict, lost response or unexpected package action; retain
   pending state without a second create, cleanup or rollback by guesswork.
5. **Start an empty dedicated session.** Supervise logging/locking before QEMU
   management. Verify original UID/GID, process generation, executable/config
   hashes, private socket identities, client URI and an empty domain inventory.
   Compare existing lab/network state. Do not define a VM, enable a network,
   import a template or set domain autostart in this step.
6. **Qualify packaging and capabilities separately.** Check the supported
   versioned i440fx machine, firmware, KVM access, persistent TAP ownership,
   storage access and runtime-image socket transport. The current process
   provider requires its caller to share the QEMU PID namespace; mounting host
   procfs alone is insufficient. Do not weaken that check to make a container
   connection work. If the image packaging cannot satisfy the requirements,
   record the blocker before selecting another deployment architecture.
7. **Proceed to the VM gates.** Only after these checks and explicit operational
   authorization, create the V2 bundles/overlays and qualify boot, mappings,
   console, guest traffic, shutdown and recovery. A daemon start is not VM
   qualification or a public backend cutover.

KVM device access may require a dedicated supplementary group; its actual ID
and permissions must come from the host, not a guessed group name. Do not grant
blanket host capabilities or use a setuid bridge helper as an implicit fix.
TAP creation/bridging remains owned by the qualified dNLab networking path;
libvirt networks with NAT/DHCP remain outside this architecture.

## Recovery and host lifecycle

Recovery rechecks the same installation intent and current resource identities
before advancing. Package-manager partial states require explicit completion,
not blind repetition of an install command. An uncertain service start is
observed through its original unit/process/socket proof before another action.
Do not erase state or remove packages/accounts because no VD is visible.

All guests must be drained through verified lifecycle operations before stopping
logging/locking infrastructure or dismantling its account/state. Host shutdown
also needs a separately qualified ordering; these draft units do not guarantee
guest persistence across a reboot. Do not enable libvirt-guests or domain
autostart to obtain implicit suspend/restore behavior: it would change the
agreed runtime lifecycle. Unrelated libvirt resources remain outside ownership.
[Libvirt guest-service behavior](https://libvirt.org/manpages/libvirt-guests.html).

The user's installation authorization is recorded above. A simulation of the six explicitly versioned root packages
(`libvirt-daemon`, QEMU driver, log, lock, lockd plugin and clients), with
recommendations disabled, completed: 16 new packages, zero upgrades and zero
removals. Dpkg status and boot were unchanged. The additional dependencies
include polkitd and systemd-container; they require maintainer/service-hook
inspection along with libvirt. No autoremove is part of the transaction.
All 16 exact archives were subsequently downloaded with APT authentication
enabled and checked against cached APT SHA256/size metadata. Control scripts,
units and relevant payloads were inspected as data, never executed for inspection.
The installation preflight found no pre-existing libvirt state, vendor units,
overrides, conflicting payload files or the standard package account names.
AppArmor's readonly `aa-enabled` returned 3 with its securityfs interface absent
inside the LXC; no policy loader was invoked by this preparation.

The package-only apply used the existing archives with download, upgrades,
removal and recommendations disabled. It created 13 recorded administrative
masks for the vendor libvirt services/sockets and libvirt-guests. A nonce-bound
temporary policy-rc.d denied package-time service actions and was removed only
after its original inode/content were verified. The masks remain deliberately
installed; they protect the system instance while the dedicated session is
prepared. No pre-existing administrative policy was replaced.

APT exited 0, all 16 exact versions are configured, and the installed libvirtd,
virtlogd and virtlockd hashes match the inspected archives. Both the apply and an
independent readonly check verified all 13 vendor units masked/inactive and the
temporary policy absent. D-Bus retained its original process generation; polkit
and machines.target were inactive after the package operation. Preset-denied
messages in the logs are expected consequences of the administrative masks.

The completed package operation has its own original receipts; a fresh
post-install host baseline remains pending. Do not replay the old pre-install
dpkg hash as if no installation had occurred. The next work
is a tracked dedicated-account/directory/config/unit setup, followed by empty
session qualification. No dedicated daemon, VM, KVM/TAP test or runtime image
has been started or changed by the package-only operation. Keep the verified
archives and installation receipts available for recovery and subsequent setup.

## Composed adapter: positive temporary-filesystem test qualified

`libvirt_install_adapter.ProvisioningAdapter` composes the original window,
complete prerequisite snapshot, explicit directory dependencies, account helper
protocol and file/directory primitives. The first sandbox run stopped at fchown
to fixture UID1001/GID1002 with EINVAL. A separately authorized diagnostic found
only UID/GID0 mapped in that sandbox; the synthetic ownership call reproduced
EINVAL without changing the original file.

The exact positive composed test was then separately authorized and repeated
outside the sandbox, with fixture and guard unchanged: 1 passed in 0.28s, exit0.
It reached installed_not_started and verified replay without a second account
creation, using real temporary filesystem operations and simulated accounts.
The original sandbox failure remains recorded. A subsequent sandbox run passed
four rejection cases in 0.14s: last-file conflict and changed window, snapshot
or dependency, all before mutations. The exact lost-account-response composition
case subsequently passed in its own authorized outside-sandbox run: 1 test in
0.27s, exit0, preserving the original account create and coordinator intent.
All six composition cases have passed across these separate runs; no full-suite
rerun is claimed. The prior 68-test result covers the earlier components.
This does not qualify actual account commands, host provisioning, libvirt
startup or VM operation. No real accounts, system paths or services changed.

## Installation preflight collector preparation

`tools/libvirt_install_preflight.py` prepares a readonly two-snapshot collector
for local account/group name and numeric-ID conflicts, explicit installed package
versions, daemon hashes, administrative mask links and occupied target paths.
It never executes package/account/service commands, allocates IDs or adopts
existing paths. Local NSS, live process/service inactivity, device access and
the provisioning window remain unqualified. Host mode requires --collect-host;
no master collection has been run.

The first exact-file synthetic run passed 10 tests in 0.17s, but pytest emitted
12 warnings while pruning directories from previous ownership tests under its
default temporary root. That old-artifact cleanup is not verified. No cleanup
correction or retry has been applied; use of a fresh exclusive --basetemp for
subsequent runs is pending discussion. The collector tests themselves used only
synthetic account/package files and daemon bytes.

### Prepared isolated synthetic test recipe

Future experimental test runs use a freshly allocated private output parent
and an initially absent child as explicit --basetemp. Never select an existing
pytest tree: pytest may erase a supplied basetemp. Existing artifacts and their
ownership remain untouched; cleanup is separate from test execution.

The prepared collector recipe selects only its exact test file, rootdir and
confcutdir, disables plugin autoload/cache, checks input hashes and preserves
logs/exit code with a 30-second timeout. Only shell syntax has been checked;
no test, host collection or cleanup ran in this preparation step. The prior
10-pass/12-warning result remains unchanged; no warning-free run is claimed.

### Isolated collector tests completed

The separately authorized recipe ran once with a fresh private basetemp and
passed all 10 tests in 0.16s, exit0, without warnings or stderr. The original
10-pass/12-warning run remains historical. Logs, exit code and basetemp path
are retained; the recipe does not select or prune old pytest trees. No host
collector mode, account command, service or old-artifact cleanup was executed.
This verifies synthetic test isolation, not a real master preflight.

### First readonly master installation snapshot completed

The separately authorized master collection completed with exit0 and no stderr,
with two matching snapshots. All16 expected installed package versions, daemon
hashes and vendor administrative mask links matched. Local passwd/group show
no conflict for dnlab-libvirt or candidate UID1001/GID1002. GID993 is the local
kvm group; device access was not exercised. These identities remain candidates,
not allocated or reserved, and NSS conflicts have not been qualified.

The only occupied proposed target is /etc/dnlab, observed as root:root0755. Its
original directory proof is preserved as an explicit dependency candidate;
no adoption, metadata change or intent to create over it was performed. The
collection records a fresh scoped post-package dpkg snapshot; it does not
qualify live service inactivity, account-helper execution, KVM/TAP permissions,
the provisioning window or session startup. Report qualified=false is retained.

## Account-helper preparation: comment format discrepancy

Before any executable account helper was enabled, upstream useradd source
review found that the current generated comment dnlab:<intent>:<nonce> contains
passwd field delimiters. useradd's VALID macro rejects colon/newline in its
comment argument. A new purely synthetic regression reproduces the invalid
generated field (1failed in0.07s); no useradd/groupadd was executed.
Source: https://raw.githubusercontent.com/shadow-maint/shadow/master/src/useradd.c
Format background: https://man7.org/linux/man-pages/man5/passwd.5.html

Correction is pending discussion. Proposed new requests use a versioned safe
marker derived from a hash of the original intent/nonce; saved old requests
remain immutable and must not be silently rewritten or adopted. The existing
positive tests used a simulated helper and therefore did not qualify this
actual command-input constraint. No operational account provisioning is enabled.

### Safe account comment implemented for new requests

New account requests now use dnlab-v1- followed by the SHA256 fingerprint of
version, original intent ID and nonce. The original values remain separate in
the journal; their raw delimiters cannot enter the passwd comment. The marker
is deterministic and distinct when either original identity changes.

Saved incompatible requests retain their original payload and are refused on
observe/create/recover before helper inspection, without automatic migration,
rewrites or adoption. Tests cover both pending and created historical records.
The targeted run passed 73 tests in0.89s, exit0, without warnings in a fresh
exclusive basetemp. This qualifies the generated field and synthetic protocol;
no useradd/groupadd, actual account provisioning or daemon startup occurred.
The prior failed regression remains historical evidence.

## Tracked account command helper preparation

`libvirt_account_commands.AccountCommandHelper` now implements the injected
account-helper interface with fixed argv plans for /usr/sbin/useradd and
/usr/sbin/groupadd, explicit IDs, safe comment, locked/nologin account and
no-create-home/no-user-group/no-log-init options. No shell interpolation, force
or non-unique-ID fallback is used. The command environment is explicit.
References: https://man7.org/linux/man-pages/man8/useradd.8.html and
https://man7.org/linux/man-pages/man8/groupadd.8.html .

The helper records arming intent before requesting a blocked non-mutating worker.
A command-bound reference and original worker process proof are persisted before
release intent. Context/config preflight, target absence and worker verification
are repeated after checkpoints before the sole release. Lost arm/release or
missing outcome never reexecutes automatically. Completion must come from the
original runner reference with exit0 and matching current identity. Failed
commands are not adopted even if a matching account row appears.

The final targeted run passed 43 tests in0.41s without warnings, including
InstallationAccounts integration for both group/user and lost release response.
All process/account operations were simulated; filesystem writes were confined
to the private test journal. No account binary, helper process or host lookup
was executed. There is still no concrete gated process runner or production
inspector/preflight. Actual executable hashes, shadow defaults/hooks/NSS and
worker launch/exit provenance require qualification before provisioning.

## Blocked account worker protocol prepared

`libvirt_account_worker.serve` independently validates the fixed account argv,
sterile environment and an already-pinned root-owned regular ELF descriptor
against its expected hash. It emits ready only after this check and requires
one bounded release frame with the original token and command fingerprint.
It verifies the same descriptor identity/hash again before the injected exec
operation. Unexpected options, root identity, writable/changed binaries and
missing/mismatched release frames are rejected before command execution.

The targeted worker/command/marker run passed 51 tests in0.34s without warnings
using memory streams, synthetic ELF bytes and mocked exec. No account binary,
child process or worker process was launched. This implements the child-side
protocol, not the concrete parent process runner, PID/exit qualification or an
operational account helper. These remain necessary before a real provisioning
window or session install can be attempted.

## Parent account runner prepared, real observer pending

`libvirt_account_runner.AccountProcessRunner` now implements parent transport
for the blocked worker. It records launch intent, pins target/interpreter/source
FDs, passes only those descriptors and uses explicit -B -I -S, environment and
cwd. It checks the bounded readiness frame and requires the captured PID to
match its original child before persisting the reference. Release intent is
durable before its final process check and the single release write.

Output collection is bounded per stream; completion requires original exit
qualification and a durable outcome. No signals, force, respawn or PID adoption
are implemented. A reopened runner can read an already committed outcome, but
a missing original waiter with pending execution remains blocked. The private
worker entrypoint execs the inherited binary FD in the same process only after
the protocol release; it is not registered as a public runtime/API operation.

The final runner/worker/command run passed60 tests in0.45s, zero warnings, using
fake child processes/observers, memory streams, temporary bytes and anonymous
local pipes. No actual Popen, account binary or worker process was executed.
A real process/namespace/pidfd/exit observer remains mandatory and has not been
provided or qualified; the runtime is not enabled for host account provisioning.
Interpreter/source/tool hashes, shadow config/hooks and NSS remain part of the
required operational preflight.


## Original account process observer prepared

`libvirt_account_process.AccountWorkerObserver` captures the original Popen
waiter, root helper credentials, boot/start ticks, executable, command and
namespace identities, holding its pidfd until a durable exit receipt exists.
This root helper does not change the dedicated non-root daemon/QEMU contract.
The runner persists the observer binding before release, checks the blocked
interpreter again before writing the release frame, and retires owned streams
and pidfds only after committing the outcome. Lost waiters are not reconstructed
from a PID; completed receipts remain readable in their original context.

An initial synthetic failure exposed two methods sharing `_read`; the file
reader is now named `_read_file`, without changing the acceptance checks.
The four targeted process/runner/worker/command suites pass 83 tests, using
synthetic procfs, fake processes and pidfds, and anonymous local pipes. No host
process, account command, daemon or VM was started or inspected by these tests.
The observer implementation is prepared, but actual procfs/process observation,
worker/interpreter and command profiles, hooks/NSS and operational provisioning
remain unqualified. No public admission or host provisioning is enabled.


## Harmless observer canary completed

The separately authorized local canary ran once using the pinned system
interpreter, `-B -I -S`, and a fixed Python child that only announced readiness
and waited for EOF. Original process/namespace binding and pidfd exit receipt
completed with exit 0; interpreter hash and metadata matched before/after.
The canary and process journals contain one matching original reference and a
durable exit receipt. No signals, account worker/commands, Docker/SSH/libvirt,
services or provisioning were used. The initial independent readonly query
assumed `runtime.sqlite3`; the implementation uses `journal.sqlite3`. Reading
the correct existing database verified the receipts without rerunning the canary.

This qualifies the observer's harmless live-process path in this environment.
It does not qualify worker exec, account tools/configuration/hooks/NSS, recovery
after a lost real waiter, libvirt services, QEMU or host provisioning.

## Account tool inventory prepared, not collected

`tools/libvirt_account_tool_inventory.py` prepares two bounded readonly
snapshots of useradd/groupadd, nsswitch.conf, login.defs, default/useradd,
passwd/group/subuid/subgid hashes, and useradd-pre.d/useradd-post.d entries.
Only the three configuration files are included as text in the private report;
account database contents are not emitted. Shadow/gshadow are not read.
Symlinks and nested hook directories are reported without following them;
listing and file sizes are bounded. No account tool, hook, NSS lookup or
subprocess is executed. This is evidence for review, never automatic permission
to provision. The host collection requires an explicit switch and separate
operational authorization.

The hook/config scope follows the Debian trixie
[useradd manual](https://dyn.manpages.debian.org/trixie/passwd/useradd.8) and
[groupadd manual](https://manpages.debian.org/trixie/passwd/groupadd.8.en.html).
Eight synthetic inventory tests pass. In addition, five synthetic composition
cases now exercise the real account runner and observer with a fake child and
procfs: shared original identity, lost release/outcome replies, waiter loss and
generation conflict at release. The four targeted suites pass 88 tests total.
No new real process, host collection, account or service operation was run.


## Account tool readonly inventory collected

One separately authorized collection completed successfully with two matching
snapshots. useradd and groupadd are regular root-owned mode0755 files; the two
fixed useradd hook directories are absent. The report records their hashes,
configuration text and account database hashes without executing any tool/hook
or reading shadow/gshadow. passwd/group NSS configuration is `files systemd`;
no NSS lookup was performed and local-file checks alone do not complete the
identity qualification. The collection remains `qualified=false`.

This was a fresh readonly observation, not adoption of identities from earlier
boot/process receipts. No worker process, account allocation, daemon, VM,
Docker/SSH/libvirt command or service mutation occurred. Account tool execution,
NSS identity checks, original provisioning window and operational installer
integration remain open before provisioning can be enabled.

## Targeted NSS probe prepared, not executed

`tools/libvirt_nss_inventory.py` provides name/UID and name/GID lookups for the
dedicated candidate, with root name/numeric positive controls and two matching
observations. Tests inject all lookup results; real calls require --query-host.
The real entry uses Python pwd/grp through the configured NSS chain, not account
commands or enumeration. It emits only names and numeric IDs, never password,
GECOS or group-member fields. An outer finite timeout is mandatory because NSS
calls may block. No lookup has been run by this preparation.

Twelve synthetic tests pass for results, collisions, malformed/error responses,
failed controls, changes between observations and explicit host opt-in. Negative
results remain `reported_absent` in a `qualified=false` report; they are not
proof that all providers were available. See the lookup status/action semantics
in [nsswitch.conf](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)
and the [Python pwd API](https://docs.python.org/3/library/pwd.html).


## Targeted NSS probe completed

One separately authorized readonly probe completed with exit0. The two
observations matched: root name/numeric controls returned UID/GID0, and no
entry was returned for dnlab-libvirt, UID1001 or GID1002. Boot, NSS config,
passwd/group and interpreter hashes/metadata matched before/after. The report
keeps `candidate_reported_absent=true` and `qualified=false`: no reservation,
resource ownership or provider-wide availability is inferred from these results.

No account command, enumeration, shadow lookup, Docker/SSH/libvirt or service
management command was executed. These IDs remain unallocated candidates.
Operational worker qualification and the original complete preflight/window
are still required before any explicit provisioning.


## Worker bootstrap-only canary prepared; cleanup regression open

A new recipe reuses the runner's inherited-FD argv builder, sends only the
initial worker request, records original identity and then closes stdin. No
release frame is sent. The expected refusal is exit1 with the original
incomplete-frame Conflict, plus qualified original process exit. This would
qualify bootstrap/stdio only; account target execution remains excluded.

The initial five targeted synthetic suites passed98 tests. An additional
cleanup boundary test then failed: BrokenPipeError from stdin.close during a
readiness-error cleanup replaces the primary error and skips waiter/other-stream
cleanup. The new recipe is not operationally ready. Failure evidence is retained;
correction is pending user confirmation. No real worker or account tool has
been executed by this preparation. Existing runtime guards remain unchanged.


## Worker bootstrap recipe cleanup corrected

After user confirmation, only the bootstrap recipe cleanup was corrected.
stdin close, original bounded wait, stdout/stderr close and observer close are
attempted independently. Cleanup errors are retained by step without replacing
the primary readiness/protocol error. Cleanup failure leaves the journal
pending, qualified=false and cleanup_verified=false; it never sends a signal,
release or retry. The failed regression remains preserved in the historical
evidence. The final five targeted suites pass101 tests, including combined
stdin BrokenPipe/wait timeout and stdout-close failure. Runtime acceptance
guards are unchanged. No real worker, account target or host provisioning ran.


## Worker bootstrap-only operational recipe ready, not executed

The recipe now also records the observed readiness reply and bounded original
stderr/outcome before closing streams after a startup failure. A focused test
verifies that this diagnostic survives cleanup; the final five targeted suites
pass102 tests. The prepared wrapper pins reviewed interpreter/groupadd hashes
and source hashes, stores a one-shot private intent and original process/exit,
and compares fresh boot/file/account-database evidence before/after. It reads
the groupadd FD but sends only the initial worker frame followed by EOF: no
release frame or account execution is permitted. Expected refusal is exit1
with the incomplete-frame Conflict; all other outcomes remain pending/failure.
No real worker has been started by this preparation. This scope qualifies only
bootstrap/transport/refusal, not target exec, account creation or libvirt startup.


## Worker startup/EOF canary completed

The separately authorized worker bootstrap canary ran exactly once. Original
worker readiness, process/namespace and pidfd exit matched the persisted
reference. After only the initial request and EOF, the worker returned the
expected incomplete-frame Conflict and exit1; the probe completed with exit0.
The journal records release_sent=false and cleanup_verified=true. Independent
readonly review found one canary and one matching original process/exit record,
with source, binary and visible account-database evidence unchanged before/after.
The groupadd FD was read and held, never executed. No account was created.

This qualifies worker bootstrap, initial transport and EOF refusal in this
environment. Account target exec, live completion/recovery, the provisioning
window/installer and libvirt services remain separate and unqualified. No
signals, retry, NSS/shadow queries, Docker/SSH/libvirt or service management
commands were used by this probe.

## Local/NSS account identity reader prepared, synthetic only

`libvirt_account_identity.LocalAccountIdentity` prepares the inspector callback
for the tracked account helper. It compares target name/numeric local rows and
injected NSS results with root positive controls, twice; absence and conflicts
never authorize adoption. Exact account home/shell/nonce-derived comment and
passwd shadow placeholder must match before reading the selected target lock.
The target shadow field must match the literal lock created by the fixed
useradd command. Shadow bytes never leave the reader; it emits only expected
identity fields. Missing, ambiguous, writable, symlinked or replaced input is
refused. No shadow is opened for absent/unrelated target identities.

The existing NSS query/parser functions are shared with the diagnostic tool
without changing lookup semantics. No host query is supplied by default to the
reader. Seventy-four targeted tests pass using temporary passwd/group/shadow
fixtures and fake NSS only, including a test that matching rows without the
original journal birth still block InstallationAccounts. No host shadow, real
NSS lookup, account command, daemon or provisioning was used in this step.
The reader is not wired into public admission or live host provisioning; the
caller must still qualify the original window, lookup execution/time bounds,
prerequisites, command completion and generation.

## Installer/account identity chain verified synthetically

A targeted integration fixture now connects the real SessionInstaller,
ProvisioningAdapter, InstallationAccounts, AccountCommandHelper and
LocalAccountIdentity. Only the worker and non-account file-resource provider
are simulated; account rows are temporary fixture files and NSS is injected.
It exercises group then account creation from the original argv plans, replay,
lost responses for each command with explicit original recovery and no second
execution, foreign identities before mutation, static preflight change at release
and account replacement after completion. No real account command or chown is
used. Five targeted suites pass81 tests. This verifies the component chain,
not live installer prerequisites, filesystem provisioning or host permissions.
The operational snapshot/window provider and live installer recipe remain open.

## Installation prerequisite and activity providers prepared

`tools.libvirt_install_snapshot.InstallationSnapshot` checks explicit installed
package versions, daemon hashes/root permissions, vendor masks, reviewed account
binary/config/hook inputs and KVM group identity. It binds fresh boot/namespace
and inactive service/job/process observations. Its frozen prerequisites exclude
mutable target account rows and generated installation resources; those remain
verified by the original account/file ownership adapters. Neither exclusion
permits target adoption. Command preflight must match the original full snapshot.

`tools.libvirt_install_activity.InstallationActivity` prepares a fixed readonly
`systemctl show --all` query and a bounded procfs census for the candidate UID,
primary/saved GIDs and supplementary group. It reads no argv/environment and
never adopts or acts on a PID. Responses and blocker identities are retained
before rejection. Missing/duplicate properties, command errors, unexpected
unit state, pending jobs and incomplete proc reads remain conflicts. Job's empty
value under --all follows the
[systemd v257.13 source](https://raw.githubusercontent.com/systemd/systemd/v257.13/src/systemctl/systemctl-show.c).
The systemctl transport is injected, not run by tests/import/construction.

Five final targeted suites pass55 tests with fake systemctl, procfs and package/
account files, including composition of the observers with the snapshot. No new
master observation, account command, systemctl or provisioning has been run.
An observe-only wrapper is prepared with source hashes and existing reviewed
profiles; it would execute only systemctl show (5s per query) and readonly file/
proc observations. It cannot prepare/apply an installation, create accounts,
install files, reload/start/stop services or connect libvirt. The result remains
qualified=false pending operational review and the original provisioning window.


## Installer prerequisite observation completed, no preparation/apply

One separately authorized observe-only run completed with two successful fixed
systemctl show queries. All16 configured units were inactive without jobs;
no process matched candidate UID/GID,17 packages matched, and no account/group
conflict was reported. The only occupied installation path was /etc/dnlab,
already known as a candidate shared-directory dependency. It was neither adopted
nor modified. Source/interpreter/systemctl and prerequisite checks completed;
raw responses and candidate-process observations are preserved privately.

The report remains qualified=false. No installer prepare/apply, account change,
NSS/shadow lookup, Docker/SSH/libvirt connection, package operation, daemon
reload/start/stop or signal to a service occurred. Actual installation still
requires the original explicit provisioning window, qualified directory
dependency and a concrete reviewed installer transaction; no service is enabled.

## Native writable configuration layout discrepancy — correction pending

Source review of libvirt11.3 QEMU configuration shows the unprivileged driver
uses its user config base for persistent domain definitions and several mutable
QEMU paths. The rendered XDG_CONFIG_HOME is /etc/dnlab, so its native QEMU tree
falls under the planned root:root0755 /etc/dnlab/libvirt parent. No writable
subtree is planned there for the dedicated UID. A pure profile/DAC contract
test fails on that exact ancestor. No daemon was run to reproduce an OS error.

The preceding readonly observation remains evidence of package/service/file
prerequisites only; it did not qualify this layout. Installation is blocked
pending a corrected separation of root-owned administrative settings and
private mutable driver state, with qemu.conf verified at its actual lookup path.
Old profile/intents and evidence remain immutable, with no automatic migration.
No account, installation file or daemon has been created by this investigation.

References: [QEMU config paths, v11.3.0](https://raw.githubusercontent.com/libvirt/libvirt/v11.3.0/src/qemu/qemu_conf.c),
[persistent domain config use](https://raw.githubusercontent.com/libvirt/libvirt/v11.3.0/src/qemu/qemu_driver.c),
[upstream user-directory helper discussion](https://lists.libvirt.org/archives/list/devel%40lists.libvirt.org/thread/E2UNNA6HJ6TLBVFMEHFPA6ASSIWMBG72/).


## Native layout corrected in version2, synthetic verification only

The authorized correction adds explicit layout_version2 and a separate
root-owned driver_config_root. qemu.conf is generated at the native driver
lookup path; the mutable qemu subtree is owned by the dedicated UID/GID.
Overlapping state/control roots, shared roots, nested driver parents, missing
explicit paths and unsupported versions are refused. The driver root is a direct
child of /var/lib; its existing OS parent still needs host qualification. Daemons/QEMU remain non-root.

Historical rendering is byte-stable, including a frozen version1 digest. Old
intents remain readable and unchanged; they cannot prepare/apply, qualify an
account command or be overwritten by a new request. Version2 needs a new
explicit preparation. Previously collected version1 evidence does not qualify
the new path inventory, and no saved request was updated implicitly.

One hundred and eleven targeted synthetic tests pass, including the original
writability regression, root-controlled qemu.conf parents, disjoint trees and
historical intent refusal. Six additional composition tests pass outside the
UID-restricted sandbox solely for ownership of new private temporary fixture
directories; accounts remain simulated. No account command, host installation,
unit update, daemon start or VM was performed. The real renderer/profile remains
qualified=false pending the later native/operational checks.
