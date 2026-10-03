# dNLab User Guide

This guide is for people who use the dNLab browser interface to create, run,
observe and share network labs. It assumes an administrator has already
deployed dNLab and created your account.

For platform setup and operations, see [ADMIN_GUIDE.md](ADMIN_GUIDE.md).

## Sign In

Open the dNLab HTTPS URL provided by your administrator, such as
`https://dnlab.example.com` or `https://192.0.2.10`. The dNLab GUI itself can
use either form. Device Web UI access requires an FQDN and that its wildcard
subdomains resolve through the site DNS service.

![dNLab login page](images/user-login.png)

After login, dNLab opens the main application shell. Your account role controls
which actions are available.

## Labs View

The Labs view is the main workspace for building and operating topologies.

![Labs view](images/user-labs-view.png)

The interface is organized around:

- a toolbar for common actions such as new/open lab, import/export, link mode,
  start, stop, delete and fit;
- a device catalog/sidebar populated from available Docker images and the
  dNLab device catalog;
- a canvas where virtual devices, RealNet objects and links are arranged;
- a properties panel for selected devices, links, management settings and
  advanced options;
- a bottom area for console and log views;
- an event footer for long-running operations such as deploy, destroy, image
  sync, capture and path tracing.

## Create Or Open A Lab

Use the new-lab workflow to create a lab with a display name and description.
dNLab stores labs by UUID internally, so different users can use the same
display name without colliding at runtime.

![New lab dialog](images/user-new-lab.png)

You can also open an existing lab from the lab list. Your role determines
whether you can edit it or only view it.

## Build A Topology

Add devices from the catalog to the canvas. The catalog provides device labels,
vendor grouping, icons, management interface defaults, resource defaults and
known Web UI metadata.

![Device catalog](images/user-device-catalog.png)

Create links by selecting endpoints on two devices. dNLab stores links as
logical `node:interface` pairs and translates the lab into Containerlab
resources during deployment.

![Link editor](images/user-link-editor.png)

Use canvas annotations and link colors when the diagram needs additional
visual structure. These objects are saved with the lab as dNLab GUI metadata;
they do not create Containerlab nodes, links or deploy-time configuration.

![Canvas annotations](images/user-canvas-annotations.png)

Right-click a link and choose **Color Link** to set a custom color. The color
picker accepts any valid hex color and can be reset later from the same action.
Runtime overlays such as active captures and Follow the Rabbit remain
temporary visual states above the saved link color.

Use the annotation tools to add text, rectangles and circles. Annotations can
be selected, moved, resized and edited without changing the topology. The
context menu lets you update text and styling, move an annotation forward or
backward in the canvas layer order, bring it to the front or send it to the
back, and delete it when it is no longer needed.

![Annotation context menu](images/user-annotation-context-menu.png)

Use the properties panel to set the Docker image, management addresses, resource
overrides, advanced node options and device-specific features. Management IPv4
and IPv6 settings can be configured globally for the lab and, when needed, per
device. Starting with release `v0.2.0`, two different labs may use the
same management IPv4 or IPv6 subnet because dNLab isolates each lab management
network in its own VRF. Addresses still must be unique and valid within the
single lab that declares them.

### Cumulus VX Breakout Ports

The Cumulus VX properties panel keeps 32 flat switch ports available and lets
you add 2x, 4x or 8x breakout groups to selected parent ports. Breakout lanes
use extra physical slots after the flat range: for example, a 4x breakout on
`swp10` is presented as `swp10s0` through `swp10s3` and maps to
`eth33` through `eth36`. Multiple groups are allocated in ascending parent
port order.

dNLab generates and mounts `/config/ports.conf`, always preallocates 64 data
NICs, and rejects breakout configurations that would exceed those 64 physical
slots. Only the 32 flat ports and configured breakout lanes are exposed in the
GUI. Changing breakout layout on a running device requires a stop and redeploy.

The dNLab Cumulus image uses the lab-only `dnlab` / `Dnlab123!` control account
to apply breakout naming and wait for `switchd` and `nvued`. The factory
`cumulus` account remains untouched, including its mandatory first-login
password change. The image uses the enhanced 4 GiB, 1-vCPU profile.

## Import And Export draw.io

dNLab can export a lab to a `.drawio` file and import it later. Files exported
by recent dNLab versions preserve dNLab metadata such as GUI kind, image, link
interfaces, RealNet objects, Web UI settings and canvas positions.

Canvas annotations and link colors are included in dNLab-generated draw.io
files. In draw.io they appear as normal cells and shapes, with dNLab metadata
attached so that importing the file back into dNLab can restore the visual
state and the original Containerlab interface mapping.

![draw.io round-trip](images/user-drawio-roundtrip.png)

External or older draw.io files are imported best effort. After import, review
the device kind, Docker image and interface choices before starting the lab.

## Start, Stop And Destroy Labs

When you start a lab, dNLab asks the orchestrator for a pre-deploy plan. Review
placement, image availability and warnings before confirming the start.

![Lab start plan](images/user-lab-start-plan.png)

During deployment and teardown, the collapsible diagnostic panel below the
canvas shows live events. Its **Logs** tab contains only operational records
correlated with the current lab, while **Trace** presents Follow the Rabbit
paths. A deployed lab has active dNLab runtime infrastructure; each virtual device also has its own state
such as `running`, `stopped`, `starting`, `reconciling`, `cancelling`,
`stopping` or `error`.

![Running lab](images/user-lab-running.png)

Use Stop or Destroy to tear down a lab when you are finished. Supported virtual
devices can keep persistent disk state on the dNLab storage root and reuse it
on later deploys. If you need to remove saved state for a supported device, use
the node wipe action only when you are sure the persistent disk is no longer
needed.

## Per-Device Actions

Right-click a device to open its Properties panel and operate one virtual
device without restarting the whole lab. A left click only selects the device.

![Node context menu](images/user-node-context-menu.png)

Common actions include:

- start or stop a single virtual device;
- reconcile a device when the backend supports live repair;
- open console or logs; use **VD Logs** in the top bar for an aggregated live
  log view of all running devices;
- open a device Web UI;
- start or stop packet capture;
- wipe persistent device data for supported kinds.

Infrastructure nodes such as `bridge`, `ovs-bridge` or `host` may not provide a
useful serial console.

### Grow A Running Lab

A per-device lab can be expanded while it is running. Add the new virtual
device to the canvas, configure its image, interfaces and options, and save it
to the topology. Then open its context menu and select **Start VD**.

dNLab schedules and deploys only the new device. It does not redeploy the lab
or run a general topology reconcile, and the existing virtual devices are not
restarted, recreated, moved or reconfigured. Their containers, placement and
forwarding remain active while the new device boots.

After Start VD is requested, Start is disabled, forced Stop is available and a
rotating gear marks the device while it is `starting` or `reconciling`. Some
virtual devices take several minutes to boot. The gear disappears when the
attempt reaches `running`, `stopped` or `error`. Forced Stop cancels the active
attempt and cleans up the new runtime without removing the device from the
saved topology.

You may request Start for more than one new device without waiting for each
boot to finish. Runtime mutations are serialized, so later requests remain
queued and start in sequence.

Links added while the lab is running are saved first and reconciled
automatically:

- `up`: both endpoints are running and the dataplane link is active;
- `partial`: an endpoint is not running yet; the link is shown as an amber
  dashed line and is completed when the endpoint starts;
- `error`: live activation failed; the link is shown as a red dashed line and
  its diagnostic remains available for a later retry.

Node and link changes remain in the topology after cancellation or live
activation errors. Correct the reported problem, then use Start VD or
Reconcile to retry without rebuilding the rest of the lab.

### Current Live-Add Limitations

- Live addition requires a lab deployed with the per-device runtime layout.
  Older legacy deployments must be stopped and redeployed once before they can
  use this workflow.
- The selected image must be available on the scheduled host, declare the
  `warm-links-v1` capability and use a supported runtime profile. FRR is the
  validated reference; other enabled development images remain experimental
  until their device-specific certification is complete.
- Live VD endpoints must use `ethN` interface names and stay within the warm
  port capacity prepared when the device boots. Using a higher interface index
  requires restarting that device with a larger supported capacity.
- A link remains `partial` until both virtual-device endpoints are running.
- Changes to the image, resource allocation or advanced configuration of an
  already deployed device are not applied by live-add and require a normal lab
  redeploy.
- Adding links is reconciled live. Removing or changing an existing link does
  not yet guarantee immediate removal of its previous runtime dataplane; stop
  and redeploy the lab when the old connection must be removed with certainty.
- Runtime mutations are serialized. Concurrent requests may be queued rather
  than executed in parallel.

## Device Web UI

Some device kinds expose HTTP or HTTPS management pages. dNLab opens these
through a per-device tunnel and the public proxy, so your browser reaches the
device without exposing internal Docker networks directly.

![Device Web UI](images/user-device-webui.png)

Administrators must configure wildcard DNS and a matching TLS certificate so
hostnames under `*.dnlab.example.com` can route to device Web UIs.

## Console And Logs

The Console and Logs tabs let you inspect device runtime behavior from the
browser.

![Console and logs](images/user-console-logs.png)

Console access is resolved through the dNLab runtime report and relay for the
host that runs the virtual device. Some virtual network devices take several
minutes before their console becomes responsive.

## Packet Capture

When capture is available for a link or interface, use the context menu to
launch or stop a capture session. dNLab validates the capture target, applies
controlled packet filters and streams packet data through a short-lived token.

![Packet capture](images/user-capture.png)

Your administrator may provide a desktop handler for opening captures in
Wireshark.

## Follow The Rabbit

Follow the Rabbit is a passive traffic-observation workflow. It correlates a
flow seen in captures and visualizes the oriented path on the canvas.

![Follow the Rabbit](images/user-follow-rabbit.png)

This feature observes existing traffic; it does not generate traffic for you.

## RealNet

RealNet objects model connectivity between a lab and external networks. A lab
may use simple NAT mode or BGP mode with administrator-managed route reflector
configuration. Device-side routing policy remains explicit: configure
neighbors, passwords and policies inside the virtual devices as required by the
scenario.

Use a RealNet object when the topology must exchange traffic with something
outside the lab. The object represents the lab-side attachment point to the
physical network; dNLab places and wires the runtime components across the
configured dNLab host or hosts as part of the normal lab deployment.

RealNet has two operating modes:

- **NAT mode** provides simple outbound connectivity from the lab toward the
  external network. Use it when devices only need egress access and the
  external network does not need to learn lab prefixes.
- **BGP mode** lets lab devices exchange routes with the administrator-managed
  RealNet route reflector. Use it when the scenario needs routed integration
  with the physical network or with other RealNet-connected labs.

The following diagram shows the BGP mode topology. It does not describe NAT
mode.

![RealNet BGP topology](images/realnet_topology.svg)

In BGP mode, RealNet can also connect different labs to each other, including
labs owned by different users. Select the RealNet node and use its properties to
choose which labs this lab is allowed to communicate with.

![RealNet properties](images/user-realnet-properties.png)

Communication must be enabled from both sides: each lab must allow the other lab
from the RealNet node properties before routes are exchanged between them. dNLab
applies RBAC to the BGP features of RealNet nodes, so the labs and actions you
can select depend on your account role and permissions.

The BGP platform parameters are global and are configured by an administrator.
For administrative setup, route-reflector status and global RealNet BGP
settings, see [ADMIN_GUIDE.md](ADMIN_GUIDE.md).

In BGP mode, the route reflector is shared platform infrastructure. dNLab
maintains the RealNet object, runtime wiring and route-reflector integration,
but it does not hide routing design from the lab. Configure the BGP neighbor,
authentication, advertised prefixes and import/export policy inside each
virtual device according to the exercise.

If RealNet BGP is unavailable, or if the route reflector status is unhealthy,
ask an administrator to check the global RealNet BGP settings and reconcile the
route reflector service.

## Roles And Access

dNLab uses role-based access control:

- `admin`: full access to all labs and administrator areas.
- `graduate`: can manage own labs and student labs; read-only elsewhere.
- `assistant`: API-only automation role with graduate-like API permissions; it
  cannot use the browser GUI or browser Web UI access.
- `student`: can manage own labs; read-only elsewhere.
- `rookie`: read-only everywhere; cannot create or own labs.

If an action is hidden or rejected, your account probably does not have the
required role for that lab.

## Troubleshooting

- If login fails, check the username/password and contact an administrator if
  the account might be inactive.
- If a device image is missing, ask an administrator to check Docker image
  discovery, image sync or image-build.
- If a virtual device does not keep configuration after redeploy, confirm with
  an administrator that the image supports dNLab persistent disks and that the
  device configuration was saved inside the guest OS.
- If Start shows warnings, read the pre-deploy plan before continuing.
- If a device Web UI does not open, confirm the lab is deployed and the device
  is running. It is unavailable when the GUI is configured with an IP address;
  dNLab opens an explanatory page with administrator contacts when configured.
  Administrators should instead configure an FQDN, wildcard DNS, TLS and proxy
  settings.
- If console is blank, wait for the virtual device to finish booting and try
  again.
- If a lab operation appears stuck, review the event footer and ask an
  administrator to run the smoke checks and inspect backend service health.
