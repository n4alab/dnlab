"""Agent-oriented documentation for the public GUI HTTP API.

Keeping this catalogue separate from the route handlers makes it possible to
document every HTTP method exposed by a multi-method ``api_route`` while
leaving the runtime routes and their operation identifiers unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI


@dataclass(frozen=True)
class OperationDoc:
    summary: str
    description: str


def _doc(summary: str, description: str) -> OperationDoc:
    return OperationDoc(summary=summary, description=description)


# Keys use the method and path exactly as they appear in openapi.json.
OPERATION_DOCS: dict[tuple[str, str], OperationDoc] = {
    # Authentication
    ("post", "/api/auth/login"): _doc(
        "Log in with local credentials",
        "Authenticate a local-database user and create a server-side session. "
        "Use the returned user profile and session cookie for later API calls. "
        "This operation is unsupported when authentication is delegated to an "
        "upstream Basic Auth, LDAP, or OIDC provider.",
    ),
    ("post", "/api/auth/logout"): _doc(
        "Log out the current session",
        "Revoke the current server-side session and clear its cookie. This has "
        "no response body and is unsupported with upstream Basic Auth, where "
        "the browser owns the cached credentials.",
    ),
    ("get", "/api/auth/whoami"): _doc(
        "Get the authenticated user",
        "Return the username, role, email address, and active authentication "
        "backend for the current session. Use this read-only call to determine "
        "the caller's identity and authorization level.",
    ),

    # User administration
    ("get", "/api/users/"): _doc(
        "List user accounts",
        "Return every persisted user account and its role, status, backend, "
        "and profile metadata. This read-only operation requires the admin role.",
    ),
    ("post", "/api/users/"): _doc(
        "Create a user account",
        "Create and persist a local user account with the requested role and "
        "credentials. This operation requires the admin role and returns the "
        "new user record; only one assistant-role account may exist.",
    ),
    ("patch", "/api/users/{user_id}"): _doc(
        "Update a user account",
        "Change role or active state on a persisted user; local-database users "
        "may also change or clear their email address. Usernames are immutable "
        "and federated email addresses are managed upstream. This persistent "
        "operation requires the admin role, revokes sessions after role changes "
        "or deactivation, and protects the last active local administrator.",
    ),
    ("post", "/api/users/{user_id}/password"): _doc(
        "Reset a user's password",
        "Replace a local user's password and revoke that user's existing "
        "sessions. This security-sensitive operation requires the admin role "
        "and returns no response body.",
    ),
    ("delete", "/api/users/{user_id}"): _doc(
        "Delete a user account",
        "Permanently delete a local user account and its sessions. This "
        "destructive operation requires the admin role and refuses to remove "
        "the last active administrator.",
    ),

    # Administrative configuration and image builds
    ("get", "/api/admin/config/{key}"): _doc(
        "Read a raw configuration file",
        "Return the selected paths, hosts, or devices configuration as raw "
        "text together with its parsed form and filesystem location. This "
        "read-only operation requires the admin role.",
    ),
    ("get", "/api/admin/config/{key}/model"): _doc(
        "Read a structured configuration model",
        "Parse the selected paths, hosts, or devices configuration and return "
        "the editable structured model. This read-only operation requires the "
        "admin role and reports invalid existing configuration as a validation "
        "error.",
    ),
    ("put", "/api/admin/config/{key}/model"): _doc(
        "Replace a structured configuration",
        "Validate, serialize, and atomically persist the supplied paths, hosts, "
        "or devices model, creating a backup of the previous file when present. "
        "This deployment-wide operation requires the admin role.",
    ),
    ("get", "/api/admin/realnet-bgp"): _doc(
        "Get RealNet BGP configuration",
        "Return the deployment-wide RealNet BGP settings and current route "
        "reflector status. This read-only operation requires the admin role.",
    ),
    ("put", "/api/admin/realnet-bgp"): _doc(
        "Update RealNet BGP configuration",
        "Validate and persist deployment-wide RealNet BGP settings, then "
        "reconcile the route-reflector container with the new configuration. "
        "This side-effecting operation requires the admin role.",
    ),
    ("post", "/api/admin/realnet-bgp/rr-password"): _doc(
        "Rotate the RealNet route-reflector password",
        "Generate and persist a new RealNet BGP route-reflector password, then "
        "reconcile the reflector. This invalidates the previous shared secret "
        "and requires the admin role.",
    ),
    ("post", "/api/admin/realnet-bgp/reconcile"): _doc(
        "Reconcile the RealNet route reflector",
        "Create or repair the deployment-wide RealNet route-reflector container "
        "from the current hosts configuration. This side-effecting operation "
        "requires the admin role and returns the reconciliation result.",
    ),
    ("get", "/api/admin/image-build/kinds"): _doc(
        "List supported image-build kinds",
        "Return the virtual-device kinds accepted by the image builder and the "
        "source requirements for each kind. This read-only operation requires "
        "the admin role and should be called before validating or uploading a "
        "source image.",
    ),
    ("post", "/api/admin/image-build/validate-filename"): _doc(
        "Validate an image source filename",
        "Check whether a source filename is safe and compatible with the "
        "selected virtual-device kind without uploading or building anything. "
        "This operation requires the admin role.",
    ),
    ("post", "/api/admin/image-build/uploads"): _doc(
        "Upload an image-build source",
        "Upload and persist a source image in a temporary build workspace. This "
        "operation requires the admin role and returns the source_path that must "
        "be supplied when creating a build job for non-self-building kinds.",
    ),
    ("post", "/api/admin/image-build/jobs"): _doc(
        "Start an image-build job",
        "Queue an asynchronous virtual-device image build. This operation "
        "requires the admin role and returns a job identifier and initial state; "
        "poll the job endpoint to follow completion.",
    ),
    ("get", "/api/admin/image-build/jobs"): _doc(
        "List image-build jobs",
        "Return known image-build jobs in newest-first order, including their "
        "current state and result metadata. This read-only operation requires "
        "the admin role.",
    ),
    ("post", "/api/admin/image-build/jobs/clear"): _doc(
        "Clear completed image-build jobs",
        "Remove finished or failed jobs from the job history while retaining "
        "queued and running jobs. This persistent cleanup operation requires "
        "the admin role and returns the number removed.",
    ),
    ("get", "/api/admin/image-build/jobs/{job_id}"): _doc(
        "Get an image-build job",
        "Return the current state, logs, and result metadata for one image-build "
        "job. This read-only operation requires the admin role and is the polling "
        "endpoint for a job created earlier.",
    ),

    # Docker inventory
    ("get", "/api/docker/images"): _doc(
        "List local Docker images",
        "Return all Docker images visible to the GUI host. Use this authenticated, "
        "read-only inventory call when raw Docker image information is needed.",
    ),
    ("get", "/api/docker/images/network"): _doc(
        "List usable network-device images",
        "Return only Docker images recognized as supported Containerlab node "
        "kinds. Use this authenticated, read-only call when selecting an image "
        "for a topology node.",
    ),
    ("get", "/api/docker/interfaces"): _doc(
        "Get node interface naming rules",
        "Return the interface-name mapping used for supported device kinds. Use "
        "this authenticated, read-only call to choose valid endpoint names when "
        "creating topology links.",
    ),

    # Lab discovery and lifecycle
    ("get", "/api/labs/"): _doc(
        "List visible labs",
        "Return every lab the caller may read, including its UUID, owner, display "
        "name, timestamps, and whether the caller may modify it. This operation "
        "does not inspect runtime containers or change lab state.",
    ),
    ("post", "/api/labs/"): _doc(
        "Create an empty lab",
        "Create and persist an empty topology owned by the caller. The response "
        "contains the lab UUID used by all later topology and lifecycle calls; "
        "rookie users cannot create labs and owner-local names must be unique.",
    ),
    ("get", "/api/labs/running"): _doc(
        "List labs with running containers",
        "Inspect Containerlab on the master and return labs with at least one live "
        "container, including orphan runtimes that have no database record. This "
        "is a best-effort, read-only runtime snapshot.",
    ),
    ("get", "/api/labs/{lab_id}/status"): _doc(
        "Get summarized lab status",
        "Return the persisted lab identity and a summarized container runtime "
        "snapshot. A lab with no active deployment is reported as stopped; this "
        "authenticated operation does not change runtime state.",
    ),
    ("post", "/api/labs/{lab_id}/deploy"): _doc(
        "Deploy a lab",
        "Deploy the persisted topology and start its runtime infrastructure. The "
        "caller must have write access to the lab; this side-effecting operation "
        "returns the deployment result and may take significant time.",
    ),
    ("post", "/api/labs/{lab_id}/destroy"): _doc(
        "Destroy a lab deployment",
        "Stop and remove the lab's runtime containers and networks while keeping "
        "the saved topology available for a later deployment. The caller must "
        "have write access to the lab.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/wipe-disk"): _doc(
        "Wipe a node's persistent disk",
        "Permanently erase the selected node's persisted writable disk so its "
        "next start uses a clean image state. This destructive operation requires "
        "write access to the lab and cannot be undone.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/start"): _doc(
        "Start one lab node",
        "Start or recreate the selected node within an existing lab deployment "
        "without redeploying the whole topology. The caller must have write "
        "access; use the status or node-list endpoint to observe the result.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/stop"): _doc(
        "Stop one lab node",
        "Stop the selected running node while leaving the rest of the lab active "
        "and preserving its configured state. The caller must have write access "
        "to the lab.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/reconcile"): _doc(
        "Reconcile one lab node",
        "Bring the selected node's runtime into agreement with its saved topology "
        "definition. This may create, replace, start, or stop runtime resources "
        "and requires write access to the lab.",
    ),
    ("post", "/api/labs/{lab_id}/links/reconcile"): _doc(
        "Reconcile one runtime link",
        "Create or repair the specified link between two nodes in a deployed lab "
        "without redeploying the full topology. Both endpoint names and interfaces "
        "are required, and the caller must have write access.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/restart"): _doc(
        "Restart one lab node",
        "Restart the selected node while leaving other lab nodes running. The lab "
        "must be deployed and the caller must have write access; the response "
        "reports the runtime operation result.",
    ),
    ("post", "/api/labs/{lab_id}/realnet/{realnet_name}/reconcile"): _doc(
        "Reconcile a RealNet attachment",
        "Create or repair the selected RealNet runtime attachment for a deployed "
        "lab from its saved topology. This changes live networking and requires "
        "write access to the lab.",
    ),
    ("delete", "/api/labs/{lab_id}"): _doc(
        "Permanently delete a lab",
        "Destroy any active deployment, clean persistent runtime data, remove the "
        "topology file, and delete the database record. This destructive operation "
        "requires write access and cannot be undone.",
    ),

    # Persisted topology editing
    ("get", "/api/labs/{lab_id}/topology"): _doc(
        "Get a lab topology",
        "Return the complete saved topology for a readable lab, including its "
        "nodes, links, management network, and agent-usable UUID. This operation "
        "does not inspect or change the live deployment, and sensitive RealNet "
        "passwords are redacted unless the caller may view them.",
    ),
    ("put", "/api/labs/{lab_id}/topology"): _doc(
        "Replace a lab topology",
        "Validate and persist a complete replacement topology for the lab. This "
        "requires write access and changes saved configuration only; reconcile or "
        "redeploy separately to apply it to an existing runtime.",
    ),
    ("get", "/api/labs/{lab_id}/realnet/importable-routers"): _doc(
        "List importable RealNet routers",
        "Return RealNet router definitions from other labs that can be referenced "
        "by the selected lab. This authenticated, read-only discovery call does "
        "not modify either topology.",
    ),
    ("get", "/api/labs/{lab_id}/realnet/config"): _doc(
        "Get public RealNet configuration",
        "Return the non-secret deployment-wide RealNet values needed to configure "
        "the selected lab, currently including the remote BGP AS number. This is "
        "a read-only call for users who may view the lab.",
    ),
    ("post", "/api/labs/{lab_id}/topology/nodes"): _doc(
        "Add a topology node",
        "Validate and persist a new node in the lab topology, then return the "
        "updated topology. This requires write access and does not create the live "
        "node until the lab or node runtime is reconciled.",
    ),
    ("patch", "/api/labs/{lab_id}/topology/nodes/{node_name}"): _doc(
        "Update a topology node",
        "Apply the supplied fields to an existing saved node, optionally renaming "
        "it, and return the updated topology. This requires write access and does "
        "not automatically reconcile an active runtime.",
    ),
    ("delete", "/api/labs/{lab_id}/topology/nodes/{node_name}"): _doc(
        "Remove a topology node",
        "Remove the selected node from the saved topology and, when it is live, "
        "remove its runtime first. This destructive operation requires write "
        "access and returns the resulting topology.",
    ),
    ("put", "/api/labs/{lab_id}/topology/mgmt"): _doc(
        "Set the topology management network",
        "Validate and persist the lab's IPv4 and IPv6 management subnets, gateways, "
        "and optional canvas position. This requires write access; runtime bridge "
        "names remain derived from the lab UUID and an active lab is not reconciled.",
    ),
    ("put", "/api/labs/{lab_id}/topology/nodes/{node_name}/mgmt-ipv4"): _doc(
        "Set a node management IPv4 address",
        "Set or clear the saved static management IPv4 address for one topology "
        "node and return the updated topology. This requires write access and does "
        "not immediately change a running node.",
    ),
    ("put", "/api/labs/{lab_id}/topology/nodes/{node_name}/mgmt-ipv6"): _doc(
        "Set a node management IPv6 address",
        "Set or clear the saved static management IPv6 address for one topology "
        "node and return the updated topology. This requires write access and does "
        "not immediately change a running node.",
    ),
    ("post", "/api/labs/{lab_id}/topology/links"): _doc(
        "Add a topology link",
        "Validate and persist a link between two saved node endpoints, then return "
        "the updated topology. This requires write access and does not create the "
        "live link until deployment or runtime reconciliation.",
    ),
    ("delete", "/api/labs/{lab_id}/topology/links"): _doc(
        "Remove a topology link",
        "Remove the matching saved link identified by node names and, when needed, "
        "interface names. This requires write access, returns the updated topology, "
        "and does not automatically remove a live link.",
    ),
    ("patch", "/api/labs/{lab_id}/topology/links/style"): _doc(
        "Set a topology link visual style",
        "Set or clear GUI-only visual styling for one saved link, such as its "
        "custom color. This requires write access, returns the updated topology, "
        "and does not change ContainerLab configuration or live runtime state.",
    ),
    ("put", "/api/labs/{lab_id}/topology/canvas-annotations"): _doc(
        "Set canvas annotations",
        "Replace the saved GUI-only canvas annotations for the selected lab, "
        "including notes and simple shapes. This requires write access, returns "
        "the updated topology, and does not create ContainerLab nodes or links.",
    ),
    ("post", "/api/labs/{lab_id}/topology/import-drawio"): _doc(
        "Import a draw.io topology",
        "Parse the uploaded draw.io XML and persist its supported graph content in "
        "the selected lab topology. This replacement-style mutation requires write "
        "access and returns the resulting topology for review.",
    ),
    ("get", "/api/labs/{lab_id}/topology/export-drawio"): _doc(
        "Export a topology as draw.io",
        "Convert the saved lab topology to draw.io XML and return it as a downloadable "
        "file. This read-only operation requires permission to view the lab.",
    ),

    # Multinode inventory and runtime reports
    ("get", "/api/hosts/"): _doc(
        "List multinode hosts",
        "Return the configured master and worker host inventory used by the "
        "multinode scheduler. This authenticated, read-only call does not probe or "
        "change host state.",
    ),
    ("get", "/api/image-sync/status"): _doc(
        "Get global image-sync status",
        "Return the latest deployment-wide image synchronization state, or mark the "
        "service unavailable when no state is present. This authenticated operation "
        "is read-only.",
    ),
    ("post", "/api/image-sync/reconcile"): _doc(
        "Trigger global image synchronization",
        "Wake the image-sync daemon to reconcile images across every worker. This "
        "admin-only operation can consume substantial network bandwidth and returns "
        "only the trigger result; monitor the status endpoint for progress.",
    ),
    ("get", "/api/labs/{lab_id}/plan"): _doc(
        "Plan a multinode lab deployment",
        "Compute and return host placement and deployment actions for the saved lab "
        "without applying them. Use this read-only call to inspect scheduling before "
        "deploying or synchronizing images.",
    ),
    ("get", "/api/labs/{lab_id}/status-live"): _doc(
        "Get detailed live lab status",
        "Probe the multinode backend and return detailed runtime, infrastructure, "
        "host-placement, and node state for a deployed lab. Unlike the summarized "
        "status endpoint, this performs a live read but makes no changes.",
    ),
    ("get", "/api/labs/{lab_id}/nodes"): _doc(
        "List live lab nodes",
        "Return the deployed nodes and their current multinode runtime metadata. "
        "Use this read-only call when selecting a node for a per-node lifecycle "
        "operation.",
    ),
    ("get", "/api/labs/{lab_id}/jumphost/password"): _doc(
        "Get the lab jumphost password",
        "Return the current labuser password for the selected lab's jumphost. This "
        "sensitive read requires lab access, is audit-logged, and should only be "
        "used to establish an authorized jumphost session.",
    ),
    ("post", "/api/labs/{lab_id}/sync-images"): _doc(
        "Synchronize images for a lab",
        "Push the images required by the saved topology to the assigned worker hosts. "
        "This bandwidth-intensive operation requires write access and should normally "
        "follow inspection of the deployment plan.",
    ),

    # Follow the Rabbit
    ("post", "/api/labs/{lab_id}/follow-rabbit/sessions"): _doc(
        "Start a packet-path tracing session",
        "Start a Follow the Rabbit session from a running source node for the "
        "specified flow tuple. This changes runtime tracing state, requires write "
        "access, and returns a session identifier for later listing or stopping.",
    ),
    ("get", "/api/labs/{lab_id}/follow-rabbit/sessions"): _doc(
        "List packet-path tracing sessions",
        "Return the active Follow the Rabbit sessions and their current path data "
        "for the selected lab. This is a read-only operation for users who may view "
        "the lab.",
    ),
    ("delete", "/api/labs/{lab_id}/follow-rabbit/sessions/{session_id}"): _doc(
        "Stop a packet-path tracing session",
        "Stop the selected Follow the Rabbit session and release its runtime tracing "
        "resources. This operation requires write access and returns the final stop "
        "result.",
    ),

    # Packet capture
    ("get", "/api/labs/{lab_id}/captures/targets"): _doc(
        "List packet-capture targets",
        "Discover the nodes, links, interfaces, and capture sides currently available "
        "in the selected lab. This read-only call returns target identifiers accepted "
        "by the capture launch operation.",
    ),
    ("post", "/api/labs/{lab_id}/captures/launch"): _doc(
        "Start a packet capture",
        "Start a live packet capture for a discovered target, optionally applying a "
        "BPF filter, snapshot length, and promiscuous mode. The response contains a "
        "session and short-lived capability URL used by the local capture handler.",
    ),
    ("get", "/api/labs/{lab_id}/captures/active"): _doc(
        "List active packet captures",
        "Return packet-capture sessions owned by the caller in the selected lab, "
        "including the session identifiers needed to stop them. This operation does "
        "not start, stop, or modify a capture.",
    ),
    ("post", "/api/labs/{lab_id}/captures/{session_id}/stop"): _doc(
        "Stop a packet capture",
        "Stop the caller-owned capture session and release its remote capture process "
        "and stream resources. The caller must be able to read the lab; the response "
        "reports the stop result.",
    ),
    ("get", "/api/captures/handler/download"): _doc(
        "Download the local capture handler",
        "Download the Python or Windows batch helper that opens dNLab capture "
        "capability URLs in a local packet analyzer. This authenticated call returns "
        "a file and does not start a capture by itself.",
    ),
    ("get", "/api/captures/{token}/status"): _doc(
        "Check a capture capability",
        "Check whether a short-lived packet-capture token is valid and ready before "
        "opening its stream. The token itself authorizes this read-only capability "
        "call; invalid or expired states are returned in the response body.",
    ),
    ("get", "/api/captures/{token}/stream"): _doc(
        "Stream captured packets",
        "Consume the live PCAP byte stream authorized by a short-lived capture token. "
        "This streaming endpoint is intended for the local capture handler or a "
        "packet analyzer, not for JSON-based management agents.",
    ),

    # Device Web UI tunnels
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/webui/open"): _doc(
        "Open a device Web UI tunnel",
        "Create an authenticated tunnel through the lab jumphost to a Web UI on a "
        "running node. The response contains a tokenized proxy URL and expiry data; "
        "the lab must be active and the node must have a management address.",
    ),
    ("post", "/api/labs/{lab_id}/nodes/{node_name}/webui/close"): _doc(
        "Close a device Web UI tunnel",
        "Close the tunnel identified by lab, node, and device port. This releases "
        "proxy resources, requires permission to read the lab, and returns whether "
        "a matching tunnel was found and closed.",
    ),
}


_HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
)
_WEBUI_PROXY_PATH = "/webui/{token}/{path}"


def _add_webui_proxy_docs() -> None:
    descriptions = {
        "get": "Retrieve a resource",
        "post": "Submit data",
        "put": "Replace a resource",
        "patch": "Partially update a resource",
        "delete": "Delete a resource",
        "options": "Query supported HTTP options",
        "head": "Retrieve response headers",
    }
    for method, action in descriptions.items():
        OPERATION_DOCS[(method, _WEBUI_PROXY_PATH)] = _doc(
            f"Proxy a device Web UI {method.upper()} request",
            f"{action} through an already-open, tokenized device Web UI tunnel using "
            f"HTTP {method.upper()}. This browser transport endpoint forwards the "
            "request and response unchanged; it is not a lab management API and "
            "requires the authenticated tunnel owner.",
        )


_add_webui_proxy_docs()


def _schema_operations(schema: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (method.lower(), path)
        for path, path_item in schema.get("paths", {}).items()
        for method in path_item
        if method.lower() in _HTTP_METHODS
    }


def enrich_openapi_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Apply the catalogue and reject undocumented or stale operations."""
    actual = _schema_operations(schema)
    documented = set(OPERATION_DOCS)
    missing = sorted(actual - documented)
    stale = sorted(documented - actual)
    if missing or stale:
        details = []
        if missing:
            details.append(f"missing documentation for {missing}")
        if stale:
            details.append(f"documentation without an operation for {stale}")
        raise RuntimeError("OpenAPI operation documentation is out of sync: " + "; ".join(details))

    for (method, path), doc in OPERATION_DOCS.items():
        operation = schema["paths"][path][method]
        operation["summary"] = doc.summary
        operation["description"] = doc.description
    return schema


def install_openapi_docs(app: FastAPI) -> None:
    """Install agent-oriented schema enrichment without changing API routes."""
    default_openapi = app.openapi

    def documented_openapi() -> dict[str, Any]:
        schema = default_openapi()
        # FastAPI caches this object; enrichment and validation are idempotent.
        return enrich_openapi_schema(schema)

    app.openapi = documented_openapi  # type: ignore[method-assign]
