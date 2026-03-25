# EDAMAME Core MCP Tools Reference

Complete reference for all MCP (Model Context Protocol) tools exposed by EDAMAME Core. These tools are available to external AI assistants (Claude Desktop, n8n, custom agents) via the MCP server.

**Server**: Streamable HTTP transport via [rmcp](https://github.com/nicholaskell/rmcp) SDK v0.8
**Protocol**: MCP 2024-11-05
**Default endpoint**: `http://127.0.0.1:3000/mcp`
**Authentication**: Dual-mode (per-client credentials or shared PSK) via `Authorization: Bearer <token>` header

---

## Authentication

The MCP server supports two authentication modes:

### 1. Per-Client Credentials (App-Mediated Pairing)

Desktop clients obtain a unique credential through the host app's pairing flow:

1. Client POSTs to the unauthenticated `/mcp/pair` endpoint with client metadata.
2. User approves the request in the host app UI.
3. Client polls `GET /mcp/pair/:request_id` until status is `approved`.
4. Client receives an `edm_mcp_...` credential and uses it as `Authorization: Bearer edm_mcp_...`. Each credential is scoped to a single client.

### 2. Shared PSK (CLI/Headless)

A legacy Bearer token passed at server start. Used by CLI tools, provisioning scripts, and automation. The PSK can be provided via the `EDAMAME_MCP_PSK` environment variable or stored in `~/.edamame_psk` (owner-read/write only, `chmod 600`). Generate with `edamame-posture mcp-generate-psk`.

---

## Pairing Endpoints

These HTTP endpoints are unauthenticated and used for the app-mediated pairing flow.

### POST /mcp/pair

Submit a pairing request. Request body (JSON):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_name` | string | Yes | Human-readable client identifier |
| `agent_type` | string | No | Agent type (e.g. `cursor`, `openclaw`) |
| `agent_instance_id` | string | No | Stable instance identifier |
| `requested_endpoint` | string | No | MCP endpoint the client will connect to |
| `workspace_hint` | string | No | Workspace or project hint for context |

**Response**: JSON with `request_id` (string). Use this ID to poll the pairing status.

### GET /mcp/pair/:request_id

Poll pairing status. Returns JSON with `status` and optional `credential`:

| Status | Description |
|--------|-------------|
| `pending` | Awaiting user approval in the host app |
| `approved` | Approved; response includes `credential` (e.g. `edm_mcp_...`) |
| `rejected` | User rejected the request |
| `expired` | Request timed out or was invalidated |

---

## Table of Contents

1. [Authentication](#authentication)
2. [Pairing Endpoints](#pairing-endpoints)
3. [Advisor Tools](#advisor-tools)
4. [Observation Tools -- System Plane Telemetry](#observation-tools----system-plane-telemetry)
5. [Identity / HIBP Management Tools](#identity--hibp-management-tools)
6. [LAN Scan Configuration Tools](#lan-scan-configuration-tools)
7. [Agentic Tools -- Automated Workflow](#agentic-tools----automated-workflow)
8. [Divergence Tools -- Two-Plane Behavioral Correlation](#divergence-tools----two-plane-behavioral-correlation)
9. [Vulnerability Detection Tools](#vulnerability-detection-tools)
10. [L7 Session Enrichment Fields](#l7-session-enrichment-fields)
11. [Server Management](#server-management)

---

## Advisor Tools

### `advisor_get_todos`

Get sorted list of security todos (threats, network devices with open ports, suspicious sessions, pwned breaches). Returns prioritized list of actionable security items that need attention.

**Parameters**: None

---

### `advisor_get_action_history`

Get history of AI agent actions (last 30 days) including what was executed, the LLM's analysis/notes, risk scores, and undo availability. Session actions also include process metadata (executable path, username, grouped UIDs). Use `limit` parameter to control result count.

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | integer | 50 | Maximum number of actions to return |

---

### `advisor_undo_action`

Undo a specific AI action by its ID (rollback threat remediation, un-dismiss ports/sessions/breaches). Reverses the automated action and restores previous state. Get action IDs from `advisor_get_action_history`.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `action_id` | string | Yes | ID of the action to undo |

---

### `advisor_undo_all_actions`

Undo ALL AI actions from current session (last 30 days). Rolls back all threat remediations, un-dismisses all ports/sessions/breaches. Returns count of successful/failed rollbacks.

**Parameters**: None

---

## Observation Tools -- System Plane Telemetry

### `get_sessions`

Get all observed network sessions with full metadata: source/destination IPs, ports, domains, ASN info, L7 protocol, anomaly status, and process attribution. Each session includes deep L7 enrichment fields (see [L7 Session Enrichment Fields](#l7-session-enrichment-fields)). Use this to detect unexpected outbound traffic that diverges from declared agent intent.

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `active_only` | boolean | true | If true, return only sessions with recent activity; if false, include inactive/stale sessions |
| `limit` | integer | 200 | Maximum number of sessions to return |

---

### `get_anomalous_sessions`

Get sessions flagged as anomalous by statistical analysis (Extended Isolation Forest, 12-dimensional feature space). These are network connections that deviate from the endpoint's normal traffic patterns. High-value signal for detecting prompt injection, tool poisoning, or data exfiltration.

**Parameters**: None

---

### `get_blacklisted_sessions`

Get sessions to known-malicious destinations (threat intelligence feeds). Highest-confidence signal -- any match here is a strong indicator of compromise regardless of declared intent.

**Parameters**: None

---

### `get_exceptions`

Get sessions that violate whitelist/policy exceptions. These are connections that fall outside the expected traffic profile and may indicate unauthorized network activity.

**Parameters**: None

---

### `get_lan_devices`

Get all discovered LAN devices with IPs, MAC addresses, hostnames, open ports, CVEs, OS fingerprints, and criticality. Enables lateral-movement detection: an agent can correlate unexpected LAN traffic with vulnerable devices on the same network segment.

**Parameters**: None

---

### `get_lan_host_device`

Get this host's own device info as discovered by the LAN scanner: IP, MAC, hostname, open ports, OS fingerprint, device type, criticality, and mDNS services. Use this to know what this machine looks like on the network -- detect exposed services (e.g. gateway bound to 0.0.0.0), verify the host's own fingerprint, and establish the local identity for two-plane correlation.

**Parameters**: None

---

### `get_breaches`

Get all HIBP (HaveIBeenPwned) breach data for monitored identities. Returns breach names, dates, compromised data classes, and affected emails. Enables credential-stuffing detection: an agent can flag login activity from breached accounts as high-risk.

**Parameters**: None

---

### `get_score`

Get the full security posture score: overall score (0-100, stars 0-5), sub-scores (network, system_integrity, services, applications, credentials), active/inactive threats with severity and remediation steps, and compliance status. Provides the quantitative baseline for before/after comparison across agent actions.

**Parameters**: None

---

## Identity / HIBP Management Tools

### `add_pwned_email`

Add an email address to HIBP (HaveIBeenPwned) breach monitoring. The email will be checked against the HIBP database and continuously monitored for new breaches. Returns true if successfully added. Use this to dynamically register identities for breach monitoring -- for example, registering the operator's email during an introspection loop.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `email` | string | Yes | Email address to add to breach monitoring |

**Returns**: JSON with `success` (boolean), `email` (string), and `message` (string).

---

### `remove_pwned_email`

Remove an email address from HIBP breach monitoring. Returns true if successfully removed.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `email` | string | Yes | Email address to remove from breach monitoring |

**Returns**: JSON with `success` (boolean), `email` (string), and `message` (string).

---

### `get_pwned_emails`

Get the list of all emails currently monitored for HIBP breaches, with per-email summary: which are auto-detected vs manually added, breach counts per email, and overall pwned status. Use this to check what identities are being watched before adding new ones.

**Parameters**: None

---

## LAN Scan Configuration Tools

### `set_lan_auto_scan`

Enable or disable continuous LAN auto-scanning. When enabled, EDAMAME periodically scans the local network for devices, open ports, and CVEs -- feeding discovered infrastructure into the security context (`advisor_get_todos`) and enabling lateral-movement detection. Should be enabled for comprehensive security monitoring.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `enabled` | boolean | Yes | Enable or disable auto-scanning |

---

## Agentic Tools -- Automated Workflow

### `agentic_process_todos`

Process all security todos with AI-powered intelligent triage. LLM analyzes each todo (threats, network issues, breaches) and makes binary decision: `auto_resolve` (safe to fix) or `escalate` (needs review with priority level). Confirmation level: `auto` executes safe items immediately, `manual` records all as pending for user confirmation. Returns categorized results: auto_resolved, requires_confirmation, escalated (with priority), failed. All actions are reversible via undo.

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `confirmation_level` | string | "manual" | `"auto"` to execute safe items immediately, `"manual"` to queue for approval |

---

### `agentic_execute_action`

Execute a pending action that requires user confirmation. Takes an `action_id` from history (where `result_status` is `requires confirmation` or `escalated`). Performs the actual remediation/dismissal and records success/failure.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `action_id` | string | Yes | ID of the pending action to execute |

---

### `agentic_get_workflow_status`

Get real-time status of current AI processing workflow. Returns detailed progress including: current phase (Starting/FetchingAnalysis/Analyzing/Decided/Executing/Completed), which todo is being processed (index/total), advice type, and current counts (auto_resolved/escalated/failed). Use to monitor progress when `agentic_process_todos` is running.

**Parameters**: None

---

## Divergence Tools -- Two-Plane Behavioral Correlation

### `upsert_behavioral_model`

Push a reasoning-plane behavioral model for two-plane correlation. The divergence engine compares this declared model against live system-plane telemetry (sessions, processes, file access) to detect behavioral drift. Models use the v3 schema with expected and negative dimensions.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `window_json` | string | Yes | JSON behavioral model (v3 schema) |

**V3 Schema Dimensions**:
- Expected: `expected_traffic`, `expected_sensitive_files`, `expected_lan_devices`, `expected_local_open_ports`, `expected_process_paths`, `expected_parent_paths`, `expected_grandparent_paths`, `expected_open_files`, `expected_l7_protocols`, `expected_system_config`
- Negative: `not_expected_traffic`, `not_expected_sensitive_files`, `not_expected_lan_devices`, `not_expected_local_open_ports`, `not_expected_process_paths`, `not_expected_parent_paths`, `not_expected_grandparent_paths`, `not_expected_open_files`, `not_expected_l7_protocols`, `not_expected_system_config`

**Scope filters** (per-prediction, restrict which sessions are in scope):
- `scope_process_paths` -- match session's own `process_path` or `cmd[0]`
- `scope_parent_paths` -- match parent's `parent_process_path`, `parent_script_path`, or `parent_cmd[0]`
- `scope_grandparent_paths` -- match grandparent's `grandparent_process_path`, `grandparent_script_path`, or `grandparent_cmd[0]`
- `scope_any_lineage_paths` -- match any of process, parent, or grandparent

Rules use glob-style wildcards (`*` matches any substring). A session matches if any populated scope level matches.

**Expected traffic syntax** (`expected_traffic` array):
- **Domain-suffix**: `host:port` (e.g. `amazonaws.com:443`) -- matches destinations whose host ends with the domain (e.g. `ec2-xxx.compute-1.amazonaws.com:443`). No glob expansion.
- **ASN-based**: `asn:OWNER_SUBSTRING` (e.g. `asn:CLOUDFLARENET`) -- matches destinations whose ASN owner (from IP-to-ASN DB) contains the substring (case-insensitive). Use for CDN providers (Cloudflare, Akamai) whose IPs lack predictable domain suffixes.

Common ASN patterns: `asn:CLOUDFLARENET`, `asn:AMAZON`, `asn:AKAMAI`, `asn:FASTLY`, `asn:GOOGLE`, `asn:MICROSOFT`, `asn:NOTION`.

---

### `upsert_behavioral_model_from_raw_sessions`

Push raw reasoning-plane sessions and let EDAMAME use its configured internal LLM provider to generate and upsert the behavioral model slice. Used by thin transcript bridges (e.g. Cursor extrapolator) that forward session metadata without running their own LLM.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `raw_sessions_json` | string | Yes | JSON-encoded `RawReasoningSessionPayload` with `agent_type`, `agent_instance_id`, `window_start`, `window_end`, and `sessions` array |

**Payload schema**: Each session in `sessions` must have `session_key`, `started_at`, `modified_at` (RFC 3339), optional `messages`, `derived_expected_traffic`, `tools_called`. The internal LLM produces `SessionPrediction` entries with scope filters and `expected_traffic` (including ASN patterns when appropriate).

---

### `get_behavioral_model`

Read the currently stored behavioral model. Returns the most recently upserted model or empty if none has been published. Useful for verifying model state before triggering divergence analysis.

**Parameters**: None

---

### `get_divergence_verdict`

Get the latest divergence verdict from the internal divergence engine. Verdict classes: `CLEAN` (model matches telemetry), `DIVERGENCE` (behavioral drift detected), `NO_MODEL` (no model published yet), `STALE` (model age exceeds freshness threshold).

**Parameters**: None

---

### `get_divergence_history`

Get rolling history of divergence verdicts. Returns time-ordered verdict entries for trend analysis and audit.

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | integer | 10 | Maximum number of history entries to return |

---

### `get_divergence_engine_status`

Get the divergence engine runtime status: whether it is running, the configured analysis interval, last analysis timestamp, and model/verdict summary.

**Parameters**: None

### `dismiss_divergence_evidence`

Dismiss a divergence evidence group by its stable `finding_key`. Acknowledges a known-benign behavioral mismatch without deleting the evidence. Reversible via `undismiss_divergence_evidence`.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `finding_key` | string | Yes | Stable key from the evidence (e.g. `divergence:ec61e11fae833735d8f6c84659f4127ab1956ab297f705a6da691c4e898f8653`) |

### `undismiss_divergence_evidence`

Restore a previously dismissed divergence evidence group by its stable `finding_key`.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `finding_key` | string | Yes | Stable key of the dismissed evidence |

### `clear_divergence_state`

Clear the current behavioral model, divergence verdict history, and divergence-engine runtime state. Use in tests or controlled resets before pushing a new model window. **SIDE EFFECTS.**

**Parameters**: None

> Note: divergence lifecycle control (`start_divergence_engine`) is a direct RPC/CLI control plane method and is intentionally **not** exposed via MCP tools.

---

## Vulnerability Detection Tools

Model-independent heuristic checks (CVE-aligned). Run on their own cadence, independent of the behavioral divergence engine. Five checks:

1. **token_exfiltration** (HIGH) -- anomalous session + sensitive credential files open
2. **skill_supply_chain** (HIGH) -- blacklisted IP session + sensitive credential files open
3. **credential_harvest** (CRITICAL) -- any session with sensitive files spanning >= N distinct label categories (default 3; configurable via `credential_harvest_min_labels` in `cve-detection-params-db.json`)
4. **sandbox_exploitation** (HIGH) -- suspicious parent process lineage (e.g. `/tmp/`)
5. **gateway_binding** -- exposed listeners on the host

### `get_vulnerability_findings`

Get the latest vulnerability findings from model-independent heuristic checks. Returns timestamped report with `findings` array; each finding has `check`, `severity` (CRITICAL/HIGH/MEDIUM), `description`, `reference` (CVE IDs or incident ref), `process_name`, `parent_process_name`, `destination_ip`, `open_files`, and `finding_key`.

**Parameters**: None

### `get_vulnerability_detector_status`

Get the current status of the vulnerability detector: enabled state, evaluation interval, last run timestamp, and latest finding count.

**Parameters**: None

### `dismiss_vulnerability_finding`

Dismiss a vulnerability finding by its stable `finding_key`. Use when a CVE-aligned heuristic finding is known/accepted.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `finding_key` | string | Yes | Stable key from the finding (e.g. `vuln:4ba5528a37997db4f405710cb1a90cc1c5605adac8beffb390c7e7ef572ab325`) |

### `undismiss_vulnerability_finding`

Restore a previously dismissed vulnerability finding by its stable `finding_key`.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `finding_key` | string | Yes | Stable key of the dismissed finding |

---

## L7 Session Enrichment Fields

Every network session returned by `get_sessions`, `get_anomalous_sessions`, `get_blacklisted_sessions`, and `get_exceptions` includes deep Layer 7 process attribution. These fields enable detection of process masquerading, script-based attacks, and unauthorized file access.

### Process Fields

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | Process ID of the network session |
| `process_name` | string | Name of the process (executable name) |
| `process_path` | string | Full filesystem path to the executable |
| `username` | string | Username running the process |
| `cmd` | array[string] | Command-line arguments |
| `cwd` | string (optional) | Current working directory |
| `memory` | integer | Memory usage in bytes |
| `start_time` | integer | Process start time (Unix timestamp) |
| `run_time` | integer | Process runtime duration |
| `cpu_usage` | integer | CPU usage percentage |
| `accumulated_cpu_time` | integer | Total accumulated CPU time |

### Parent Process Fields

| Field | Type | Description |
|-------|------|-------------|
| `parent_pid` | integer (optional) | Parent process ID |
| `parent_process_name` | string | Name of the parent process |
| `parent_process_path` | string | Full path to the parent process executable |
| `parent_cmd` | array[string] | Parent process command-line arguments |
| `parent_script_path` | string (optional) | Script path extracted from `parent_cmd` when the parent is an interpreter (bash, python, etc.). None when parent is a compiled binary. |

### Grandparent Process Fields

| Field | Type | Description |
|-------|------|-------------|
| `grandparent_pid` | integer (optional) | Grandparent process ID |
| `grandparent_process_name` | string | Name of the grandparent process |
| `grandparent_process_path` | string | Full path to the grandparent process executable |
| `grandparent_cmd` | array[string] | Grandparent process command-line arguments |
| `grandparent_script_path` | string (optional) | Script path extracted from `grandparent_cmd` when the grandparent is an interpreter. None when grandparent is a compiled binary. |

### Security-Relevant Fields

| Field | Type | Description |
|-------|------|-------------|
| `spawned_from_tmp` | boolean | True when the process or its parent originates from a writable temporary directory (`/tmp/`, `/var/tmp/`, `/dev/shm/`) |
| `open_files` | array[string] | Open file descriptor paths. Sensitive files (SSH keys, credentials, keychains) are preserved individually and survive aggregation. List capped at 100 entries with non-sensitive paths aggregated at directory level when exceeded. |

### Disk Usage Fields

| Field | Type | Description |
|-------|------|-------------|
| `total_written_bytes` | integer | Total bytes written since process start |
| `written_bytes` | integer | Bytes written in current measurement period |
| `total_read_bytes` | integer | Total bytes read since process start |
| `read_bytes` | integer | Bytes read in current measurement period |

### Refresh Cycles

- Full L7 refresh: every 5 minutes
- Sensitive file scanning: 30s (Linux), 60s (macOS), 120s (Windows)
- Sensitive files are sticky across refresh cycles -- once detected, they remain visible

---

## Server Management

The MCP server is managed via API methods (also available as CLI commands via `edamame-posture`):

| API Method | CLI Command | Description |
|------------|-------------|-------------|
| `mcp_start_server(port, psk, enable_cors, listen_all_interfaces)` | `edamame-posture mcp-start [--port PORT] [--all-interfaces] [--enable-cors]` | Start MCP server |
| `mcp_stop_server()` | `edamame-posture mcp-stop` | Stop MCP server |
| `mcp_get_server_status()` | `edamame-posture mcp-status` | Check server status |
| `mcpApprovePairing(request_id)` | (host app only) | Approve a pending pairing request |
| `mcpRejectPairing(request_id)` | (host app only) | Reject a pending pairing request |
| `mcpListPairedClients()` | (host app only) | List all paired clients (JSON array) |
| `mcpGetPendingPairingRequests()` | (host app only) | List pending pairing requests (JSON array) |
| `mcpRevokePairedClient(client_id)` | (host app only) | Revoke a paired client |
| `mcpRotatePairedClient(client_id)` | (host app only) | Rotate a client's credential |

PSK generation: `edamame-posture mcp-generate-psk`

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| Port | 3000 | Server listen port |
| Bind address | 127.0.0.1 | Use `listen_all_interfaces` for 0.0.0.0 |
| CORS | Disabled | Enable for browser-based clients |
| HTTPS | Disabled | Available for production deployments |

### Quick Start

```bash
# Generate PSK
edamame-posture mcp-generate-psk

# Start server
sudo -E edamame-posture mcp-start --port 3000

# Test with MCP Inspector
npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:3000/mcp --transport http
```

### Claude Desktop Configuration

Use a per-client credential (from pairing) or shared PSK:

```json
{
  "mcpServers": {
    "edamame": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:3000/mcp",
        "--header",
        "Authorization: Bearer <YOUR_CREDENTIAL>"
      ]
    }
  }
}
```

`<YOUR_CREDENTIAL>` is either an `edm_mcp_...` token from pairing or a shared PSK.

---

## Tool Summary

| # | Tool | Category | Description |
|---|------|----------|-------------|
| 1 | `advisor_get_todos` | Advisor | Security todos list |
| 2 | `advisor_get_action_history` | Advisor | AI action audit trail |
| 3 | `advisor_undo_action` | Advisor | Rollback specific action |
| 4 | `advisor_undo_all_actions` | Advisor | Rollback all actions |
| 5 | `get_sessions` | Observation | All sessions with L7 enrichment |
| 6 | `get_anomalous_sessions` | Observation | ML-flagged anomalous sessions |
| 7 | `get_blacklisted_sessions` | Observation | Sessions to known-bad destinations |
| 8 | `get_exceptions` | Observation | Whitelist/policy violations |
| 9 | `get_lan_devices` | Observation | LAN device inventory |
| 10 | `get_lan_host_device` | Observation | This host's LAN identity |
| 11 | `get_breaches` | Observation | HIBP breach data |
| 12 | `get_score` | Observation | Full posture score |
| 13 | `add_pwned_email` | Identity | Add email to breach monitoring |
| 14 | `remove_pwned_email` | Identity | Remove email from monitoring |
| 15 | `get_pwned_emails` | Identity | List monitored emails |
| 16 | `set_lan_auto_scan` | LAN Config | Toggle continuous scanning |
| 17 | `agentic_process_todos` | Agentic | AI-powered todo processing |
| 18 | `agentic_execute_action` | Agentic | Execute pending action |
| 19 | `agentic_get_workflow_status` | Agentic | Workflow progress |
| 20 | `upsert_behavioral_model` | Divergence | Push reasoning-plane behavioral model |
| 21 | `get_behavioral_model` | Divergence | Read stored behavioral model |
| 22 | `get_divergence_verdict` | Divergence | Get latest divergence verdict |
| 23 | `get_divergence_history` | Divergence | Rolling divergence verdict history |
| 24 | `get_divergence_engine_status` | Divergence | Divergence engine status |
