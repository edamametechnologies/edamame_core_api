# EDAMAME Core MCP Tools Reference

Complete reference for all MCP (Model Context Protocol) tools exposed by EDAMAME Core. These tools are available to external AI assistants (Claude Desktop, n8n, custom agents) via the MCP server.

**Server**: Streamable HTTP transport via [rmcp](https://github.com/nicholaskell/rmcp) SDK v0.8
**Protocol**: MCP 2024-11-05
**Default endpoint**: `http://127.0.0.1:3000/mcp`
**Authentication**: Dual-mode (per-client credentials or shared PSK) via `Authorization: Bearer <token>` header

---

## Observer-Independence Policy (Important)

EDAMAME implements a two-plane runtime monitoring architecture:

- **Reasoning plane**: the LLM agent (Claude Desktop, Cursor, OpenClaw, etc.) declaring intent.
- **System plane**: EDAMAME observing actual system behavior and producing security findings (vulnerability detector, divergence engine).

For this architecture to be meaningful, the **observed** (the LLM agent) must not be able to silence findings about its **own** behavior. Otherwise an attacker who has compromised the agent could trivially dismiss the very findings that would catch them.

The MCP tool surface therefore enforces a strict read-only contract for security findings and dismissal state:

| Concern | MCP exposure | Operator surface |
|---|---|---|
| Read divergence verdicts / history / engine status | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Read vulnerability findings / history / detector status | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Read active dismissal rules + audit log | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Dismiss a vulnerability finding | **NO** | EDAMAME app (AI tab > Radar > Dismiss), edamame_cli RPC |
| Undismiss a vulnerability finding | **NO** | EDAMAME app, edamame_cli RPC |
| Dismiss a divergence evidence group | **NO** | EDAMAME app (AI tab > Brain Scan > Dismiss), edamame_cli RPC |
| Undismiss a divergence evidence group | **NO** | EDAMAME app, edamame_cli RPC |
| Dismiss with scope (recurrence-aware rules) | **NO** | EDAMAME app (Dismiss with scope... dialog), edamame_cli RPC |
| Remove / promote / demote a dismissal rule | **NO** | EDAMAME app (Dismissal rules section), edamame_cli RPC |
| Reset all dismissal rules | **NO** | EDAMAME app, edamame_cli RPC |
| Clear divergence state (model + verdicts + engine state) | **NO** | edamame_cli RPC, integration tests only |
| Clear vulnerability history | **NO** | edamame_cli RPC, integration tests only |
| Reset vulnerability suppressions | **NO** | edamame_cli RPC, integration tests only |
| Clear dismissal audit log | **NO** | EDAMAME app, edamame_cli RPC |

The corresponding **RPC** endpoints (`agentic_dismiss_with_scope`, `dismiss_vulnerability_finding`, `clear_divergence_state`, ...) remain available -- only their MCP tool exposure has been removed. RPC is the operator-facing control plane (EDAMAME app, `edamame_cli`); MCP is the LLM-facing observation plane.

CI integration tests that need to clear vulnerability/divergence state between scenarios call the RPC layer directly (`edamame_cli rpc clear_vulnerability_history`, `edamame_cli rpc clear_divergence_state`, etc.) -- these never went through the MCP tool path.

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

1. [Observer-Independence Policy](#observer-independence-policy-important)
2. [Authentication](#authentication)
3. [Pairing Endpoints](#pairing-endpoints)
4. [Advisor Tools](#advisor-tools)
5. [Observation Tools -- System Plane Telemetry](#observation-tools----system-plane-telemetry)
6. [Identity / HIBP Management Tools](#identity--hibp-management-tools)
7. [LAN Scan Configuration Tools](#lan-scan-configuration-tools)
8. [Agentic Tools -- Automated Workflow](#agentic-tools----automated-workflow)
9. [Divergence Tools -- Two-Plane Behavioral Correlation](#divergence-tools----two-plane-behavioral-correlation)
10. [Vulnerability Detection Tools](#vulnerability-detection-tools)
11. [Recurrence-Aware Dismissal Rules (read-only)](#recurrence-aware-dismissal-rules-read-only)
12. [L7 Session Enrichment Fields](#l7-session-enrichment-fields)
13. [Server Management](#server-management)

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

> **Observer-independence**: Mutation operations on divergence findings (`dismiss_divergence_evidence`, `undismiss_divergence_evidence`, `dismiss_divergence_evidence_with_scope`, `clear_divergence_state`) are intentionally **not** exposed via MCP. The reasoning plane must not be able to silence findings about its own behavior. Use the EDAMAME app (AI tab > Brain Scan) or `edamame_cli rpc` for these operations.
>
> Lifecycle controls (`start_divergence_engine`, `start_vulnerability_detector`, `agentic_set_auto_processing`, `start_file_monitor`, `stop_file_monitor`) are direct RPC/CLI control plane methods and are intentionally **not** exposed via MCP tools either.

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

### `get_vulnerability_history`

Get historical vulnerability reports (summaries, most recent first). Each entry is a timestamped snapshot containing the active findings, severities, and stable finding keys at that tick. Useful for tracking how vulnerability posture evolves over time.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `limit` | integer | Yes | Maximum number of past reports to return (most recent first) |

> **Observer-independence**: Mutation operations on vulnerability findings (`dismiss_vulnerability_finding`, `undismiss_vulnerability_finding`, `dismiss_vulnerability_finding_with_scope`, `clear_vulnerability_history`, `reset_vulnerability_suppressions`) are intentionally **not** exposed via MCP. The reasoning plane must not be able to silence vulnerability findings about its own behavior. Use the EDAMAME app (AI tab > Radar > Dismiss) or `edamame_cli rpc` for these operations.
>
> The vulnerability detector itself is model-independent and does not require an LLM provider. Findings will still surface (and gate consumers like `edamame_posture vulnerability-status --fail-on-findings`) without an LLM. For CI/security and chat workflows, configuring an LLM via `agentic_set_llm_config` is strongly recommended -- EDAMAME can then adjudicate findings, suppress likely false positives, and produce clearer alert text.

---

## Recurrence-Aware Dismissal Rules (read-only)

EDAMAME supports recurrence-aware dismissal rules that suppress entire classes of findings (for example "all `process_for_check` findings for `node` running `cursor-stable`" or "all `agent_workspace_pattern` divergence findings for one Cursor workspace"). See [edamame_core/AGENTICIMPROVEMENTS.md](https://github.com/edamametechnologies/edamame_core/blob/main/AGENTICIMPROVEMENTS.md) for the full rule model.

The MCP surface exposes these rules as **read-only**: the LLM can see what is being suppressed (and feed that into reasoning prompts) but cannot create, modify, or remove rules. Operators manage rules through the EDAMAME app's `AI > Dismissal rules` section or the `edamame_cli` RPC surface.

### `list_agentic_dismissal_rules`

READ-ONLY. List active recurrence-aware dismissal rules. Each rule entry includes:

- `id` -- stable rule identifier
- `domain` -- `vulnerability` or `divergence`
- `scope` -- `finding`, `process_for_check`, `process_lineage`, `process_and_material_class`, or `agent_workspace_pattern`
- `matcher` -- the structured matcher (process name/path, parent lineage, agent identity, material classes, etc.)
- `source` -- `operator` (created via UI/CLI) or `legacy_migration` (imported from a v1 dismissal)
- `severity_ceiling` -- `high_and_below` (default) or `critical_capable`
- `created_at`, `expires_at` -- lifecycle timestamps
- `hit_count`, `last_hit_at` -- telemetry showing how often the rule has fired

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `domain` | string | `""` | `""` for all, `"vulnerability"`, or `"divergence"` |

### `list_agentic_dismissal_audit_log`

READ-ONLY. List the recurrence-aware dismissal audit log. Each entry records when a rule was:

- created
- removed
- expired
- had its `severity_ceiling` changed
- imported from a legacy v1 dismissal

Useful for incident review and explaining "why didn't I see this finding?".

**Parameters**:

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `limit` | integer | 50 | Maximum number of entries to return; `0` returns all entries |

> **Observer-independence**: The corresponding mutation tools (`dismiss_vulnerability_finding_with_scope`, `dismiss_divergence_evidence_with_scope`, `remove_agentic_dismissal_rule`, `set_agentic_dismissal_rule_severity_ceiling`, `reset_agentic_dismissal_rules`, `clear_agentic_dismissal_audit_log`) are intentionally **not** exposed via MCP. Operators mutate dismissal state via the EDAMAME app or `edamame_cli rpc`.

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
| `mcp_approve_pairing(request_id)` (Flutter bridge: `mcpApprovePairing`) | (host app only) | Approve a pending pairing request |
| `mcp_reject_pairing(request_id)` (Flutter bridge: `mcpRejectPairing`) | (host app only) | Reject a pending pairing request |
| `mcp_list_paired_clients()` (Flutter bridge: `mcpListPairedClients`) | (host app only) | List all paired clients (JSON array) |
| `mcp_get_pending_pairing_requests()` (Flutter bridge: `mcpGetPendingPairingRequests`) | (host app only) | List pending pairing requests (JSON array) |
| `mcp_revoke_paired_client(client_id)` (Flutter bridge: `mcpRevokePairedClient`) | (host app only) | Revoke a paired client |
| `mcp_rotate_paired_client(client_id)` (Flutter bridge: `mcpRotatePairedClient`) | (host app only) | Rotate a client's credential |

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
| 21 | `upsert_behavioral_model_from_raw_sessions` | Divergence | Build + push model directly from raw session JSON |
| 22 | `get_behavioral_model` | Divergence | Read stored behavioral model |
| 23 | `get_divergence_verdict` | Divergence | Get latest divergence verdict |
| 24 | `get_divergence_history` | Divergence | Rolling divergence verdict history |
| 25 | `get_divergence_engine_status` | Divergence | Divergence engine status |
| 26 | `get_vulnerability_findings` | Vulnerability | Active findings (read-only) |
| 27 | `get_vulnerability_detector_status` | Vulnerability | Detector running state and counts |
| 28 | `get_vulnerability_history` | Vulnerability | Rolling history of detector reports |
| 29 | `list_agentic_dismissal_rules` | Dismissal Rules | Read-only list of recurrence-aware dismissal rules |
| 30 | `list_agentic_dismissal_audit_log` | Dismissal Rules | Read-only dismissal audit log |
| 31 | `get_file_events` | FIM | Recent FIM events snapshot |
| 32 | `get_file_monitor_status` | FIM | FIM watcher running state and roots |
| 33 | `get_file_event_summary` | FIM | Aggregated FIM event summary |
