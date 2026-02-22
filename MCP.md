# EDAMAME Core MCP Tools Reference

Complete reference for all MCP (Model Context Protocol) tools exposed by EDAMAME Core. These tools are available to external AI assistants (Claude Desktop, n8n, custom agents) via the MCP server.

**Server**: Streamable HTTP transport via [rmcp](https://github.com/nicholaskell/rmcp) SDK v0.8
**Protocol**: MCP 2024-11-05
**Default endpoint**: `http://127.0.0.1:3000/mcp`
**Authentication**: PSK (Pre-Shared Key) via `Authorization: Bearer <psk>` header

---

## Table of Contents

1. [Advisor Tools](#advisor-tools)
2. [Observation Tools -- System Plane Telemetry](#observation-tools----system-plane-telemetry)
3. [Identity / HIBP Management Tools](#identity--hibp-management-tools)
4. [LAN Scan Configuration Tools](#lan-scan-configuration-tools)
5. [Agentic Tools -- Automated Workflow](#agentic-tools----automated-workflow)
6. [L7 Session Enrichment Fields](#l7-session-enrichment-fields)
7. [Server Management](#server-management)

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

**Parameters**: None

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

The MCP server is managed via three API methods (also available as CLI commands via `edamame-posture`):

| API Method | CLI Command | Description |
|------------|-------------|-------------|
| `mcp_start_server(port, psk, enable_cors, listen_all_interfaces)` | `edamame-posture mcp-start [--port PORT] [--all-interfaces] [--enable-cors]` | Start MCP server |
| `mcp_stop_server()` | `edamame-posture mcp-stop` | Stop MCP server |
| `mcp_get_server_status()` | `edamame-posture mcp-status` | Check server status |

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

```json
{
  "mcpServers": {
    "edamame": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://127.0.0.1:3000/mcp",
        "--header",
        "Authorization: Bearer <YOUR_PSK>"
      ]
    }
  }
}
```

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
