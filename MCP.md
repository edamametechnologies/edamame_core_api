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
- **System plane**: EDAMAME observing actual system behavior and producing security findings (attack pattern detector, divergence engine).

For this architecture to be meaningful, the **observed** (the LLM agent) must not be able to silence findings about its **own** behavior. Otherwise an attacker who has compromised the agent could trivially dismiss the very findings that would catch them.

The MCP tool surface therefore enforces a strict read-only contract for security findings and dismissal state:

| Concern | MCP exposure | Operator surface |
|---|---|---|
| Read divergence verdicts / history / engine status | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Read vulnerability findings / history / detector status | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Read active dismissal rules + audit log | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Read agent visibility (MCP inventory, SBOM + drift, capability graph + reachability, recursion, flight recorder, drift timelines, data-flow / memory / A2A maps, alignment rollup, firewall status/receipts, response catalog/history, policy pack/evaluation/attestations, zone promotions, agent inventory) | YES (read-only) | EDAMAME app, edamame_cli RPC |
| Refresh any visibility domain / set capture tier | **NO** | EDAMAME app (Agents tab), edamame_cli RPC |
| Approve / revoke an agent, promote an SBOM baseline | **NO** | EDAMAME app (Agents tab), edamame_cli RPC |
| Set tool-call firewall mode (recommend/confirm/block) | **NO** | EDAMAME app, edamame_cli RPC |
| Request / undo a response action, export a case bundle | **NO** | EDAMAME app, edamame_cli RPC |
| Set policy pack / attest evaluation or SBOM | **NO** | EDAMAME app, edamame_cli RPC |
| Request / decide a cross-zone promotion | **NO** | EDAMAME app, edamame_cli RPC |
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
10. [Attack Pattern Detection Tools](#attack-pattern-detection-tools)
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

## Attack Pattern Detection Tools

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

Get the current status of the attack pattern detector: enabled state, evaluation interval, last run timestamp, and latest finding count.

**Parameters**: None

### `get_vulnerability_history`

Get historical vulnerability reports (summaries, most recent first). Each entry is a timestamped snapshot containing the active findings, severities, and stable finding keys at that tick. Useful for tracking how vulnerability posture evolves over time.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `limit` | integer | Yes | Maximum number of past reports to return (most recent first) |

> **Observer-independence**: Mutation operations on vulnerability findings (`dismiss_vulnerability_finding`, `undismiss_vulnerability_finding`, `dismiss_vulnerability_finding_with_scope`, `clear_vulnerability_history`, `reset_vulnerability_suppressions`) are intentionally **not** exposed via MCP. The reasoning plane must not be able to silence vulnerability findings about its own behavior. Use the EDAMAME app (AI tab > Radar > Dismiss) or `edamame_cli rpc` for these operations.
>
> The attack pattern detector itself is model-independent and does not require an LLM provider. Findings will still surface (and gate consumers like `edamame_posture vulnerability-status --fail-on-findings`) without an LLM. For CI/security and chat workflows, configuring an LLM via `agentic_set_llm_config` is strongly recommended -- EDAMAME can then adjudicate findings, suppress likely false positives, and produce clearer alert text.

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

## Agent Visibility Tools

Read-only structural visibility into the agents running on this host, spanning the full staged roadmap (Stage A discovery through Stage D+ governance): the MCP attack surface, per-agent software bill-of-materials, the capability graph and trust-zone reachability, recursion/delegation risk, the hash-chained run flight recorder, goal/delegation drift timelines, sensitive data-flow / memory / agent-to-agent maps, the composite alignment rollup, the tool-call firewall status and receipts, the ADR response-action catalog and history, and the enterprise policy pack / evaluation / attestations / cross-zone promotion log. Each tool lazily ensures a fresh snapshot before returning. All output is **metadata-only** -- it never includes secret values, credential bodies, or transcript content (only structural markers and goal hashes are derived). Requires the `agentic` feature flag.

These tools share their names and behavior with the corresponding RPC methods documented in [API_REFERENCE.md](API_REFERENCE.md#agent-visibility); the MCP exposure is read-only by design (observer-independence I1). Every mutator -- `refresh_*`, `set_visibility_capture_tier`, `set_firewall_mode`, `approve_agent` / `revoke_agent_approval` / `approve_agent_sbom_baseline`, `request_response_action` / `undo_response_action` / `export_visibility_case`, `set_policy_pack`, `attest_policy_evaluation` / `attest_agent_sbom`, `request_zone_promotion` / `decide_zone_promotion` -- plus the typed UI reads (`get_visibility_summary`, `get_visibility_capture_tier`, `get_visibility_roadmap`) are operator/UI control-plane only and are intentionally **not** exposed as MCP tools. An observed agent can read every structural finding about itself but cannot weaken, silence, or self-approve the controls that watch it.

### `get_mcp_inventory`

READ-ONLY. Discover every MCP server configured for any supported agent on this host (the host's MCP attack surface). Returns the inventory: each endpoint has `transport` (stdio/http/sse/ws), `exposure_scope`, `auth_strength`, `tool_privilege_classes`, plus deterministic risk findings (e.g. a public endpoint with no auth). Metadata-only -- never includes secret values or file bodies.

**Parameters**: None

### `get_mcp_findings`

READ-ONLY. List just the deterministic MCP risk findings (no endpoint inventory). Each finding has a stable `finding_key`, `domain` = `mcp`, `rule_id`, `severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL), `title`, `description`, `subject_id`, and metadata-only evidence. HIGH/CRITICAL findings are alertable.

**Parameters**: None

### `get_agent_sboms`

READ-ONLY. Get the agent software bill-of-materials (SBOM) for every discovered agent: components (the agent app, each MCP server it connects to, tool classes, models) and their dependency edges. CycloneDX-shaped projection derived from live discovery. Metadata-only.

**Parameters**: None

### `get_agent_sbom_cyclonedx`

READ-ONLY. Export one agent's SBOM as standard CycloneDX JSON (for ingestion by external SBOM/SCA tooling). Returns `{}` when no SBOM exists for that agent.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `agent_type` | string | Yes | Agent type to export (e.g. `cursor`, `claude_code`, `openclaw`) |

### `get_capability_graph`

READ-ONLY. Get the agent capability graph: edges between agents, MCP servers, tool classes, network endpoints, files, and models. Each edge has `src`/`dst` type+id, `edge_type` (`declares`/`exposes`/`connects_to`/...), and `confidence` (`declared` = config-only latent capability, `observed` = corroborated by live telemetry). Reveals the effective vs latent capability surface.

**Parameters**: None

### `get_recursion_risk`

READ-ONLY. Get per-agent recursion/delegation analysis derived from agent transcripts: a delegation tree per agent with `max_depth`, `total_nodes`, `loop_detected` (a repeated goal recurring at increasing depth), and findings. Surfaces runaway recursive-spawn / delegation-loop risk. Metadata-only -- only structural spawn markers and goal hashes are derived, never transcript bodies.

**Parameters**: None

### `get_agent_inventory`

READ-ONLY. Operator inventory of every supported agent with any footprint on this host. Each entry has `agent_type`, `display_name`, a `classification` (`approved`/`shadow`/`unmanaged`/`unknown`), the installed/discovered/observer_enabled/approved booleans, and per-agent `mcp_endpoint_count`, `sbom_component_count`, `alertable_finding_count`. The reasoning plane can read its own classification but cannot change the operator allow-list. Metadata-only.

**Parameters**: None

### `get_graph_reachability`

READ-ONLY. Per-agent trust-zone reachability over the declared capability graph. Trust zones: `trust0` (agent identity), `trust1` (local service boundary -- stdio/loopback MCP servers, tool classes), `trust2` (untrusted surface -- LAN/public/unknown). Each entry has `agent_type`, `reachable_node_count`, `max_zone`, `crosses_to_untrusted`, and `boundary_edge_ids`. Surfaces which agents can pivot from their identity out to an untrusted network surface.

**Parameters**: None

### `get_effective_capabilities`

READ-ONLY. Per-agent effective (transitively reachable) capabilities over the declared capability graph. Each entry has `agent_type`, the deduped `capabilities` set (human-readable labels e.g. `Shell`, `Git`), `high_privilege` (a filesystem/shell/network-class capability is reachable), and `reaches_untrusted` (a trust2 node is reachable). Reveals the real capability surface beyond directly-declared tools.

**Parameters**: None

### `list_recent_runs`

READ-ONLY. List the recorded reasoning runs (the flight-recorder index). Each summary has `run_id` (`agent_type::agent_instance_id::session_key`), timestamps, event/alertable counts, max severity, and a chain-valid flag. Pass a `run_id` to `get_run_provenance` for the full record.

**Parameters**: None

### `get_run_provenance`

READ-ONLY. Get the full flight record for one run: the ordered, replayable, hash-chained event stream (`session_start` -> `tool_call`/`command`/`expected_egress` -> `divergence_verdict` -> `divergence_evidence` -> `session_end`), each event carrying plane/kind/summary/severity and `prev_hash`/`hash` chain links, plus the causal edges and `max_severity`/`alertable_event_count`/`chain_valid`. Returns `{}` when the run is unknown. Metadata-only.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `run_id` | string | Yes | Run id from `list_recent_runs` |

### `explain_run_event`

READ-ONLY. Prove why a single recorded event happened: returns the causal backtrace (chronological ancestor chain walked transitively into the target), the downstream descendants, the edges traversed, `backtrace_complete`, and `chain_valid`. This is the recorder's prove-why for any divergence evidence or declared action. Metadata-only.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `run_id` | string | Yes | Run id from `list_recent_runs` |
| `event_id` | string | Yes | Event id within the run (from `get_run_provenance`) |

### `get_agent_drift`

READ-ONLY. List per-agent goal/delegation drift timelines, highest peak drift first. Each agent (keyed `agent_key` = `agent_type::agent_instance_id`) carries its ordered drift events (category, point-in-time `drift_score` 0-100, severity, backing divergence finding keys), `peak_drift_score`, `current_drift_score`, and whether it is currently diverging. Drift is a deterministic re-projection of divergence history -- not a new judgement. Metadata-only.

**Parameters**: None

### `get_agent_drift_timeline`

READ-ONLY. Get one agent's full drift timeline: the ordered drift events with per-event `drift_score`/severity/category, backing divergence finding keys and process paths, plus peak/current scores and the delegation summary. Returns `{}` when the agent is unknown. Metadata-only.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `agent_key` | string | Yes | Agent key from `get_agent_drift` |

### `explain_agent_drift`

READ-ONLY. Prove why a single drift event fired: returns the category and score band, the contributing divergence findings, the prior verdict state it moved from, and a human-readable rationale of which signals drove the score. Metadata-only.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `agent_key` | string | Yes | Agent key from `get_agent_drift` |
| `event_id` | string | Yes | Drift event id (from `get_agent_drift_timeline`) |

### `get_dataflow_maps`

READ-ONLY. Per-agent latent `source -> sink` data-flow maps (credential store, file, network egress, ...), each edge marked `latent` (config-derived) or `observed` (corroborated by divergence taint evidence), with a severity for sensitive-sink reach. Metadata-only.

**Parameters**: None

### `get_dataflow_map`

READ-ONLY. One agent's data-flow map. Returns `{}` when no map exists for that agent.

**Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `agent_type` | string | Yes | Agent type (e.g. `cursor`) |

### `get_memory_inventory`

READ-ONLY. The memory/RAG inventory: discovered persistent context stores (vector DBs, memory files, RAG corpora) each agent can read/write, with scope and a poisoning-risk severity. Metadata-only.

**Parameters**: None

### `get_alignment_rollup`

READ-ONLY. The composite alignment rollup: the 0-100 `score`, the `band` (`aligned`/`drifting`/`misaligned`/`critical`), `hard_fail` (a catastrophic domain forces failure regardless of score), and the per-domain contribution breakdown. The single headline "how aligned are the agents on this host" number.

**Parameters**: None

### `get_firewall_status`

READ-ONLY. The tool-call firewall status envelope: current `mode` (`recommend`/`confirm`/`block`), `receipt_count`, `alertable_count`, `catastrophic_count`, `pending_confirmation_count`, `chain_intact`, `first_broken_index`, and `chain_head_hash`. Reading the mode does not let the agent change it (`set_firewall_mode` is operator-only).

**Parameters**: None

### `get_firewall_evaluations`

READ-ONLY. The hash-chained tool-call firewall receipts: per evaluated tool call the verdict (`allow`/`recommend`/`confirm`/`block`), severity, catastrophic flag, triggering rule, `resolved` state, and `prev_hash`/`receipt_hash` chain links. Metadata-only.

**Parameters**: None

### `get_response_action_catalog`

READ-ONLY. The catalog of available response-action kinds: each entry carries `kind`, `description`, `reversible`, `operator_gated`, `simulate_required`, and `wired`. `wired` indicates whether the action's live side-effect primitive is implemented in this build; when false, a non-simulated request records an auditable operator-decision intent only (no live containment). Requesting an action (`request_response_action`) is operator-only.

**Parameters**: None

### `get_response_action_history`

READ-ONLY. The append-only response-action history: each requested/simulated/applied/undone action with kind, target, reason, simulated flag, timestamps, and outcome. Metadata-only.

**Parameters**: None

### `get_policy_pack`

READ-ONLY. The active enterprise policy pack: `pack_id`, `version`, and the declarative rules (each with kind, parameters, and the severity of a violation). Defaults to the built-in `EDAMAME Baseline` pack. Changing the pack (`set_policy_pack`) is operator-only.

**Parameters**: None

### `get_policy_evaluation`

READ-ONLY. The most recent policy-pack evaluation: overall `compliant` flag, `violated_rules`/`total_rules` counts, and a per-rule pass/fail result with the deterministic inputs that drove each verdict.

**Parameters**: None

### `get_policy_attestations`

READ-ONLY. The attestation log: each tamper-evident attestation with its subject (policy evaluation or agent SBOM), the SHA-256 `content_digest`, and the timestamp. Producing an attestation (`attest_policy_evaluation`/`attest_agent_sbom`) is operator-only.

**Parameters**: None

### `get_zone_promotions`

READ-ONLY. The cross-zone promotion log: each operator request to let an agent operate in a more-trusted firewall origin zone, with `promotion_id`, agent, target zone, reason, status (`requested`/`approved`/`denied`), and decision timestamp. Requesting/deciding a promotion is operator-only -- an observed agent cannot self-promote.

**Parameters**: None

### `get_agent_fleet_overview`

READ-ONLY. Fleet command-centre rollup for all observed agents: headline counts (agents discovered/paused, sessions observed / with tool errors), estimated spend for the window plus today's historized spend, the deterministic waste/friction signal, the security join (active alertable attack-pattern findings, divergence verdict), 24h hourly cost/error sparklines, and ranked panels (agents by spend, top costly sessions, top recurring failure clusters). Pure read-only projection over state the core already computes; no LLM.

**Parameters**:
- `window_minutes` (integer, optional): Look-back window; `0` uses the 24h default.

### `get_agent_failure_clusters`

READ-ONLY. Deterministic failed-intent clusters: agent tool errors grouped by stable `<tool>|<error_class>` keys (error classes: timeout / permission / not_found / rate_limit / syntax / network / cancelled / other, classified by a fixed keyword pass -- no LLM). Each cluster has count, affected agents and session count, first/last seen, and a capture-tier-gated example snippet.

**Parameters**:
- `window_minutes` (integer, optional): Look-back window; `0` uses the 24h default.
- `agent_type` (string, optional): Scope to one agent type; empty covers all supported agents.

> **Observer-independence**: The visibility control-plane mutators (every `refresh_*`, `set_visibility_capture_tier`, `set_firewall_mode`, `approve_agent`, `revoke_agent_approval`, `approve_agent_sbom_baseline`, `request_response_action`, `undo_response_action`, `export_visibility_case`, `set_policy_pack`, `attest_policy_evaluation`, `attest_agent_sbom`, `request_zone_promotion`, `decide_zone_promotion`) and the typed UI reads (`get_visibility_summary`, `get_visibility_capture_tier`, `get_visibility_roadmap`) are intentionally **not** exposed via MCP. Refresh is implicit (lazy TTL); enforcement, governance, and capture-tier are operator/UI surfaces. Use the EDAMAME app (Agents tab) or `edamame_cli rpc` for those.

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
| 34 | `get_mcp_inventory` | Visibility | Discovered MCP attack surface (read-only) |
| 35 | `get_mcp_findings` | Visibility | Deterministic MCP risk findings (read-only) |
| 36 | `get_agent_sboms` | Visibility | Per-agent software bill-of-materials (read-only) |
| 37 | `get_agent_sbom_cyclonedx` | Visibility | One agent's SBOM as CycloneDX JSON (read-only) |
| 38 | `get_capability_graph` | Visibility | Agent capability graph edges (read-only) |
| 39 | `get_recursion_risk` | Visibility | Recursion/delegation tree risk (read-only) |
| 40 | `get_agent_inventory` | Visibility | Agent inventory + shadow classification (read-only) |
| 41 | `get_graph_reachability` | Visibility | Per-agent trust-zone reachability (read-only) |
| 42 | `get_effective_capabilities` | Visibility | Per-agent transitive capabilities (read-only) |
| 43 | `list_recent_runs` | Visibility | Flight-recorder run index (read-only) |
| 44 | `get_run_provenance` | Visibility | Full hash-chained run flight record (read-only) |
| 45 | `explain_run_event` | Visibility | Causal backtrace for one run event (read-only) |
| 46 | `get_agent_drift` | Visibility | Per-agent goal/delegation drift timelines (read-only) |
| 47 | `get_agent_drift_timeline` | Visibility | One agent's full drift timeline (read-only) |
| 48 | `explain_agent_drift` | Visibility | Prove-why for one drift event (read-only) |
| 49 | `get_dataflow_maps` | Visibility | Per-agent source->sink data-flow maps (read-only) |
| 50 | `get_dataflow_map` | Visibility | One agent's data-flow map (read-only) |
| 51 | `get_memory_inventory` | Visibility | Agent memory/RAG store inventory (read-only) |
| 52 | `get_alignment_rollup` | Visibility | Composite alignment score + bands (read-only) |
| 53 | `get_firewall_status` | Visibility | Tool-call firewall status envelope (read-only) |
| 54 | `get_firewall_evaluations` | Visibility | Hash-chained firewall receipts (read-only) |
| 55 | `get_response_action_catalog` | Visibility | Response-action kinds catalog (read-only) |
| 56 | `get_response_action_history` | Visibility | Response-action history (read-only) |
| 57 | `get_policy_pack` | Visibility | Active enterprise policy pack (read-only) |
| 58 | `get_policy_evaluation` | Visibility | Latest policy-pack evaluation (read-only) |
| 59 | `get_policy_attestations` | Visibility | Tamper-evident attestation log (read-only) |
| 60 | `get_zone_promotions` | Visibility | Cross-zone promotion log (read-only) |
| 61 | `get_agent_fleet_overview` | Fleet | Fleet command-centre rollup (read-only) |
| 62 | `get_agent_failure_clusters` | Fleet | Deterministic failed-intent clusters (read-only) |
