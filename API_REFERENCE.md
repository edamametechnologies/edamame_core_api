# EDAMAME Core API Reference

Complete reference of all RPC-registered API methods in EDAMAME Core. Each method is callable via:
- **Direct Rust call** -- `method_name_async()` or blocking `method_name()`
- **Flutter bridge** -- Auto-generated Dart function
- **gRPC** -- `rpc_call("method_name", [args])` via handler registry
- **MCP** -- Selected methods exposed as MCP tools

Methods are organized by API domain. Health-related methods are omitted from this reference.

---

## Table of Contents

- [Core](#core)
- [Score & Threats](#score--threats)
- [Network / Flodbadd](#network--flodbadd)
- [Breach Detection / Pwned](#breach-detection--pwned)
- [Trust & Compliance](#trust--compliance)
- [Advisor](#advisor)
- [Agentic / AI Automation](#agentic--ai-automation)
- [Metrics History](#metrics-history)
- [Health](#health)
- [File Integrity Monitoring (FIM)](#file-integrity-monitoring-fim)
- [Privacy](#privacy)
- [Agent Visibility](#agent-visibility)
- [MCP Server](#mcp-server)
- [Test Utilities](#test-utilities)
- [RPC Discovery](#rpc-discovery)

---

## Core

System initialization, lifecycle management, device information, and platform utilities.

**Source**: `api/api_core.rs`

### initialize

> **Note**: `initialize` is a special entry point, not registered via the `rpc!()` macro. It must be called before any other API method. Events are delivered separately, through `create_event_stream`.

```
initialize(
    executable_type: String,
    branch: String,
    language: String,
    system_info: SystemInfoAPI,
    computing_enabled: bool,
    reporting_enabled: bool,
    community_enabled: bool,
    server_enabled: bool,
    analytics_enabled: bool,
    demo_mode: bool
) -> ()
```

Initialize EDAMAME Core. Must be called before any other API method.

Parameters:
- `executable_type`: Identifies the consumer (e.g. "app", "posture", "cli")
- `branch`: Threat model branch to use (typically "main")
- `language`: User locale for localized threat descriptions (e.g. "EN", "FR")
- `system_info`: The host description the consumer collected (`SystemInfoAPI`)
- `computing_enabled`: Run the score and threat computation
- `reporting_enabled`: Report the score to the Hub
- `community_enabled`: Join the LAN community (peer device sharing)
- `server_enabled`: This process owns the runtime (the EDAMAME app, the posture daemon): only then are the MCP server auto-started from its saved config and session capture / the file monitor started or stopped for the agentic loops. A CLI one-shot passes `false`.
- `analytics_enabled`: Send product analytics
- `demo_mode`: Serve the demo data set

Events: `create_event_stream(name: String, mask: u128, stream: StreamSink<u128>)` subscribes a named stream to the `CoreEvent` bits in `mask`; each delivery carries one event bit.

### terminate

```
terminate(exit: bool) -> ()
```

Clean shutdown. When `exit` is true, triggers process exit after cleanup.

### get_device_info

```
get_device_info() -> SystemInfoAPI
```

Returns hardware and OS information for the current device: hostname, OS version, platform, architecture, machine UID, etc.

### get_core_version

```
get_core_version() -> String
```

Returns the EDAMAME Core library version string.

### get_core_info

```
get_core_info() -> String
```

Returns build information including version, branch, and feature flags.

### get_branch

```
get_branch() -> String
```

Returns the active threat model branch (e.g., "main").

### get_admin_status

```
get_admin_status() -> bool
```

Returns whether the process is running with administrator/root privileges.

### is_helper_enabled

```
is_helper_enabled() -> bool
```

Returns whether the privileged helper daemon is available.

### get_helper_state

```
get_helper_state() -> String
```

Returns the current state of the helper daemon (active, inactive, etc.).

### get_helper_url

```
get_helper_url() -> String
```

Returns the URL of the helper daemon's gRPC endpoint.

### is_outdated_app

```
is_outdated_app() -> bool
```

Returns whether the current application version is outdated.

### get_app_url

```
get_app_url() -> String
```

Returns the download URL for the latest application version.

### is_from_store

```
is_from_store() -> bool
```

Returns whether the application was installed from an app store (macOS App Store, etc.).

### set_demo_mode

```
set_demo_mode(demo_mode_on: bool, report_to_backend: Option<bool>) -> ()
```

Toggle demo mode. When enabled, uses simulated data for demonstrations.

`report_to_backend` is optional and defaults to `false`, in which case the
synthetic demo score stays local and the device stops reporting to the Hub for
as long as demo mode is on. Set it to `true` to keep reporting the demo score
under the real identity, so the device stays live in the fleet while local
surfaces show demo data. It is only meaningful together with
`demo_mode_on: true`.

### set_demo_platform

```
set_demo_platform(platform: String) -> ()
```

Override the detected platform for demo purposes (e.g., simulate Windows threats on macOS).

### clear_demo_platform

```
clear_demo_platform() -> ()
```

Clear the platform override and return to the actual detected platform.

### get_all_logs

```
get_all_logs() -> String
```

Returns the complete log output since initialization.

### get_new_logs

```
get_new_logs() -> String
```

Returns log output since the last call to this method.

### unified_log

```
unified_log(level: LogLevel, log: String) -> ()
```

Send a log message from the consumer (Flutter/CLI) into the unified log. `LogLevel`: Trace, Debug, Info, Warn, Error.

### get_globalpreferences_status

```
get_globalpreferences_status() -> bool
```

(macOS) Returns whether Full Disk Access / input monitoring permissions are granted.

### prompt_globalpreferences

```
prompt_globalpreferences(title: String, message: String) -> ()
```

(macOS) Show a dialog prompting the user to grant system privacy permissions.

### withdraw_globalpreferences

```
withdraw_globalpreferences() -> ()
```

(macOS) Withdraw the pending privacy permissions prompt.

## Score & Threats

Security scoring engine, threat evaluation, and remediation management.

**Source**: `api/api_score.rs`, `api/api_score_threats.rs`, `api/api_score_history.rs`

### compute_score

```
compute_score() -> ()
```

Trigger a full security score computation. Evaluates all threat metrics for the current platform. Fires `ScoreComputationStarted`, `MetricCompleted` (for each metric), and `ScoreCompleted` events.

### get_score

```
get_score(complete_only: bool, with_ai_details: bool) -> ScoreAPI
```

Returns the current security score and all evaluated threats. When `complete_only` is true, waits for any in-progress computation to finish.

When `with_ai_details` is true, `ScoreAPI.ai_details` carries the local AI governance detail bundle for the `ai` domain:

| Field | Meaning |
|---|---|
| `domain` | Always `"ai"` |
| `mode` | Hub export consent: `"denied"` / `"enabled"` / `"forced"` |
| `coverage[]` | Agent inventory rows (`kind`, `key`, `present`, `monitored`) |
| `checks[]` | Per-Active-check failure causes (`check`, `references[]`, `causes[]`, `context[]`, `truncated`). `references[]` are the check-level framework tokens (`OWASP-ASI05`, `OWASP-LLM06`, `AML.T0053`, `TC-AID-01`, `ISO42001-A.4.5`, `ISO27001-A.8.31`) derived from the same crosswalk as the OWASP / ATLAS / Trust Controls scorecards; metadata only, never consulted for severity or acceptance |

Consent gates Hub export, not on-device observation: the local payload is included even when `mode` is `"denied"`. When `with_ai_details` is false, `ai_details` is `null`. See `edamame_core/AIGOVERNANCE.md`.

`ScoreAPI` also includes: overall score (0–100) and stars (0.0–5.0), the five dimension scores, `ai` (since 2.0: the AI Agent Posture axis, an overlay computed from the metrics tagged `AI Agent Posture`; it does not change `overall` and is `-1` when the model has no such metric), threat lists with status, model metadata, and compliance.

### get_threat_by_name

```
get_threat_by_name(name: String) -> Option<ThreatAPI>
```

Returns details for a specific threat metric by its identifier.

### check_policy

```
check_policy(minimum_score: f32, threat_ids: Vec<String>, tag_prefixes: Vec<String>) -> bool
```

Check whether the current security posture meets a policy. Returns true if: score >= minimum_score AND none of the specified threats are active AND all tag-prefixed threats are resolved.

### get_tag_prefixes

```
get_tag_prefixes() -> Vec<String>
```

Returns all available threat tag prefixes (e.g., "SOC 2", "CIS", "ISO-27001", "PCI-DSS", "HIPAA").

### remediate

```
remediate(name: String, dont_report: bool) -> ThreatResultAPI
```

Remediate a specific threat. Executes platform-specific remediation commands. When `dont_report` is false, reports the result to the backend.

### rollback

```
rollback(name: String, dont_report: bool) -> ThreatResultAPI
```

Rollback a previously applied remediation, restoring the original state.

### get_threats_url

```
get_threats_url() -> String
```

Returns the URL of the active threat model definition file.

### get_history

```
get_history() -> OrderHistoryAPI
```

Returns the complete remediation history (all remediations and rollbacks performed).

---

## Network / Flodbadd

LAN device scanning, packet capture, session analysis, whitelists/blacklists, and ML anomaly detection. All methods require the `flodbadd` feature flag.

**Source**: `api/api_flodbadd.rs`

### Scanning

#### get_lanscan

```
get_lanscan(scan: bool, deep_scan: bool, wide_scan: bool) -> LANScanAPI
```

Perform a LAN scan. `scan` triggers a new scan; `deep_scan` performs port scanning; `wide_scan` extends to full subnet range. Returns all discovered devices with vendor, services, and open ports.

#### get_lanscan_status

```
get_lanscan_status() -> LANScanStatusAPI
```

LAN scan state without the device lists and event history: `auto_scan`, `device_count`, `last_scan` (RFC 3339, empty before the first scan) and `scan_in_progress`. Never starts a scan. For always-on UI; `get_lanscan` carries seven device lists and the seen-event history.

#### get_devices

```
get_devices() -> Vec<DeviceInfoAPI>
```

Returns all discovered network devices with full details (IP, MAC, vendor, hostname, open ports, mDNS services, vulnerabilities).

#### cancel_scan

```
cancel_scan() -> ()
```

Cancel any running LAN scan.

#### get_last_gateway_scan

```
get_last_gateway_scan() -> String
```

Returns the timestamp of the last gateway scan.

#### mdns_start

```
mdns_start() -> ()
```

Start mDNS service discovery for enhanced device identification.

### Packet Capture

#### start_capture

```
start_capture() -> ()
```

Start packet capture on the active network interface. Requires `standalone` feature or appropriate platform permissions. This is the operator's switch: a capture started (or taken over) here survives a single detection engine stopping (`start_attack_pattern_detector(false)`, ...), while a capture an agentic loop started on its own stops once all three loops are off; `agentic_set_protection(false)` stops it either way.

#### stop_capture

```
stop_capture() -> ()
```

Stop packet capture. Also clears the mark of a capture protection started, so turning protection back on starts a fresh one.

#### is_capturing

```
is_capturing() -> bool
```

Returns whether packet capture is currently active.

#### get_packet_stats

```
get_packet_stats() -> PacketStatsAPI
```

Returns capture statistics (packets captured, bytes processed, etc.).

#### get_analyzer_stats

```
get_analyzer_stats() -> AnalyzerStatsAPI
```

Returns ML anomaly analyzer statistics (model state, feature distributions, etc.).

#### get_scan_stats

```
get_scan_stats() -> ScanStatsAPI
```

Returns LAN-scan lifecycle status (in-progress, progress percent, last scan / last gateway scan timestamps, auto-scan, consent, deep/wide flags, device counts) together with a snapshot of the adaptive scan-rate governor (`ScanGovernorStatsAPI`): targets tracked, throttled count, per-target concurrency pool size, minimum rate factor, and the throttled targets with their per-target rate factor, concurrency limit, baseline RTT, and last-active age.

### Sessions

#### get_sessions

```
get_sessions() -> Vec<SessionInfoAPI>
```

Returns all captured network sessions.

#### get_current_sessions

```
get_current_sessions() -> Vec<SessionInfoAPI>
```

Returns currently active sessions.

#### get_lan_sessions

```
get_lan_sessions(all: bool) -> LANSessionsAPI
```

Returns LAN-specific sessions. When `all` is true, includes historical sessions.

#### get_lan_sessions_status

```
get_lan_sessions_status() -> LANSessionsStatusAPI
```

Capture state without the session lists: `is_capturing`, `session_count` (current sessions, 0 while not capturing) and `last_capture` (RFC 3339, empty before the first capture). For always-on UI that only needs these flags; `get_lan_sessions` carries every session's L7 detail up to four times over and is for views that list sessions.

#### get_session_by_uid

```
get_session_by_uid(uid: String) -> Option<SessionInfoAPI>
```

Returns a specific session by its unique identifier.

#### filter_global_sessions

```
filter_global_sessions(sessions: Vec<SessionInfoAPI>) -> Vec<SessionInfoAPI>
```

Filter sessions to only external (WAN) traffic.

#### format_sessions_log

```
format_sessions_log(sessions: Vec<SessionInfoAPI>) -> Vec<String>
```

Format sessions as human-readable log lines.

#### format_sessions_zeek

```
format_sessions_zeek(sessions: Vec<SessionInfoAPI>) -> Vec<String>
```

Format sessions in Zeek (Bro) log format for interoperability.

### Anomaly Detection & Security

#### get_anomalous_sessions

```
get_anomalous_sessions() -> Vec<SessionInfoAPI>
```

Returns sessions flagged as anomalous by the ML model (Extended Isolation Forest).

#### get_blacklisted_sessions

```
get_blacklisted_sessions() -> Vec<SessionInfoAPI>
```

Returns sessions matching blacklist rules.

#### get_whitelist_exceptions

```
get_whitelist_exceptions() -> Vec<SessionInfoAPI>
```

Returns sessions that violate the active whitelist.

#### get_whitelist_conformance

```
get_whitelist_conformance() -> bool
```

Returns true if all current traffic conforms to the active whitelist.

#### get_anomalous_status

```
get_anomalous_status() -> bool
```

Returns true if any anomalous sessions have been detected.

#### get_blacklisted_status

```
get_blacklisted_status() -> bool
```

Returns true if any blacklisted sessions have been detected.

### Whitelists & Blacklists

#### set_whitelist

```
set_whitelist(whitelist_name: String) -> ()
```

Set the active whitelist by name (from the threat models repository).

#### set_custom_whitelists

```
set_custom_whitelists(whitelist_json: String) -> ()
```

Set custom whitelist rules from JSON.

#### augment_custom_whitelists

```
augment_custom_whitelists() -> String
```

Augment the current custom whitelist with new rules from observed traffic. Returns updated whitelist JSON.

#### augment_custom_whitelists_info

```
augment_custom_whitelists_info() -> (String, f64)
```

Returns augmented whitelist JSON and a similarity score compared to the current whitelist.

#### merge_custom_whitelists

```
merge_custom_whitelists(whitelist1_json: String, whitelist2_json: String) -> String
```

Merge two whitelists into one. Returns combined JSON.

#### compare_custom_whitelists

```
compare_custom_whitelists(whitelist1_json: String, whitelist2_json: String) -> f64
```

Compare two whitelists and return a similarity score (0.0 to 1.0).

#### create_custom_whitelists

```
create_custom_whitelists() -> String
```

Generate a new whitelist from all captured traffic. Returns whitelist JSON.

#### create_custom_whitelists_with_process

```
create_custom_whitelists_with_process() -> String
```

Generate a whitelist from captured traffic, including process attribution.

#### create_and_set_custom_whitelist

```
create_and_set_custom_whitelist() -> ()
```

Generate and immediately activate a whitelist from current traffic.

#### set_custom_blacklists

```
set_custom_blacklists(blacklist_json: String) -> ()
```

Set custom blacklist rules from JSON.

#### get_whitelists

```
get_whitelists() -> String
```

Returns the current whitelist definition as JSON.

#### get_blacklists

```
get_blacklists() -> String
```

Returns the current blacklist definition as JSON.

#### get_whitelist_name

```
get_whitelist_name() -> String
```

Returns the name of the active whitelist.

### Filters

#### set_filter

```
set_filter(filter: SessionFilterAPI) -> ()
```

Set a display filter for session listings.

### Network Configuration

#### get_network

```
get_network() -> NetworkAPI
```

Returns the current network configuration (interface, SSID, gateway, etc.).

#### set_network

```
set_network(network: NetworkAPI) -> ()
```

Set network configuration.

#### grant_consent

```
grant_consent() -> ()
```

Grant network monitoring consent (required on some platforms before scanning).

#### consent_given

```
consent_given() -> bool
```

Returns whether network monitoring consent has been granted.

#### forget_network

```
forget_network() -> ()
```

Clear stored network configuration and history.

#### set_auto_scan

```
set_auto_scan(auto_scan: bool) -> ()
```

Enable/disable automatic periodic LAN scanning.

#### set_network_name

```
set_network_name(network_name: String) -> ()
```

Set a custom name for the current network.

### Device Management

#### get_device_by_ip

```
get_device_by_ip(ip_address: String) -> Option<DeviceInfoAPI>
```

Look up a device by IP address.

#### get_device_by_stable_id

```
get_device_by_stable_id(stable_id: String) -> Option<DeviceInfoAPI>
```

Look up a device by its stable identifier (persists across IP changes).

#### set_custom_device_name

```
set_custom_device_name(ip_address: String, custom_name: String) -> ()
```

Set a user-defined name for a device.

#### dislike_device_type

```
dislike_device_type(ip_address: String, note: String) -> ()
```

Report incorrect device type classification with a note.

#### delete_device

```
delete_device(ip_address: String) -> ()
```

Soft-delete a device from the device list.

#### undelete_device

```
undelete_device(ip_address: String) -> ()
```

Restore a soft-deleted device.

#### delete_event

```
delete_event(event: EventAPI) -> ()
```

Delete a network event.

#### delete_network

```
delete_network(network: NetworkAPI) -> ()
```

Delete a stored network configuration.

### Port Management

#### dismiss_device_port

```
dismiss_device_port(ip_address: String, port: u16) -> ()
```

Dismiss a specific open port finding on a device.

#### undismiss_device_port

```
undismiss_device_port(ip_address: String, port: u16) -> ()
```

Undismiss a previously dismissed port finding.

#### dismiss_all_device_ports

```
dismiss_all_device_ports(ip_address: String) -> ()
```

Dismiss all open port findings for a device.

#### undismiss_all_device_ports

```
undismiss_all_device_ports(ip_address: String) -> ()
```

Undismiss all port findings for a device.

### Remediation

#### get_device_remediation

```
get_device_remediation(ip_address: String) -> String
```

Get AI-generated remediation advice for a network device.

#### has_device_remediation

```
has_device_remediation(ip_address: String) -> bool
```

Returns whether remediation advice is available for a device.

#### get_session_remediation

```
get_session_remediation(uid: String) -> String
```

Get AI-generated remediation advice for a network session.

#### has_session_remediation

```
has_session_remediation(uid: String) -> bool
```

Returns whether remediation advice is available for a session.

### Dismiss Rules

Since 2.0 a session dismissal is a recurrence-aware dismissal rule in the
`session` domain (see "Recurrence-Aware Dismissal Rules" below): the four RPCs
here keep their names and create or remove Session-domain rules, so a
dismissed session carries `dismissed_by_rule`, gets hit counts and an audit
trail, shows up in `agentic_list_dismissal_rules("session")`, and comes back
through `agentic_remove_dismissal_rule` like a finding does. The capture store's
own `SessionDismissRule` list is imported once at startup and no longer
written.

#### add_dismiss_rule_from_session

```
add_dismiss_rule_from_session(uid: String) -> ()
```

Dismiss the session and every later session with the same destination host and port from the same process (a `destination`-scope rule in the `session` domain).

#### remove_dismiss_rule_from_session

```
remove_dismiss_rule_from_session(uid: String) -> ()
```

Restore the session: removes every Session-domain rule covering it.

#### add_dismiss_rule_from_port

```
add_dismiss_rule_from_port(uid: String) -> ()
```

Dismiss every session to this destination port from the same process (a `destination_port`-scope rule).

#### add_dismiss_rule_from_process

```
add_dismiss_rule_from_process(uid: String) -> ()
```

Dismiss every session from this process, whatever the destination (a `process`-scope rule).

#### kill_process

```
kill_process(pid: u32, expected_path: String) -> String
```

Operator hard kill (`SIGKILL` / `TerminateProcess`) of the process behind a
finding, a divergence verdict or a session. Returns a fallible envelope
`{"success": bool, "outcome": {...}, "error"?: String}` where `outcome.outcome`
is one of `killed`, `not_running`, `identity_mismatch`, `refused`,
`permission_denied`, `failed`. `expected_path` is the image shown on screen:
when it no longer matches the pid's current image (recycled pid) the kill is
refused as `identity_mismatch`. System-critical and EDAMAME processes are
always `refused`. Standalone daemons kill directly; the sandboxed app crosses
to the helper. Operator-only -- deliberately not exposed as an MCP tool.

### Community Sharing

## Breach Detection / Pwned

Email breach monitoring via HaveIBeenPwned integration. Requires the `pwned` feature flag.

**Source**: `api/api_pwned.rs`

### add_pwned_email

```
add_pwned_email(email: String) -> String
```

Add an email address to monitor for breaches. Fallible envelope:
`{ "success": bool, "error": string?, "outcome": string, "tracked": bool? }`.

`success` means the requested end state holds, so re-adding an already-monitored
address is a success (`outcome: "unchanged"`), not an error. `tracked` is whether
the address is monitored after the call — `true` on success, and `null` when the
call did not succeed, because a refusal leaves the prior state intact and a flat
`false` there would be a fresh false claim.

| `outcome` | `success` | Meaning |
|---|---|---|
| `changed` | `true` | Address was not monitored and now is |
| `unchanged` | `true` | Address was already monitored; idempotent repeat |
| `invalid_email` | `false` | Address was empty or whitespace-only |
| `demo_mode_no_op` | `false` | Demo mode is active and its monitored address set is fixed |
| `failed` | `false` | Registry write failed; `error` carries the reason |

### remove_pwned_email

```
remove_pwned_email(email: String) -> String
```

Remove an email from breach monitoring. Same envelope and `outcome` vocabulary as
`add_pwned_email`, with `changed` meaning the address was monitored and now is not,
and `unchanged` meaning it was already absent. `tracked` is `false` on success and
`null` otherwise — notably, a `demo_mode_no_op` refusal leaves the address
monitored, so reporting `false` would be wrong.

### get_breaches_for_email

```
get_breaches_for_email(email: String) -> PwnedAPI
```

Returns all known breaches for a specific email address.

### get_all_breaches

```
get_all_breaches() -> PwnedAPI
```

Returns all known breaches across all monitored emails.

### get_breach_by_name_and_email

```
get_breach_by_name_and_email(name: String, email: String) -> Option<PwnedItemAPI>
```

Returns details for a specific breach by name and email.

### get_multi_email_summary

```
get_multi_email_summary() -> PwnedMultiEmailAPI
```

Returns a summary view of breaches across all monitored emails.

### toggle_breach_for_email

```
toggle_breach_for_email(email: String, name: String, dismiss: bool) -> ()
```

Dismiss or undismiss a specific breach for an email.

### get_breach_remediation

```
get_breach_remediation(name: String, description: String, is_service: bool) -> String
```

Get AI-generated remediation advice for a specific breach.

---

## Trust & Compliance

Domain connection, policy enforcement, PIN authentication, and compliance reporting. Requires the `trust` feature flag.

**Source**: `api/api_trust.rs`

### set_credentials

```
set_credentials(user: String, domain: String, pin: String) -> ()
```

Set credentials for connecting to a managed domain (EDAMAME Hub).

### connect_domain

```
connect_domain() -> ()
```

Connect to the configured managed domain. Begins continuous security reporting.

### disconnect_domain

```
disconnect_domain() -> ()
```

Disconnect from the managed domain.

### request_pin

```
request_pin() -> ()
```

Request a new PIN for domain authentication.

### get_connection

```
get_connection() -> ConnectionStatusAPI
```

Returns the current domain connection status (connected, disconnected, error, etc.).

### get_last_report_secs

```
get_last_report_secs() -> i64
```

Returns seconds since the last security report was sent to the backend.

### get_last_report_signature

```
get_last_report_signature() -> String
```

Returns the cryptographic signature of the last reported security score.

### get_signature_from_score_with_email

```
get_signature_from_score_with_email(email: String) -> String
```

Generate a cryptographically signed security score for the given email. Used for verifiable compliance attestation.

### request_report_from_signature

```
request_report_from_signature(email: String, signature: String, format: String) -> ()
```

Request a formal compliance report based on a signed score. Format: "pdf" or "html".

### check_policy_for_domain

```
check_policy_for_domain(signature: String, domain: String, policy_name: String) -> bool
```

Check whether a signed score meets a specific domain policy.

### check_policies_for_domain

```
check_policies_for_domain(signature: String, domain: String) -> Vec<PoliciesStatusAPI>
```

Check all policies for a domain against a signed score.

### check_policies_for_current_domain

```
check_policies_for_current_domain() -> Vec<PoliciesStatusAPI>
```

Check all policies for the currently connected domain.

### get_ai_whitelist_status

```
get_ai_whitelist_status() -> AiWhitelistStatusAPI
```

Returns the last AI whitelist answer the Hub gave for this device: whether the
observed agent activity fits the admin-defined whitelists, which selectors were
never allowed (`violations`), and the per-whitelist breakdown (`whitelists`).

This is a cached read, refreshed on the report cycle alongside policies -- it
never performs a network round trip, so it is safe to call on every UI rebuild.
When the Hub has not answered yet, `answered` is `false`, `verdict` is
`Unknown`, and every other field is meaningless. Verdict values are `Unknown`,
`NotCovered`, `Inconclusive`, `Fits`, and `DoesNotFit`.

### user_feedback

```
user_feedback(context: String, note: String, email: String, app_log: bool, helper_log: bool) -> ()
```

Submit user feedback with optional log attachments.

---

## Security Findings (advisor RPCs)

Security recommendations engine providing prioritized, actionable security todos. The advisor aggregates findings from threats, network analysis, breach detection, and compliance into a unified list.

**Source**: `api/api_advisor.rs`

### get_advisor

```
get_advisor() -> AdvisorAPI
```

Returns the full advisor state including all security todos with priorities, categories, and resolution status.

Since 2.0 each `AdvisorTodoAPI` carries `agentic_action`: the assistant's latest non-obsolete action record on that todo, or `null` when the assistant has not reviewed it (and always `null` on builds without the `agentic` feature). The app's Security radar reads it to colour and rank the todo by the assistant's state without re-deriving it client-side.

| `agentic_action` field | Meaning |
|---|---|
| `action_id` | Id of the action record in `agentic_get_action_history` |
| `result_status` | `auto_resolved` / `requires confirmation` / `escalated` / `failed` |
| `timestamp` | When the assistant last processed the todo |
| `priority` | The assistant's priority (`low` .. `critical`) |
| `reasoning` | The assistant's reasoning summary |
| `success` | Whether the recorded action succeeded |
| `undo_available` | Whether the action can still be undone |

## Security AI (agentic RPCs)

AI-powered security automation with support for multiple LLM providers. Requires the `agentic` feature flag.

**Source**: `api/api_agentic.rs`

### Processing

#### agentic_process_todos

```
agentic_process_todos(confirmation_level: i32) -> AgenticResultsAPI
```

The security-assistant entry point. Processes the security findings using the configured LLM:
- `confirmation_level = 0`: Auto-resolve safe actions, escalate risky ones
- `confirmation_level = 1`: Analyze and recommend only (no execution)

Returns results categorized as: auto_resolved, requires_confirmation, escalated, failed.

The scheduled assistant loop retries a todo whose analysis failed only after a backoff (10 min, doubling to 6 h); this operator-requested entry point clears that backoff and retries every failed todo now.

#### agentic_execute_action

```
agentic_execute_action(action_id: String) -> bool
```

Execute a specific pending action that was previously escalated for confirmation.

#### agentic_undo_action

```
agentic_undo_action(action_id: String) -> bool
```

Undo (rollback) a specific completed action. All actions are transactional and reversible.

#### agentic_retry_action

```
agentic_retry_action(action_id: String) -> bool
```

Retry a previously failed action.

#### agentic_undo_all_actions

```
agentic_undo_all_actions() -> UndoAllResultAPI
```

Undo all completed actions. Returns counts of successful and failed undos.

### Agentic Protection

The Assistant (auto-processing), the attack pattern detector and the divergence engine are off until an operator turns them on, together, with one switch. Nothing turns them on implicitly (capture consent, a model connection, a behavioral model). Operator-only: none of these is exposed over MCP.

#### agentic_set_protection

```
agentic_set_protection(enabled: bool) -> String
```

Turn the three loops on or off together. On enables the Assistant at its persisted level (Review unless the operator chose Auto, see `agentic_set_auto_processing`) and, on desktop (macOS, Windows, Linux), the attack pattern detector and the divergence engine, starting packet capture and the file monitor if they are not running; off turns all three off and stops packet capture and the file monitor whoever started them (detection off means nothing watches sessions or files; `start_capture` / `start_file_monitor` can start either again). The setting persists across restarts. Returns `{"success": true}`, or `{"success": false, "error": "..."}` (for example in demo mode).

#### agentic_get_protection_status

```
agentic_get_protection_status() -> AgenticProtectionStatusAPI
```

Returns `enabled` (true while any of the three loops runs, so one call to `agentic_set_protection(false)` always turns everything off), `assistant`, `attack_pattern_detection`, `divergence_detection`, and `detection_available` (whether the detection engines exist on this platform).

### Auto-Processing

#### agentic_set_auto_processing

```
agentic_set_auto_processing(enabled: bool, interval_secs: u64, mode: i32) -> bool
```

Configure the Assistant's level (`mode`: 1 = Review, recommend and wait for confirmation; 0 = Auto, fix safe issues) and cadence. Its on/off is normally driven by `agentic_set_protection`; this call never starts or stops the detection engines. The ticker runs every 5 seconds when enabled and triggers processing at the configured interval.

#### agentic_get_auto_processing_status

```
agentic_get_auto_processing_status() -> AgenticAutoProcessingStatusAPI
```

Returns the current auto-processing configuration and status.

### LLM Configuration

#### agentic_set_llm_config

```
agentic_set_llm_config(
    provider: String,
    api_key: String,
    model: String,
    base_url: String,
    mcp_psk: String,
    slack_bot_token: String,
    slack_actions_channel: String,
    slack_escalations_channel: String,
    telegram_bot_token: String,
    telegram_chat_id: String,
    slack_enabled: bool,
    telegram_enabled: bool,
    export_to_portal: bool
) -> bool
```

Configure the LLM provider. Supported providers:
- `"internal"` -- EDAMAME Portal managed LLM (OAuth or API key)
- `"claude"` -- Anthropic Claude (API key required)
- `"openai"` -- OpenAI GPT (API key required)
- `"ollama"` -- Local Ollama instance (base_url required)

This same call also persists optional team-delivery routing for runtime security notifications:
- Slack bot token + separate action and escalation channels
- Telegram bot token + destination chat ID
- `slack_enabled` / `telegram_enabled` -- enable the corresponding notification channel
- `export_to_portal` -- when true, agentic action history is exported to EDAMAME Portal

#### agentic_get_llm_config

```
agentic_get_llm_config() -> LLMConfigInfoAPI
```

Returns the current LLM configuration and saved delivery-channel settings (provider, model, base_url, API key presence and value, Slack routing, Telegram routing, Telegram interactive state, and export_to_portal flag).

#### agentic_set_telegram_interactive_config

```
agentic_set_telegram_interactive_config(enabled: bool, allowed_user_ids: Vec<i64>) -> bool
```

Enable or disable Telegram interactive reply cards for predefined actions such as dismissing divergence evidence or vulnerability findings. Callback handling stays allowlist-based: only explicitly listed Telegram user IDs can invoke interactive actions, while the bot token and destination chat remain configured through `agentic_set_llm_config`.

#### agentic_test_llm

```
agentic_test_llm() -> LLMTestResultAPI
```

Test connectivity and authentication with the configured LLM provider.

### EDAMAME API Key (Headless/CLI)

#### agentic_set_edamame_api_key

```
agentic_set_edamame_api_key(api_key: String) -> bool
```

Set an EDAMAME API key for headless/CLI authentication (alternative to OAuth).

### Status & History

#### agentic_get_action_history

```
agentic_get_action_history() -> Vec<ActionRecordAPI>
```

Returns the complete action audit trail (last 30 days). Three kinds of record share the list, told apart by `action_type`: advisor actions (`RemediateThreat`, `DismissSession`, ...), attack-pattern findings (`action_type = "VulnerabilityDetection"`, `advice_type = "Vulnerability"`, kept until dismissed) and, since 2.0.0, divergence evidence (`action_type = "DivergenceDetection"`, `advice_type = "Divergence"`, aged out after 30 days). Both finding kinds carry a `finding_key`, a `dismissed` flag and the same flattened finding fields; for divergence rows `vulnerability_check` is the evidence category, `vulnerability_reference` names the plane and category, `vulnerability_open_files` lists the unexpected sensitive paths and `vulnerability_detection_basis` the trigger reason. Dismiss either kind through `agentic_dismiss_with_scope` with the matching `domain` (`scope = finding` for a one-off), and restore by removing the rule named in the row's `dismissed_by_rule` with `agentic_remove_dismissal_rule`.

#### agentic_get_workflow_status

```
agentic_get_workflow_status() -> Option<AgenticWorkflowStatusAPI>
```

Returns the status of the currently running workflow, or None if idle.

#### agentic_get_summary

```
agentic_get_summary() -> AgenticSummaryAPI
```

Returns summary statistics (total actions, success rate, etc.).

#### agentic_get_token_usage_stats

```
agentic_get_token_usage_stats() -> TokenUsageStatsAPI
```

Returns LLM token consumption statistics (input tokens, output tokens, total cost).

#### agentic_get_loop_token_usage

```
agentic_get_loop_token_usage() -> LoopTokenUsageAPI
```

Returns per-loop LLM token usage broken down across four buckets: `agentic` (the Security assistant: todo analysis and escalation adjudication), `vuln` (attack pattern detector LLM adjudication), `divergence` (divergence engine LLM adjudication, including the raw-session model ingest path), and `coach` (the AI coach, counted apart from the assistant since 2.0; counters persisted before 2.0 keep their coach spend in `agentic_*`). Each bucket reports `*_in` and `*_out` token counts plus a shared `since_unix_secs` reset timestamp. Used to attribute LLM cost to the loop that generated it.

#### agentic_reset_loop_token_usage

```
agentic_reset_loop_token_usage() -> bool
```

Reset the per-loop LLM token usage counters back to zero and persist the reset to disk. Returns `true` when persistence succeeded.

#### get_agentic_memory_stats

```
get_agentic_memory_stats() -> String
```

Returns a JSON snapshot of in-memory cache sizes for the agentic subsystem (action history, divergence/vulnerability buffers, etc.). Used for diagnosing memory growth and tuning history caps.

#### get_agentic_notification_history

```
get_agentic_notification_history(limit: usize) -> String
```

Returns the last `limit` notifications core authored as a JSON array, most recent first. Each entry is `{notification_id, timestamp, source, severity, title, body, route, section, arguments}`: `source` is the message kind (`vulnerability_alert`, `divergence_alert`, `action_report`, ... plus, since 2.0, the system-plane kinds `score_increased`, `score_decreased`, `anomalous_sessions`, `blacklisted_sessions`, `new_devices`, `policy_compliance`, `identity_breaches`, `helper_outdated`, `app_outdated`, `backend_outdated`, `domain_limit`, `subscription_limit`), `section` is the rail section whose notification toggle applies (`Security`, `Agents`, `Threats`, `Identity`, `Network`, `System`, `Trust`, `General`), `route` plus `arguments` (all strings, including `tab` and every localizable value) form the deep link, and `title` / `body` are the English fallback. The app renders from this list and deduplicates on `notification_id`; it composes no notification of its own since 2.0.

#### agentic_get_subscription_status

```
agentic_get_subscription_status() -> AgenticSubscriptionStatusAPI
```

Returns subscription plan info and current usage for the Internal provider.

#### agentic_get_portal_url

```
agentic_get_portal_url() -> String
```

Returns the EDAMAME Portal URL.

#### agentic_clear_action_history

```
agentic_clear_action_history() -> bool
```

Clear the Assistant's action records (the app's AI History "Clear actions"). Attack-pattern and divergence findings are kept: they have their own clears (`clear_vulnerability_history` / `clear_attack_pattern_history`, `clear_divergence_history`). Since 2.0 core also clears the Assistant's records by itself when the model is disconnected (a Portal sign-out, an own model cleared, provider `none`: a config that could call a model and no longer can); switching to another working model keeps them.

### Action Management

#### agentic_mark_action_read

```
agentic_mark_action_read(action_id: String) -> bool
```

Mark a specific action as read in the history.

#### agentic_mark_action_unread

```
agentic_mark_action_unread(action_id: String) -> bool
```

Mark a specific action as unread.

#### agentic_mark_all_actions_read

```
agentic_mark_all_actions_read() -> bool
```

Mark all actions as read.

### OAuth Authentication (Internal Provider)

#### oauth_signin_internal

```
oauth_signin_internal() -> String
```

Initiate OAuth 2.0 sign-in for the Internal LLM provider. Opens the browser for authentication and waits (up to 300 s) for the loopback callback on `127.0.0.1:8765`. On iOS and Android core cannot open a browser: it parks the authorize URL for `oauth_take_browser_url` instead. Signing in never turns a loop on (only `agentic_set_protection` does); if protection is already on, the Assistant starts working with the new session. Returns status message.

#### oauth_refresh_internal

```
oauth_refresh_internal() -> String
```

Refresh OAuth tokens using the stored refresh token.

#### oauth_signout_internal

```
oauth_signout_internal() -> String
```

Sign out and clear OAuth tokens. On desktop it also opens the Cognito logout URL to clear the Hosted UI session; iOS and Android skip that step (sign-in always asks for credentials again via `prompt=login`).

#### oauth_cancel_signin

```
oauth_cancel_signin() -> String
```

Cancel an in-flight OAuth sign-in and release the localhost callback port (`127.0.0.1:8765`) so a retry can bind immediately. Returns JSON with `success` and `cancelled` (`true` when an in-flight attempt was aborted).

#### oauth_take_browser_url

```
oauth_take_browser_url() -> String
```

Take the sign-in URL parked by an in-flight `oauth_signin_internal` on iOS and Android, where core cannot open a browser. The app polls it while the sign-in runs and opens the URL in its in-app browser (SFSafariViewController / Custom Tabs); the app stays in the foreground, so the loopback callback completes as on desktop. Returns the URL once and clears it; empty when nothing is waiting, which is always the case on desktop. `oauth_cancel_signin` also clears it.

#### oauth_get_status

```
oauth_get_status() -> OAuthStatusAPI
```

Returns OAuth authentication status: authenticated, user_id, subscription_active, subscription_tier.

#### oauth_open_signup

```
oauth_open_signup() -> bool
```

Open the browser to the EDAMAME Portal sign-up page.

### Divergence Detection

Behavioral model management and divergence detection between the reasoning plane (agent intent, produced by EDAMAME's host-side transcript observer for any discovered on-disk agent, or by an in-agent extrapolator for off-host coverage) and the execution plane (observed traffic). Requires the `agentic` feature flag.

#### upsert_behavioral_model

```
upsert_behavioral_model(window_json: String) -> String
```

Push a behavioral window from the operator plane. Accepts a JSON-encoded window of predicted behavior. Returns status JSON. **Operator-plane only** -- not an MCP tool (retired 2026-09-09); the host-side transcript observer is the sole shipped model producer. An `agent_instance_id` ending in `-observer` is rewritten to `-pushed` at intake.

Behavioral window schema (v3):
- `window_start`, `window_end`, `ingested_at`, `version`, `hash`
- `predictions[]` with `session_key`, `action`, `tools_called`
- expected dimensions: `expected_traffic`, `expected_sensitive_files`, `expected_lan_devices`, `expected_local_open_ports`, `expected_process_paths`, `expected_parent_paths`, `expected_open_files`, `expected_l7_protocols`, `expected_system_config`
- negative dimensions: `not_expected_traffic`, `not_expected_sensitive_files`, `not_expected_lan_devices`, `not_expected_local_open_ports`, `not_expected_process_paths`, `not_expected_parent_paths`, `not_expected_open_files`, `not_expected_l7_protocols`, `not_expected_system_config`

#### upsert_behavioral_model_from_raw_sessions

```
upsert_behavioral_model_from_raw_sessions(raw_sessions_json: String) -> String
```

Build and upsert a behavioral-model window directly from a JSON array of raw session records (instead of supplying a pre-aggregated window). Used by the in-process transcript observer, plus tests and operator tools that already have observed sessions and want EDAMAME to derive predicted dimensions automatically. Returns the resulting window JSON. **Operator-plane only** -- not an MCP tool (retired 2026-09-09).

#### get_behavioral_model

```
get_behavioral_model() -> String
```

Read the current behavioral model as JSON.

#### get_behavioral_model_history

```
get_behavioral_model_history(limit: usize) -> String
```

Get recent behavioral-model injection snapshots as JSON. `limit` caps the number of entries returned.

#### get_behavioral_model_contributors

```
get_behavioral_model_contributors() -> String
```

Get the list of components/clients (MCP, helper, tests) that have currently contributed to the behavioral model, with their last-injection timestamps and provided dimensions. Used by the UI and diagnostics to show "who is feeding the cortex".

#### get_divergence_verdict

```
get_divergence_verdict() -> String
```

Get the latest divergence detection verdict as JSON.
Includes evidence from deterministic correlation, safety-floor rules, and attack-pattern-detection findings.

#### get_divergence_history

```
get_divergence_history(limit: usize) -> String
```

Get rolling history of divergence verdicts as JSON. `limit` caps the number of entries returned.

#### get_divergence_incidents

```
get_divergence_incidents(limit: usize) -> String
```

Get the rolling list of divergence incidents (groups of correlated verdicts) as JSON. `limit` caps the number of incidents returned. Each entry summarizes a multi-verdict episode rather than individual verdicts.

#### get_divergence_incident

```
get_divergence_incident(incident_id: String) -> String
```

Get the full record for a single divergence incident (matched by `incident_id`) as JSON. Returns `{ "incident": null }` when the id is unknown.

#### reset_divergence_suppressions

```
reset_divergence_suppressions() -> String
```

Reset every dismissed divergence evidence item so it surfaces again in verdicts and notifications. Returns JSON with `{ "success": true, "changed": bool }` indicating whether any dismissals were actually cleared.

#### get_divergence_debug_trace

```
get_divergence_debug_trace(entry_id: String) -> String
```

Get the per-rule evaluation trace for a specific divergence-history entry (matched by `entry_id`) as JSON. Used to diagnose why the cortex extrapolator emitted a given verdict. Returns `{ "trace": null }` when the entry id is unknown.

#### debug_run_divergence_tick

```
debug_run_divergence_tick() -> String
```

Force a single divergence-engine tick out of band (without waiting for the scheduled interval). Diagnostic-only; used by tests and the CLI when developers need a deterministic re-evaluation.

#### clear_behavioral_model

```
clear_behavioral_model() -> ()
```

Reset the behavioral model. For testing and debugging only. Not exposed via MCP.

#### clear_behavioral_model_history

```
clear_behavioral_model_history() -> ()
```

Clear stored behavioral-model injection history.

#### clear_divergence_history

```
clear_divergence_history() -> ()
```

Clear stored divergence verdict history.

#### clear_divergence_state

```
clear_divergence_state() -> ()
```

Clear the live divergence state, including the current verdict cache.

#### start_divergence_engine

```
start_divergence_engine(enabled: bool, interval_secs: u64) -> String
```

Enable or disable the divergence engine with optional interval configuration. Returns status JSON.

#### set_divergence_adjudication_mode

```
set_divergence_adjudication_mode(mode: String) -> String
```

Operator plane. Whether the divergence engine consults the LLM: `llm` (deterministic fallback when the LLM is unavailable), `deterministic` (never consult it; verdicts carry `DETERMINISTIC_ONLY` provenance), or `auto` (default since 2.0.0: `advisory` while the LLM config carries credentials, `deterministic` otherwise -- it follows the connection). `advisory` is accepted and behaves as `llm` for this engine. Persisted with the agentic config. Fallible envelope: `{"success": true, "mode": "<setting>", "effective_mode": "<mode the engine runs in now>"}` or `{"success": false, "error": "invalid adjudication_mode ..."}`. Added 2026-09-13; `auto` and `effective_mode` in 2.0.0.

#### get_divergence_engine_status

```
get_divergence_engine_status() -> String
```

Get engine status as JSON: running state, interval, last run timestamp, model age, last verdict, `ticker_last_tick_at` / `ticker_stalled` (liveness of the driver; `running` is configuration), `adjudication_mode` (the mode the engine runs in now) and `adjudication_auto` (2.0.0: that mode was resolved from the LLM connection rather than pinned).

**MCP tools**: Four of these methods are exposed as MCP tools: `get_behavioral_model`, `get_divergence_verdict`, `get_divergence_history`, and `get_divergence_engine_status`.

`upsert_behavioral_model` and `upsert_behavioral_model_from_raw_sessions` were **retired from MCP on 2026-09-09** (their names are held in `FORBIDDEN_MCP_MUTATORS` in `src/mcp/handler.rs` so the route-table test asserts their absence). The RPCs remain, on the operator plane only: the host-side transcript observer is the sole shipped model producer, and a window that arrives over RPC claiming the observer's `-observer` instance id is rewritten to `-pushed` at intake (`pushed_instance_id`) so it cannot inherit the policy plane's observer exemptions.

`start_divergence_engine`, `start_vulnerability_detector`, `set_divergence_adjudication_mode`, `set_vulnerability_adjudication_mode`, `agentic_set_auto_processing`, `clear_behavioral_model`, `start_file_monitor`, and `stop_file_monitor` are direct API control-plane methods and are not exposed via MCP tools.

### Attack Pattern Detector

Model-independent detection for sensitive-file access, critical CVE exposure, and other safety-floor findings. Requires the `agentic` feature flag. Eleven checks: token_exfiltration (anomalous + creds), skill_supply_chain (blacklisted + creds), credential_harvest (any session + >= N credential label categories), sandbox_exploitation (suspicious lineage), sensitive_material_egress (sensitive or secret-like files open + sustained egress), file_system_tampering (FIM writes to sensitive / temp-staged files, writer-attributed), agent_control_tampering (an agent's enforcement config weakened), agent_denylist_bypass (a denied command re-spelled and run), package_install_lifecycle (install-time lineage -- a dependency tree under a package-manager runtime -- reaching off-host or writing outside the tree; LOW unless corroborated), process_memory_scrape (a process obtaining another process's task port or memory, from the kernel task-access stream; CRITICAL for agent / credential-holder targets, HIGH for other control-port / memory-open access; kernel-vouched platform binaries and uncorroborated read-only ports are not reported), cloud_metadata_egress (a process querying the cloud instance metadata service -- IMDS `169.254.169.254`, ECS/Fargate `169.254.170.2`, the Azure wire server -- and forwarding the session it gets; LOW on its own, HIGH with corroboration; platform agents and CI-runner internals never fire). The `credential_harvest` threshold is configurable via `credential_harvest_min_labels` in `cve-detection-params-db.json` (default 3); per-check default severities are overridable there too. Only HIGH/CRITICAL findings are alertable (`active_alertable_findings`); LOW findings stay visible without alerting.

#### start_vulnerability_detector

```
start_vulnerability_detector(enabled: bool, interval_secs: u64) -> String
```

Enable or disable the attack pattern detector with optional interval configuration. Returns status JSON.

#### set_vulnerability_adjudication_mode

```
set_vulnerability_adjudication_mode(mode: String) -> String
```

Operator plane. How the detector publishes when the LLM adjudicator is absent: `llm` (a tick the LLM did not answer is withheld -- empty report, `adjudication_status: error|unavailable`; what a CI gate wants, see `edamame_posture`), `advisory` (the LLM is consulted; on failure or with no provider the deterministic result is published with `decision_source: DETERMINISTIC_ONLY`), `deterministic` (the LLM, the benign verdict cache and history reuse are never consulted; every tick publishes deterministically), or `auto` (default since 2.0.0: `advisory` while the LLM config carries credentials -- Portal tokens or API key, an own-model key, an Ollama endpoint -- and `deterministic` otherwise, so nothing is ever withheld on a host that did not pin `llm`). Persisted with the agentic config; `get_vulnerability_detector_status` reports the mode the detector runs in as `adjudication_mode` and whether it was resolved as `adjudication_auto`. Fallible envelope: `{"success": true, "mode": "<setting>", "effective_mode": "<mode>"}`. Not exposed over MCP: the observed agent must not choose its own adjudication. Added 2026-09-13; `auto` in 2.0.0; the measured trade is in `edamame_core/VULNERABILITYDETECTION.md`, "What The Adjudicator Adds, And Publication Without It".

#### get_vulnerability_findings

```
get_vulnerability_findings() -> String
```

Get the latest active vulnerability / safety-floor report as JSON.

#### get_vulnerability_history

```
get_vulnerability_history(limit: usize) -> String
```

Get rolling history of attack pattern detector reports as JSON. `limit` caps the number of entries returned.

#### dismiss_augmentation_todo

```
dismiss_augmentation_todo(scope_key: String, todo_key: String) -> String
```

Dismiss one Enlightenment Path Next Steps todo in a scope (operator-only; never MCP). Path derives todos client-side from `get_self_augmentation_report`; core only stores opaque dismiss/read state. Key contract: `scope_key` is the workspace slug or `__aggregate__`; `todo_key` is `${Dart _StepKind.name}|${subject}` (camelCase, e.g. `ghostReuse|deploy.sh`). Returns JSON with `{ "success": true, "changed": bool }`.

#### undismiss_augmentation_todo

```
undismiss_augmentation_todo(scope_key: String, todo_key: String) -> String
```

Restore a previously dismissed augmentation todo. Same key contract as `dismiss_augmentation_todo`. Returns JSON with `{ "success": true, "changed": bool }`.

#### set_augmentation_todo_read

```
set_augmentation_todo_read(scope_key: String, todo_key: String, read: bool) -> String
```

Mark an augmentation todo read or unread. Same key contract as `dismiss_augmentation_todo`. Returns JSON with `{ "success": true, "changed": bool }`.

#### get_augmentation_todo_states

```
get_augmentation_todo_states(scope_key: String) -> String
```

Return the durable dismiss/read map for one scope as a bare JSON object `{ todo_key: { dismissed, read, dismissed_at, read_at } }`. Empty object means every derived todo is active and unread. Same `scope_key` contract as the mutators.

#### clear_vulnerability_history

```
clear_vulnerability_history() -> ()
```

Clear stored attack pattern detector report history.

#### reset_vulnerability_suppressions

```
reset_vulnerability_suppressions() -> String
```

Reset every dismissed vulnerability finding so it surfaces again in reports and alerts. Returns JSON with `{ "success": true, "changed": bool }` indicating whether any dismissals were actually cleared.

#### get_vulnerability_debug_trace

```
get_vulnerability_debug_trace(report_id: String) -> String
```

Get the per-check evaluation trace for a specific vulnerability report (matched by `report_id`) as JSON. Used for diagnosing why a finding was or was not raised. Returns `{ "trace": null }` when the report id is unknown.

#### get_vulnerability_detector_status

```
get_vulnerability_detector_status() -> String
```

Get detector status as JSON: running state, interval, last run timestamp, current active-finding counts, `adjudication_mode` (the mode the detector runs in now), `adjudication_auto` (2.0.0: resolved from the LLM connection rather than pinned), `adjudication_status`, capture / content-scan / ticker liveness fields.

#### debug_run_vulnerability_detector_tick

```
debug_run_vulnerability_detector_tick() -> String
```

Force a single attack-pattern-detector tick out of band (without waiting for the scheduled interval). Diagnostic-only; used by tests and the CLI when developers need a deterministic re-evaluation. Returns JSON describing whether a tick was actually executed (it may be skipped if a concurrent tick is already in flight).

**LLM dependency**: The attack pattern detector itself runs model-independent checks and does not require an LLM provider to surface findings. For CI/security gates and automation flows it is strongly recommended to also configure an LLM via `agentic_set_llm_config`: EDAMAME can then adjudicate findings, suppress likely false positives, and produce clearer alert text. Without an LLM, raw heuristic findings still surface and gate consumers (e.g. `edamame_posture vulnerability-status --fail-on-findings`).

#### Attack Pattern Detector RPCs (canonical names since 2.0.0)

Since 2.0.0 the `*_attack_pattern_*` methods below carry the implementation; the corresponding `*_vulnerability_*` methods above are legacy wire-level aliases kept for one release and removed in the next major (MCP tool names are unchanged). Each `*_vulnerability_*` method is a legacy alias delegating to its canonical `*_attack_pattern_*` twin (same arguments, same return shape, same behavior). New integrations should use the `attack_pattern_*` names; existing integrations using `*_vulnerability_*` continue to work until the next major. See the workspace rule "Vulnerability -> Attack Pattern Detection Terminology Transition" in `edamame_app/.cursor/rules/workspace.mdc` for the full policy.

#### start_attack_pattern_detector

```
start_attack_pattern_detector(enabled: bool, interval_secs: u64) -> String
```

Canonical name; `start_vulnerability_detector` is its legacy alias.

#### set_attack_pattern_adjudication_mode

```
set_attack_pattern_adjudication_mode(mode: String) -> String
```

Canonical name of `set_vulnerability_adjudication_mode` (same modes `llm` / `advisory` / `deterministic` / `auto`, same persisted setting, same envelope `{"success": true, "mode": "<setting>", "effective_mode": "<mode>"}`). Operator plane only, not exposed over MCP.

#### get_attack_pattern_findings

```
get_attack_pattern_findings() -> String
```

Canonical name; `get_vulnerability_findings` is its legacy alias.

#### get_attack_pattern_history

```
get_attack_pattern_history(limit: usize) -> String
```

Canonical name; `get_vulnerability_history` is its legacy alias.

#### clear_attack_pattern_history

```
clear_attack_pattern_history() -> ()
```

Canonical name; `clear_vulnerability_history` is its legacy alias.

#### reset_attack_pattern_suppressions

```
reset_attack_pattern_suppressions() -> String
```

Canonical name; `reset_vulnerability_suppressions` is its legacy alias.

#### get_attack_pattern_debug_trace

```
get_attack_pattern_debug_trace(report_id: String) -> String
```

Canonical name; `get_vulnerability_debug_trace` is its legacy alias.

#### get_attack_pattern_detector_status

```
get_attack_pattern_detector_status() -> String
```

Canonical name; `get_vulnerability_detector_status` is its legacy alias.

#### debug_run_attack_pattern_detector_tick

```
debug_run_attack_pattern_detector_tick() -> String
```

Canonical name; `debug_run_vulnerability_detector_tick` is its legacy alias.

#### export_attack_pattern_finding_details

```
export_attack_pattern_finding_details(request_json: String) -> String
```

Export a neutral, consumer-agnostic diagnostic record for a single attack-pattern finding currently held in vulnerability history. The `request_json` envelope is `{ "finding_key": "<key>" }`. On success, returns:

```json
{
  "success": true,
  "details": {
    "finding_key":      "<key>",
    "finding":          { /* VulnerabilityFinding */ },
    "report_id":        "<uuid>",
    "report_timestamp": "<ISO8601>",
    "debug_trace":      { /* VulnerabilityDebugTrace */ } | null,
    "captured_at":      "<ISO8601>",
    "core_version":     "<X.Y.Z>",
    "platform":         "macos" | "linux" | "windows" | "ios" | "android",
    "host_label":       "<hostname>"
  }
}
```

On failure, returns `{ "success": false, "error": "..." }`. The `debug_trace` field carries the full `VulnerabilityDebugTrace` (including the `input_snapshot` used for replay) when the daemon was started with `set_keep_history_debug_traces { keep: true }`, and `null` otherwise.

This RPC is consumer-neutral by design. Known consumers:

- **FP corpus capture**: piped through `edamame_core/tools/fp_corpus_from_export.sh <export.json> <FP-ID>` to produce a Shape A or Shape B entry under `edamame_core/tests/fp_corpus/<FP-ID>/`, replayed by `cargo test --test fp_replay`.
- **Operator bug reports**: paste raw JSON into a JIRA / GitHub issue.
- **Adversarial regression fixtures**: copy raw JSON into the adversarial test corpus.
- **Support escalation**: customer attaches raw JSON to a support ticket for offline replay.
- **Detector forensics**: `jq '.details.debug_trace.llm_decision'` to inspect past LLM adjudication.

### Recurrence-Aware Dismissal Rules

Operator-only dismissal-rule plane: every `agentic_*_dismissal*` RPC mutates EDAMAME's local dismissal store and is **not** exposed via MCP (per the observer-independence policy). Rules dismiss vulnerability or divergence findings under explicit scopes (`finding`, `process_for_check`, `process_lineage`, `process_and_material_class`, `agent_workspace_pattern`, `folder_context`) with optional TTL and a severity ceiling that controls whether the rule may suppress CRITICAL findings.

Since 2.0 the same store holds the `session` domain: network-session dismissals under the scopes `destination` (matcher `destination_ip` + `destination_port`, plus `process_name` / `process_path` when the session is attributed), `destination_port` (`destination_port`, plus the process when attributed) and `process` (`process_name` or `process_path`). Session scopes are rejected on the finding domains and the finding scopes on the session domain. Session rules carry the fixed severity `HIGH` and are created by the `add_dismiss_rule_from_*` RPCs above or directly through `agentic_add_dismissal_rule`.

#### agentic_dismiss_with_scope

```
agentic_dismiss_with_scope(request_json: String) -> String
```

The single entry point for adding a dismissal rule (the lower-level `agentic_add_dismissal_rule` RPC was retired on 2026-09-19, nothing called it): dismiss a single finding under a chosen scope, auto-filling the matcher when `scope = "finding"`. The `request_json` envelope carries the rule fields (`scope`, `matcher`, `reason`, ...) plus a top-level `finding_key`. Returns `{ "success": bool, "error"?: string }`. The previously returned `rule_id` field was structurally dead (no consumer read it) and has been removed; the underlying rule is still persisted internally and accessible via `agentic_get_dismissal_rules`.

#### agentic_report_dismissal

```
agentic_report_dismissal(request_json: String) -> String
```

Operator-initiated, opt-in report of a vulnerability or divergence dismissal to the EDAMAME backend. Mirrors the device-feedback `dislike_device_type` shape: this RPC does NOT change local policy (the dismissal rule is already applied via `agentic_dismiss_with_scope` before this is called) -- it only sends the operator's feedback. Carries the matcher fields, the dismissal scope/severity ceiling/TTL, agent identity, and an optional consent note + email. The core attaches, from its own history, what the adjudicator saw and said about the finding (`adjudication`: detector report id, decision source, per-finding model verdict and reasoning, pre-adjudication severity, guardrail tier, detection basis, and the `FindingEvidence` packet and CRS score as JSON), so every reported dismissal is stored as a (features, model verdict, human verdict) row; callers pass nothing extra for it. Returns `{ "success": bool, "error"?: string }`. Since 2.0 the EDAMAME Portal is the only destination (the Hub e-mail copy is gone) and the call is no longer best-effort: it returns `{"success": false, "error": ...}` when the Portal post fails or when the device has no Portal identity (an EDAMAME API key, or a Portal sign-in with valid tokens) -- an own model alone gives none, so the app offers the report only with a Portal identity. The local dismissal stays applied either way.

#### agentic_remove_dismissal_rule

```
agentic_remove_dismissal_rule(rule_id: String) -> String
```

Remove a dismissal rule by id. Returns `{ "success": bool, "removed": bool, "error"?: string }`.

#### agentic_list_dismissal_rules

```
agentic_list_dismissal_rules(domain: String) -> String
```

List dismissal rules. `domain` may be `""` (all), `"vulnerability"`, `"divergence"`, or `"session"`. Returns `{ "success": true, "rules": [DismissalRuleAPI, ...] }`. `DismissalRuleMatcherAPI` carries the optional `destination_ip` (canonical address text) used by the session `destination` scope.

#### agentic_list_dismissal_audit_log

```
agentic_list_dismissal_audit_log(limit: u32) -> String
```

List the dismissal audit log, newest first. `limit = 0` uses the bounded default read limit. Returns `{ "success": true, "entries": [DismissalAuditEntryAPI, ...] }`.

#### agentic_reset_dismissal_rules

```
agentic_reset_dismissal_rules() -> String
```

Remove every dismissal rule. Returns `{ "success": true, "changed": bool }` indicating whether any rules were actually cleared.

#### agentic_prune_expired_dismissal_rules

```
agentic_prune_expired_dismissal_rules() -> String
```

Force a single sweep that removes any dismissal rules whose `ttl_secs` has elapsed. Returns `{ "success": true, "removed": <count> }`. The detector tick performs this sweep automatically; this RPC is for operator-driven maintenance.

### Agent Plugins (read-only registry; mutators retired 1.7.0)

**Retired in EDAMAME 1.7.0:** `provision_agent_plugin`, `get_agent_plugin_status`,
`test_agent_plugin`, `get_agent_plugin_health`, and `uninstall_agent_plugin` were
removed from the product. Host-side transcript observation is automatic; Level-2
plugin install is no longer exposed. **`list_agent_plugins` remains** for registry
metadata and UI icons.

#### list_agent_plugins

```
list_agent_plugins() -> String
```

Returns a JSON array of supported agent types with registry metadata (display name,
repo, strategy kind, sort order, discovery layout). Read-only; no install state in 1.7.0+.

<!-- RETIRED 1.7.0 -- the following RPCs are documented for historical reference only:
get_agent_plugin_status, provision_agent_plugin, test_agent_plugin,
get_agent_plugin_health, uninstall_agent_plugin -->

### External Transcript Observer

Per-agent host-side observer that reads each discovered agent's transcripts from disk and feeds the existing `upsert_behavioral_model_from_raw_sessions` pipeline (see `AGENTIC.md`). Discovery (`discovered`: transcript root on disk) is independent of both plugin install (`installed`) and product presence (`installed_on_host`: config or instruction root on disk). An agent can be installed on the host before it has ever written transcripts; the inventory lists that as installed, not yet observed. Pausing the observer for a discovered agent trips the corresponding `unsecured_<agent>` internal threat. An installed-but-never-run agent is not unsecured.

#### get_transcript_observer_status

```
get_transcript_observer_status() -> String
```

Returns a JSON snapshot of the per-agent observer state: discovered agents, enabled flag per agent, last tick timestamp, last hash, and any error text. Used by the AI / Config tab and diagnostics.

#### set_transcript_observer_enabled

```
set_transcript_observer_enabled(agent_type: String, enabled: bool) -> String
```

Enable or disable the transcript observer for a specific agent (e.g. `cursor`, `claude_code`, `claude_desktop`, `openclaw`). Disabling a discovered agent's observer trips `unsecured_<agent>`. Returns the updated observer-status JSON.

#### run_transcript_observer_tick_for

```
run_transcript_observer_tick_for(agent_type: String) -> String
```

Force a single observer tick for the given agent without waiting for the scheduled interval. Used by tests and the CLI when developers need a deterministic re-evaluation. Returns the updated observer-status JSON, or an error JSON when the agent type is unknown.

#### get_raw_agent_activity

```
get_raw_agent_activity(agent_type: String, active_window_minutes: u64, limit: u32) -> String
```

Returns the JSON-serialized `CollectResult` produced by the foundation transcript parser (`edamame_foundation::agent_transcripts::collect`) for the given agent -- the same pre-LLM payload that feeds `upsert_behavioral_model_from_raw_sessions` in the transcript observer tick, but without any LLM call. This is the operator surface for inspecting deterministic agent activity (chat text, tool invocations, derived `expected_*` hints) when no LLM provider is configured, or when the caller wants the raw parser view instead of the extrapolated `BehavioralWindow` returned by `get_behavioral_model` / `get_behavioral_model_contributors`.

`agent_type` is one of `cursor`, `claude_code`, `claude_desktop`, `codex`, `openclaw`. Unknown agent types return an empty payload + diagnostics (`transcripts_root_accessible: false`) rather than an error so operator-side discovery probing is well-defined.

Windowing matches the LLM ingest path: the parser keeps the most recently modified `limit` sessions whose mtime falls within the last `active_window_minutes`. Pass `0` for either parameter to fall back to the observer defaults (`limit=3`, `active_window_minutes=30`). On the macOS app path the call crosses the sandbox via the helper daemon; on standalone / posture CLI it reads the user's real home directory directly.

The returned JSON has shape `{ "payload": CollectedPayload, "diagnostics": CollectDiagnostics }`. `payload.sessions[*].derived_expected_traffic` / `derived_expected_file_access` / `derived_expected_commands` carry the deterministic hints the parser was able to extract from `user_text` / `assistant_text` / tool invocations; the LLM extrapolation step adds the broader `expected_*` / `not_expected_*` slices on top of these hints when a provider is configured.

### Agent Economics

LLM-free economics reads over the same transcripts the observer parses, plus EDAMAME's own configured-provider call telemetry. These back the Agents tab Fleet / Behavior surfaces and the economics posture commands. No LLM call is made to produce them.

#### get_agent_run_economics

```
get_agent_run_economics(active_window_minutes: u64, limit: u32) -> String
```

Returns the JSON-serialized per-agent run economics over the window: per agent the token volume (input/output/total), an estimated dollar cost, and per-session breakdowns parsed from the agent's own transcripts. Token figures are exact when the transcript carries usage metadata; the dollar conversion comes from the embedded per-model price table (`cost_is_estimate`). Agents whose transcripts carry no usage (e.g. Cursor's `.txt` export) report `has_token_data = false`. Pass `0` for either parameter to use the economics defaults (24h window, 25 sessions per agent). Dispatch mirrors `get_raw_agent_activity`: the macOS app path crosses the sandbox via the helper per agent; standalone / posture CLI calls the foundation parser directly.

#### get_self_augmentation_report

```
get_self_augmentation_report(window_minutes: u64, agent_type: String, workspace_slug: String) -> String
```

Self-augmentation analytics: joins *used* skills/commands (transcript-mined, historized in the metrics TSDB) against *available* instruction artifacts (agent-global + per-workspace component inventory) and scores how effectively the operator augments their agents with skills, rules, and commands. Returns the JSON-serialized `SelfAugmentationReport`: a composite score plus six radar sub-scores (coverage, utilization, diversity, leverage, efficiency, trend), aggregate totals, the used/dormant/dead skill table, per-workspace context-tax weight, the per-(agent, workspace, skill) usage tree rows, and the skill reference graph edges. Pass `0` for `window_minutes` to use the 24h default. `agent_type` and `workspace_slug` scope the report (empty = all): window usage, the leverage partition, task economics, the usage tree, and the workspace inventory (context tax, coverage, efficiency) are computed from the filtered session set; per-skill lifetime usage stays fleet-wide (the TSDB by-name family carries no agent/workspace dimension) and the trend axis is scoped per agent only when `agent_type` is set. Demo-gated: demo mode returns the curated fixture regardless of scope.

### Enlightenment Coach

On-demand, guardrailed LLM coaching over the deterministic augmentation aggregate (the same scoped report `get_self_augmentation_report` returns). The LLM only ever sees the aggregate JSON, never raw transcripts, and every answer must pass a strict envelope validator (schema, caps, evidence-ref allowlist) or generation fails. Insights are content-addressed by aggregate hash, so identical aggregates never re-call the LLM. User-initiated from the Path UI only — never a background tick. Not exposed via MCP (operator-only).

#### generate_augmentation_coach_insight

```
generate_augmentation_coach_insight(kind: String, window_minutes: u64, agent_type: String, workspace_slug: String) -> String
```

Generate (or return a cached) one coach insight for a template `kind` over the scoped aggregate. `window_minutes` / `agent_type` / `workspace_slug` scope the aggregate exactly like `get_self_augmentation_report` (empty strings = all, `0` = 24h default). Fallible envelope: `{"success": true, "cache_hit": bool, "insight": {...CoachInsightRecord...}}` on success (the UI renders `insight.envelope` and badges `insight.transport`), `{"success": false, "error": "..."}` on failure (unknown `kind`, no LLM transport configured, LLM call failed, or the produced envelope was rejected by the validator).

#### get_augmentation_coach_insights

```
get_augmentation_coach_insights() -> String
```

Return all cached coach insights as a JSON array of `CoachInsightRecord`. Read-only; the UI matches records to its current scope via `scope_key` and decides staleness by comparing each record's `aggregate_hash` against a freshly computed aggregate.

#### get_coach_transport_status

```
get_coach_transport_status() -> String
```

Return coach transport availability as JSON `CoachTransportStatus`: which LLM provider is configured, whether it is usable right now, and the transport label generation would use — so the UI can badge what "Coach me" will do before the user taps it. Read-only.

### In-Agent Fix Runs

Operator-initiated "run it for me" fixes: send a rendered fix prompt (the CloudModel template, never LLM output) to a detected agent CLI with a report-listed workspace as cwd, launched in a real interactive terminal. Always behind an explicit UI confirmation dialog. Guardrails: the agent must have a detected CLI on this host, and the workspace must already be present in the augmentation report. Not an MCP tool (operator-only, I1). Dispatch is three-arm: standalone calls the foundation directly; the desktop app path crosses the sandbox via the helper (which, running as SYSTEM/root, crosses back into the operator's desktop session to open the terminal); unsupported platforms error.

#### run_fix_prompt_in_workspace_interactive

```
run_fix_prompt_in_workspace_interactive(agent_type: String, workspace_path: String, prompt: String) -> String
```

Human-in-the-loop fix run: opens a real terminal window in the operator's desktop session, seeds the fix prompt, and launches the agent's normal interactive TUI so its own approval UI gates each tool call — the operator reads and confirms every step. No auto-approve / print-mode flag (`-p`, `--force`, `--trust`, `exec`) is passed. Session persistence is ON, so the resulting session is recorded and re-graded by the transcript observer like any other. On desktop the privileged helper (SYSTEM on Windows, root on macOS) crosses into the operator's active session to open the terminal (`WTSQueryUserToken` + `CreateProcessAsUserW` on Windows, `launchctl asuser` on macOS); in standalone mode (posture; Linux has no helper) the daemon launches directly, dropping to the operator (`sudo -u` + `DISPLAY`/`XAUTHORITY` discovery on Linux). Fallible envelope: `{"success": true, "spawn": {...CoachFixSpawn: agent_type, binary, workspace_path, pid, command...}}` on success, `{"success": false, "error": "..."}` on failure (no CLI detected, workspace not in the report, terminal launch failed). Interactive runs are not log-captured — the operator watches the live terminal.

### Agent Fleet Command Centre

Fleet-level rollups backing the Agents tab Fleet subtab (fleet health band) and the per-agent drill-down card. Pure joins over state the core already computes (run economics, transcript-observer status, detector status, divergence verdicts, the failure-cluster projection, and metrics-history families) -- no new collection, no LLM call (I3), joined in core so consumers never re-derive fleet state client-side (I2).

#### get_agent_fleet_overview

```
get_agent_fleet_overview(window_minutes: u64) -> String
```

One-call fleet command-centre rollup: headline counts (agents discovered/paused, sessions observed / in error), estimated spend for the window plus today's historized spend, the deterministic waste/friction signal, the security join (active alertable attack-pattern findings, divergence verdict), 24h hourly cost/error sparklines from the metrics TSDB, and the ranked panels (agents by spend, top recurring failure clusters). Returns the JSON-serialized `AgentFleetOverview`. Pass `0` for `window_minutes` to use the 24h default. Demo-gated through its inputs. Also exposed as a read-only MCP tool (I1-safe projection).

#### get_agent_overview

```
get_agent_overview(agent_type: String, window_minutes: u64) -> String
```

Per-agent detail join: everything the per-agent drill-down card needs in one payload -- inventory footprint, observer state, run economics (session list + efficiency), OS confinement + deterministic blast-radius verdict with reasons, host privilege, detected governance harnesses, failure clusters scoped to the agent, per-instance drift summaries, and the agent's augmentation (skills) slice. Returns the JSON-serialized `AgentOverview`. Pass `0` for `window_minutes` to use the 24h default. Demo-gated through its inputs.

#### get_agent_failure_clusters

```
get_agent_failure_clusters(window_minutes: u64, agent_type: String) -> String
```

Failed-intent explorer: deterministic clustering of agent tool errors into recurring failure shapes. Each cluster is keyed by the stable `<tool>|<error_class>` pair (error classes: timeout / permission / not_found / rate_limit / syntax / network / cancelled / other, classified by a fixed keyword pass over the transcript error text -- no LLM, I3). Per cluster: total count, affected agents and session count, first/last seen, trend vs the previous window, and a redacted example snippet only populated when the visibility capture tier allows excerpts (I5). Returns the JSON-serialized `AgentFailureClusterReport`. Re-parses the same transcripts the observer already reads; short-TTL cached. Pass `0` for `window_minutes` to use the 24h default; empty `agent_type` covers all supported agents. Demo-gated. Also exposed as a read-only MCP tool.

### Agent Budgets

Operator-set per-agent daily budgets with staged enforcement (I6: `recommend` -> `confirm`). Budgets are evaluated by the metrics rollup tick against the same TSDB daily buckets the reads report; crossing a cap records a `budget_exceeded` action-history entry (MEDIUM, finding-key deduped per agent x cap x UTC day) plus a runtime notification, and plugs into the existing dismissal model (I4). Operator-only surface: NONE of these are MCP tools (I1).

#### get_agent_budgets

```
get_agent_budgets() -> String
```

Return the JSON-serialized `AgentBudgetReport`: the UTC `day` plus one entry per agent carrying the optional `daily_cost_usd_cap` / `daily_token_cap`, the `enforcement_mode` (`recommend` or `confirm`), today's `cost_today_usd` / `tokens_today` actuals, and the derived `cost_breached` / `tokens_breached` flags.

#### set_agent_budget

```
set_agent_budget(agent_type: String, daily_cost_usd_cap: f64, daily_token_cap: u64) -> String
```

Set or clear the daily budget for one agent type. A cap value `<= 0` clears that cap; when both end up unset the budget entry is removed entirely. The existing enforcement stage is preserved when only the caps are edited (graduation is managed by `set_agent_budget_enforcement`). Fallible: returns the `{"success": bool, "error": "..."}` envelope (validates the agent type and cap values).

#### set_agent_budget_enforcement

```
set_agent_budget_enforcement(agent_type: String, mode: String) -> String
```

Graduate (or revert) one agent's budget between the `recommend` and `confirm` enforcement stages (I6 staged enforcement). Under `confirm` a breach escalates the notification to CRITICAL (never digested) and suggests the pause-observer response action; the breach record itself stays MEDIUM so CI alertable gates are unaffected. Fallible: `{"success": bool, "error": "..."}` envelope (validates the mode and requires an existing budget entry).

### Notification Digest

#### agentic_get_notification_digest_status

```
agentic_get_notification_digest_status() -> String
```

Return the notification digest preference snapshot as JSON: `{enabled, pending_count, last_flush_at}`. When the digest is enabled, Info-severity channel notifications (agentic action reports, divergence CLEARED messages) are queued and flushed as one summary message twice daily instead of being sent instantly; Warning/Critical notifications are never digested. Operator-only, never MCP.

#### agentic_set_notification_digest_enabled

```
agentic_set_notification_digest_enabled(enabled: bool) -> ()
```

Toggle the notification digest preference. Infallible: turning the digest off flushes anything still queued so no notification is stranded. Operator-only, never MCP.

---

## Metrics History

Read-only projection of the durable metrics-history time-series database (TSDB). The core's `metrics_rollup_task` folds per-agent and per-session telemetry into bounded `hourly` and `daily` buckets (token/cost by agent, LLM calls by model, MCP calls by server, network bytes in/out by domain, file events by type, ...), persisted to user-space storage with a retention policy. This is the LLM-free backend for the Agents tab Behavior subtab Trends charts. Requires the `agentic` feature flag.

**Source**: `api/api_metrics.rs`. See `AGENTIC.md` ("Metrics history") in the core repo for the rollup families and retention model.

### get_metrics_history

```
get_metrics_history(family: String, granularity: String, range_minutes: u64) -> String
```

Return the matching metric buckets as a JSON-serialized `MetricsHistoryAPI`: the echoed query (`family`, `granularity`, `range_minutes`, `generated_at`) plus `buckets` (ascending by `start`). Each bucket carries its aligned `start` instant and a `series` array of `{ family, dimension, sum, count, min, max, avg }` entries (`min`/`max` populated only for gauge families; counters leave them `null`). `family = ""` (or `"all"`) returns every family; otherwise pass a canonical family name (e.g. `tokens_total_by_agent`, `est_cost_usd_by_agent`, `llm_calls_total_by_model`, `mcp_calls_by_server`, `net_bytes_in_by_domain`, `net_bytes_out_by_domain`, `files_by_event_type`). `granularity` accepts `hourly` / `daily` (aliases `hour`/`h`, `day`/`d`); an unrecognized granularity returns an `{"error": ...}` object rather than throwing, so callers always get parseable output. `range_minutes` bounds the look-back window from now.

### clear_metrics_history

```
clear_metrics_history() -> ()
```

Clear the durable metrics-history TSDB (the Agents tab "clear history" control). Infallible mutator: a persist failure is logged core-side rather than surfaced. Triggers `AgentMetricsUpdated` so the Flutter tabs refresh at once. Operator-only, never MCP.

---

## Health

Personal health scoring plane (physical activity, rest and recovery, physiological stress indicators, health habits). Data points are pushed by the platform health integrations (HealthKit / Health Connect) through the Flutter bridge; the core folds them into a `HealthAPI` score projection. Requires the `health` feature flag.

**Source**: `api/api_health.rs`.

### get_health

```
get_health(compute_requested: bool) -> HealthAPI
```

Return the current health score projection: per-pillar scores (`physical_activity`, `rest_and_recovery`, `physio_stress_indicators`, `health_habits`), the `overall` score and `stars` rating, plus compute progress metadata (`compute_in_progress`, `compute_progress_percent`, `last_completed_metric`, `last_compute`). When `compute_requested` is `true`, a recompute is requested before the projection is returned; `false` reads the cached state.

### add_point

```
add_point(json: String) -> ()
```

Ingest one health data point. `json` is a serialized `HealthDataPoint` (`data_type`, `value`, `unit`, `date_from`, `date_to`, `platform_type`, `device_id`, `source_id`, `source_name`). Infallible mutator: a malformed payload is logged and dropped core-side rather than surfaced to the caller.

---

## File Integrity Monitoring (FIM)

File integrity monitoring engine. Watches a configured set of paths for create / modify / rename / delete events, hashes content with BLAKE3 (subject to `fim_hash_size_threshold`), and feeds events into the attack pattern detector for sensitive-path / temp-staging analysis. Requires the `fim` feature flag.

**Source**: `api/api_fim.rs`. See `FIM.md` in the core repo for the engine architecture and helper/standalone convergence story.

### start_file_monitor

```
start_file_monitor(paths: Vec<String>) -> ()
```

Start the FIM watcher on the supplied list of root paths. When `paths` is empty, the engine falls back to the converged default set computed by `edamame_foundation::fim_support`. The watcher initialization is non-blocking (the recursive `notify` walk runs on `spawn_blocking` so the gRPC handler returns promptly even on hosts with very large watch trees). This is the operator's switch: a monitor started (or taken over) here survives the attack pattern detector stopping on its own, while one the detector started stops once neither detection engine runs; `agentic_set_protection(false)` stops it either way.

### stop_file_monitor

```
stop_file_monitor() -> ()
```

Stop the FIM watcher and release its inotify / FSEvents / ReadDirectoryChangesW handles. Also clears the mark of a monitor the detector started.

### get_file_events

```
get_file_events() -> FimSnapshotAPI
```

Return the rolling snapshot of recent FIM events (path, kind, timestamp, hash, writer process attribution when available). The snapshot is a bounded window; older events fall off as the buffer fills.

The `hash` field is BLAKE3 over the file content and is populated **only when the event's `is_sensitive` flag is set** (i.e. the path matches `flodbadd::open_files::is_sensitive_path`). Non-sensitive events kept under a temp-staging root (`/tmp/`, `%TEMP%\AppData\Local\Temp\`, ...) or under an operator-supplied explicit watch root carry `hash == null` regardless of file size. This is intentional (FP-CI-2): hashing non-sensitive transient build artifacts on Windows races with build-tool exclusive opens, and the deterministic attack pattern detector only consumes `hash` for change-tracking of sensitive findings. `size` is always populated.

### get_file_monitor_status

```
get_file_monitor_status() -> FileMonitorStatusAPI
```

Return the watcher state: running flag, watch root list, last-error string, and per-platform engine details. Used by the UI and the vulnerability gate's `dump_vulnerability_findings: true` step.

### clear_file_events

```
clear_file_events() -> ()
```

Truncate the in-memory FIM event buffer. Operator-driven hygiene; equivalent to `edamame_cli rpc clear_file_events`.

## Privacy

Privacy preferences toggles for analytics, crash reporting, and AI failure-detail export to Hub. Persisted on disk and applied at runtime where possible. Persisted struct: `PrivacyPreferences` (see core repo invariants -- new fields MUST add `#[serde(default)]`).

**Source**: `api/api_privacy.rs`

### get_privacy_preferences

```
get_privacy_preferences() -> PrivacyPreferencesAPI
```

Return the current privacy preferences as a struct: `analytics_enabled`, `crash_reports_enabled`, `export_ai_failure_details`. Used by the Privacy settings tab.

### set_analytics_enabled

```
set_analytics_enabled(enabled: bool) -> ()
```

Persist the analytics toggle and apply it to the live analytics instance. The launch-time `CoreOptions.analytics_enabled` is the outer gate; this preference toggles the inner gate. When the user enables analytics here but the launch-time toggle was false (CLI), the inner gate is still flipped so any future re-init picks up the new preference.

### set_crash_reports_enabled

```
set_crash_reports_enabled(enabled: bool) -> ()
```

Persist the crash-reports toggle. Crash reports are honored at app launch only; flipping this at runtime takes effect on next launch (the Flutter UI surfaces this with a snackbar).

### set_export_ai_failure_details

```
set_export_ai_failure_details(enabled: bool) -> ()
```

Persist whether structured AI posture failure facts may be included on Hub `report_score`. Default is `false` (consumer opt-in). Facts are metadata-only (agent names, process basenames, harness slugs, secret labels) — never transcripts, env values, or secret content. Posture/Intune can force export via `EDAMAME_EXPORT_AI_FAILURE_DETAILS` / `--export-ai-failure-details` regardless of this toggle; the report's `ai` detail bundle then carries `mode: "forced"`.

### get_consent_document

```
get_consent_document(document: String, locale: String) -> String
```

Return operator-facing consent markdown. Tries `raw.githubusercontent.com/edamametechnologies/threatmodels/{branch}/consent/` first, then the snapshot embedded by `edamame_foundation/update-threats.sh`. `document` is one of `compliance-scanner`, `user-feedback`, `profiling-feedback`, `request-report`, `vulnerability-feedback`, `privacy-LLM`, `privacy-detailed`, `privacy-detailed-ai`. `locale` is `EN` or `FR` (anything else falls back to English). Unknown ids return an empty string.

---

## Agent Visibility

Agent-visibility surface spanning MCP discovery, component inventory, capability graph,
recursion, flight recorder, drift timelines, and data-flow / memory / A2A maps.
**Retired 1.7.0:** tool-call firewall (INC-10), ADR response/case export (INC-11),
and policy pack / attestation / zone-promotion RPCs (INC-13). Prevention via
**nono** / **srt** harnesses on blast radius. The first-seen agent classification
(`acknowledged` / `new` / `shadow`) and its `acknowledge_agent` /
`unacknowledge_agent` mutators were removed too: the observer is on by default,
so the only operator-relevant state is "discovered on disk but not observed",
derived from the inventory row's footprint booleans and reported as the
`unsecured_<agent>` internal threat. Requires the `agentic` feature flag.

Observer-independence (I1): read RPCs may be exposed as read-only MCP tools where
still compiled; mutators are operator/UI only. See `VISIBILITYIMPROVEMENTS.md`.

**Source**: `api/api_visibility.rs`

### refresh_agent_visibility

```
refresh_agent_visibility() -> String
```

Force a structural visibility recollection (MCP discovery + component inventory + capability graph). Returns a `{"success": bool, ...}` envelope; on success carries `endpoint_count`, `finding_count`, `component_inventory_count`, and `graph_edge_count`. Most callers can rely on the lazy `ensure_*` refresh in the read RPCs instead of calling this explicitly.

### agentic_approve_mcp_tool_baseline

```
agentic_approve_mcp_tool_baseline(endpoint_key: String) -> String
```

Accept the current tool definitions of one MCP server (`endpoint_key` = `<agent_type>|<server_name>`) as the approved baseline, which clears its `mcp_tool_definition_changed` finding (the rug-pull shape: a server now advertising a different tool surface than the one approved) and the `mcp_risk` threat it raises; the structural visibility pass re-runs at once. Fallible envelope `{"success": bool, "error": "..."}` (unknown key: refresh agent visibility first). Operator control plane only: never an MCP tool (listed in `FORBIDDEN_MCP_MUTATORS`, since the observed agent must not approve its own rug pull) and not on the Flutter bridge; call it through `edamame_cli rpc`. Retired in 2.0 as caller-less and restored before release: without it a changed server kept its finding for good.

### get_visibility_summary

```
get_visibility_summary() -> VisibilitySummaryAPI
```

Return a compact typed summary across all visibility domains: snapshot timestamp/presence, MCP endpoint/finding counts (with HIGH/CRITICAL breakdown), component-inventory and component counts, capability-graph edge count, recursion tree/loop counts and max delegation depth, and the total alertable finding count. Used by the top-level Agents tab header and badges. Lazily ensures both the structural and recursion snapshots are fresh.

### get_mcp_inventory

```
get_mcp_inventory() -> String
```

Return the full MCP inventory as JSON (`McpInventory`): discovered endpoints plus the findings derived from them, with a `generated_at` timestamp. Lazily ensures a fresh structural snapshot.

### get_mcp_endpoints

```
get_mcp_endpoints() -> String
```

Return just the discovered MCP endpoints as a JSON array (`Vec<McpEndpoint>`) -- transport, exposure scope, auth strength, and per-tool privilege classification. Lazily ensures a fresh structural snapshot.

### get_mcp_findings

```
get_mcp_findings() -> String
```

Return just the MCP risk findings as a JSON array (`Vec<VisibilityFinding>`) -- severity-graded issues such as unauthenticated or network-exposed endpoints and over-privileged tool surfaces. Lazily ensures a fresh structural snapshot.

### get_agent_component_inventories

```
get_agent_component_inventories() -> String
```

Return the per-agent component inventory as a JSON array (`Vec<AgentComponentInventory>`): the agent runtime plus its installed plugins/skills/MCP components. Feeds the constellation view and the self-augmentation instruction-component discovery. Lazily ensures a fresh structural snapshot.

### get_capability_graph

```
get_capability_graph() -> String
```

Return the agent capability graph as a JSON array of edges (`Vec<GraphEdge>`): which agents can reach which tools/MCP endpoints/resources, each annotated with a confidence level. Lazily ensures a fresh structural snapshot.

### get_graph_reachability

```
get_graph_reachability() -> String
```

(INC-10) Return per-agent trust-zone reachability over the declared capability graph as a JSON array. Trust zones: `trust0` (agent identity), `trust1` (local service boundary -- stdio/loopback MCP servers, tool classes), `trust2` (untrusted surface -- LAN/public/unknown endpoints). Each entry carries `agent_type`, `reachable_node_count`, `max_zone`, `crosses_to_untrusted`, and the `boundary_edge_ids` that cross out to trust2. Lazily ensures a fresh structural snapshot.

### get_effective_capabilities

```
get_effective_capabilities() -> String
```

(INC-10) Return per-agent effective (transitively reachable) capability classes over the declared capability graph as a JSON array. Each entry carries `agent_type`, the deduped human-readable `capabilities` set (e.g. `Shell`, `Git`), `high_privilege` (a filesystem/shell/network-class capability is reachable), and `reaches_untrusted` (a trust2 node is reachable). Reveals the real capability surface beyond an agent's directly-declared tools. Lazily ensures a fresh structural snapshot.

### get_host_blast_radius

```
get_host_blast_radius() -> String
```

(C3 / INC-10) Return the host blast-radius bundle as a JSON envelope -- `host_privilege` (the shared host-privilege assessment: admin membership / passwordless-root / elevated session), `agent_sandboxes` (per-agent OS-confinement assessment), `harnesses` (one entry per known AI agent governance harness -- AgentField, Rippletide, ... -- each with a `detected` flag plus the on-disk evidence that matched), and `blast_radius_agents` (the canonical per-agent blast-radius verdicts, the same deterministic rule the score threat uses, scoped to the present sandboxes). Answers "if any agent here is compromised, what can it reach on this machine without further authentication, is it OS-confined, and is it wrapped by a governance harness?". Informational, never alertable.

### get_recursion_risk

```
get_recursion_risk() -> String
```

Return the recursive/delegation-detection result as a JSON array (`Vec<DelegationTree>`): reconstructed agent spawn/delegation trees with max depth, loop-detection flag, and severity-graded findings for unbounded recursion. Lazily ensures a fresh recursion snapshot.

### refresh_run_provenance

```
refresh_run_provenance() -> String
```

(INC-5 flight recorder) Force a rebuild of the append-only, hash-chained run-provenance index. Returns `{"success": true, "run_count": N}`. Reads refresh lazily, so this is only needed to force an immediate recompute.

### list_recent_runs

```
list_recent_runs() -> String
```

(INC-5) Return the run-provenance index as a JSON array: one summary per recorded reasoning run (`run_id` = `agent_type::agent_instance_id::session_key`, timestamps, event/alertable counts, max severity, chain-valid flag). Lazily ensures a fresh index.

### get_run_provenance

```
get_run_provenance(run_id: String) -> String
```

(INC-5) Return the full flight record for one run as JSON: the ordered, replayable, hash-chained event stream (`session_start` -> `tool_call`/`command`/`expected_egress` -> `divergence_verdict` -> `divergence_evidence` -> `session_end`), each event carrying plane/kind/summary/severity and `prev_hash`/`hash` links, plus the causal edges and `max_severity`/`alertable_event_count`/`chain_valid`. Returns `{}` when the run is unknown.

### explain_run_event

```
explain_run_event(run_id: String, event_id: String) -> String
```

(INC-5) Prove why one recorded event happened: returns the causal backtrace (chronological ancestor chain walked transitively into the target), the downstream descendants, the edges traversed, `backtrace_complete`, and `chain_valid`. Returns `{}` when the run/event is unknown.

### list_structural_runs

```
list_structural_runs() -> String
```

LLM-free structural flight recorder index. Returns a JSON array of run summaries projected directly from raw agent transcripts -- the reasoning-plane session lifecycle (session start -> tool calls / commands / declared egress -> session end) with NO divergence correlation and NO behavioral-model predictions. This is the LLM-free Agents-tab counterpart to the divergence-correlated `list_recent_runs`. Built on demand (like `get_agent_run_economics`); no refresh mutator. Observer-independence (I1): exposed as a read-only MCP tool.

### get_structural_run_provenance

```
get_structural_run_provenance(run_id: String) -> String
```

Return the full structural flight record for one run as JSON (pass a `run_id` from `list_structural_runs`): the ordered, replayable event stream projected from the transcript, with NO divergence verdicts or behavioral-model predictions. Returns `{}` when the run is unknown. Read-only MCP-safe (I1).

### explain_structural_run_event

```
explain_structural_run_event(run_id: String, event_id: String) -> String
```

Causality-map drill-in for the LLM-free structural recorder: given a `run_id` from `list_structural_runs` and an `event_id` from that run's flight record, walks the run's hash-chained causal edges and returns the JSON-serialized `RunEventExplanation` -- the event itself, its `ancestors` ("prove why" backtrace toward the session root), its `descendants` (downstream impact), the traversed `edges`, plus `backtrace_complete` (the ancestor walk reached the session root) and `chain_valid` (the hash chain verified). Returns `{}` when the run or event is unknown. Read-only projection; MCP-safe (I1).

### refresh_agent_drift

```
refresh_agent_drift() -> String
```

(INC-6 goal/delegation drift) Force a re-projection of divergence history + recursion analysis into per-agent drift timelines. Returns `{"success": true, "agent_count": N}`. Reads refresh lazily.

### get_agent_drift

```
get_agent_drift() -> String
```

(INC-6) Return all per-agent drift timelines as a JSON array, highest peak drift first. Each agent (keyed `agent_key` = `agent_type::agent_instance_id`) carries its ordered drift events (category, point-in-time `drift_score` 0-100, severity, backing divergence finding keys), `peak_drift_score`, `current_drift_score`, and whether it is currently diverging. Drift is a deterministic re-projection of divergence history, not a new judgement.

### get_agent_drift_timeline

```
get_agent_drift_timeline(agent_key: String) -> String
```

(INC-6) Return one agent's full drift timeline as JSON (pass `agent_key` from `get_agent_drift`): the ordered drift events with per-event score/severity/category, backing divergence finding keys and process paths, plus peak/current scores and the delegation summary. Returns `{}` when the agent is unknown.

### explain_agent_drift

```
explain_agent_drift(agent_key: String, event_id: String) -> String
```

(INC-6) Prove why one drift event fired: returns the category and score band, the contributing divergence findings, the prior verdict state it moved from, and a human-readable rationale of which signals drove the score. Returns `{}` when the agent/event is unknown.

### refresh_dataflow_maps

```
refresh_dataflow_maps() -> String
```

(INC-7 sensitive data-flow) Force a rebuild of per-agent latent source->sink data-flow maps (observed-upgraded by divergence taint evidence). Returns `{"success": true, "agent_count": N}`. Reads refresh lazily.

### get_dataflow_maps

```
get_dataflow_maps() -> String
```

(INC-7) Return all per-agent data-flow maps as a JSON array: latent `source -> sink` edges (credential store, file, network egress, ...) per agent, each marked `latent` (config-derived) or `observed` (corroborated by divergence taint evidence), with a severity for sensitive-sink reach.

### get_dataflow_map

```
get_dataflow_map(agent_type: String) -> String
```

(INC-7) Return one agent's data-flow map as JSON (pass `agent_type`). Returns `{}` when no map exists for that agent.

### refresh_memory_inventory

```
refresh_memory_inventory() -> String
```

(INC-8 memory/RAG inventory) Force a rebuild of the persistent agent memory / RAG store inventory. Returns `{"success": true, "store_count": N}`. Reads refresh lazily.

### get_memory_inventory

```
get_memory_inventory() -> String
```

(INC-8) Return the memory/RAG inventory as JSON: discovered persistent context stores (vector DBs, memory files, RAG corpora) each agent can read/write, with scope and a poisoning-risk severity.

### refresh_a2a_graph

```
refresh_a2a_graph() -> String
```

(INC-9 agent-to-agent surface) Force a rebuild of the A2A peer graph. Returns `{"success": true, "peer_count": N, "cross_zone_edge_count": M}`. Reads refresh lazily.

### get_a2a_graph

```
get_a2a_graph() -> String
```

(INC-9) Return the agent-to-agent surface map as JSON: discovered inter-agent communication peers and the `cross_zone_edges` where one agent can reach another across a trust boundary, severity-graded.

### get_owasp_scorecard

```
get_owasp_scorecard() -> String
```

Return the OWASP GenAI crosswalk scorecard as JSON: static per-category coverage grades (from `OWASPGENAI.md`) plus live finding attribution parsed from the `OWASP-<id>` reference tokens already carried by visibility and attack-pattern findings, with the `headline_status` (`clean`/`attention`/`critical`) derived directly from the attributed alertable findings. Read-only, derived; no separate refresh. MCP-safe read.

### get_trust_controls_scorecard

```
get_trust_controls_scorecard() -> String
```

Return the Trust Controls (trustcontrols.ai) scorecard as JSON: static per-control coverage grades and enforcement flags (from the trustcontrols.ai catalog, encoded in `edamame_foundation::agent_trust_controls`) plus live finding attribution that reuses the same `OWASP-<id>` reference pipeline, with the `headline_status` derived directly from the attributed alertable/critical findings. The trustcontrols.ai counterpart to `get_owasp_scorecard`. Read-only, derived; no separate refresh. MCP-safe read.

### get_atlas_scorecard

```
get_atlas_scorecard() -> String
```

Return the MITRE ATLAS runtime detection coverage map as JSON: the scoped catalog of ATLAS techniques a host/network runtime observer can actually see (39 parent techniques across 12 tactics, encoded in `edamame_foundation::agent_atlas`), each with a static coverage grade, a `coverage_rationale` naming the backing telemetry, and live finding attribution. Grouped by tactic in matrix order as `tactics: [{tactic_id, tactic, rows: [...]}]`, with `technique_count` so a consumer can state the denominator against the 170+ ATLAS publishes. Techniques outside a runtime observer's reach (training-time poisoning, model theft, adversary research infrastructure) are absent from the catalog rather than reported as uncovered.

Unlike `get_trust_controls_scorecard`, this does **not** re-project the `OWASP-<id>` pipeline: findings carry their own `AML.T<id>` reference tokens, so a technique row is independent evidence. Each row's `owasp_refs` is a displayed cross-reference only. `headline_status` is derived from the attributed alertable findings on the same rule as the sibling scorecards. Read-only, derived; no separate refresh.

**Not an MCP tool (operator-only).** Every row's `coverage_rationale` names the exact telemetry that backs or fails to back a detection claim, which in a reasoning plane is an evasion guide. Read-only is not sufficient justification for MCP exposure when the content itself is the hazard.

### get_agent_subprocess_usage

```
get_agent_subprocess_usage(window_minutes: u64) -> String
```

Return agent critical-subprocess usage as JSON -- read-only, derived, LLM-free. Reveals which discovered agents are/have been spawning `ssh`/`scp`/`nc`/shells/`docker`/... by classifying the L7 process lineage on captured sessions and attributing it to a known agent identity. Findings are capped at MEDIUM (reveal, not alert) and demo-guarded in the CoreManager method. `window_minutes` selects the timeline projection: `0` = live capture horizon (used by blast radius + the MCP read tool); `>0` = project the retained 30-day history over that many minutes (the UI's 24h / 7d / 30d selector). MCP-safe read.

<!-- RETIRED 1.7.0: tool-call firewall + pre-execution enforcement RPCs removed.
Historical names: get_firewall_status, get_firewall_evaluations, refresh_firewall_evaluations,
set_firewall_mode, get_agent_enforcement_capabilities, evaluate_pre_execution_tool_call,
get_pending_tool_calls, resolve_pending_tool_call. Prevention: nono/srt harnesses on blast radius. -->

<!-- RETIRED 1.7.0: ADR response / case export (INC-11) removed.
Historical names: get_response_action_catalog, get_response_action_history,
request_response_action, undo_response_action, export_visibility_case. -->

<!-- RETIRED 1.7.0: policy packs / attestation / zone promotion (INC-13) removed.
Historical names: get_policy_pack, get_policy_evaluation, refresh_policy_evaluation,
set_policy_pack, simulate_policy_pack, attest_policy_evaluation, get_policy_attestations,
get_zone_promotions, request_zone_promotion, decide_zone_promotion. -->

### get_agent_inventory

```
get_agent_inventory() -> String
```

Return the operator agent inventory as a JSON array: every supported agent with any footprint on this host, each with `agent_type`, `display_name`, presence booleans, and per-agent endpoint/component/alertable counts. Presence flags are independent:

- `installed` -- an EDAMAME plugin is present in the agent's MCP config
- `installed_on_host` -- the agent product itself has an on-disk footprint (config or instruction root). An agent in daily use can be installed on the host before it has ever written transcripts
- `discovered` -- a transcript root is present on disk (the agent has been observed writing sessions)
- `observer_enabled` -- the host-side transcript observer is watching this agent

An agent with a footprint on disk (`discovered` or `installed_on_host`) whose
`observer_enabled` is false is running unobserved -- the same condition the
`unsecured_<agent>` internal threat reports. There is no separate classification
axis; the observer is enabled by default for every agent, so an unobserved agent
is always the result of an explicit operator pause.

MCP-safe read.

> Removed in 1.7.0: the `classification` (`acknowledged` / `shadow` / `new`) and
> `acknowledged` fields, along with the `acknowledge_agent` /
> `unacknowledge_agent` mutators (legacy wire names `approve_agent` /
> `revoke_agent_approval`). Derive the unobserved state from the booleans above,
> and use `set_transcript_observer_enabled` to change it.

### get_visibility_capture_tier

```
get_visibility_capture_tier() -> VisibilityCaptureTierAPI
```

Return the current visibility data-capture privacy tier (`metadata_only`, `redacted_excerpt`, or `forensic_full_content`) with its human-readable label and description. Backed by the persisted `PrivacyPreferences.visibility_capture_tier` (privacy tier I5).

### set_visibility_capture_tier

```
set_visibility_capture_tier(tier: String) -> String
```

Set the visibility data-capture privacy tier. Accepts `metadata_only`, `redacted_excerpt`, or `forensic_full_content`. Returns a `{"success": bool, ...}` envelope; on success echoes the persisted `tier`, on failure carries an `error` describing the accepted values. Persisted to `PrivacyPreferences`.

### get_instruction_content

```
get_instruction_content(path: String, requested_tier: String) -> String
```

Read a single on-disk instruction artifact (skill / command / rule) body so the Augmentation drill-down can show what a skill actually contains. The `requested_tier` is clamped to the persisted `visibility_capture_tier` ceiling (I5): `metadata_only` returns an empty body (path + size only), `redacted_excerpt` a bounded head slice with secret-like spans masked, `forensic_full_content` a bounded full body (break-glass; audited). The path is re-validated on the privileged side (confined to recognized instruction artifacts under the user's home dir), so this can never become an arbitrary-file read. Returns the JSON-serialized `InstructionContentResult`; callers read its `found` / `error` fields -- a tier-refused or absent body is a normal displayable outcome, not an exception.

### reveal_path_in_file_manager

```
reveal_path_in_file_manager(path: String) -> String
```

Reveal a transcript or instruction path in the OS file manager (Finder / Explorer / xdg-open). On macOS the sandboxed app cannot open paths under the real home via `Uri.file`; this RPC runs on the privileged helper (or in-process under `standalone`), resolves dash-encoded workspace slugs such as `-Users-me-code-repo` to `~/.claude/projects/<slug>` when present, confines the target under the user's home, and opens it. Returns JSON `{"success": bool, "opened_path": "...", "error": "..."}`.

---

## MCP Server

Model Context Protocol server management and pairing. Requires the `mcp` feature flag (which implies `agentic`).

**Source**: `api/api_agentic.rs` (MCP section)

### mcp_start_server

```
mcp_start_server(port: u16, psk: String, enable_cors: bool, listen_all_interfaces: bool) -> String
```

Start the MCP server. PSK must be at least 32 characters when using shared PSK mode.

### mcp_stop_server

```
mcp_stop_server() -> String
```

Stop the running MCP server.

### mcp_get_server_status

```
mcp_get_server_status() -> String
```

Returns the MCP server status (running/stopped, port, etc.).

### mcp_generate_psk

```
mcp_generate_psk() -> String
```

Generate a cryptographically secure base64 PSK suitable for shared-PSK mode
(at least 32 characters, satisfying `mcp_start_server`'s minimum). Pure
random-bytes-plus-base64 with no core state, so unlike every other method here
it is also callable without an initialized runtime -- which is what lets
`edamame-posture mcp-generate-psk` run as a standalone CLI command.

### mcp_approve_pairing

(Flutter bridge: `mcpApprovePairing`)

```
mcp_approve_pairing(request_id: String) -> String
```

Approve a pending pairing request. The client receives its credential when polling `GET /mcp/pair/:request_id`. Called by the host app when the user approves in the pairing UI.

### mcp_reject_pairing

(Flutter bridge: `mcpRejectPairing`)

```
mcp_reject_pairing(request_id: String) -> String
```

Reject a pending pairing request. Called by the host app when the user rejects in the pairing UI.

### mcp_list_paired_clients

(Flutter bridge: `mcpListPairedClients`)

```
mcp_list_paired_clients() -> String
```

Returns a JSON array of all paired clients with their metadata (client_id, client_name, agent_type, agent_instance_id, created_at, etc.).

### mcp_get_pending_pairing_requests

(Flutter bridge: `mcpGetPendingPairingRequests`)

```
mcp_get_pending_pairing_requests() -> String
```

Returns a JSON array of pending pairing requests awaiting user approval (request_id, client_name, agent_type, agent_instance_id, requested_endpoint, workspace_hint, created_at, etc.).

### mcp_revoke_paired_client

(Flutter bridge: `mcpRevokePairedClient`)

```
mcp_revoke_paired_client(client_id: String) -> String
```

Revoke a paired client. The client's credential is invalidated and the client can no longer connect.

### mcp_rotate_paired_client

(Flutter bridge: `mcpRotatePairedClient`)

```
mcp_rotate_paired_client(client_id: String) -> String
```

Rotate a paired client's credential. Returns the new credential. The old credential is invalidated.

### mcp_delete_paired_client

```
mcp_delete_paired_client(client_id: String) -> String
```

Permanently delete a previously revoked paired client from the persistent registry. Unlike `mcp_revoke_paired_client`, which keeps the entry for audit and can be reactivated by the user, `mcp_delete_paired_client` removes the row outright. Only operates on clients that are already revoked; returns an error JSON otherwise.

### MCP Tool Surface

The MCP server exposes a subset of these RPCs as MCP tools from `mcp/handler.rs`. The canonical, authoritative list lives in [`MCP.md`](./MCP.md) (see "Tool Summary"). Per the observer-independence policy, mutating dismissal / observer-state RPCs are RPC-only and intentionally excluded from MCP tools (see `MCP.md` "Observer-Independence Policy").

Lifecycle controls such as `start_divergence_engine`, `start_vulnerability_detector`, `set_divergence_adjudication_mode`, `set_vulnerability_adjudication_mode`, `agentic_set_auto_processing`, `clear_behavioral_model`, `start_file_monitor`, and `stop_file_monitor` remain direct API/CLI operations and are intentionally excluded from MCP tools.

---

## Test Utilities

Notification trigger methods for testing event delivery and UI notifications.

**Source**: `api/api_test.rs`

| Method | Returns | Triggers |
|--------|---------|----------|
| `trigger_blacklisted_session_notification` | String | Simulated blacklisted session alert |
| `trigger_anomalous_session_notification` | String | Simulated anomaly alert |
| `trigger_device_notification` | String | Simulated new device alert |
| `trigger_score_decrease_notification` | String | Simulated score decrease |
| `trigger_score_increase_notification` | String | Simulated score increase |
| `trigger_advisor_notification` | String | Simulated advisor update |
| `trigger_agentic_confirmed_notification` | String | Simulated agentic confirmation (feature: agentic) |
| `trigger_agentic_escalated_notification` | String | Simulated agentic escalation (feature: agentic) |
| `trigger_domain_limit_notification` | String | Simulated domain limit alert |

---

## RPC Discovery

Methods for runtime API discovery. Used by `edamame_cli` for dynamic method invocation.

**Source**: `api/api_rpc.rs`

### get_api_methods

```
get_api_methods() -> Vec<String>
```

Returns a list of all registered RPC method names.

### get_api_info

```
get_api_info(method: String) -> Option<APIInfo>
```

Returns metadata for a specific method: parameter names/types, return type.

`APIInfo` structure:
```
{
    "method": "get_score",
    "args": [{"name": "complete_only", "type": "bool"}],
    "return_type": "ScoreAPI"
}
```
