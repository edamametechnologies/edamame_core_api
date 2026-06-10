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

> **Note**: `initialize` is a special entry point, not registered via the `rpc!()` macro. It accepts a platform-specific `StreamSink` for event delivery (Flutter) or is called without it (standalone/CLI). It must be called before any other API method.

```
initialize(
    executable_type: String,
    branch: String,
    locale: String,
    device_info: String,
    sink: StreamSink<u64>,       // Flutter event stream (omitted in standalone)
    pwned: bool,
    flodbadd: bool,
    trust: bool,
    agentic: bool
) -> ()
```

Initialize EDAMAME Core. Must be called before any other API method. Configures feature availability and event delivery.

Parameters:
- `executable_type`: Identifies the consumer (e.g., "app", "posture", "cli")
- `branch`: Threat model branch to use (typically "main")
- `locale`: User locale for localized threat descriptions (e.g., "en", "fr")
- `device_info`: JSON-encoded device information string
- `sink`: Flutter `StreamSink<u64>` for receiving event bitmasks (omitted in standalone builds)
- `pwned`: Enable breach detection feature
- `flodbadd`: Enable network scanning and capture feature
- `trust`: Enable domain connection and compliance feature
- `agentic`: Enable AI automation feature

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

### get_app_latest_version

```
get_app_latest_version() -> String
```

Returns the latest available application version string.

### is_from_store

```
is_from_store() -> bool
```

Returns whether the application was installed from an app store (macOS App Store, etc.).

### set_demo_mode

```
set_demo_mode(demo_mode_on: bool) -> ()
```

Toggle demo mode. When enabled, uses simulated data for demonstrations.

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

### get_demo_platform

```
get_demo_platform() -> String
```

Returns the current demo platform override, or empty string if none.

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

### get_community_devices

```
get_community_devices() -> Vec<CommunityDeviceAPI>
```

Returns devices shared via the P2P community protocol on the local network.

### get_p2p_stats

```
get_p2p_stats() -> P2PStatsAPI
```

Returns P2P network statistics (peers connected, data exchanged, etc.).

---

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
get_score(complete_only: bool) -> ScoreAPI
```

Returns the current security score and all evaluated threats. When `complete_only` is true, waits for any in-progress computation to finish.

`ScoreAPI` includes: overall score (0.0-5.0), list of threats with status, platform, computation timestamp.

### get_last_computed_secs

```
get_last_computed_secs() -> i64
```

Returns the number of seconds since the last score computation completed.

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

### update_threats

```
update_threats() -> ()
```

Update threat model definitions from the cloud repository.

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

#### get_devices

```
get_devices() -> Vec<DeviceInfoAPI>
```

Returns all discovered network devices with full details (IP, MAC, vendor, hostname, open ports, mDNS services, vulnerabilities).

#### get_active_local_devices

```
get_active_local_devices() -> Vec<DeviceInfoAPI>
```

Returns only currently active devices on the local network.

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

Start packet capture on the active network interface. Requires `standalone` feature or appropriate platform permissions.

#### stop_capture

```
stop_capture() -> ()
```

Stop packet capture.

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

#### set_percentiles

```
set_percentiles(suspicious_percentile: f64, abnormal_percentile: f64) -> String
```

Configure the anomaly detection thresholds for the Extended Isolation Forest model.

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

#### get_session_by_uid

```
get_session_by_uid(uid: String) -> Option<SessionInfoAPI>
```

Returns a specific session by its unique identifier.

#### filter_local_sessions

```
filter_local_sessions(sessions: Vec<SessionInfoAPI>) -> Vec<SessionInfoAPI>
```

Filter sessions to only local (LAN) traffic.

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

#### is_whitelist_stable

```
is_whitelist_stable(old_whitelist_json: String, new_whitelist_json: String, threshold_percentage: f64) -> bool
```

Returns whether the whitelist has stabilized (change below threshold).

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

#### get_filter

```
get_filter() -> SessionFilterAPI
```

Returns the current session display filter.

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

#### add_dismiss_rule_from_session

```
add_dismiss_rule_from_session(uid: String) -> ()
```

Create a dismiss rule based on a session (suppress future alerts for similar sessions).

#### remove_dismiss_rule_from_session

```
remove_dismiss_rule_from_session(uid: String) -> ()
```

Remove a session-based dismiss rule.

#### add_dismiss_rule_from_port

```
add_dismiss_rule_from_port(uid: String) -> ()
```

Create a dismiss rule based on a port.

#### add_dismiss_rule_from_process

```
add_dismiss_rule_from_process(uid: String) -> ()
```

Create a dismiss rule based on a process.

### Community Sharing

#### get_shared_device_infos

```
get_shared_device_infos() -> Vec<DeviceInfoAPI>
```

Returns device information shared to the community.

#### get_received_device_infos

```
get_received_device_infos() -> Vec<DeviceInfoAPI>
```

Returns device information received from the community.

---

## Breach Detection / Pwned

Email breach monitoring via HaveIBeenPwned integration. Requires the `pwned` feature flag.

**Source**: `api/api_pwned.rs`

### add_pwned_email

```
add_pwned_email(email: String) -> bool
```

Add an email address to monitor for breaches. Returns true if added successfully.

### remove_pwned_email

```
remove_pwned_email(email: String) -> bool
```

Remove an email from breach monitoring. Returns true if removed.

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

### user_feedback

```
user_feedback(context: String, note: String, email: String, app_log: bool, helper_log: bool) -> ()
```

Submit user feedback with optional log attachments.

---

## Advisor

Security recommendations engine providing prioritized, actionable security todos. The advisor aggregates findings from threats, network analysis, breach detection, and compliance into a unified list.

**Source**: `api/api_advisor.rs`

### get_advisor

```
get_advisor() -> AdvisorAPI
```

Returns the full advisor state including all security todos with priorities, categories, and resolution status.

### get_advisor_state

```
get_advisor_state() -> AdvisorStateAPI
```

Returns a summary of the advisor state (counts by category, overall progress).

### is_advisor_fully_resolved

```
is_advisor_fully_resolved() -> bool
```

Returns true if all security todos have been resolved.

### get_advisor_rag_prompt

```
get_advisor_rag_prompt() -> String
```

Returns a RAG-enriched prompt containing the current security context, suitable for passing to an LLM for analysis.

### get_advisor_remediation

```
get_advisor_remediation(question: String) -> String
```

Get AI-generated advice for a specific security question, enriched with the current device context.

### request_advisor_report

```
request_advisor_report(email: String) -> ()
```

Request a full advisor report to be sent to the specified email address.

---

## Agentic / AI Automation

AI-powered security automation with support for multiple LLM providers. Requires the `agentic` feature flag.

**Source**: `api/api_agentic.rs`

### Processing

#### agentic_process_todos

```
agentic_process_todos(confirmation_level: i32) -> AgenticResultsAPI
```

The main "Do It For Me" entry point. Processes all security todos using the configured LLM:
- `confirmation_level = 0`: Auto-resolve safe actions, escalate risky ones
- `confirmation_level = 1`: Analyze and recommend only (no execution)

Returns results categorized as: auto_resolved, requires_confirmation, escalated, failed.

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

#### agentic_cancel_processing

```
agentic_cancel_processing() -> bool
```

Cancel the currently running agentic processing.

### Auto-Processing

#### agentic_set_auto_processing

```
agentic_set_auto_processing(enabled: bool, interval_secs: u64, mode: i32) -> bool
```

Configure automatic periodic processing. The ticker runs every 5 seconds when enabled and triggers processing at the configured interval.

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

This same call also persists optional team-delivery routing for Security Agent notifications:
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

#### agentic_has_edamame_api_key

```
agentic_has_edamame_api_key() -> bool
```

Returns whether an EDAMAME API key is configured.

### Status & History

#### agentic_get_action_history

```
agentic_get_action_history() -> Vec<ActionRecordAPI>
```

Returns the complete action audit trail (last 30 days).

#### agentic_get_workflow_status

```
agentic_get_workflow_status() -> Option<AgenticWorkflowStatusAPI>
```

Returns the status of the currently running workflow, or None if idle.

#### agentic_get_status

```
agentic_get_status() -> AgenticStatusAPI
```

Returns the overall agentic system status (configured, authenticated, error state, etc.).

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

Returns per-loop LLM token usage broken down across the three agentic loops: `agentic` (todo auto-processing), `vuln` (attack pattern detector LLM adjudication), and `divergence` (divergence engine LLM adjudication, including the raw-session model ingest path). Each loop reports `*_in` and `*_out` token counts plus a shared `since_unix_secs` reset timestamp. Used to attribute LLM cost to the loop that generated it.

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

Returns the last `limit` agentic notifications dispatched (Slack/Telegram/Portal/local) as JSON, most recent first. Useful for auditing alert delivery without re-running detector ticks.

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

#### agentic_clear_error

```
agentic_clear_error() -> bool
```

Clear the current error state.

#### agentic_clear_action_history

```
agentic_clear_action_history() -> bool
```

Clear all action history records.

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

#### agentic_dismiss_action

```
agentic_dismiss_action(finding_key: String) -> bool
```

Dismiss a specific agentic finding (vulnerability or divergence) so it stops appearing in active reports/notifications. Returns `true` when a matching record was dismissed.

#### agentic_undismiss_action

```
agentic_undismiss_action(finding_key: String) -> bool
```

Restore a previously dismissed agentic finding so it surfaces again in reports/notifications. Returns `true` when a matching dismissal was cleared.

### OAuth Authentication (Internal Provider)

#### oauth_signin_internal

```
oauth_signin_internal() -> String
```

Initiate OAuth 2.0 sign-in for the Internal LLM provider. Opens the browser for authentication. Returns status message.

#### oauth_refresh_internal

```
oauth_refresh_internal() -> String
```

Refresh OAuth tokens using the stored refresh token.

#### oauth_signout_internal

```
oauth_signout_internal() -> String
```

Sign out and clear OAuth tokens.

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

Behavioral model management and divergence detection between the reasoning plane (cortex extrapolator) and the execution plane (observed traffic). Requires the `agentic` feature flag.

#### upsert_behavioral_model

```
upsert_behavioral_model(window_json: String) -> String
```

Push behavioral predictions from the reasoning plane. Accepts a JSON-encoded window of predicted behavior. Returns status JSON.

Behavioral window schema (v3):
- `window_start`, `window_end`, `ingested_at`, `version`, `hash`
- `predictions[]` with `session_key`, `action`, `tools_called`
- expected dimensions: `expected_traffic`, `expected_sensitive_files`, `expected_lan_devices`, `expected_local_open_ports`, `expected_process_paths`, `expected_parent_paths`, `expected_open_files`, `expected_l7_protocols`, `expected_system_config`
- negative dimensions: `not_expected_traffic`, `not_expected_sensitive_files`, `not_expected_lan_devices`, `not_expected_local_open_ports`, `not_expected_process_paths`, `not_expected_parent_paths`, `not_expected_open_files`, `not_expected_l7_protocols`, `not_expected_system_config`

#### upsert_behavioral_model_from_raw_sessions

```
upsert_behavioral_model_from_raw_sessions(raw_sessions_json: String) -> String
```

Build and upsert a behavioral-model window directly from a JSON array of raw session records (instead of supplying a pre-aggregated window). Used by tests and tools that already have observed sessions and want EDAMAME to derive predicted dimensions automatically. Returns the resulting window JSON.

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

#### dismiss_divergence_evidence

```
dismiss_divergence_evidence(finding_key: String) -> String
```

Dismiss one divergence evidence item by finding key. Returns JSON with `{ "success": true, "changed": bool }`.

#### undismiss_divergence_evidence

```
undismiss_divergence_evidence(finding_key: String) -> String
```

Restore a previously dismissed divergence evidence item by finding key. Returns JSON with `{ "success": true, "changed": bool }`.

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

#### get_divergence_engine_status

```
get_divergence_engine_status() -> String
```

Get engine status as JSON: running state, interval, last run timestamp, model age, last verdict.

**MCP tools**: Five of these methods are exposed as MCP tools: `upsert_behavioral_model`, `get_behavioral_model`, `get_divergence_verdict`, `get_divergence_history`, and `get_divergence_engine_status`.

`start_divergence_engine`, `start_vulnerability_detector`, `agentic_set_auto_processing`, `clear_behavioral_model`, `start_file_monitor`, and `stop_file_monitor` are direct API control-plane methods and are not exposed via MCP tools.

### Attack Pattern Detector

Model-independent detection for sensitive-file access, critical CVE exposure, and other safety-floor findings. Requires the `agentic` feature flag. Five checks: token_exfiltration (anomalous + creds), skill_supply_chain (blacklisted + creds), credential_harvest (any session + >= N credential label categories), sandbox_exploitation (suspicious lineage), gateway_binding (exposed listeners). The `credential_harvest` threshold is configurable via `credential_harvest_min_labels` in `cve-detection-params-db.json` (default 3).

#### start_vulnerability_detector

```
start_vulnerability_detector(enabled: bool, interval_secs: u64) -> String
```

Enable or disable the attack pattern detector with optional interval configuration. Returns status JSON.

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

#### dismiss_vulnerability_finding

```
dismiss_vulnerability_finding(finding_key: String) -> String
```

Dismiss one vulnerability or safety-floor finding by finding key. Returns JSON with `{ "success": true, "changed": bool }`.

#### undismiss_vulnerability_finding

```
undismiss_vulnerability_finding(finding_key: String) -> String
```

Restore a previously dismissed vulnerability or safety-floor finding by finding key. Returns JSON with `{ "success": true, "changed": bool }`.

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

Get detector status as JSON: running state, interval, last run timestamp, and current active-finding count.

#### debug_run_vulnerability_detector_tick

```
debug_run_vulnerability_detector_tick() -> String
```

Force a single attack-pattern-detector tick out of band (without waiting for the scheduled interval). Diagnostic-only; used by tests and the CLI when developers need a deterministic re-evaluation. Returns JSON describing whether a tick was actually executed (it may be skipped if a concurrent tick is already in flight).

**LLM dependency**: The attack pattern detector itself runs model-independent checks and does not require an LLM provider to surface findings. For CI/security gates and automation flows it is strongly recommended to also configure an LLM via `agentic_set_llm_config`: EDAMAME can then adjudicate findings, suppress likely false positives, and produce clearer alert text. Without an LLM, raw heuristic findings still surface and gate consumers (e.g. `edamame_posture vulnerability-status --fail-on-findings`).

#### Attack Pattern Detector RPC Aliases (preferred names; transition surface)

We are transitioning the user-facing surface from "Vulnerability Detection" to "Attack Pattern Detection". The RPCs below are wire-level aliases of the corresponding `*_vulnerability_*` methods above. Each alias is a thin delegate to the legacy implementation (same arguments, same return shape, same behavior). New integrations should use the `attack_pattern_*` names; existing integrations using `*_vulnerability_*` continue to work. The legacy names will be deprecated in a future major version. See the workspace rule "Vulnerability -> Attack Pattern Detection Terminology Transition" in `edamame_app/.cursor/rules/workspace.mdc` for the full policy.

#### start_attack_pattern_detector

```
start_attack_pattern_detector(enabled: bool, interval_secs: u64) -> String
```

Alias of `start_vulnerability_detector`.

#### get_attack_pattern_findings

```
get_attack_pattern_findings() -> String
```

Alias of `get_vulnerability_findings`.

#### get_attack_pattern_history

```
get_attack_pattern_history(limit: usize) -> String
```

Alias of `get_vulnerability_history`.

#### dismiss_attack_pattern_finding

```
dismiss_attack_pattern_finding(finding_key: String) -> String
```

Alias of `dismiss_vulnerability_finding`.

#### undismiss_attack_pattern_finding

```
undismiss_attack_pattern_finding(finding_key: String) -> String
```

Alias of `undismiss_vulnerability_finding`.

#### clear_attack_pattern_history

```
clear_attack_pattern_history() -> ()
```

Alias of `clear_vulnerability_history`.

#### reset_attack_pattern_suppressions

```
reset_attack_pattern_suppressions() -> String
```

Alias of `reset_vulnerability_suppressions`.

#### get_attack_pattern_debug_trace

```
get_attack_pattern_debug_trace(report_id: String) -> String
```

Alias of `get_vulnerability_debug_trace`.

#### get_attack_pattern_detector_status

```
get_attack_pattern_detector_status() -> String
```

Alias of `get_vulnerability_detector_status`.

#### debug_run_attack_pattern_detector_tick

```
debug_run_attack_pattern_detector_tick() -> String
```

Alias of `debug_run_vulnerability_detector_tick`.

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

Operator-only dismissal-rule plane: every `agentic_*_dismissal*` RPC mutates EDAMAME's local dismissal store and is **not** exposed via MCP (per the observer-independence policy). Rules dismiss vulnerability or divergence findings under explicit scopes (`finding`, `process_for_check`, `process_lineage`, `process_and_material_class`, `agent_workspace_pattern`) with optional TTL and a severity ceiling that controls whether the rule may suppress CRITICAL findings.

#### agentic_add_dismissal_rule

```
agentic_add_dismissal_rule(rule_json: String) -> String
```

Add a dismissal rule. `rule_json` carries the operator-supplied envelope:

```
{
  "domain":  "vulnerability" | "divergence",
  "scope":   "finding" | "process_for_check" | "process_lineage" |
             "process_and_material_class" | "agent_workspace_pattern",
  "matcher": { ...DismissalRuleMatcherAPI... },
  "ttl_secs": <i64?>,
  "reason":   <string?>,
  "source_finding_key": <string?>,
  "severity_ceiling": "high_and_below" | "critical_capable",
  "source_context": { "finding_title", "check_or_category", "process_name", "severity", "details" }
}
```

Returns `{ "success": bool, "rule_id"?: string, "error"?: string }`.

#### agentic_dismiss_with_scope

```
agentic_dismiss_with_scope(request_json: String) -> String
```

Convenience wrapper around `agentic_add_dismissal_rule`: dismiss a single finding under a chosen scope, auto-filling the matcher when `scope = "finding"`. The `request_json` envelope mirrors `agentic_add_dismissal_rule` plus a top-level `finding_key`. Returns `{ "success": bool, "error"?: string }`. The previously returned `rule_id` field was structurally dead (no consumer read it) and has been removed; the underlying rule is still persisted internally and accessible via `agentic_get_dismissal_rules`.

#### agentic_report_dismissal

```
agentic_report_dismissal(request_json: String) -> String
```

Operator-initiated, opt-in report of a vulnerability or divergence dismissal to the EDAMAME backend. Mirrors the device-feedback `dislike_device_type` shape: this RPC does NOT change local policy (the dismissal rule is already applied via `agentic_dismiss_with_scope` before this is called) -- it only sends the operator's feedback. Carries the matcher fields, the dismissal scope/severity ceiling/TTL, agent identity, and an optional consent note + email. Returns `{ "success": bool, "error"?: string }`.

#### agentic_remove_dismissal_rule

```
agentic_remove_dismissal_rule(rule_id: String) -> String
```

Remove a dismissal rule by id. Returns `{ "success": bool, "removed": bool, "error"?: string }`.

#### agentic_list_dismissal_rules

```
agentic_list_dismissal_rules(domain: String) -> String
```

List dismissal rules. `domain` may be `""` (all), `"vulnerability"`, or `"divergence"`. Returns `{ "success": true, "rules": [DismissalRuleAPI, ...] }`.

#### agentic_list_dismissal_audit_log

```
agentic_list_dismissal_audit_log(limit: u32) -> String
```

List the dismissal audit log, newest first. `limit = 0` uses the bounded default read limit. Returns `{ "success": true, "entries": [DismissalAuditEntryAPI, ...] }`.

#### agentic_set_dismissal_rule_severity_ceiling

```
agentic_set_dismissal_rule_severity_ceiling(request_json: String) -> String
```

Promote or demote a rule's `severity_ceiling`. `request_json`:

```
{ "rule_id": "<uuid>", "severity_ceiling": "high_and_below" | "critical_capable", "reason": "<required for promotion to critical_capable>" }
```

Returns `{ "success": bool, "changed": bool, "error"?: string }`.

#### agentic_reset_dismissal_rules

```
agentic_reset_dismissal_rules() -> String
```

Remove every dismissal rule. Returns `{ "success": true, "changed": bool }` indicating whether any rules were actually cleared.

#### agentic_clear_dismissal_audit_log

```
agentic_clear_dismissal_audit_log() -> String
```

Truncate the dismissal audit log. Returns `{ "success": true, "changed": bool }`.

#### agentic_prune_expired_dismissal_rules

```
agentic_prune_expired_dismissal_rules() -> String
```

Force a single sweep that removes any dismissal rules whose `ttl_secs` has elapsed. Returns `{ "success": true, "removed": <count> }`. The detector tick performs this sweep automatically; this RPC is for operator-driven maintenance.

### Agent Plugins

Provisioning helpers for first-class third-party agent integrations (Cursor, Claude Code, Claude Desktop, etc.). Each plugin owns its install layout, configuration, and uninstall routine; the API surfaces here are CLI/UI thin wrappers over `edamame_foundation::agent_plugin`. Requires the `agentic` feature flag.

#### list_agent_plugins

```
list_agent_plugins() -> String
```

Returns a JSON array of supported agent plugins with their metadata (display name, repo, strategy kind, sort order, install state, version, install path).

#### get_agent_plugin_status

```
get_agent_plugin_status(agent_type: String) -> String
```

Returns a JSON `AgentPluginStatus` record for the given agent type (e.g. `cursor`, `claude_code`, `claude_desktop`): install state, version, install path, error (if any), and display metadata.

#### provision_agent_plugin

```
provision_agent_plugin(agent_type: String, workspace_root: String) -> String
```

Install or update the agent plugin of the given type into `workspace_root`. Standalone builds run the operation in-process; managed deployments delegate to the helper service. Returns JSON `AgentPluginProvisionResult` with `success`, `version`, `install_path`, and a human-readable `message`.

#### test_agent_plugin

```
test_agent_plugin(agent_type: String) -> String
```

Run the plugin's self-test (typically: ensure binaries are reachable and configuration is valid) and return JSON describing the outcome. Used by the UI to surface "Plugin healthy" / "Plugin broken: <reason>" badges.

#### get_agent_plugin_health

```
get_agent_plugin_health(agent_type: String) -> String
```

Return a richer health JSON for the given agent plugin: install state, version, last self-test outcome, MCP bridge reachability, and any background telemetry (e.g. transcript observer status) the plugin contributes. Used by the UI's plugin detail view.

#### uninstall_agent_plugin

```
uninstall_agent_plugin(agent_type: String) -> String
```

Remove the agent plugin of the given type from disk and clear its configuration. Returns JSON describing whether the operation succeeded and any removed paths.

### External Transcript Observer

Per-agent host-side observer that reads each discovered agent's transcripts from disk and feeds the existing `upsert_behavioral_model_from_raw_sessions` pipeline (see `AGENTIC.md`). Discovery is independent of plugin install state, so divergence detection works end-to-end without an in-agent bridge. Pausing the observer for a discovered agent trips the corresponding `unsecured_<agent>` internal threat.

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

---

## File Integrity Monitoring (FIM)

File integrity monitoring engine. Watches a configured set of paths for create / modify / rename / delete events, hashes content with BLAKE3 (subject to `fim_hash_size_threshold`), and feeds events into the attack pattern detector for sensitive-path / temp-staging analysis. Requires the `fim` feature flag.

**Source**: `api/api_fim.rs`. See `FIM.md` in the core repo for the engine architecture and helper/standalone convergence story.

### start_file_monitor

```
start_file_monitor(paths: Vec<String>) -> ()
```

Start the FIM watcher on the supplied list of root paths. When `paths` is empty, the engine falls back to the converged default set computed by `edamame_foundation::fim_support`. The watcher initialization is non-blocking (the recursive `notify` walk runs on `spawn_blocking` so the gRPC handler returns promptly even on hosts with very large watch trees).

### stop_file_monitor

```
stop_file_monitor() -> ()
```

Stop the FIM watcher and release its inotify / FSEvents / ReadDirectoryChangesW handles.

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

### get_fim_suspicious_status

```
get_fim_suspicious_status() -> bool
```

Return `true` when the FIM event buffer currently contains at least one event flagged as suspicious by the FIM heuristic (sensitive-path write, temp-script staging, etc.). Surfaced in the score bar.

---

## Privacy

Privacy preferences toggles for analytics and crash reporting. Persisted on disk and applied at runtime where possible. Persisted struct: `PrivacyPreferences` (see core repo invariants -- new fields MUST add `#[serde(default)]`).

**Source**: `api/api_privacy.rs`

### get_privacy_preferences

```
get_privacy_preferences() -> PrivacyPreferencesAPI
```

Return the current privacy preferences as a struct: `analytics_enabled`, `crash_reports_enabled`. Used by the Privacy settings tab.

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

### get_analytics_enabled

```
get_analytics_enabled() -> bool
```

Read the persisted analytics preference. Mirror of the `analytics_enabled` field in `get_privacy_preferences`.

### get_crash_reports_enabled

```
get_crash_reports_enabled() -> bool
```

Read the persisted crash-reports preference. Mirror of the `crash_reports_enabled` field in `get_privacy_preferences`.

---

## Agent Visibility

Agent-visibility surface spanning the staged roadmap (Stage A discovery through Stage D+ governance): MCP server discovery + risk analysis, agent SBOM + drift, capability graph + trust-zone reachability, recursion/delegation detection, the hash-chained run flight recorder, goal/delegation drift timelines, sensitive data-flow / memory / agent-to-agent maps, the composite alignment rollup, the tool-call firewall, ADR response actions + case export, and enterprise policy packs / attestations / cross-zone approval. Requires the `agentic` feature flag. Rich, deeply-nested domain data is returned as a JSON `String` (same convention as agentic findings/history); only the capture tier, the compact summary, and the roadmap get a typed FRB mirror. Read RPCs lazily ensure a fresh snapshot (TTL-bounded `ensure_*`/`get_*`) so a single-shot caller gets data without a separate refresh call.

Observer-independence (I1): the read RPCs are also exposed as read-only MCP tools (see [MCP.md](MCP.md#agent-visibility-tools)), but every **mutator** here (`refresh_*`, `set_firewall_mode`, `approve_agent`/`revoke_agent_approval`/`approve_agent_sbom_baseline`, `request_response_action`/`undo_response_action`, `set_policy_pack`, `attest_policy_evaluation`/`attest_agent_sbom`, `request_zone_promotion`/`decide_zone_promotion`, `set_visibility_capture_tier`) is operator/UI control-plane only and is never an MCP tool -- an observed agent must not be able to weaken, silence, or self-approve the controls that watch it. Staged enforcement (I6): the tool-call firewall defaults to `recommend` (never gates); `confirm`/`block` are opt-in operator modes. See `VISIBILITYIMPROVEMENTS.md`.

**Source**: `api/api_visibility.rs`

### refresh_agent_visibility

```
refresh_agent_visibility() -> String
```

Force a structural visibility recollection (MCP discovery + SBOM + capability graph). Returns a `{"success": bool, ...}` envelope; on success carries `endpoint_count`, `finding_count`, `sbom_count`, and `graph_edge_count`. Most callers can rely on the lazy `ensure_*` refresh in the read RPCs instead of calling this explicitly.

### refresh_recursion_risk

```
refresh_recursion_risk() -> String
```

Force a recursion/delegation-tree recorrelation. Returns a `{"success": bool, ...}` envelope; on success carries `tree_count`. The recursion read RPC refreshes lazily, so this is only needed to force an immediate recompute.

### get_visibility_summary

```
get_visibility_summary() -> VisibilitySummaryAPI
```

Return a compact typed summary across all visibility domains: snapshot timestamp/presence, MCP endpoint/finding counts (with HIGH/CRITICAL breakdown), SBOM and component counts, capability-graph edge count, recursion tree/loop counts and max delegation depth, and the total alertable finding count. Used by the top-level Agents tab header and badges. Lazily ensures both the structural and recursion snapshots are fresh.

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

### get_agent_sboms

```
get_agent_sboms() -> String
```

Return the per-agent software bill-of-materials as a JSON array (`Vec<AgentSbom>`): the agent runtime plus its installed plugins/skills/MCP components and their dependencies. Lazily ensures a fresh structural snapshot.

### get_agent_sbom_cyclonedx

```
get_agent_sbom_cyclonedx(agent_type: String) -> String
```

Return the SBOM for a single agent type exported in CycloneDX JSON format (for ingestion by external SCA/SBOM tooling). Returns `{}` when no SBOM exists for that agent type. Lazily ensures a fresh structural snapshot.

### get_agent_sbom_diff

```
get_agent_sbom_diff(agent_type: String) -> String
```

Return the diff between the current SBOM and the stored baseline for an agent type as JSON (`SbomDiff`): added, removed, and version-changed components since the baseline was captured. Lazily ensures a fresh structural snapshot.

### approve_agent_sbom_baseline

```
approve_agent_sbom_baseline(agent_type: String) -> String
```

(INC-10) Operator: promote an agent's current SBOM to be the new drift baseline, resetting `get_agent_sbom_diff` to empty. Returns `{"success": bool, ...}`; `success:false` with an `error` when no current SBOM exists for that agent type. Operator-only mutator -- NOT an MCP tool (observer-independence I1: an observed agent must not be able to silence drift against its own baseline).

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

### refresh_alignment_rollup

```
refresh_alignment_rollup() -> String
```

(INC-12 alignment rollup) Force a recompute of the single composite alignment score across every visibility domain plus the attack-pattern alertable count. Returns `{"success": true, "score": N, "band": "...", "hard_fail": bool}`. Reads refresh lazily.

### get_alignment_rollup

```
get_alignment_rollup() -> String
```

(INC-12) Return the composite alignment rollup as JSON: the 0-100 `score`, the `band` (`aligned`/`drifting`/`misaligned`/`critical`), `hard_fail` (a catastrophic domain forces failure regardless of score), and the per-domain contribution breakdown. This is the single headline number for "how aligned are the agents on this host".

### get_firewall_status

```
get_firewall_status() -> String
```

(INC-10 tool-call firewall) Return the firewall status envelope as JSON: current `mode` (`recommend`/`confirm`/`block`), `receipt_count`, `alertable_count`, `catastrophic_count`, `pending_confirmation_count` (always 0 in `recommend` -- it never gates, I6), `chain_intact`, `first_broken_index`, and `chain_head_hash`. MCP-safe read.

### get_firewall_evaluations

```
get_firewall_evaluations() -> String
```

(INC-10) Return the hash-chained tool-call firewall receipts as a JSON array: per evaluated tool call the verdict (`allow`/`recommend`/`confirm`/`block`), severity, catastrophic flag, the triggering rule, `resolved` state, and `prev_hash`/`receipt_hash` chain links. MCP-safe read.

### refresh_firewall_evaluations

```
refresh_firewall_evaluations() -> String
```

(INC-10) Force a re-evaluation of recent tool calls against the active firewall rules. Returns `{"success": true, "receipt_count": N}`. Operator/UI refresh; reads refresh lazily.

### set_firewall_mode

```
set_firewall_mode(mode: String) -> String
```

(INC-10) Set the firewall enforcement mode. Accepts `recommend` (default, never gates -- I6), `confirm` (gates non-catastrophic verdicts pending operator confirmation), or `block` (gates catastrophic verdicts outright). Returns `{"success": bool, ...}`; `success:false` with an `error` for an unknown mode. Operator-only mutator -- NOT an MCP tool (I1: an observed agent must not relax its own firewall).

### get_response_action_catalog

```
get_response_action_catalog() -> String
```

(INC-11 response actions) Return the catalog of available response-action kinds as a JSON array: each kind with its target class, whether it is reversible, and whether it requires a prior simulate run. MCP-safe read.

### get_response_action_history

```
get_response_action_history() -> String
```

(INC-11) Return the append-only response-action history as a JSON array: each requested/simulated/applied/undone action with kind, target, reason, simulated flag, timestamps, and outcome. MCP-safe read.

### request_response_action

```
request_response_action(kind: String, target_ref: String, reason: String, simulated: bool) -> String
```

(INC-11) Request a response action (e.g. quarantine a session, revoke an agent, isolate a memory store). Returns `{"success": true, "record": {...}}` on success; `success:false` with an `error` when the kind is unknown, the target is empty, or an irreversible action was requested without a prior simulate run (I6 requires a `simulated:true` pass first). Operator-only mutator -- NOT an MCP tool (I1).

### undo_response_action

```
undo_response_action(action_id: String) -> String
```

(INC-11) Undo a previously-applied reversible response action by id. Returns `{"success": bool}` (`false` when the id is unknown or the action is irreversible). Operator-only mutator -- NOT an MCP tool (I1).

### export_visibility_case

```
export_visibility_case(run_id: String) -> String
```

(INC-11 case export) Assemble a single portable incident-case bundle for one run as JSON: the flight record, correlated divergence/attack-pattern findings, the agent's drift timeline, data-flow/memory/A2A context, and any response actions taken. Returns `{}` when the run is unknown. Operator/UI export (not an MCP tool).

### get_policy_pack

```
get_policy_pack() -> String
```

(INC-13 governance) Return the active enterprise policy pack as JSON: `pack_id`, `version`, and the declarative rules (each with kind, parameters, and the severity of a violation). Defaults to the built-in `EDAMAME Baseline` pack (7 rules). MCP-safe read.

### get_policy_evaluation

```
get_policy_evaluation() -> String
```

(INC-13) Return the most recent policy-pack evaluation as JSON: overall `compliant` flag, `violated_rules`/`total_rules` counts, and a per-rule pass/fail result with the deterministic inputs that drove each verdict. MCP-safe read.

### refresh_policy_evaluation

```
refresh_policy_evaluation() -> String
```

(INC-13) Re-evaluate the active policy pack against freshly-assembled deterministic INC-5..13 inputs. Returns `{"success": true, "compliant": bool, "violated_rules": N, "total_rules": M}`. Reads refresh lazily.

### set_policy_pack

```
set_policy_pack(pack_json: String) -> String
```

(INC-13) Replace the active policy pack with a caller-supplied JSON `PolicyPack` (persisted to `VisibilityPreferences`). Returns `{"success": true, "pack_id": ..., "version": ..., "rule_count": N}` on success; `success:false` with an `error` when the JSON is invalid. Operator-only mutator -- NOT an MCP tool (I1: an observed agent must not weaken its own governance pack).

### attest_policy_evaluation

```
attest_policy_evaluation() -> String
```

(INC-13) Produce a content-addressed, tamper-evident attestation (SHA-256 `content_digest`) over the current policy evaluation and append it to the attestation log. Returns `{"success": true, "attestation": {...}}`. Operator-only mutator -- NOT an MCP tool (I1: an observed agent must not fabricate its own compliance attestation).

### attest_agent_sbom

```
attest_agent_sbom(agent_type: String) -> String
```

(INC-13) Produce a content-addressed, tamper-evident attestation over one agent's current SBOM and append it to the attestation log. Returns `{"success": true, "attestation": {...}}`; `success:false` with an `error` when no SBOM exists for that agent. Operator-only mutator -- NOT an MCP tool (I1).

### get_policy_attestations

```
get_policy_attestations() -> String
```

(INC-13) Return the attestation log as a JSON array: each attestation with its subject (policy evaluation or agent SBOM), the SHA-256 `content_digest`, and the timestamp. Use `content_digest` to verify tamper-evidence against the attested object. MCP-safe read.

### get_zone_promotions

```
get_zone_promotions() -> String
```

(INC-13 cross-zone approval) Return the cross-zone promotion log as a JSON array: each operator request to let an agent operate in a more-trusted firewall origin zone, with its `promotion_id`, agent, target zone, reason, status (`requested`/`approved`/`denied`), and decision timestamp. MCP-safe read.

### request_zone_promotion

```
request_zone_promotion(agent_type: String, target_zone: String, reason: String) -> String
```

(INC-13) Request that an agent be promoted into a more-trusted firewall origin zone (e.g. `trust1`). Returns `{"success": true, "record": {...}}` with a `requested` record; `success:false` with an `error` for an invalid target zone. Operator-only mutator -- NOT an MCP tool (I1: an observed agent must not self-promote into a trusted zone).

### decide_zone_promotion

```
decide_zone_promotion(promotion_id: String, approve: bool) -> String
```

(INC-13) Operator-decide a pending zone promotion by id: `approve:true` transitions it to `approved`, `false` to `denied`. Returns `{"success": bool}` (`false` when no matching `requested` record exists). Operator-only mutator -- NOT an MCP tool (I1).

### get_agent_inventory

```
get_agent_inventory() -> String
```

(INC-10 shadow-agent classification) Return the operator agent inventory as a JSON array: every supported agent with any footprint on this host, each with `agent_type`, `display_name`, a `classification` (`approved`/`shadow`/`unmanaged`/`unknown`), the installed/discovered/observer_enabled/approved booleans, and per-agent endpoint/component/alertable counts. MCP-safe read.

### approve_agent

```
approve_agent(agent_type: String) -> String
```

(INC-10) Operator: add an agent type to the approved allow-list, clearing its shadow classification. Returns `{"success": bool, "changed": bool}`; `success:false` with an `error` for an empty agent type. Operator-only mutator -- NOT an MCP tool (I1: an observed agent must not allow-list itself).

### revoke_agent_approval

```
revoke_agent_approval(agent_type: String) -> String
```

(INC-10) Operator: remove an agent type from the approved allow-list. Returns `{"success": bool, "changed": bool}`. Operator-only mutator -- NOT an MCP tool (I1).

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

### get_visibility_roadmap

```
get_visibility_roadmap() -> VisibilityRoadmapAPI
```

Return the visibility feature roadmap: every increment (MVP/v1/v2) with its id, title, tier, status (`available` or `planned`), and the RPC names it exposes (live or reserved). Lets the UI render planned-feature placeholders without registering speculative always-failing stub RPCs. See `VISIBILITYIMPROVEMENTS.md`.

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

Lifecycle controls such as `start_divergence_engine`, `start_vulnerability_detector`, `agentic_set_auto_processing`, `clear_behavioral_model`, `start_file_monitor`, and `stop_file_monitor` remain direct API/CLI operations and are intentionally excluded from MCP tools.

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
