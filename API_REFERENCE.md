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
- [MCP Server](#mcp-server)
- [Test Utilities](#test-utilities)
- [RPC Discovery](#rpc-discovery)

---

## Core

System initialization, lifecycle management, device information, and platform utilities.

**Source**: `api/api_core.rs`

### initialize

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

Returns all available threat tag prefixes (e.g., "SOC-2", "CIS", "ISO-27001", "PCI-DSS", "HIPAA").

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
    slack_escalations_channel: String
) -> bool
```

Configure the LLM provider. Supported providers:
- `"internal"` -- EDAMAME Portal managed LLM (OAuth or API key)
- `"claude"` -- Anthropic Claude (API key required)
- `"openai"` -- OpenAI GPT (API key required)
- `"ollama"` -- Local Ollama instance (base_url required)

#### agentic_get_llm_config

```
agentic_get_llm_config() -> LLMConfigInfoAPI
```

Returns the current LLM configuration (provider, model, base_url -- API keys are redacted).

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

---

## MCP Server

Model Context Protocol server management. Requires the `mcp` feature flag (which implies `agentic`).

**Source**: `api/api_agentic.rs` (MCP section)

### mcp_start_server

```
mcp_start_server(port: u16, psk: String, enable_cors: bool, listen_all_interfaces: bool) -> String
```

Start the MCP server. PSK must be at least 32 characters.

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
