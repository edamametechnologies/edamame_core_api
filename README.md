# EDAMAME Core API

Public documentation for the **EDAMAME Core** API -- the closed-source Rust engine that powers the [EDAMAME security platform](https://github.com/edamametechnologies).

EDAMAME Core provides cross-platform security assessment, threat remediation, network visibility, AI-powered automation, and compliance reporting through a unified API surface. It is consumed by GUI applications (Flutter), CLI tools, and external AI agents via MCP.

**EDAMAME Core is available for OEM integration.** If you are interested in embedding EDAMAME's security engine into your own product, contact [EDAMAME Technologies](https://www.edamame.tech).

For the full ecosystem overview, see the [EDAMAME Technologies profile](https://github.com/edamametechnologies).

---

## Table of Contents

1. [Architecture](#architecture)
2. [Language and Build](#language-and-build)
3. [Feature Flags](#feature-flags)
4. [Multi-Platform Support](#multi-platform-support)
5. [API Overview](#api-overview)
6. [Event System](#event-system)
7. [gRPC Interface](#grpc-interface)
8. [MCP Server](#mcp-server)
9. [Integration Patterns](#integration-patterns)
10. [API Reference](#api-reference)
11. [OEM Licensing](#oem-licensing)

---

## Architecture

EDAMAME Core follows a strict **three-layer architecture**:

```
+------------------------------------------------------------------+
|                    Consumer Layer                                  |
|   Flutter Bridge (GUI)  |  gRPC (CLI)  |  MCP (AI Agents)        |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                      API Layer (api_*.rs)                          |
|  - Thin wrappers around business logic                            |
|  - Type conversions (internal -> serializable API types)          |
|  - RPC endpoint registration via rpc!() macro                     |
|  - Background task orchestration                                  |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|               Core Manager Layer (core_manager_*.rs)              |
|  - ALL business logic                                             |
|  - State management                                               |
|  - Guard protection for concurrent access                         |
|  - Event triggering                                               |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                    Core State (core_state.rs)                      |
|  - Shared state containers (Arc<CustomRwLock<>>)                  |
|  - Thread-safe concurrent access                                  |
|  - Feature-gated fields                                           |
+------------------------------------------------------------------+
```

### Key Principles

- **API Layer** is always thin: no business logic, only type conversion and delegation
- **CoreManager** owns all workflows, validation, and orchestration
- **CoreState** wraps all shared data in `Arc<CustomRwLock<>>` for thread safety
- **Events** broadcast state changes to all consumers (Flutter streams, gRPC streams, internal listeners)

### API Domains

| Domain | Description |
|--------|-------------|
| **Core** | Initialization, lifecycle, device info, logging, versioning |
| **Score & Threats** | Security scoring, threat detection, remediation, rollback |
| **Network (Flodbadd)** | LAN scanning, packet capture, session analysis, whitelists |
| **Breach Detection** | Email breach monitoring via HaveIBeenPwned |
| **Trust** | Domain connection, policy enforcement, compliance reporting |
| **Advisor** | Security recommendations, RAG-enriched advice |
| **Agentic** | AI-powered automation, LLM integration, action history |
| **MCP** | Model Context Protocol server for external AI agents |

---

## Language and Build

EDAMAME Core is written in **Rust** using the [Tokio](https://tokio.rs) async runtime. It compiles as a static library (for Apple platforms), dynamic library (for Windows/Linux/Android), or standalone binary (for CLI tools).

```bash
# Default build (with Flutter bridge)
cargo build

# Standalone build (CLI tools, no Flutter)
cargo build --features standalone

# macOS CLI with Swift linking
cargo build --features swiftrs
```

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime (full features) |
| `flutter_rust_bridge` | Flutter FFI bridge (pinned v2.11.1) |
| `tonic` / `prost` | gRPC server and client |
| `rmcp` | MCP server (Streamable HTTP, v0.8) |
| `oauth2` / `jsonwebtoken` | OAuth 2.0 and JWT validation |
| `serde` / `serde_json` | Serialization for API types |

### Crate Types

```toml
[lib]
crate-type = ["staticlib", "cdylib", "lib"]
```

- **staticlib**: Apple platforms (macOS, iOS) -- linked into Xcode projects
- **cdylib**: Windows, Linux, Android -- dynamic library for Flutter or standalone use
- **lib**: Rust library for direct linking (CLI tools like `edamame_posture`, `edamame_cli`)

---

## Feature Flags

Feature flags control which capabilities are compiled into the binary:

| Feature | Default | Description |
|---------|---------|-------------|
| `standalone` | No | Builds without Flutter bridge; enables packet capture for CLI tools |
| `swiftrs` | No | Enables Swift-RS linking for macOS CLI tools (without Xcode project) |
| `pwned` | Yes | Password breach detection via HaveIBeenPwned |
| `flodbadd` | Yes | Network scanning, packet capture, session analysis, ML anomaly detection |
| `trust` | Yes | Domain connection, policy enforcement, compliance |
| `agentic` | Yes | AI-powered security automation (OAuth, JWT, LLM providers) |
| `mcp` | Yes | MCP server for AI agent integration (requires `agentic`) |
| `userdefaults` | Yes | macOS UserDefaults for settings persistence |

### Default Feature Set

```toml
default = ["userdefaults", "pwned", "flodbadd", "trust", "agentic", "mcp"]
```

### Feature Dependencies

```
mcp --> agentic --> [oauth2, jsonwebtoken, webbrowser, async-stream]
standalone --> [edamame_foundation/packetcapture, flodbadd/packetcapture, flodbadd/asyncpacketcapture]
```

---

## Multi-Platform Support

EDAMAME Core targets all major desktop and mobile platforms through conditional compilation:

| Platform | GUI App | Posture CLI | Helper Daemon | Network Capture | eBPF |
|----------|---------|-------------|---------------|-----------------|------|
| macOS | Yes | Yes | Yes | Yes | No |
| Windows | Yes | Yes | Yes | Yes (Npcap) | No |
| Linux | Yes | Yes | Yes | Yes | Yes (x86_64, aarch64) |
| iOS | Yes | No | No | Limited | No |
| Android | Yes | No | No | Limited | No |

### Platform-Specific Code

Platform-specific functionality is isolated behind `#[cfg(target_os = "...")]` gates:

- **macOS/iOS**: Native Swift integration via `swift-rs` for system APIs (notifications, UserDefaults, keychain)
- **Windows**: Windows Service integration, Npcap for network capture
- **Linux**: eBPF support for zero-copy packet capture and process attribution
- **Android**: JNI integration for native Android APIs

### How the Flutter App Uses EDAMAME Core

[EDAMAME Security](https://github.com/edamametechnologies/edamame_security) is a Flutter desktop/mobile application that consumes EDAMAME Core through `flutter_rust_bridge`:

```
Flutter (Dart)
    |
    v
flutter_rust_bridge (auto-generated FFI)
    |
    v
EDAMAME Core API Layer (api_*.rs)
    |
    v
CoreManager (business logic) --> CoreState (shared state)
    |
    v
Events --> StreamSink<u64> --> BehaviorSubject --> Flutter UI
```

**Key integration points:**
- **Direct function calls**: Each `rpc!()` endpoint becomes a callable Dart function (e.g., `getScore()`, `remediate()`, `agenticProcessTodos()`)
- **Reactive event streams**: CoreEvent bitmasks flow through `StreamSink` to Dart `BehaviorSubject`, driving UI updates
- **Bridge regeneration**: After modifying API endpoints, run `tear_down_walls.sh` to regenerate the Flutter bridge code

### How the Posture CLI Uses EDAMAME Core

[EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_cli) is a CLI tool for CI/CD and headless environments that links directly to EDAMAME Core as a Rust library:

```
edamame_posture (Rust binary)
    |
    v  (direct Rust function calls)
EDAMAME Core API Layer
    |
    v
CoreManager --> CoreState
```

**Key integration points:**
- **Direct static linking**: `edamame_posture` calls API functions directly (e.g., `compute_score()`, `remediate()`, `get_sessions()`)
- **Feature flag `standalone`**: Built without Flutter bridge, enables packet capture
- **Synchronous wrappers**: Uses the `_sync` variants of async functions for CLI convenience
- **Exit codes**: Translates API results into CI/CD-compatible exit codes (0=success, 1=policy fail, 2=server error, 3=param error, 4=timeout)

Example Posture CLI commands and the API calls they map to:

| CLI Command | API Calls |
|-------------|-----------|
| `edamame-posture get-score` | `compute_score()` then `get_score(true)` |
| `edamame-posture remediate-all-threats` | `get_score(false)` then `remediate(name, false)` for each threat |
| `edamame-posture check-policy 3.5 "firewall" "SOC-2"` | `check_policy(3.5, [...], [...])` |
| `edamame-posture lanscan` | `get_lanscan(true, false, false)` |
| `edamame-posture get-sessions` | `get_sessions()` |
| `edamame-posture background-start ...` | `initialize()` + `start_capture()` + daemon loop |

### How EDAMAME CLI Provides Generic API Access

[EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli) provides **dynamic RPC access** to the entire EDAMAME Core API surface:

```
edamame_cli (Rust binary)
    |
    v  (dynamic RPC dispatch)
rpc_call(method_name, json_args) --> EDAMAME Core Handler Registry
    |
    v
API Layer --> CoreManager --> CoreState
```

**Key integration points:**
- **Method discovery**: `list-methods` and `get-method-info` enumerate all registered RPC endpoints at runtime
- **Dynamic invocation**: `rpc <method> [json_args]` calls any API method by name with JSON arguments
- **Interactive REPL**: `interactive` mode for exploring the API
- **Remote RPC**: Can connect to a running EDAMAME Core instance over TLS-secured gRPC

Example EDAMAME CLI usage:

```bash
# List all available API methods
edamame-cli list-methods

# Get method signature and types
edamame-cli get-method-info get_score

# Call API methods with JSON arguments
edamame-cli rpc get_score '["true"]'
edamame-cli rpc get_device_info --pretty
edamame-cli rpc remediate '["firewall_disabled", "false"]'

# Interactive exploration
edamame-cli interactive
```

---

## API Overview

All API methods are registered via the `rpc!()` macro, which generates:

1. **Async implementation** (`method_name_async()`) -- the actual function
2. **Handler** -- registered in the handler registry for gRPC dispatch
3. **Remote RPC wrappers** -- for calling a remote EDAMAME Core instance
4. **API metadata** -- parameter names, types, and return type for discovery

### RPC Macro Pattern

```rust
// Declaration
rpc!(get_score(complete_only: bool) -> ScoreAPI);

// Generated async function (implemented by developer)
pub async fn get_score_async(complete_only: bool) -> ScoreAPI {
    CORE_MANAGER.read().await.get_score(complete_only).await
}

// Auto-generated: handler, remote RPC wrappers, metadata registration
```

### API Registries

| Registry | Purpose |
|----------|---------|
| `HANDLER_REGISTRY` | Maps method name to async handler for gRPC dispatch |
| `RPC_REGISTRY` | Maps method name to sync RPC wrapper |
| `RPC_ASYNC_REGISTRY` | Maps method name to async RPC wrapper |
| `API_REGISTRY` | Maps method name to `APIInfo` (args, return type) for discovery |

---

## Event System

EDAMAME Core uses a bitmask-based event system for broadcasting state changes. Each event is a power of 2, allowing efficient OR-combined event masks.

Events are delivered to all registered consumers:
- **Flutter**: `StreamSink<u64>` delivering to Dart `BehaviorSubject`
- **gRPC**: Server-streaming RPC (`subscribe_to_events`)
- **Internal**: `mpsc::Sender` channels for in-process listeners

### Event Definitions (36 events, excluding health-related)

See [EVENTS.md](EVENTS.md) for the complete event reference.

| Event | Value | Description |
|-------|-------|-------------|
| `AppOutdated` | 1 | Application version is outdated |
| `ConnectionError` | 2 | Backend connection failed |
| `ConnectionStatusUpdated` | 4 | Connection status changed |
| `ConnectionSuccess` | 8 | Backend connection established |
| `DeviceAdded` | 16 | New device discovered on network |
| `DevicesProgress` | 32 | Device scan progress update |
| `DevicesUpdated` | 64 | Device list changed |
| `HelperStateChanged` | 1024 | Privileged helper daemon state changed |
| `LANScanCancelStarted` | 2048 | LAN scan cancellation initiated |
| `LANScanCompleted` | 4096 | LAN scan finished |
| `LANScanStarted` | 8192 | LAN scan started |
| `MetricCompleted` | 16384 | Single threat metric evaluation completed |
| `NetworkChanged` | 32768 | Network configuration changed |
| `PINError` | 65536 | Domain PIN verification failed |
| `PINSuccess` | 131072 | Domain PIN verification succeeded |
| `ScoreCanceled` | 262144 | Score computation was canceled |
| `LANScanUpdated` | 524288 | LAN scan results updated incrementally |
| `ScoreComputationRequested` | 1048576 | Score computation was requested |
| `ScoreComputationStarted` | 2097152 | Score computation began |
| `ScoreDecreased` | 4194304 | Security score decreased |
| `ScoreIncreased` | 8388608 | Security score increased |
| `ScoreCompleted` | 16777216 | Score computation finished |
| `ScoreReported` | 33554432 | Score was reported to backend |
| `PoliciesStatusChanged` | 67108864 | Policy compliance status changed |
| `CommunityDevicesUpdated` | 134217728 | Community/P2P device list updated |
| `BreachesUpdated` | 268435456 | Breach data updated |
| `SessionsUpdated` | 536870912 | Network sessions updated |
| `AnomalousSessionsAdded` | 1073741824 | ML-detected anomalous sessions found |
| `BlacklistedSessionsAdded` | 2147483648 | Blacklisted sessions detected |
| `AdvisorUpdated` | 4294967296 | Security advisor recommendations changed |
| `AgenticUpdated` | 8589934592 | AI automation state changed |
| `AgenticConfirmed` | 17179869184 | AI action confirmed |
| `AgenticEscalated` | 34359738368 | AI action escalated for review |
| `DomainLimitReached` | 68719476736 | Domain device limit reached |
| `AgenticStatusUpdated` | 137438953472 | AI subscription/status changed |
| `SubscriptionLimitReached` | 274877906944 | Subscription usage limit reached |

### Event Broadcasting

```rust
// Trigger an event from CoreManager
event_manager.trigger_event(CoreEvent::ScoreCompleted);

// Events are OR-combined for efficient delivery
// A consumer receiving value 16777224 means:
//   ScoreCompleted (16777216) | ConnectionSuccess (8) both fired
```

---

## gRPC Interface

EDAMAME Core exposes a gRPC server for remote API access and event streaming. This is the interface used by `edamame_cli` and can be used by any gRPC client.

### Protocol Definition

```protobuf
syntax = "proto2";
package edamame;

message HelperRequest {
  required string ordertype = 1;
  required string subordertype = 2;
  required string arg1 = 3;
  required string arg2 = 4;
  required string signature = 5;
  required string version = 6;
}

message HelperResponse {
  required string output = 1;
}

service EDAMAMEHelper {
  rpc Execute(HelperRequest) returns (HelperResponse);
}
```

### RPC Call Flow

```
Client (edamame_cli / custom)
    |
    | TLS (mTLS with client certificates)
    v
gRPC Server (api_rx.rs)
    |
    v
HANDLER_REGISTRY.get(method_name)
    |
    v
API Handler --> CoreManager --> Response (JSON serialized)
```

### Security

- **mTLS**: Client and server certificates for mutual authentication
- **Certificate configuration** via environment variables:
  - `EDAMAME_CA_PEM` -- Certificate Authority
  - `EDAMAME_CLIENT_PEM` -- Client certificate
  - `EDAMAME_CLIENT_KEY` -- Client private key

### Event Streaming

Clients can subscribe to real-time events via server-streaming RPC:

```
Client --> subscribe_to_events() --> Stream<u64>
                                      |
                                      v
                              Bitmask of fired events
```

---

## MCP Server

EDAMAME Core includes an MCP (Model Context Protocol) server, enabling external AI assistants (like Claude Desktop, n8n, or custom agents) to interact with the security platform.

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Transport | Streamable HTTP | rmcp SDK v0.8 |
| Port | 3000 | Configurable |
| Bind address | 127.0.0.1 | `listen_all_interfaces` for remote access |
| Authentication | PSK (Pre-Shared Key) | Bearer token, minimum 32 characters |

### MCP Tools Exposed

| Tool | Description |
|------|-------------|
| `advisor_get_todos` | Get all security recommendations |
| `advisor_get_action_history` | Audit trail of AI actions |
| `advisor_undo_action` | Rollback a specific action |
| `advisor_undo_all_actions` | Rollback all actions |
| `agentic_process_todos` | AI-powered "Do It For Me" workflow |
| `agentic_execute_action` | Execute a pending action |
| `agentic_get_workflow_status` | Get current workflow progress |

### MCP API Methods

```
mcp_start_server(port, psk, enable_cors, listen_all_interfaces) -> String
mcp_stop_server() -> String
mcp_get_server_status() -> String
```

> PSK generation is available via the Posture CLI: `edamame-posture mcp-generate-psk`

---

## Integration Patterns

### Pattern 1: GUI Application (Flutter)

Used by [EDAMAME Security](https://github.com/edamametechnologies/edamame_security).

```
Flutter App
    |-- flutter_rust_bridge (FFI) --> EDAMAME Core (staticlib/cdylib)
    |-- Event streams via StreamSink
    |-- Direct function calls to all API endpoints
    |-- Full feature set (all default features enabled)
```

Build: `cargo build` (default features, with Flutter bridge)

### Pattern 2: CLI Tool with Domain-Specific Commands

Used by [EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_cli).

```
edamame_posture (Rust binary)
    |-- Links edamame_core as Rust library dependency
    |-- Calls API functions directly (no FFI overhead)
    |-- Built with `standalone` feature (no Flutter, enables packet capture)
    |-- Translates results to exit codes for CI/CD
```

Build: `cargo build --features standalone`

### Pattern 3: Generic RPC Explorer

Used by [EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli).

```
edamame_cli (Rust binary)
    |-- Links edamame_core as Rust library dependency
    |-- Dynamic method discovery via API_REGISTRY
    |-- Calls any method by name with JSON arguments
    |-- Interactive REPL for exploration
    |-- Can also connect to remote instances via gRPC
```

Build: `cargo build --features standalone,swiftrs` (macOS) or `cargo build --features standalone` (other)

### Pattern 4: AI Agent via MCP

Used by Claude Desktop, n8n, or custom AI agents.

```
AI Agent (Claude Desktop / n8n / custom)
    |-- Streamable HTTP (localhost:3000)
    |-- PSK Bearer token authentication
    |-- Tool calls: advisor_get_todos, agentic_process_todos, etc.
    |-- Human-in-the-loop: agents escalate risky actions
```

Configuration: Start MCP server via `mcp_start_server()` API call or `edamame-posture mcp-start`

---

## API Reference

Complete list of all RPC-registered API methods, organized by domain. Each method is callable via:
- Direct Rust function call (CLI tools)
- Flutter bridge (GUI app)
- gRPC RPC dispatch (remote clients)
- MCP tools (AI agents, for selected methods)

See [API_REFERENCE.md](API_REFERENCE.md) for the full API reference with parameter types and descriptions.

### Core (26 methods)

System lifecycle, device information, and platform management.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `initialize` | executable_type, branch, locale, ... | void | Initialize EDAMAME Core |
| `terminate` | exit: bool | void | Clean shutdown |
| `get_device_info` | -- | SystemInfoAPI | Device hardware/OS info |
| `get_core_version` | -- | String | Core library version |
| `get_core_info` | -- | String | Core build info |
| `get_branch` | -- | String | Active threat model branch |
| `get_admin_status` | -- | bool | Whether running with admin/root |
| `is_helper_enabled` | -- | bool | Helper daemon availability |
| `get_helper_state` | -- | String | Helper daemon state |
| `get_helper_url` | -- | String | Helper daemon URL |
| `is_outdated_app` | -- | bool | Whether app is outdated |
| `get_app_url` | -- | String | App download URL |
| `get_app_latest_version` | -- | String | Latest available version |
| `is_from_store` | -- | bool | Whether installed from app store |
| `set_demo_mode` | demo_mode_on: bool | void | Toggle demo mode |
| `set_demo_platform` | platform: String | void | Override platform for demo |
| `clear_demo_platform` | -- | void | Clear platform override |
| `get_demo_platform` | -- | String | Current demo platform |
| `get_all_logs` | -- | String | Complete log output |
| `get_new_logs` | -- | String | Logs since last call |
| `unified_log` | level: LogLevel, log: String | void | Send log from consumer |
| `get_globalpreferences_status` | -- | bool | macOS privacy settings |
| `prompt_globalpreferences` | title, message | void | Prompt for privacy access |
| `withdraw_globalpreferences` | -- | void | Withdraw privacy prompt |
| `get_community_devices` | -- | Vec\<CommunityDeviceAPI\> | P2P community devices |
| `get_p2p_stats` | -- | P2PStatsAPI | P2P network statistics |

### Score & Threats (11 methods)

Security scoring, threat detection, and remediation.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `compute_score` | -- | void | Trigger score computation |
| `get_score` | complete_only: bool | ScoreAPI | Get security score and threats |
| `get_last_computed_secs` | -- | i64 | Seconds since last computation |
| `get_threat_by_name` | name: String | Option\<ThreatAPI\> | Get specific threat details |
| `check_policy` | minimum_score, threat_ids, tag_prefixes | bool | Check policy compliance |
| `get_tag_prefixes` | -- | Vec\<String\> | Available threat tag prefixes |
| `remediate` | name: String, dont_report: bool | ThreatResultAPI | Remediate a threat |
| `rollback` | name: String, dont_report: bool | ThreatResultAPI | Rollback a remediation |
| `update_threats` | -- | void | Update threat models from cloud |
| `get_threats_url` | -- | String | Threat model source URL |
| `get_history` | -- | OrderHistoryAPI | Remediation history |

### Network / Flodbadd (71 methods)

LAN scanning, packet capture, session analysis, whitelists/blacklists, and anomaly detection.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `get_lanscan` | scan, deep_scan, wide_scan | LANScanAPI | Perform LAN scan |
| `get_devices` | -- | Vec\<DeviceInfoAPI\> | All discovered devices |
| `get_active_local_devices` | -- | Vec\<DeviceInfoAPI\> | Currently active devices |
| `cancel_scan` | -- | void | Cancel running scan |
| `start_capture` | -- | void | Start packet capture |
| `stop_capture` | -- | void | Stop packet capture |
| `is_capturing` | -- | bool | Capture running status |
| `get_sessions` | -- | Vec\<SessionInfoAPI\> | All captured sessions |
| `get_current_sessions` | -- | Vec\<SessionInfoAPI\> | Active sessions |
| `get_lan_sessions` | all: bool | LANSessionsAPI | LAN-specific sessions |
| `get_anomalous_sessions` | -- | Vec\<SessionInfoAPI\> | ML-detected anomalies |
| `get_blacklisted_sessions` | -- | Vec\<SessionInfoAPI\> | Blacklisted sessions |
| `get_whitelist_exceptions` | -- | Vec\<SessionInfoAPI\> | Whitelist violations |
| `get_whitelist_conformance` | -- | bool | Whitelist compliance status |
| `get_anomalous_status` | -- | bool | Any anomalies detected |
| `get_blacklisted_status` | -- | bool | Any blacklisted traffic |
| `set_whitelist` | whitelist_name: String | void | Set active whitelist |
| `set_custom_whitelists` | whitelist_json: String | void | Set custom whitelist rules |
| `create_custom_whitelists` | -- | String | Generate whitelist from traffic |
| `set_custom_blacklists` | blacklist_json: String | void | Set custom blacklist rules |
| `set_filter` | filter: SessionFilterAPI | void | Set session display filter |
| `get_filter` | -- | SessionFilterAPI | Get current filter |
| `get_network` | -- | NetworkAPI | Current network info |
| `set_network` | network: NetworkAPI | void | Set network config |
| `get_device_remediation` | ip_address: String | String | AI remediation for device |
| `get_session_remediation` | uid: String | String | AI remediation for session |
| `get_packet_stats` | -- | PacketStatsAPI | Capture statistics |
| `get_analyzer_stats` | -- | AnalyzerStatsAPI | ML analyzer statistics |
| ... | | | See [API_REFERENCE.md](API_REFERENCE.md) for all 71 methods |

### Breach Detection / Pwned (8 methods)

Email breach monitoring via HaveIBeenPwned integration.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `add_pwned_email` | email: String | bool | Monitor email for breaches |
| `remove_pwned_email` | email: String | bool | Stop monitoring email |
| `get_breaches_for_email` | email: String | PwnedAPI | Breaches for specific email |
| `get_all_breaches` | -- | PwnedAPI | All breaches across emails |
| `get_breach_by_name_and_email` | name, email | Option\<PwnedItemAPI\> | Specific breach details |
| `get_multi_email_summary` | -- | PwnedMultiEmailAPI | Summary across all emails |
| `toggle_breach_for_email` | email, name, dismiss: bool | void | Dismiss/undismiss a breach |
| `get_breach_remediation` | name, description, is_service | String | AI remediation advice |

### Trust & Compliance (13 methods)

Domain connection, policy enforcement, and compliance reporting.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `set_credentials` | user, domain, pin | void | Set domain credentials |
| `connect_domain` | -- | void | Connect to managed domain |
| `disconnect_domain` | -- | void | Disconnect from domain |
| `request_pin` | -- | void | Request domain PIN |
| `get_connection` | -- | ConnectionStatusAPI | Connection status |
| `get_last_report_secs` | -- | i64 | Seconds since last report |
| `get_last_report_signature` | -- | String | Cryptographic report signature |
| `get_signature_from_score_with_email` | email: String | String | Generate signed score |
| `request_report_from_signature` | email, signature, format | void | Request compliance report |
| `check_policy_for_domain` | signature, domain, policy_name | bool | Check specific policy |
| `check_policies_for_domain` | signature, domain | Vec\<PoliciesStatusAPI\> | Check all policies |
| `check_policies_for_current_domain` | -- | Vec\<PoliciesStatusAPI\> | Policies for current domain |
| `user_feedback` | context, note, email, app_log, helper_log | void | Submit user feedback |

### Advisor (6 methods)

Security recommendations and AI-enriched advice.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `get_advisor` | -- | AdvisorAPI | Full advisor state with todos |
| `get_advisor_state` | -- | AdvisorStateAPI | Summary advisor state |
| `is_advisor_fully_resolved` | -- | bool | All todos resolved |
| `get_advisor_rag_prompt` | -- | String | RAG-enriched prompt for LLM |
| `get_advisor_remediation` | question: String | String | AI advice for question |
| `request_advisor_report` | email: String | void | Email advisor report |

### Agentic / AI Automation (30 methods)

AI-powered security automation with multiple LLM providers.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `agentic_process_todos` | confirmation_level: i32 | AgenticResultsAPI | AI-powered todo processing |
| `agentic_get_action_history` | -- | Vec\<ActionRecordAPI\> | Action audit trail |
| `agentic_execute_action` | action_id: String | bool | Execute pending action |
| `agentic_undo_action` | action_id: String | bool | Undo specific action |
| `agentic_retry_action` | action_id: String | bool | Retry failed action |
| `agentic_undo_all_actions` | -- | UndoAllResultAPI | Undo all actions |
| `agentic_cancel_processing` | -- | bool | Cancel current processing |
| `agentic_set_auto_processing` | enabled, interval_secs, mode | bool | Configure auto-processing |
| `agentic_get_auto_processing_status` | -- | AgenticAutoProcessingStatusAPI | Auto-processing config |
| `agentic_set_llm_config` | provider, api_key, model, ... | bool | Configure LLM provider |
| `agentic_get_llm_config` | -- | LLMConfigInfoAPI | Current LLM config |
| `agentic_test_llm` | -- | LLMTestResultAPI | Test LLM connectivity |
| `agentic_get_workflow_status` | -- | Option\<AgenticWorkflowStatusAPI\> | Current workflow state |
| `agentic_get_status` | -- | AgenticStatusAPI | Overall agentic status |
| `agentic_get_summary` | -- | AgenticSummaryAPI | Summary statistics |
| `agentic_get_token_usage_stats` | -- | TokenUsageStatsAPI | LLM token consumption |
| `agentic_get_subscription_status` | -- | AgenticSubscriptionStatusAPI | Subscription info |
| `agentic_get_portal_url` | -- | String | EDAMAME Portal URL |
| `agentic_set_edamame_api_key` | api_key: String | bool | Set EDAMAME API key |
| `agentic_has_edamame_api_key` | -- | bool | API key configured |
| `agentic_clear_error` | -- | bool | Clear error state |
| `agentic_clear_action_history` | -- | bool | Clear action history |
| `agentic_mark_action_read` | action_id: String | bool | Mark action as read |
| `agentic_mark_action_unread` | action_id: String | bool | Mark action as unread |
| `agentic_mark_all_actions_read` | -- | bool | Mark all as read |
| `oauth_signin_internal` | -- | String | OAuth sign-in to EDAMAME Portal |
| `oauth_refresh_internal` | -- | String | Refresh OAuth tokens |
| `oauth_signout_internal` | -- | String | Sign out |
| `oauth_get_status` | -- | OAuthStatusAPI | OAuth authentication status |
| `oauth_open_signup` | -- | bool | Open sign-up page |

### MCP Server (3 methods)

MCP server management (feature-gated: `mcp`).

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `mcp_start_server` | port, psk, enable_cors, listen_all_interfaces | String | Start MCP server |
| `mcp_stop_server` | -- | String | Stop MCP server |
| `mcp_get_server_status` | -- | String | Server running status |

> **Note**: PSK generation (`mcp_generate_psk`) is provided by the [EDAMAME Posture CLI](https://github.com/edamametechnologies/edamame_posture_cli), not by EDAMAME Core directly.

---

## OEM Licensing

EDAMAME Core is **closed source** and available for OEM integration into third-party products. OEM partners receive:

- **Pre-built libraries** for all supported platforms (macOS, Windows, Linux, iOS, Android)
- **API documentation** and integration guides
- **Feature flag configuration** to include only the capabilities needed
- **Technical support** for integration

### What You Get

- The complete EDAMAME security engine as a linkable library
- All 175+ API methods across security scoring, network analysis, breach detection, AI automation, and compliance
- Cross-platform support from a single codebase
- Reactive event system for building responsive UIs
- gRPC interface for remote management
- MCP server for AI agent integration

### Contact

For OEM licensing inquiries: [EDAMAME Technologies](https://www.edamame.tech)

---

## Related Resources

- [EDAMAME Technologies](https://github.com/edamametechnologies) -- Organization profile and ecosystem overview
- [EDAMAME Security](https://github.com/edamametechnologies/edamame_security) -- Flutter GUI application
- [EDAMAME Posture CLI](https://github.com/edamametechnologies/edamame_posture_cli) -- CI/CD security tool
- [EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli) -- RPC explorer and API access
- [EDAMAME Foundation](https://github.com/edamametechnologies/edamame_foundation) -- Open source security library
- [EDAMAME Backend](https://github.com/edamametechnologies/edamame_backend) -- API data structures
- [Threat Models](https://github.com/edamametechnologies/threatmodels) -- Security benchmarks and policies
- [Flodbadd](https://github.com/edamametechnologies/flodbadd) -- Network visibility engine
