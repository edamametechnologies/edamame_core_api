# EDAMAME Core Event System

EDAMAME Core uses a bitmask-based event system for broadcasting state changes from the Rust core to all consumers: Flutter UI, gRPC clients, and internal listeners.

## Design

Each event is assigned a unique power-of-2 value, enabling multiple events to be OR-combined into a single `u64` bitmask for efficient delivery.

```rust
// Example: receiving combined event value 16777224
// 16777224 = 16777216 | 8 = ScoreCompleted | ConnectionSuccess
let events: u64 = 16777224;
if events & 16777216 != 0 { /* ScoreCompleted fired */ }
if events & 8 != 0 { /* ConnectionSuccess fired */ }
```

## Delivery Channels

| Channel | Transport | Consumer |
|---------|-----------|----------|
| Flutter StreamSink | `StreamSink<u64>` via flutter_rust_bridge | EDAMAME Security app (Dart) |
| gRPC Stream | Server-streaming RPC `subscribe_to_events` | EDAMAME CLI, remote clients |
| Internal Listener | `mpsc::Sender<u64>` | In-process components |

### Flutter Integration

```dart
// Dart side: events arrive as u64 bitmask
coreEventStream.listen((u64 eventMask) {
    if (eventMask & 16777216 != 0) {
        // ScoreCompleted -- refresh score UI
        refreshScore();
    }
    if (eventMask & 4096 != 0) {
        // LANScanCompleted -- refresh device list
        refreshDevices();
    }
});
```

### gRPC Integration

```rust
// Subscribe to events via gRPC streaming
let stream = client.subscribe_to_events(Request::new(())).await?;
while let Some(event) = stream.message().await? {
    let event_mask: u64 = event.value;
    // Process event bitmask
}
```

## Triggering Events

Events are triggered from the CoreManager layer:

```rust
// Inside CoreManager methods
self.state.read().await.event_manager.trigger_event(CoreEvent::ScoreCompleted);
```

## Event Reference

### Connection Events

| Event | Value | Description |
|-------|-------|-------------|
| `ConnectionError` | 2 | Backend connection failed |
| `ConnectionStatusUpdated` | 4 | Connection status changed (connecting, connected, error) |
| `ConnectionSuccess` | 8 | Backend connection established successfully |

### Application Events

| Event | Value | Description |
|-------|-------|-------------|
| `AppOutdated` | 1 | Current application version is outdated; update available |

### Score Events

| Event | Value | Description |
|-------|-------|-------------|
| `MetricCompleted` | 16384 | A single threat metric evaluation completed |
| `ScoreCanceled` | 262144 | Score computation was canceled |
| `ScoreComputationRequested` | 1048576 | Score computation was requested |
| `ScoreComputationStarted` | 2097152 | Score computation has begun |
| `ScoreDecreased` | 4194304 | Security score decreased (regression) |
| `ScoreIncreased` | 8388608 | Security score increased (improvement) |
| `ScoreCompleted` | 16777216 | Score computation finished; results available |
| `ScoreReported` | 33554432 | Score was reported to the backend |

### Network Events

| Event | Value | Description |
|-------|-------|-------------|
| `DeviceAdded` | 16 | New device discovered on the local network |
| `DevicesProgress` | 32 | Device scan progress update (incremental) |
| `DevicesUpdated` | 64 | Device list changed |
| `LANScanCancelStarted` | 2048 | LAN scan cancellation initiated |
| `LANScanCompleted` | 4096 | LAN scan finished |
| `LANScanStarted` | 8192 | LAN scan started |
| `LANScanUpdated` | 524288 | LAN scan results updated incrementally |
| `NetworkChanged` | 32768 | Network configuration changed (interface, SSID, gateway) |
| `SessionsUpdated` | 536870912 | Network sessions updated |
| `AnomalousSessionsAdded` | 1073741824 | ML-detected anomalous sessions found |
| `BlacklistedSessionsAdded` | 2147483648 | Blacklisted sessions detected |

### Breach Events

| Event | Value | Description |
|-------|-------|-------------|
| `BreachesUpdated` | 268435456 | Breach data updated (new breaches found or status changed) |

### Trust & Domain Events

| Event | Value | Description |
|-------|-------|-------------|
| `PINError` | 65536 | Domain PIN verification failed |
| `PINSuccess` | 131072 | Domain PIN verification succeeded |
| `PoliciesStatusChanged` | 67108864 | Policy compliance status changed |
| `DomainLimitReached` | 68719476736 | Domain device limit reached |

### Helper Events

| Event | Value | Description |
|-------|-------|-------------|
| `HelperStateChanged` | 1024 | Privileged helper daemon state changed (active/inactive) |

### Community Events

| Event | Value | Description |
|-------|-------|-------------|
| `CommunityDevicesUpdated` | 134217728 | Community/P2P device list updated |

### Advisor Events

| Event | Value | Description |
|-------|-------|-------------|
| `AdvisorUpdated` | 4294967296 | Security advisor recommendations changed |

### Agentic Events

| Event | Value | Description |
|-------|-------|-------------|
| `AgenticUpdated` | 8589934592 | AI automation state changed (new results, processing complete) |
| `AgenticConfirmed` | 17179869184 | An AI action was confirmed by the user |
| `AgenticEscalated` | 34359738368 | An AI action was escalated for human review |
| `AgenticStatusUpdated` | 137438953472 | AI subscription/configuration status changed |
| `SubscriptionLimitReached` | 274877906944 | Subscription usage limit reached |

## Event Mask Examples

Common event mask patterns:

| Use Case | Events | Combined Mask |
|----------|--------|---------------|
| Score changes | `ScoreCompleted \| ScoreIncreased \| ScoreDecreased` | 29360128 |
| Network alerts | `AnomalousSessionsAdded \| BlacklistedSessionsAdded` | 3221225472 |
| AI updates | `AgenticUpdated \| AgenticConfirmed \| AgenticEscalated` | 60129542144 |
| All connection | `ConnectionError \| ConnectionStatusUpdated \| ConnectionSuccess` | 14 |
| LAN scan lifecycle | `LANScanStarted \| LANScanUpdated \| LANScanCompleted` | 536576 |
