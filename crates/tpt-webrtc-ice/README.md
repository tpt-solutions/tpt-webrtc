# tpt-webrtc-ice

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-ice.svg)](https://crates.io/crates/tpt-webrtc-ice)
[![Documentation](https://docs.rs/tpt-webrtc-ice/badge.svg)](https://docs.rs/tpt-webrtc-ice)
[![License](https://img.shields.io/crates/l/tpt-webrtc-ice.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

ICE connectivity layer (RFC 8445) with STUN (RFC 8489) and TURN (RFC 8656) clients.

- **IceAgent** — Gathers host/server-reflexive/relayed candidates, pairs them with the peer's candidates, performs connectivity checks, and nominates a pair. Driven explicitly so applications control timing; SDP is exchanged out of band by the caller.
- **StunClient** — Stateless RFC 8489 codec facade for binding requests/indications.
- **TurnClient** — Basic TURN allocation, permission, and channel binding.

## Features

- **Full ICE Agent** — Candidate gathering, pair formation, connectivity checks, nomination, state machine
- **STUN Client** — Binding requests, indications, error responses, attributes
- **TURN Client** — Allocate, refresh, create-permission, channel-bind, send/recv
- **Candidate Types** — Host, server-reflexive, peer-reflexive, relayed
- **Explicit Control** — Application drives the event loop for testability

## Installation

```toml
[dependencies]
tpt-webrtc-ice = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_ice::{IceAgent, IceConfig, StunClient};
use tpt_webrtc_core::UdpWebRtcSocket;
use std::net::SocketAddr;

let socket = UdpWebRtcSocket::bind("0.0.0.0:0").await?;
let config = IceConfig::new(true); // controlling = true
let agent = IceAgent::new(config, socket);

assert_eq!(agent.state(), IceState::New);

// Gather candidates
agent.gather_candidates().await?;

// Drive the agent (in a loop)
while agent.state() != IceState::Completed {
    agent.poll().await?;
}
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `agent` | `IceAgent`, `IceConfig`, `IceState`, `CandidatePair`, `PairState` |
| `client` | `StunClient` for STUN message encoding/decoding |
| `stun` | `StunMessage`, `StunAttribute`, `StunMessageType`, `StunError` |
| `turn` | `TurnClient`, `TurnAllocation`, `TurnError` |

## ICE Agent States

```
New → Gathering → Checking → Connected → Completed
                     ↓
                  Failed
                     ↓
                Disconnected
```

## STUN/TURN Support

| RFC | Feature | Status |
|-----|---------|--------|
| RFC 8489 | STUN Binding Request/Response | ✅ |
| RFC 8489 | STUN Indications | ✅ |
| RFC 8489 | STUN Attributes (XOR-MAPPED-ADDRESS, etc.) | ✅ |
| RFC 8656 | TURN Allocate/Refresh | ✅ |
| RFC 8656 | TURN CreatePermission | ✅ |
| RFC 8656 | TURN ChannelBind | ✅ |
| RFC 8656 | TURN Send/Data Indications | ✅ |

## Testing

Run the loopback integration test:

```bash
cargo test -p tpt-webrtc-ice --test ice_loopback
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).