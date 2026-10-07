# tpt-webrtc-sctp

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-sctp.svg)](https://crates.io/crates/tpt-webrtc-sctp)
[![Documentation](https://docs.rs/tpt-webrtc-sctp/badge.svg)](https://docs.rs/tpt-webrtc-sctp)
[![License](https://img.shields.io/crates/l/tpt-webrtc-sctp.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

SCTP over DTLS for WebRTC data channels (RFC 8831, RFC 4960 subset):

- Association establishment (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK)
- Ordered and unordered DATA with SACK-driven (re)transmission
- DataChannel establishment protocol (PPID 50/51)

## Features

- **SCTP Association** — Full 4-way handshake, cookie-based validation
- **Data Channels** — Reliable/unordered, configurable retransmission
- **Stream Multiplexing** — Multiple streams per association
- **SACK Processing** — Selective acknowledgment, fast retransmit
- **PPID Support** — Binary (53), String (51), DataChannel control (50/51)

## Installation

```toml
[dependencies]
tpt-webrtc-sctp = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_sctp::{SctpTransport, SctpStreamConfig, Reliability};
use tpt_webrtc_dtls::DtlsTransport;

// Assuming DTLS transport is connected
let sctp = SctpTransport::new(dtls_transport).await?;

// Open a reliable ordered data channel
let config = SctpStreamConfig {
    stream_id: 1,
    reliability: Reliability::Reliable,
    label: "chat".to_string(),
    protocol: "".to_string(),
};
let channel = sctp.open_stream(config).await?;

// Send/receive
channel.send(b"Hello, World!").await?;
if let Some(msg) = channel.recv().await? {
    println!("Received: {:?}", msg);
}
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `association` | `SctpAssociation`, `SctpTransport`, `SctpState`, `DataChannelOpen`, `SctpMessage`, `SctpStreamConfig`, `Reliability` |
| `chunk` | `Chunk`, `ChunkType` — DATA, INIT, INIT_ACK, SACK, HEARTBEAT, etc. |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PPID_DATA_CHANNEL_OPEN` | 50 | Data channel open (RFC 8831) |
| `PPID_DATA_CHANNEL_ACK` | 51 | Data channel ack |
| `PPID_STRING` | 51 | UTF-8 string data |
| `PPID_BINARY` | 53 | Binary data |
| `WEBRTC_SCTP_PORT` | 5000 | Default SCTP port (RFC 8831 §5.1) |

## SCTP State Machine

```
Closed → Cookie-Wait → Cookie-Echoed → Established → Shutdown-Pending → Closed
                              ↓
                         Shutdown-Received
                              ↓
                         Shutdown-Ack-Sent
```

## Reliability Types

| Type | Description |
|------|-------------|
| `Reliable` | Ordered, retransmitted until acknowledged |
| `Unordered` | Unordered, retransmitted until acknowledged |
| `PartialReliableRtx(u32)` | Max retransmission count |
| `PartialReliableTime(u32)` | Max lifetime in ms |

## Testing

Run the SCTP-over-DTLS integration test:

```bash
cargo test -p tpt-webrtc-sctp --test sctp_over_dtls
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).