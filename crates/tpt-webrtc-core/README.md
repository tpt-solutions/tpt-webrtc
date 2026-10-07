# tpt-webrtc-core

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-core.svg)](https://crates.io/crates/tpt-webrtc-core)
[![Documentation](https://docs.rs/tpt-webrtc-core/badge.svg)](https://docs.rs/tpt-webrtc-core)
[![License](https://img.shields.io/crates/l/tpt-webrtc-core.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

Foundation layer for the `tpt-webrtc` stack: configuration types, async socket abstraction, workspace-wide error taxonomy, shared ICE candidate type, and cryptographic primitives (via `ring`) used by all protocol crates.

This crate is the only place where `ring` is touched for primitives; protocol crates depend on these helpers so that crypto policy stays in one place. It contains no protocol logic.

## Features

- **Configuration** — `WebRtcConfig`, `IceServer`, `CodecPreferences`, `BweAlgorithm`
- **Socket Abstraction** — `WebRtcSocket` trait and `UdpWebRtcSocket` for async UDP I/O
- **Error Taxonomy** — `WebRtcError` enum covering all crate-specific error types
- **ICE Candidates** — `IceCandidate`, `CandidateType` shared across the stack
- **Cryptographic Primitives** — HMAC, SHA, CRC32, random bytes, ECDSA helpers, DTLS certificate generation

## Installation

```toml
[dependencies]
tpt-webrtc-core = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_core::{WebRtcConfig, IceServer, UdpWebRtcSocket, DtlsCertificate};

// Create a WebRTC configuration
let config = WebRtcConfig::default();

// Create a self-signed DTLS certificate for ICE/DTLS
let cert = DtlsCertificate::generate().unwrap();

// Bind a UDP socket
let socket = UdpWebRtcSocket::bind("0.0.0.0:0").await?;
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `config` | `WebRtcConfig`, `IceServer`, `CodecPreferences`, `BweAlgorithm` |
| `socket` | `WebRtcSocket` trait, `UdpWebRtcSocket` implementation |
| `error` | `WebRtcError` and all protocol-specific error enums |
| `candidate` | `IceCandidate`, `CandidateType` (host/srflx/relayed) |
| `crypto` | HMAC, SHA, CRC32, random bytes, ECDSA, DTLS certificate helpers |

## Architecture

```
┌─────────────────────────────────────┐
│         tpt-webrtc-core             │
├─────────────────────────────────────┤
│  config  │  socket  │  error        │
│  crypto  │ candidate│               │
└──────────┴──────────┴───────────────┘
        ▲              ▲
        │              │
        ▼              ▼
┌─────────────┐  ┌──────────────┐
│ tpt-webrtc  │  │ tpt-webrtc   │
│    -sdp     │  │    -ice      │
│  ...etc     │  │  ...etc      │
└─────────────┘  └──────────────┘
```

All downstream crates (`tpt-webrtc-sdp`, `tpt-webrtc-ice`, `tpt-webrtc-dtls`, `tpt-webrtc-rtp`, `tpt-webrtc-sctp`, `tpt-webrtc-app`, `tpt-webrtc-media`, `tpt-webrtc-codecs`) depend on this crate.

## License

Dual-licensed under `MIT OR Apache-2.0`. See [LICENSE-MIT](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT) and [LICENSE-APACHE](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-APACHE).

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md) in the repository root.