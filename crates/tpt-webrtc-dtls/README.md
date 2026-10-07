# tpt-webrtc-dtls

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-dtls.svg)](https://crates.io/crates/tpt-webrtc-dtls)
[![Documentation](https://docs.rs/tpt-webrtc-dtls/badge.svg)](https://docs.rs/tpt-webrtc-dtls)
[![License](https://img.shields.io/crates/l/tpt-webrtc-dtls.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

Security layer: a purpose-built DTLS 1.2 (RFC 6347) implementation for the WebRTC profile — ECDHE-ECDSA with a single self-signed certificate fingerprinted in SDP (RFC 8122), the `use_srtp` extension (RFC 5764) and the `EXTRACTOR-dtls_srtp` key export (RFC 5705) — plus SRTP sessions (RFC 3711).

## Scope (Deliberate)

- One handshake cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B)
- No X.509 chain validation (WebRTC checks the SDP fingerprint instead)
- SRTP session operates on raw packet bytes; RTP-typed helpers live in `tpt-webrtc-rtp`
- Single curve: secp256r1 (0x0017)

## Features

- **DTLS 1.2 Handshake** — Client/server, ECDHE-ECDSA, single cipher suite
- **DTLS-SRTP** — `use_srtp` extension, key export via RFC 5705
- **SRTP Sessions** — AES-CM/HMAC-SHA1, AEAD-AES-GCM (RFC 3711, RFC 7714)
- **Record Layer** — Fragmentation, reassembly, epoch management
- **PRF** — TLS 1.2 PRF with SHA-256 for key expansion

## Installation

```toml
[dependencies]
tpt-webrtc-dtls = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_dtls::{DtlsConfig, DtlsRole, DtlsTransport};
use tpt_webrtc_core::DtlsCertificate;

let cert = DtlsCertificate::generate().unwrap();
let config = DtlsConfig {
    certificate: cert,
    role: DtlsRole::Client,
    expected_fingerprint: None,
};
let transport = DtlsTransport::new(config);

assert_eq!(transport.state(), DtlsState::New);

// Drive handshake
transport.handshake().await?;

// Get SRTP keys for media protection
let srtp_keys = transport.srtp_keys().unwrap();
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `handshake` | DTLS handshake state machine, messages, flights |
| `record` | `RecordLayer` — fragmentation, encryption, epochs |
| `prf` | TLS 1.2 PRF (SHA-256) for key derivation |
| `srtp` | `SrtpSession`, `SrtpCipher`, `Direction` |
| `transport` | `DtlsTransport`, `DtlsConfig`, `DtlsRole`, `DtlsState` |

## DTLS State Machine

```
New → Handshaking → Connected → Closed
              ↓
           Failed
```

## Cipher Suites & Profiles

| Constant | Value | Description |
|----------|-------|-------------|
| `CIPHER_SUITE` | 0xC02B | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| `SRTP_AES128_CM_HMAC_SHA1_80` | 0x0001 | Default DTLS-SRTP profile |
| `SRTP_AEAD_AES_128_GCM` | 0x0007 | AEAD profile (RFC 7714) |
| `GROUP_SECP256R1` | 0x0017 | Named group for ECDHE |

## Testing

Run the DTLS loopback test:

```bash
cargo test -p tpt-webrtc-dtls --test dtls_loopback
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).