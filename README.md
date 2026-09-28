# tpt-webrtc

A complete, production-ready WebRTC implementation in pure Rust.

**Mission**: replace Google's 2-million-line C++ libwebrtc with a memory-safe,
AV1-first, formally-verified WebRTC stack:

- **Full protocol stack** — ICE, STUN, TURN, DTLS-SRTP, RTP/RTCP, SCTP data channels
- **AV1-first codecs** — AV1 / VP8 / VP9 / Opus; **zero H.264** (patent-royalty avoidance)
- **Zero libwebrtc** — no Google C++ code, no GN build hell, no hidden patent traps
- **Formally verified core state machines** — ICE and DTLS handshake contracts verified via `tpt-telos`
- **Async-native** — built on `tokio` for high-concurrency server and client use

Dual-licensed under `MIT OR Apache-2.0`. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

## Crates

| Crate | Layer |
|---|---|
| `tpt-webrtc-core` | Async runtime integration, socket abstraction, errors, crypto primitives |
| `tpt-webrtc-sdp` | SDP parser/generator (RFC 8866), BUNDLE / RTCP-MUX, offer/answer model |
| `tpt-webrtc-ice` | ICE agent (RFC 8445), STUN (RFC 8489), TURN (RFC 8656) |
| `tpt-webrtc-dtls` | DTLS 1.2 (RFC 6347), DTLS-SRTP key derivation, SRTP sessions |
| `tpt-webrtc-rtp` | RTP/RTCP packetization, payload packetizers, RTCP feedback, jitter buffer |
| `tpt-webrtc-sctp` | SCTP over DTLS (RFC 8831) for data channels |
| `tpt-webrtc-codecs` | AV1 (rav1e/dav1d), VP8/VP9, Opus, hardware acceleration |
| `tpt-webrtc-media` | Audio processing (AEC/NS/AGC), BWE (GCC/TWCC/REMB), simulcast |
| `tpt-webrtc-app` | High-level `PeerConnection` API, signaling integration |

The full design lives in [spec.txt](spec.txt); the build plan in
[todo.md](todo.md).

## Status

Work in progress. Phases 1–2 (foundation, security & transport) are the
current focus.
