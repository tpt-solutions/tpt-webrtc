# Changelog

All notable changes to `tpt-webrtc-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- Foundation layer for the tpt-webrtc stack
- `WebRtcConfig` — centralized configuration for all WebRTC components
- `IceServer` — STUN/TURN server configuration with credentials
- `CodecPreferences` — codec ordering and parameter negotiation
- `BweAlgorithm` — bandwidth estimation algorithm selection (GCC, TWCC, REMB, BBR)
- `WebRtcSocket` trait — async UDP socket abstraction for testability
- `UdpWebRtcSocket` — Tokio-based UDP socket implementation
- `WebRtcError` — unified error taxonomy covering all protocol crates
- `IceCandidate` / `CandidateType` — shared ICE candidate representation
- Cryptographic primitives via `ring`:
  - `DtlsCertificate::generate()` — self-signed ECDSA P-256 certificates
  - `Fingerprint` — SHA-256 certificate fingerprints for SDP
  - HMAC-SHA1, HMAC-SHA256, SHA-1, SHA-256, MD5, CRC32-IEEE
  - Constant-time comparison, random bytes/integers
  - ECDSA DER/fixed format conversion, P-256 point verification

### Security
- All cryptographic operations use `ring` (RustCrypto, audited)
- Certificate generation uses CSPRNG via `getrandom`
- Constant-time comparison for fingerprint verification

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-core-v0.1.0