# Changelog

All notable changes to `tpt-webrtc-dtls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- DTLS 1.2 (RFC 6347) handshake:
  - Client and server roles
  - Single cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B)
  - Single named group: secp256r1 (0x0017)
  - Flight-based retransmission with exponential backoff
  - Cookie exchange for DoS protection
- DTLS-SRTP (RFC 5764):
  - `use_srtp` extension negotiation
  - Key export via `EXTRACTOR-dtls_srtp` (RFC 5705)
  - Profiles: `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001), `SRTP_AEAD_AES_128_GCM` (0x0007)
- SRTP Sessions (RFC 3711, RFC 7714):
  - `SrtpSession` with AES-CM/HMAC-SHA1 and AEAD-AES-GCM
  - `protect_rtp` / `unprotect_rtp` / `protect_rtcp` / `unprotect_rtcp`
  - ROC (Roll-Over Counter) management
  - Replay protection with bitmap
- Record Layer:
  - Fragmentation/reassembly
  - Epoch management (handshake vs application data)
  - AEAD encryption/decryption with implicit IV
- TLS 1.2 PRF (SHA-256) for key expansion
- Integration test: `dtls_loopback` — full DTLS handshake + SRTP over loopback

### Scope Notes (Deliberate)
- No X.509 chain validation (WebRTC verifies SDP fingerprint instead)
- No cipher suite negotiation (WebRTC profile mandates single suite)
- No renegotiation (not used in WebRTC)
- No DTLS 1.3 (WebRTC uses DTLS 1.2)

### Constants
- `CIPHER_SUITE = 0xC02B`
- `SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001`
- `SRTP_AEAD_AES_128_GCM = 0x0007`
- `GROUP_SECP256R1 = 0x0017`

### Security
- All crypto via `ring` (RustCrypto)
- Constant-time operations where applicable
- Replay protection enabled by default
- Certificate fingerprint verification delegated to application (via SDP)

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-dtls-v0.1.0