# Changelog

All notable changes to `tpt-webrtc-sctp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- SCTP Association (RFC 4960 subset, RFC 8831):
  - 4-way handshake: INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK
  - Cookie-based validation (HMAC-SHA1)
  - State machine: Closed → Cookie-Wait → Cookie-Echoed → Established → Shutdown-Pending → Closed
  - Heartbeats for path monitoring
- Stream Multiplexing:
  - Multiple streams per association
  - Stream sequence numbers
  - Stream reset (not yet implemented)
- DATA Chunk Handling:
  - Ordered/unordered delivery
  - Fragmentation/reassembly (RFC 4960 §6.10)
  - SACK-driven retransmission (fast retransmit on 3 duplicate TSNs)
  - Cumulative and selective ACKs
- WebRTC Data Channels (RFC 8831):
  - `DataChannelOpen` / `DataChannelAck` (PPID 50/51)
  - `Reliability` policies: Reliable, Unordered, PartialReliableRtx, PartialReliableTime
  - `SctpStreamConfig` for stream creation
  - `SctpTransport` wrapping DTLS transport
- Chunk Types:
  - INIT, INIT_ACK, SACK, HEARTBEAT, HEARTBEAT_ACK, ABORT, SHUTDOWN, SHUTDOWN_ACK, ERROR, COOKIE_ECHO, COOKIE_ACK, DATA
- Integration test: `sctp_over_dtls` — full SCTP handshake + data channel over DTLS loopback

### Constants
- `PPID_DATA_CHANNEL_OPEN = 50`
- `PPID_DATA_CHANNEL_ACK = 51`
- `PPID_STRING = 51`
- `PPID_BINARY = 53`
- `WEBRTC_SCTP_PORT = 5000` (RFC 8831 §5.1)

### Scope Notes (Deliberate)
- Subset of RFC 4960 sufficient for WebRTC data channels
- No multihoming (single path)
- No dynamic address reconfiguration
- No stream reset (RFC 6525) — planned

### Security
- Runs over DTLS (handled by `tpt-webrtc-dtls`)
- Cookie validation prevents reflection attacks
- HMAC-SHA1 for cookie integrity

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-sctp-v0.1.0