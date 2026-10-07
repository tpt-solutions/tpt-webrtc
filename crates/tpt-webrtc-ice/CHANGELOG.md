# Changelog

All notable changes to `tpt-webrtc-ice` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- ICE Agent (RFC 8445):
  - Candidate gathering: host, server-reflexive (STUN), relayed (TURN)
  - Candidate pair formation and prioritization
  - Connectivity checks with exponential backoff
  - Nomination (controlling/controlled roles)
  - State machine: New → Gathering → Checking → Connected → Completed/Failed/Disconnected
- STUN Client (RFC 8489):
  - Binding Request/Response/Indication/Error Response
  - Attributes: MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, USERNAME, MESSAGE-INTEGRITY, FINGERPRINT, ERROR-CODE, UNKNOWN-ATTRIBUTES, REALM, NONCE, SOFTWARE, ALTERNATE-SERVER
  - Stateless codec facade (`StunClient`)
- TURN Client (RFC 8656):
  - Allocate/Refresh requests
  - CreatePermission
  - ChannelBind
  - Send/Data Indications
  - `TurnAllocation` management
- Explicit event loop control via `IceAgent::poll()` for testability
- Integration test: `ice_loopback` — full ICE negotiation over loopback UDP

### Supported RFCs
- RFC 8445 — ICE
- RFC 8489 — STUN
- RFC 8656 — TURN
- RFC 5769 — STUN Server (test compatibility)

### Security
- Message integrity (HMAC-SHA1) for STUN/TURN
- FINGERPRINT attribute for all messages
- Short-term credentials (username/password) for TURN

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-ice-v0.1.0