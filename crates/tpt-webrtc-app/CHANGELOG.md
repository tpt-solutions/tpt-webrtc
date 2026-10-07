# Changelog

All notable changes to `tpt-webrtc-app` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- `PeerConnection` — high-level WebRTC API:
  - `create_offer()` / `create_answer()` — SDP with ICE/DTLS/candidates
  - `set_local_description()` / `set_remote_description()`
  - `poll()` — event loop driving ICE, DTLS, SCTP, RTP
  - State machine: New → Connecting → Connected → Disconnected → Failed/Closed
- Signaling Abstraction:
  - `SignalingTransport` trait for custom signaling (WebSocket, HTTP, etc.)
  - `LoopbackSignaling` for testing
- Data Channels:
  - `create_data_channel(label, config)` — reliable/unordered
  - `DataChannel` — send/recv `DataChannelMessage` (Text/Binary)
  - `DataChannelState` — Connecting/Open/Closing/Closed
- Media Tracks:
  - `add_track()` / `add_transceiver()` — `MediaStreamTrack`
  - `RtpSender` — send audio/video frames
  - `RtpReceiver` — receive audio/video frames
  - `TrackKind` — Audio/Video
- Configuration:
  - `PeerConnectionConfig` — STUN/TURN servers, codec preferences, BWE algorithm
- Datagram Classification (RFC 7983):
  - `classify_datagram()` — STUN/DTLS/RTP/Unknown demux
  - `DatagramKind` enum
- Examples:
  - `audio_call.rs` — full audio call with loopback signaling
  - `data_channel_pingpong.rs` — data channel echo test
- Integration test: `full_connection` — end-to-end PeerConnection over loopback

### Architecture
```
PeerConnection
├── SDP (tpt-webrtc-sdp)
├── ICE (tpt-webrtc-ice)
├── DTLS-SRTP (tpt-webrtc-dtls)
├── SCTP (tpt-webrtc-sctp)
└── RTP (tpt-webrtc-rtp)
```

### State Machines

**PeerConnection:**
```
New → Connecting → Connected → Disconnected
              ↓              ↓
           Failed         Closed
```

**ICE Connection:**
```
New → Checking → Connected → Completed
            ↓
         Failed
            ↓
      Disconnected
```

**Signaling:**
```
Stable → Have-Local-Offer → Have-Remote-Offer → Stable
              ↓                   ↓
         (rollback)          (rollback)
```

### Testing
```bash
cargo run -p tpt-webrtc-app --example audio_call
cargo run -p tpt-webrtc-app --example data_channel_pingpong
cargo test -p tpt-webrtc-app --test full_connection
```

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-app-v0.1.0