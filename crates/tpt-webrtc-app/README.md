# tpt-webrtc-app

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-app.svg)](https://crates.io/crates/tpt-webrtc-app)
[![Documentation](https://docs.rs/tpt-webrtc-app/badge.svg)](https://docs.rs/tpt-webrtc-app)
[![License](https://img.shields.io/crates/l/tpt-webrtc-app.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

The application layer: `PeerConnection` wires the whole stack — SDP offer/answer (`tpt_webrtc_sdp`), ICE connectivity (`tpt_webrtc_ice`), DTLS-SRTP (`tpt_webrtc_dtls`), SCTP data channels (`tpt_webrtc_sctp`) and RTP media (`tpt_webrtc_rtp`) — behind one API.

## Features

- **PeerConnection** — High-level API mirroring WebRTC's `RTCPeerConnection`
- **SDP Negotiation** — Offer/answer with ICE candidates, DTLS fingerprints
- **ICE Integration** — Automatic candidate gathering, connectivity checks
- **DTLS-SRTP** — Secure media transport
- **SCTP Data Channels** — Reliable/unordered, labeled channels
- **RTP Media** — `RtpSender`/`RtpReceiver` for audio/video tracks
- **Signaling Abstraction** — `SignalingTransport` trait for custom signaling

## Installation

```toml
[dependencies]
tpt-webrtc-app = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_app::{PeerConnection, PeerConnectionConfig, LoopbackSignaling};

let config = PeerConnectionConfig::default();
let pc = PeerConnection::new(config).unwrap();

// Create offer
let offer = pc.create_offer().unwrap();

// Exchange via signaling (example uses loopback)
let signaling = LoopbackSignaling::new();
signaling.send(offer).await?;

// Receive answer and set remote description
let answer = signaling.receive().await?;
pc.set_remote_description(answer).unwrap();

// Drive the connection
loop {
    pc.poll().await?;
    // Handle events: data channel open, media frames, etc.
}
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `config` | `PeerConnectionConfig` — STUN/TURN servers, codec preferences |
| `peer` | `PeerConnection`, `PeerConnectionState`, `SignalingState`, `IceConnectionState` |
| `data_channel` | `DataChannel`, `DataChannelConfig`, `DataChannelState`, `DataChannelMessage` |
| `media` | `MediaStreamTrack`, `RtpSender`, `RtpReceiver`, `TrackKind` |
| `signaling` | `SignalingTransport` trait, `LoopbackSignaling` for testing |

## PeerConnection Lifecycle

```
New → Connecting → Connected → Disconnected → Failed/Closed
           ↓
      (negotiation)
```

## Data Channels

```rust
// Create a data channel
let dc = pc.create_data_channel("chat", DataChannelConfig::reliable()).await?;

// Send
dc.send(DataChannelMessage::Text("Hello".into())).await?;

// Receive
while let Some(msg) = dc.recv().await? {
    match msg {
        DataChannelMessage::Text(t) => println!("Text: {}", t),
        DataChannelMessage::Binary(b) => println!("Binary: {:?}", b),
    }
}
```

## Media Tracks

```rust
// Create sender for local audio
let sender = pc.add_track(MediaStreamTrack::audio("mic")).await?;

// Send audio frames
sender.send_audio_frame(frame).await?;

// Create receiver for remote video
let receiver = pc.add_transceiver(TrackKind::Video).await?;
while let Some(frame) = receiver.recv_video_frame().await? {
    // render frame...
}
```

## Examples

See the `examples/` directory:

- `audio_call.rs` — Full audio call with loopback signaling
- `data_channel_pingpong.rs` — Data channel echo test

Run with:

```bash
cargo run -p tpt-webrtc-app --example audio_call
```

## Testing

Run the full connection integration test:

```bash
cargo test -p tpt-webrtc-app --test full_connection
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).