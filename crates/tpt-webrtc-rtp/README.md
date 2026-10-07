# tpt-webrtc-rtp

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-rtp.svg)](https://crates.io/crates/tpt-webrtc-rtp)
[![Documentation](https://docs.rs/tpt-webrtc-rtp/badge.svg)](https://docs.rs/tpt-webrtc-rtp)
[![License](https://img.shields.io/crates/l/tpt-webrtc-rtp.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

Media transport: RTP packet codec (RFC 3550), payload-specific packetizers (AV1, VP8, VP9, Opus), RTCP with feedback messages (NACK, TWCC, PLI, FIR, REMB), and the jitter buffer.

SRTP protection lives in `tpt_webrtc_dtls::SrtpSession` on raw bytes; `SrtpPacketExt` layers typed helpers on top so media code can work with `RtpPacket` values directly.

## Features

- **RTP Packet Codec** — RFC 3550 serialization/parsing, header extensions
- **Payload Packetizers** — AV1 (OBU), VP8, VP9, Opus with proper framing
- **RTCP** — Sender/Receiver Reports, SDES, NACK, TWCC, PLI, FIR, REMB
- **Jitter Buffer** — Adaptive, with NACK generation for missing packets
- **SRTP Integration** — Typed `protect`/`unprotect` via `SrtpPacketExt`

## Installation

```toml
[dependencies]
tpt-webrtc-rtp = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_rtp::{RtpPacket, OpusPacketizer, JitterBuffer, SrtpPacketExt};
use tpt_webrtc_dtls::SrtpSession;

// Create an Opus packetizer
let mut packetizer = OpusPacketizer::new(48000, 2); // 48kHz, stereo

// Encode audio frames to RTP packets
let packets = packetizer.packetize(&audio_frame)?;

// Protect with SRTP
let mut srtp = SrtpSession::new(...);
for pkt in &packets {
    let protected = pkt.protect(&mut srtp)?;
    socket.send(&protected).await?;
}

// Receive and depacketize
let jitter = JitterBuffer::new(100);
while let Ok(wire) = socket.recv().await {
    let pkt = RtpPacket::unprotect(&mut srtp, &wire)?;
    jitter.insert(pkt)?;
    while let Some(frame) = jitter.next_frame() {
        let audio = packetizer.depacketize(&frame)?;
        // play audio...
    }
}
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `packet` | `RtpPacket`, header parsing/serialization, extensions |
| `packetizer` | `Packetizer` trait, `OpusPacketizer`, `Av1Packetizer`, `Vp8Packetizer`, `Vp9Packetizer` |
| `jitter` | `JitterBuffer` — adaptive, loss detection, NACK generation |
| `rtcp` | `RtcpPacket`, `SenderReport`, `ReceiverReport`, `SdesChunk` |
| `rtcp::feedback` | `TransportLayerFeedback` (NACK, TWCC), `PayloadSpecificFeedback` (PLI, FIR) |
| `media` | `AudioFrame`, `VideoFrame`, `MediaFrame` |

## Supported Payload Formats

| Codec | Packetizer | RFC/Spec |
|-------|------------|----------|
| Opus | `OpusPacketizer` | RFC 7587 |
| AV1 | `Av1Packetizer` | AV1 RTP spec (OBU) |
| VP8 | `Vp8Packetizer` | RFC 7741 |
| VP9 | `Vp9Packetizer` | VP9 RTP draft |

## RTCP Feedback Messages

| Type | Message | Purpose |
|------|---------|---------|
| Transport | NACK (RFC 4585) | Request retransmission |
| Transport | TWCC (draft-ietf-avtext-rtp-twcc) | Transport-wide congestion control |
| Payload | PLI (RFC 4585) | Request keyframe |
| Payload | FIR (RFC 5104) | Full intra request |
| Payload | REMB (draft-alvestrand-rmcat-remb) | Receiver estimated max bitrate |

## Benchmarks

Run the throughput benchmark:

```bash
cargo bench -p tpt-webrtc-rtp
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).