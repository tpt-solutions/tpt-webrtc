# tpt-webrtc-codecs

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-codecs.svg)](https://crates.io/crates/tpt-webrtc-codecs)
[![Documentation](https://docs.rs/tpt-webrtc-codecs/badge.svg)](https://docs.rs/tpt-webrtc-codecs)
[![License](https://img.shields.io/crates/l/tpt-webrtc-codecs.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

Codec layer (spec module 7): `VideoEncoder`/`VideoDecoder` abstractions, frame/packet types, and the AV1-first encoder built on `rav1e` (pure Rust — no H.264 anywhere, per spec's patent-royalty avoidance strategy).

Decode-side native codecs (dav1d for AV1, libvpx for VP8/VP9, libopus for audio) bind to the C libraries behind the `native` feature and are exercised in the Linux/WSL environment.

## Features

- **Encoder/Decoder Traits** — `VideoEncoder`, `VideoDecoder` with async support
- **AV1 Encoding** — Pure Rust via `rav1e` (threading support)
- **Frame Types** — `VideoFrame` (YUV420, I420), `EncodedPacket`, `VideoCodec`
- **Hardware Acceleration** — Pluggable via traits (VAAPI, NVENC, VideoToolbox)
- **No H.264** — Patent-royalty avoidance by policy

## Installation

```toml
[dependencies]
tpt-webrtc-codecs = "0.1"
# For native decoders (requires C libraries):
# tpt-webrtc-codecs = { version = "0.1", features = ["native"] }
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_codecs::{VideoEncoder, Av1Encoder, Av1EncoderConfig, VideoFrame, PixelFormat};

// Configure encoder
let config = Av1EncoderConfig {
    width: 1280,
    height: 720,
    bitrate: 2_500_000,
    framerate: 30,
    speed_preset: 10,
    keyframe_interval: 60,
};

// Create encoder
let mut encoder = Av1Encoder::new(config).unwrap();

// Create a video frame
let frame = VideoFrame::new(
    PixelFormat::Yuv420,
    1280, 720,
    vec![0u8; 1280 * 720 * 3 / 2], // YUV data
);

// Encode
let packets = encoder.encode(&frame).await?;
for pkt in packets {
    // Send RTP packet...
    println!("Encoded: {} bytes, keyframe: {}", pkt.data.len(), pkt.is_keyframe);
}
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `traits` | `VideoEncoder`, `VideoDecoder`, `CodecError` |
| `frame` | `VideoFrame`, `EncodedPacket`, `PixelFormat`, `VideoCodec` |
| `av1` | `Av1Encoder` (rav1e), `Av1Decoder` (dav1d, behind `native` feature) |

## Encoder/Decoder Traits

```rust
pub trait VideoEncoder {
    type Config: Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync;

    fn new(config: Self::Config) -> Result<Self, Self::Error>
    where Self: Sized;

    async fn encode(&mut self, frame: &VideoFrame) -> Result<Vec<EncodedPacket>, Self::Error>;

    fn set_bitrate(&mut self, bitrate: u32) -> Result<(), Self::Error>;
    fn force_keyframe(&mut self) -> Result<(), Self::Error>;
}

pub trait VideoDecoder {
    type Config: Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync;

    fn new(config: Self::Config) -> Result<Self, Self::Error>
    where Self: Sized;

    async fn decode(&mut self, packet: &EncodedPacket) -> Result<Option<VideoFrame>, Self::Error>;

    fn reset(&mut self) -> Result<(), Self::Error>;
}
```

## AV1 Encoder Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `width` | 1280 | Frame width in pixels |
| `height` | 720 | Frame height in pixels |
| `bitrate` | 2_500_000 | Target bitrate (bps) |
| `framerate` | 30 | Framerate hint |
| `speed_preset` | 10 | 0=slow/best, 10=fast/worst |
| `keyframe_interval` | 60 | Keyframe every N frames |

## Supported Codecs

| Codec | Encode | Decode | Status |
|-------|--------|--------|--------|
| AV1 | ✅ rav1e (pure Rust) | 🔄 dav1d (native feature) | Primary |
| VP8 | ❌ | 🔄 libvpx (native feature) | Planned |
| VP9 | ❌ | 🔄 libvpx (native feature) | Planned |
| Opus | 🔄 (external) | 🔄 (external) | Via `tpt-webrtc-media` |

## Hardware Acceleration

Implement `VideoEncoder` for your platform:

```rust
struct VaapiEncoder { ... }
impl VideoEncoder for VaapiEncoder { ... }
```

Then select at runtime based on availability.

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).