# Changelog

All notable changes to `tpt-webrtc-codecs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- Encoder/Decoder Traits:
  - `VideoEncoder` — async encoding, bitrate control, keyframe forcing
  - `VideoDecoder` — async decoding, reset
  - `CodecError` — unified error type
- Frame Types:
  - `VideoFrame` — YUV420/I420 pixel data with metadata
  - `EncodedPacket` — encoded payload with keyframe flag, timestamp
  - `PixelFormat` — Yuv420, I420 (extensible)
  - `VideoCodec` — Av1, Vp8, Vp9, H264 (H264 excluded by policy)
- AV1 Encoder:
  - `Av1Encoder` — pure Rust via `rav1e` (threading feature)
  - `Av1EncoderConfig` — width, height, bitrate, framerate, speed_preset, keyframe_interval
  - Default config: 1280×720, 2.5 Mbps, 30fps, speed=10, keyint=60
- Opus Application Types:
  - `OpusApplication::Voip` — voice optimized
  - `OpusApplication::Audio` — music optimized
  - `OpusApplication::LowDelay` — lowest latency
- Native Decoders (behind `native` feature):
  - `Av1Decoder` — dav1d (AV1)
  - `Vp8Decoder` / `Vp9Decoder` — libvpx
  - `OpusDecoder` — libopus
  - Requires C libraries; exercised in Linux/WSL (see todo.md Phase 3)

### Codec Policy
- **No H.264** — patent-royalty avoidance by spec mandate
- AV1-first: primary codec for all new deployments
- VP8/VP9 decode-only for interop with legacy endpoints

### Configuration

```rust
let config = Av1EncoderConfig {
    width: 1920,
    height: 1080,
    bitrate: 5_000_000,
    framerate: 30,
    speed_preset: 6,  // better quality
    keyframe_interval: 30,
};
```

### Hardware Acceleration
Traits are designed for hardware encoder plugins:
```rust
// VAAPI, NVENC, VideoToolbox, AMF, etc.
struct HardwareEncoder { ... }
impl VideoEncoder for HardwareEncoder { ... }
```

### Dependencies
- `rav1e` 0.7 (pure Rust AV1 encoder)
- `thiserror` for error handling
- `native` feature: `dav1d-sys`, `vpx-sys`, `opus-sys` (C bindings)

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-codecs-v0.1.0