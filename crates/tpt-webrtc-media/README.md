# tpt-webrtc-media

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-media.svg)](https://crates.io/crates/tpt-webrtc-media)
[![Documentation](https://docs.rs/tpt-webrtc-media/badge.svg)](https://docs.rs/tpt-webrtc-media)
[![License](https://img.shields.io/crates/l/tpt-webrtc-media.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

Media processing (spec module 8): bandwidth estimation, audio processing (AGC / noise suppression / echo cancellation), video scaling and color conversion, and simulcast fan-out.

All algorithms are pure Rust. The audio DSP is deliberately simple (single-pole gates/normalizers, a time-domain adaptive AEC) — good enough for the "real algorithms" bar of this stack; heavier spectral methods can slot behind the same traits.

## Features

- **Bandwidth Estimation** — GCC, TWCC, REMB, BBR estimators
- **Audio Processing** — AGC, noise suppression, echo cancellation (AEC)
- **Video Processing** — Scaling, YUV420↔RGBA conversion
- **Simulcast** — Layer management and fan-out
- **Congestion Control** — `BitrateControl` + `CongestionController` traits

## Installation

```toml
[dependencies]
tpt-webrtc-media = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_media::{GccEstimator, BandwidthEstimator, AutomaticGainControl, NoiseSuppressor, AdaptiveEchoCanceller, VideoScaler};

// Bandwidth estimation (GCC)
let mut gcc = GccEstimator::new();
gcc.update_delay(0.05); // 50ms RTT
gcc.update_loss(0.02);  // 2% loss
let bitrate = gcc.estimate_bitrate(); // bps

// Audio processing chain
let mut agc = AutomaticGainControl::new();
let mut ns = NoiseSuppressor::new();
let mut aec = AdaptiveEchoCanceller::new(48000);

let processed = agc.process(&mut frame);
let processed = ns.process(&mut processed);
let processed = aec.process(&mut processed, &far_end_frame);

// Video scaling
let scaler = VideoScaler::new();
let scaled = scaler.scale_yuv420(&frame, 1280, 720, 640, 360)?;
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `bwe` | `BandwidthEstimator`, `GccEstimator`, `TwccEstimator`, `RembEstimator`, `BbrEstimator` |
| `audio` | `AutomaticGainControl`, `NoiseSuppressor`, `NoiseGate`, `PeakNormalizingAgc`, `AcousticEchoCanceller`, `AdaptiveEchoCanceller` |
| `video` | `VideoScaler`, `bilinear_resize_yuv420`, `rgba_to_yuv420`, `yuv420_to_rgba` |
| `simulcast` | `SimulcastLayer`, `SimulcastScaler` |
| `adaptation` | `BitrateControl`, `CongestionController` |

## Bandwidth Estimation Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| **GCC** | Google Congestion Control — delay-based + loss-based | Default WebRTC |
| **TWCC** | Transport-Wide Congestion Control — per-packet feedback | Modern WebRTC |
| **REMB** | Receiver Estimated Max Bitrate — receiver-side | Legacy |
| **BBR** | Bottleneck Bandwidth and RTT — model-based | High throughput |

## Audio Processing Chain

```
Input → Noise Gate → AGC → Noise Suppressor → AEC → Output
```

Each component is independently configurable and can be swapped.

## Video Processing

| Function | Input | Output |
|----------|-------|--------|
| `bilinear_resize_yuv420` | YUV420 planar | YUV420 planar |
| `rgba_to_yuv420` | RGBA | YUV420 planar |
| `yuv420_to_rgba` | YUV420 planar | RGBA |
| `VideoScaler::scale_yuv420` | YUV420 + dims | YUV420 + new dims |

## Simulcast

```rust
use tpt_webrtc_media::{SimulcastLayer, SimulcastScaler};

let layers = vec![
    SimulcastLayer { scale: 1.0, bitrate: 2_500_000 },  // High
    SimulcastLayer { scale: 0.5, bitrate: 800_000 },    // Medium
    SimulcastLayer { scale: 0.25, bitrate: 200_000 },   // Low
];

let scaler = SimulcastScaler::new(layers);
for (i, frame) in scaler.fan_out(&input_frame).enumerate() {
    // Encode each layer with appropriate bitrate
    encoder[i].encode(&frame)?;
}
```

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).