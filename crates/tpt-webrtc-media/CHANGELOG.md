# Changelog

All notable changes to `tpt-webrtc-media` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- Bandwidth Estimation:
  - `GccEstimator` — Google Congestion Control (delay-based + loss-based)
  - `TwccEstimator` — Transport-Wide Congestion Control (per-packet feedback)
  - `RembEstimator` — Receiver Estimated Max Bitrate
  - `BbrEstimator` — Bottleneck Bandwidth and RTT (model-based)
  - `BandwidthEstimator` trait for unified interface
- Audio Processing:
  - `AutomaticGainControl` — target level adjustment
  - `PeakNormalizingAgc` — peak-based normalization
  - `NoiseGate` — simple gate for silence suppression
  - `NoiseSuppressor` — spectral subtraction (simplified)
  - `AcousticEchoCanceller` — time-domain adaptive filter
  - `AdaptiveEchoCanceller` — NLMS-based with double-talk detection
- Video Processing:
  - `VideoScaler` — bilinear YUV420 resizing
  - `bilinear_resize_yuv420` — standalone function
  - `rgba_to_yuv420` / `yuv420_to_rgba` — color conversion
- Simulcast:
  - `SimulcastLayer` — scale + bitrate per layer
  - `SimulcastScaler` — fan-out single frame to multiple layers
- Congestion Control:
  - `BitrateControl` trait — encoder bitrate adjustment
  - `CongestionController` trait — network congestion response

### Algorithms

| Component | Algorithm | Complexity |
|-----------|-----------|------------|
| GCC | Kalman filter (delay) + loss-based | O(1) per sample |
| TWCC | Per-packet RTT + delay gradient | O(1) per packet |
| REMB | Receiver-side max bitrate | O(1) per report |
| BBR | BTL bandwidth + RTT model | O(1) per ACK |
| AGC | Single-pole IIR + target level | O(n) per frame |
| Noise Suppression | Spectral subtraction (simplified) | O(n log n) |
| AEC | NLMS adaptive filter | O(n·L) per frame |
| Video Scaling | Bilinear interpolation | O(n) per frame |

### Design Notes
- Pure Rust implementations — no C dependencies
- Audio DSP deliberately simple for "real algorithms" bar
- Traits allow swapping heavier algorithms (RNNoise, WebRTC APM) later
- Simulcast fan-out is CPU-bound; consider hardware scaling for high-res

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-media-v0.1.0