//! # tpt-webrtc-media
//!
//! Media processing (spec module 8): bandwidth estimation, audio
//! processing (AGC / noise suppression / echo cancellation), video
//! scaling and color conversion, and simulcast fan-out.
//!
//! All algorithms are pure Rust. The audio DSP is deliberately simple
//! (single-pole gates/normalizers, a time-domain adaptive AEC) — good
//! enough for the Phase 5 "real algorithms" bar of this stack; heavier
//! spectral methods can slot behind the same traits.

pub mod audio;
pub mod bwe;
pub mod simulcast;
pub mod video;

pub use audio::{
    AcousticEchoCanceller, AdaptiveEchoCanceller, AutomaticGainControl, NoiseGate, NoiseSuppressor,
    PeakNormalizingAgc,
};
pub use bwe::{BandwidthEstimator, BbrEstimator, GccEstimator, RembEstimator, TwccEstimator};
pub use simulcast::{SimulcastLayer, SimulcastScaler};
pub use video::{bilinear_resize_yuv420, rgba_to_yuv420, yuv420_to_rgba, VideoScaler};
