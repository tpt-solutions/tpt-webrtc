//! # tpt-webrtc-codecs
//!
//! Codec layer (spec module 7): the [`VideoEncoder`]/[`VideoDecoder`]
//! abstractions, frame/packet types, and the AV1-first encoder built on
//! `rav1e` (pure Rust — no H.264 anywhere, per spec's patent-royalty
//! avoidance strategy).
//!
//! Decode-side native codecs (dav1d for AV1, libvpx for VP8/VP9, libopus
//! for audio) bind to the C libraries behind the `native` feature and are
//! exercised in the Linux/WSL environment — see todo.md Phase 3.

pub mod av1;
pub mod frame;
pub mod traits;

pub use frame::{EncodedPacket, PixelFormat, VideoCodec, VideoFrame};
pub use traits::{CodecError, VideoDecoder, VideoEncoder};

/// Config for [`av1::Av1Encoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Av1EncoderConfig {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Target bitrate in bits per second.
    pub bitrate: u32,
    /// Framerate hint.
    pub framerate: u32,
    /// Speed preset 0–10 (lower = slower/better).
    pub speed_preset: u8,
    /// Keyframe interval in frames.
    pub keyframe_interval: u32,
}

impl Default for Av1EncoderConfig {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            bitrate: 2_500_000,
            framerate: 30,
            speed_preset: 10,
            keyframe_interval: 60,
        }
    }
}

/// Application type for audio encoders (mirrors libopus' enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusApplication {
    /// Voice-optimized.
    Voip,
    /// Music-optimized.
    Audio,
    /// Lowest latency.
    LowDelay,
}
