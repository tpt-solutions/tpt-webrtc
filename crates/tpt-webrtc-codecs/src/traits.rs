//! The codec abstraction traits (spec module 7 signatures).

use std::time::Duration;

use thiserror::Error;

use crate::frame::{AudioFrame, EncodedPacket, VideoFrame};

/// Codec-layer failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The encoder rejected the frame or configuration.
    #[error("encode failed: {0}")]
    Encode(String),
    /// The decoder rejected the packet or produced no output.
    #[error("decode failed: {0}")]
    Decode(String),
    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Codec unavailable on this platform/build.
    #[error("unsupported codec: {0}")]
    Unsupported(String),
}

/// Video encoder abstraction (spec: encode / set_bitrate /
/// request_keyframe / set_resolution / set_framerate).
pub trait VideoEncoder: Send {
    /// Encodes one frame, returning zero or more access units (zero when
    /// the codec buffers, e.g. look-ahead).
    ///
    /// # Errors
    /// [`CodecError::Encode`] on encoder failure.
    fn encode(&mut self, frame: &VideoFrame) -> Result<Vec<EncodedPacket>, CodecError>;

    /// Updates the target bitrate.
    ///
    /// # Errors
    /// [`CodecError::Config`] when unsupported.
    fn set_bitrate(&mut self, bitrate: u32) -> Result<(), CodecError>;

    /// Forces the next frame to be a keyframe.
    fn request_keyframe(&mut self);

    /// Changes the resolution (reinitializes the encoder).
    ///
    /// # Errors
    /// [`CodecError::Config`] for invalid dimensions.
    fn set_resolution(&mut self, width: u32, height: u32) -> Result<(), CodecError>;

    /// Changes the target framerate.
    ///
    /// # Errors
    /// [`CodecError::Config`] when unsupported.
    fn set_framerate(&mut self, fps: u32) -> Result<(), CodecError>;
}

/// Video decoder abstraction.
pub trait VideoDecoder: Send {
    /// Decodes one packet, returning zero or more frames.
    ///
    /// # Errors
    /// [`CodecError::Decode`] on failure.
    fn decode(&mut self, packet: &EncodedPacket) -> Result<Vec<VideoFrame>, CodecError>;

    /// Drains buffered frames.
    ///
    /// # Errors
    /// [`CodecError::Decode`] on failure.
    fn flush(&mut self) -> Result<Vec<VideoFrame>, CodecError>;
}

/// Audio encoder abstraction (spec).
pub trait AudioEncoder: Send {
    /// Encodes one PCM frame into an audio packet.
    ///
    /// # Errors
    /// [`CodecError::Encode`] on failure.
    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError>;

    /// Updates the target bitrate.
    ///
    /// # Errors
    /// [`CodecError::Config`] when unsupported.
    fn set_bitrate(&mut self, bitrate: u32) -> Result<(), CodecError>;
}

/// A monotonically-advancing timestamp helper for encoders.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TimestampScale {
    pub frames: u64,
    pub fps: u32,
}

impl TimestampScale {
    pub(crate) fn advance(&mut self) -> Duration {
        let d = Duration::from_secs_f64(self.frames as f64 / f64::from(self.fps));
        self.frames += 1;
        d
    }
}
