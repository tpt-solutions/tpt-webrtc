//! Frame and packet types shared by the codec abstractions.

use std::time::Duration;

use crate::CodecError;

/// Pixel formats supported by the abstraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PixelFormat {
    /// 4:2:0 planar YUV.
    Yuv420,
    /// 4:2:2 planar.
    Yuv422,
    /// 4:4:4 planar.
    Yuv444,
    /// NV12 (Y + interleaved UV).
    Nv12,
    /// Packed RGBA8.
    Rgba,
}

/// An uncompressed video frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Plane data (layout per `format`).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: Duration,
}

/// Codec identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    /// AV1 — the stack's primary codec.
    Av1,
    /// VP8.
    Vp8,
    /// VP9.
    Vp9,
}

impl VideoCodec {
    /// The payload name as it appears in SDP `a=rtpmap` entries.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Av1 => "AV1",
            Self::Vp8 => "VP8",
            Self::Vp9 => "VP9",
        }
    }
}

/// One encoded access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPacket {
    /// Encoded bitstream (one temporal unit).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: Duration,
    /// Random access point (keyframe).
    pub is_keyframe: bool,
    /// Which codec produced it.
    pub codec: VideoCodec,
}

impl EncodedPacket {
    /// Builds a packet, rejecting empty payloads.
    ///
    /// # Errors
    /// [`CodecError::Encode`] when `data` is empty.
    pub fn new(
        data: Vec<u8>,
        timestamp: Duration,
        is_keyframe: bool,
        codec: VideoCodec,
    ) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::Encode("empty encoded packet".into()));
        }
        Ok(Self {
            data,
            timestamp,
            is_keyframe,
            codec,
        })
    }
}

/// A PCM audio frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Interleaved 16-bit samples.
    pub samples: Vec<i16>,
    /// Sample rate in Hz (48000 typical).
    pub sample_rate: u32,
    /// Channel count.
    pub channels: u16,
    /// Capture timestamp.
    pub timestamp: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_rejects_empty() {
        assert!(EncodedPacket::new(Vec::new(), Duration::ZERO, true, VideoCodec::Av1).is_err());
        let p = EncodedPacket::new(
            vec![1, 2, 3],
            Duration::from_millis(33),
            true,
            VideoCodec::Av1,
        )
        .unwrap();
        assert!(p.is_keyframe);
        assert_eq!(p.codec.name(), "AV1");
    }
}
