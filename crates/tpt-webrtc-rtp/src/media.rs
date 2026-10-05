//! Media frame types used by the packetizers.
//!
//! Minimal stand-ins for the codec layer's types (spec places the rich
//! `VideoFrame`/`AudioFrame` in `tpt-webrtc-codecs`; the packetizers only
//! need encoded bytes, an RTP timestamp and the keyframe flag).

use std::time::Duration;

/// An encoded video frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// Encoded bitstream (codec-specific temporal unit).
    pub data: Vec<u8>,
    /// Frame capture timestamp.
    pub timestamp: Duration,
    /// Whether the frame is a keyframe (random access point).
    pub keyframe: bool,
    /// Frame width in pixels (metadata for simulcast layers).
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
}

/// An encoded audio frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Encoded audio packet (e.g. one Opus packet).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: Duration,
}

/// Media frame handed to a [`crate::Packetizer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaFrame {
    /// Encoded audio.
    Audio(AudioFrame),
    /// Encoded video.
    Video(VideoFrame),
}

impl MediaFrame {
    /// Encoded bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Audio(a) => &a.data,
            Self::Video(v) => &v.data,
        }
    }

    /// RTP timestamp in the media clock (90 kHz for video, 48 kHz Opus).
    #[must_use]
    pub fn rtp_timestamp(&self, clock_rate: u32) -> u32 {
        let dur = match self {
            Self::Audio(a) => a.timestamp,
            Self::Video(v) => v.timestamp,
        };
        (dur.as_secs_f64() * f64::from(clock_rate)) as u32
    }

    /// Keyframe flag (audio is always "random access").
    #[must_use]
    pub fn keyframe(&self) -> bool {
        match self {
            Self::Audio(_) => true,
            Self::Video(v) => v.keyframe,
        }
    }
}
