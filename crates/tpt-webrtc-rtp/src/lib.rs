//! # tpt-webrtc-rtp
//!
//! Media transport: RTP packet codec (RFC 3550), payload-specific
//! packetizers (AV1, VP8, VP9, Opus), RTCP with the feedback messages the
//! stack uses (NACK, TWCC, PLI, FIR, REMB) and the jitter buffer.
//!
//! SRTP protection lives in [`tpt_webrtc_dtls::SrtpSession`] on raw bytes;
//! [`SrtpPacketExt`] layers typed helpers on top so media code can work
//! with [`RtpPacket`] values directly.

pub mod jitter;
pub mod media;
pub mod packet;
pub mod packetizer;
pub mod rtcp;

pub use jitter::JitterBuffer;
pub use media::{AudioFrame, MediaFrame, VideoFrame};
pub use packet::RtpPacket;
pub use packetizer::{
    Av1Packetizer, OpusPacketizer, Packetizer, VideoPacketizerContext, Vp8Packetizer, Vp9Packetizer,
};
pub use rtcp::{
    FullIntraRequest, Nack, ReceiverReport, Remb, ReportBlock, RtcpPacket, SdesChunk, SenderReport,
    SourceDescription, TransportWideCongestionControl,
};

/// Re-exported error types used throughout the crate.
pub use tpt_webrtc_core::{PacketizerError, RtpError};

use tpt_webrtc_dtls::SrtpSession;

/// Typed SRTP helpers over [`RtpPacket`].
pub trait SrtpPacketExt {
    /// Serializes, protects and returns the wire bytes.
    ///
    /// # Errors
    /// See [`SrtpSession::protect_rtp`](tpt_webrtc_dtls::SrtpSession::protect_rtp).
    fn protect(&self, session: &mut SrtpSession) -> Result<Vec<u8>, RtpError>;

    /// Unprotects wire bytes into a packet.
    ///
    /// # Errors
    /// See [`SrtpSession::unprotect_rtp`](tpt_webrtc_dtls::SrtpSession::unprotect_rtp).
    fn unprotect(session: &mut SrtpSession, wire: &[u8]) -> Result<Self, RtpError>
    where
        Self: Sized;
}

impl SrtpPacketExt for RtpPacket {
    fn protect(&self, session: &mut SrtpSession) -> Result<Vec<u8>, RtpError> {
        session
            .protect_rtp(&self.serialize())
            .map_err(|e| RtpError::Packetization(e.to_string()))
    }

    fn unprotect(session: &mut SrtpSession, wire: &[u8]) -> Result<Self, RtpError> {
        let plain = session
            .unprotect_rtp(wire)
            .map_err(|e| RtpError::Packetization(e.to_string()))?;
        RtpPacket::parse(&plain)
    }
}
