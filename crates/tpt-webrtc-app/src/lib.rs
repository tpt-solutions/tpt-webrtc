//! # tpt-webrtc-app
//!
//! The application layer: [`PeerConnection`] wires the whole stack —
//! SDP offer/answer ([`tpt_webrtc_sdp`]), ICE connectivity
//! ([`tpt_webrtc_ice`]), DTLS-SRTP ([`tpt_webrtc_dtls`]), SCTP data
//! channels ([`tpt_webrtc_sctp`]) and RTP media ([`tpt_webrtc_rtp`]) —
//! behind one API:
//!
//! 1. [`PeerConnection::create_offer`] / answer (SDP with ICE credentials,
//!    DTLS fingerprint and host/srflx candidates),
//! 2. exchange descriptions + candidates over any [`signaling::SignalingTransport`],
//! 3. [`PeerConnection::poll`] — the event loop that drives ICE checks,
//!    the DTLS handshake, SCTP establishment and the media/data path,
//! 4. [`PeerConnection::create_data_channel`] + send/recv, and
//!    [`RtpSender`]/[`RtpReceiver`] for SRTP-protected media.
//!
//! # Example
//! ```
//! use tpt_webrtc_app::{PeerConnection, PeerConnectionConfig};
//!
//! let config = PeerConnectionConfig::default();
//! let pc = PeerConnection::new(config).unwrap();
//! assert_eq!(pc.peer_connection_state(), tpt_webrtc_app::PeerConnectionState::New);
//! ```

pub mod config;
pub mod data_channel;
pub mod media;
pub mod peer;
pub mod signaling;

pub use config::PeerConnectionConfig;
pub use data_channel::{DataChannel, DataChannelConfig, DataChannelMessage, DataChannelState};
pub use media::{MediaStreamTrack, RtpReceiver, RtpSender, TrackKind};
pub use peer::{IceConnectionState, PeerConnection, PeerConnectionState, SignalingState};
pub use signaling::{LoopbackSignaling, SignalingTransport};

/// Re-exported errors.
pub use tpt_webrtc_core::WebRtcError;

use std::time::Duration;

/// How long a single [`PeerConnection::poll`] receive step waits before
/// flushing the outbox.
pub const POLL_STEP: Duration = Duration::from_millis(5);

/// Classifies a datagram on the ICE 5-tuple (RFC 7983 demux):
/// STUN / DTLS / RTP-and-RTCP / drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    /// STUN (connectivity checks, consent).
    Stun,
    /// DTLS records.
    Dtls,
    /// RTP / RTCP (first byte 128..=191).
    Rtp,
    /// Anything else (dropped, per RFC 7983).
    Unknown,
}

/// RFC 7983 demultiplexing.
#[must_use]
pub fn classify_datagram(data: &[u8]) -> DatagramKind {
    match data.first() {
        None => DatagramKind::Unknown,
        Some(&b) if (0..=3).contains(&b) => DatagramKind::Stun,
        Some(&b) if (20..=63).contains(&b) => DatagramKind::Dtls,
        Some(&b) if (64..=127).contains(&b) => DatagramKind::Unknown,
        Some(&b) if (128..=191).contains(&b) => DatagramKind::Rtp,
        Some(200..=204) => DatagramKind::Stun, // STUN methods 0x008-0x011 start low; kept for safety
        _ => DatagramKind::Unknown,
    }
}
