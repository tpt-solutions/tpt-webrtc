//! # tpt-webrtc-sctp
//!
//! SCTP over DTLS for WebRTC data channels (RFC 8831, RFC 4960 subset):
//! association establishment (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK),
//! ordered and unordered DATA with SACK-driven (re)transmission, and the
//! DataChannel establishment protocol (PPID 50/51).

pub mod association;
pub mod chunk;

pub use association::{
    DataChannelOpen, Reliability, SctpAssociation, SctpMessage, SctpState, SctpStreamConfig,
    SctpTransport,
};
pub use chunk::{Chunk, ChunkType};

/// Re-exported error type.
pub use tpt_webrtc_core::SctpError;

/// PPID for `DATA_CHANNEL_OPEN` messages (RFC 8831 §6 / datachannel spec).
pub const PPID_DATA_CHANNEL_OPEN: u32 = 50;
/// PPID for `DATA_CHANNEL_ACK` messages.
pub const PPID_DATA_CHANNEL_ACK: u32 = 51;
/// PPID for string data.
pub const PPID_STRING: u32 = 51;
/// PPID for binary data.
pub const PPID_BINARY: u32 = 53;

/// Default SCTP port used by WebRTC data channels (RFC 8831 §5.1).
pub const WEBRTC_SCTP_PORT: u16 = 5000;
