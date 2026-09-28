//! Workspace-wide error taxonomy.
//!
//! Every protocol crate maps its failures into these types; the
//! application-layer crate surfaces [`WebRtcError`] upward.

use thiserror::Error;

/// Top-level error for the whole stack.
#[derive(Debug, Error)]
pub enum WebRtcError {
    /// ICE (RFC 8445) failure.
    #[error("ICE: {0}")]
    Ice(#[from] IceError),
    /// DTLS (RFC 6347) failure.
    #[error("DTLS: {0}")]
    Dtls(#[from] DtlsError),
    /// RTP media transport failure.
    #[error("RTP: {0}")]
    Rtp(#[from] RtpError),
    /// SCTP / data channel failure.
    #[error("SCTP: {0}")]
    Sctp(#[from] SctpError),
    /// Codec failure.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// SDP (RFC 8866) failure.
    #[error("SDP: {0}")]
    Sdp(#[from] SdpError),
    /// SRTP failure.
    #[error("SRTP: {0}")]
    Srtp(#[from] SrtpError),
    /// Underlying socket / I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the ICE layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IceError {
    /// No candidates could be gathered or are available for pairing.
    #[error("no candidates available")]
    NoCandidatesAvailable,
    /// Connectivity checks failed for every candidate pair.
    #[error("connectivity check failed")]
    ConnectivityCheckFailed,
    /// Nomination did not complete in time.
    #[error("nomination timed out")]
    NominationTimeout,
    /// The agent is in a state that does not permit the operation.
    #[error("invalid ICE state")]
    InvalidState,
}

/// Errors from the DTLS layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DtlsError {
    /// The handshake did not complete (alert, timeout or protocol error).
    #[error("handshake failed")]
    HandshakeFailed,
    /// The remote certificate fingerprint did not match the SDP offer/answer.
    #[error("certificate verification failed")]
    CertificateVerificationFailed,
    /// A record could not be decrypted / authenticated.
    #[error("decryption failed")]
    DecryptionFailed,
    /// The transport is in a state that does not permit the operation.
    #[error("invalid DTLS state")]
    InvalidState,
    /// Cryptographic primitive failure.
    #[error("crypto failure")]
    Crypto,
}

/// Errors from the RTP layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RtpError {
    /// The byte stream is not a valid RTP packet.
    #[error("malformed RTP packet")]
    MalformedPacket,
    /// The byte stream is not a valid RTCP packet.
    #[error("malformed RTCP packet")]
    MalformedRtcpPacket,
    /// Packetization failed (e.g. frame does not fit the requested MTU).
    #[error("packetization failed: {0}")]
    Packetization(String),
    /// Depacketization failed (missing fragments or invalid structure).
    #[error("depacketization failed: {0}")]
    Depacketization(String),
}

/// Errors from the SCTP layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SctpError {
    /// The association is not established for the requested operation.
    #[error("invalid SCTP state")]
    InvalidState,
    /// A chunk failed to parse.
    #[error("malformed SCTP chunk")]
    MalformedChunk,
    /// The requested stream does not exist or is already open/closed.
    #[error("stream error: {0}")]
    Stream(String),
    /// Protocol violation by the peer.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

/// Errors from the codec layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The encoder rejected the frame or configuration.
    #[error("encode failed: {0}")]
    Encode(String),
    /// The decoder rejected the packet or produced no output.
    #[error("decode failed: {0}")]
    Decode(String),
    /// Configuration is invalid (unsupported resolution, bitrate, ...).
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Codec not compiled in or not supported on this platform.
    #[error("unsupported codec: {0}")]
    Unsupported(String),
}

/// Errors from the SDP layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SdpError {
    /// Syntax error at the given line (1-based) with a reason.
    #[error("SDP syntax error at line {line}: {reason}")]
    Syntax {
        /// 1-based line number where the error occurred.
        line: usize,
        /// Why the line is invalid.
        reason: String,
    },
    /// A mandatory SDP line or attribute is missing.
    #[error("SDP missing required element: {0}")]
    Missing(String),
    /// The semantic content is invalid (e.g. unknown media type).
    #[error("SDP semantic error: {0}")]
    Semantic(String),
}

/// Errors from the SRTP layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SrtpError {
    /// Authentication tag mismatch after unprotection.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Replay detected (sequence number already seen).
    #[error("replay detected")]
    Replay,
    /// Key material has the wrong length for the negotiated cipher.
    #[error("invalid key material")]
    InvalidKeys,
}

/// Errors from the RTP payload packetizers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketizerError {
    /// The frame cannot be packetized for this codec.
    #[error("packetizer error: {0}")]
    Packetize(String),
    /// The packet sequence cannot be reassembled into a frame.
    #[error("depacketizer error: {0}")]
    Depacketize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_non_empty() {
        assert!(!WebRtcError::Ice(IceError::InvalidState)
            .to_string()
            .is_empty());
        assert!(!WebRtcError::Io(std::io::Error::other("x"))
            .to_string()
            .is_empty());
        assert!(!SdpError::Syntax {
            line: 1,
            reason: "nope".into()
        }
        .to_string()
        .is_empty());
        assert!(!DtlsError::HandshakeFailed.to_string().is_empty());
        assert!(!SrtpError::Replay.to_string().is_empty());
        assert!(!PacketizerError::Packetize("bad".into())
            .to_string()
            .is_empty());
    }

    #[test]
    fn from_conversions_work() {
        let e: WebRtcError = IceError::NoCandidatesAvailable.into();
        assert!(matches!(
            e,
            WebRtcError::Ice(IceError::NoCandidatesAvailable)
        ));
        let e: WebRtcError = DtlsError::DecryptionFailed.into();
        assert!(matches!(e, WebRtcError::Dtls(DtlsError::DecryptionFailed)));
    }
}
