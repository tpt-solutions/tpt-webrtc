//! # tpt-webrtc-sdp
//!
//! SDP (RFC 8866) parser and generator with the WebRTC-specific extensions
//! the stack needs — BUNDLE grouping, RTCP-MUX, ICE candidates/credentials,
//! DTLS fingerprints/setup, simulcast (RFC 8851), RTP header extensions and
//! SSRC descriptions — plus the offer/answer model ([`OfferAnswerModel`])
//! built on top of [`tpt_webrtc_core::WebRtcConfig`].
//!
//! # Example
//! ```
//! use tpt_webrtc_sdp::{parse_sdp, generate_sdp};
//!
//! let raw = "v=0\r\no=- 8 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
//! let session = parse_sdp(raw).unwrap();
//! assert_eq!(session.session_name, "-");
//! assert_eq!(generate_sdp(&session).unwrap(), raw);
//! ```

mod generate;
mod model;
mod offer_answer;
mod parse;

pub use generate::generate_sdp;
pub use model::{
    Attribute, Connection, Direction, MediaDescription, MediaType, Origin, SdpSession, SetupRole,
    SimulcastConfig, SsrcAttribute, SsrcGroupAttribute, Timing,
};
pub use offer_answer::{CodecNegotiation, NegotiatedCodec, OfferAnswerModel};
pub use parse::parse_sdp;

/// Re-exported error type used throughout the crate.
pub use tpt_webrtc_core::SdpError;
