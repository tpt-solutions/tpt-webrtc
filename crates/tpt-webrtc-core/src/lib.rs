//! # tpt-webrtc-core
//!
//! Foundation layer for the `tpt-webrtc` stack: configuration types, the
//! async socket abstraction, the workspace-wide error taxonomy, the shared
//! ICE candidate type, and cryptographic primitives (via `ring`) used by the
//! later protocol crates.
//!
//! This crate is the only place where `ring` is touched for primitives;
//! protocol crates depend on these helpers so that crypto policy stays in
//! one place. It contains no protocol logic.
//!
//! See `spec.txt` at the repository root for the full design document.

pub mod candidate;
pub mod config;
pub mod crypto;
pub mod error;
pub mod socket;

pub use candidate::{CandidateType, IceCandidate};
pub use config::{BweAlgorithm, CodecKind, CodecPreferences, IceServer, WebRtcConfig};
pub use crypto::{
    constant_time_eq, crc32_ieee, ecdsa_der_to_fixed, ecdsa_fixed_to_der, hmac_sha1, hmac_sha256,
    md5, random_bytes, random_u32, random_u64, sha1, sha256, DtlsCertificate, Fingerprint,
};
pub use error::{
    CodecError, DtlsError, IceError, PacketizerError, RtpError, SctpError, SdpError, SrtpError,
    WebRtcError,
};
pub use socket::{UdpWebRtcSocket, WebRtcSocket};
