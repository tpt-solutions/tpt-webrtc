//! # tpt-webrtc-dtls
//!
//! Security layer: a purpose-built DTLS 1.2 (RFC 6347) implementation for
//! the WebRTC profile — ECDHE-ECDSA with a single self-signed certificate
//! fingerprinted in SDP (RFC 8122), the `use_srtp` extension (RFC 5764) and
//! the `EXTRACTOR-dtls_srtp` key export (RFC 5705) — plus SRTP sessions
//! (RFC 3711).
//!
//! Scope notes (deliberate, matching the todo):
//! - one handshake cipher suite: `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`;
//! - no X.509 chain validation (WebRTC checks the SDP fingerprint instead);
//! - the SRTP session operates on raw packet bytes; the RTP-typed helpers
//!   live in `tpt-webrtc-rtp` so this crate stays below the media layer.
//!
//! # Example
//! ```
//! use tpt_webrtc_dtls::{DtlsConfig, DtlsRole, DtlsTransport};
//!
//! let cert = tpt_webrtc_core::DtlsCertificate::generate().unwrap();
//! let config = DtlsConfig { certificate: cert, role: DtlsRole::Client, expected_fingerprint: None };
//! let transport = DtlsTransport::new(config);
//! assert_eq!(transport.state(), tpt_webrtc_dtls::DtlsState::New);
//! ```

/// The DTLS-SRTP key material (RFC 5764 §4.2), split per direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpKeys {
    /// 16-byte client SRTP master key.
    pub client_key: Vec<u8>,
    /// 16-byte server SRTP master key.
    pub server_key: Vec<u8>,
    /// 14-byte client SRTP salt.
    pub client_salt: Vec<u8>,
    /// 14-byte server SRTP salt.
    pub server_salt: Vec<u8>,
}

/// SRTP protection profiles (RFC 3711, RFC 7714).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpCipher {
    /// `AES128_CM_HMAC_SHA1_80` — default DTLS-SRTP profile.
    Aes128CmHmacSha1_80,
    /// `AES256_CM_HMAC_SHA1_80` (32-byte keys).
    Aes256CmHmacSha1_80,
    /// `AEAD_AES_128_GCM` (RFC 7714).
    AeadAes128Gcm,
    /// `AEAD_AES_256_GCM` (32-byte keys).
    AeadAes256Gcm,
}

pub mod handshake;
pub mod prf;
pub mod record;
pub mod srtp;
pub mod transport;

pub use record::RecordLayer;
pub use srtp::{Direction, SrtpSession};
pub use transport::{DtlsConfig, DtlsRole, DtlsState, DtlsTransport};

/// Re-exported error type used throughout the crate.
pub use tpt_webrtc_core::DtlsError;

/// The single negotiated handshake cipher suite:
/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
pub const CIPHER_SUITE: u16 = 0xC02B;

/// `SRTP_AES128_CM_HMAC_SHA1_80` use_srtp profile (RFC 5764 §4.1.2).
pub const SRTP_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
/// `SRTP_AEAD_AES_128_GCM` use_srtp profile (RFC 7714).
pub const SRTP_AEAD_AES_128_GCM: u16 = 0x0007;

/// secp256r1 named group (TLS supported_groups registry).
pub const GROUP_SECP256R1: u16 = 0x0017;
