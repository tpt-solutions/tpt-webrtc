//! `PeerConnection` configuration.

use tpt_webrtc_core::{BweAlgorithm, CodecPreferences, DtlsCertificate, IceServer};

/// Top-level configuration for a [`crate::PeerConnection`].
#[derive(Debug, Clone)]
pub struct PeerConnectionConfig {
    /// STUN/TURN servers for candidate gathering.
    pub ice_servers: Vec<IceServer>,
    /// Codec preference order for SDP negotiation.
    pub codec_preferences: CodecPreferences,
    /// Bandwidth estimation algorithm.
    pub bandwidth_estimation: BweAlgorithm,
    /// Local DTLS certificates. Empty → a fresh self-signed certificate is
    /// generated per connection.
    pub dtls_certificates: Vec<DtlsCertificate>,
    /// Connectivity-check timeout.
    pub ice_timeout: std::time::Duration,
    /// Explicit local addresses for host candidates (skips the route
    /// probe). Empty = auto-detect.
    pub local_addresses: Vec<std::net::IpAddr>,
}

impl Default for PeerConnectionConfig {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            codec_preferences: CodecPreferences::default(),
            bandwidth_estimation: BweAlgorithm::default(),
            dtls_certificates: Vec::new(),
            ice_timeout: std::time::Duration::from_secs(10),
            local_addresses: Vec::new(),
        }
    }
}
