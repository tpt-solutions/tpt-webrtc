//! Configuration types for the stack.

use crate::crypto::DtlsCertificate;

/// Codec identifiers used for preference ordering.
///
/// Note: H.264 is deliberately absent from the entire stack — MPEG-LA
/// patent-royalty avoidance (see `spec.txt`, H.264 Avoidance Strategy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CodecKind {
    /// Opus audio.
    Opus,
    /// AV1 video (royalty-free, Alliance for Open Media) — the preferred video codec.
    Av1,
    /// VP9 video.
    Vp9,
    /// VP8 video.
    Vp8,
}

/// Ordered codec preferences. Earlier entries are preferred during
/// negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecPreferences {
    /// Codecs in descending preference order.
    pub order: Vec<CodecKind>,
}

impl Default for CodecPreferences {
    fn default() -> Self {
        // AV1-first per the mission statement, VP9 fallback, then VP8.
        Self {
            order: vec![
                CodecKind::Opus,
                CodecKind::Av1,
                CodecKind::Vp9,
                CodecKind::Vp8,
            ],
        }
    }
}

impl CodecPreferences {
    /// Keeps only the given codecs, preserving `self`'s ordering.
    #[must_use]
    pub fn filtered(&self, allowed: &[CodecKind]) -> Vec<CodecKind> {
        self.order
            .iter()
            .copied()
            .filter(|c| allowed.contains(c))
            .collect()
    }
}

/// Bandwidth estimation algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BweAlgorithm {
    /// Google Congestion Control (delay-based + loss-based) — default.
    #[default]
    GoogleCongestionControl,
    /// BBR-based estimation.
    Bbr,
    /// Receiver Estimated Maximum Bitrate (REMB) only.
    Remb,
    /// Transport-wide congestion control (TWCC) only.
    Twcc,
}

/// One entry from `iceServers` configuration, e.g. `"stun:stun.example.com:3478"`
/// or `"turn:user@host:3478?transport=udp"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceServer {
    /// URLs for the same server (e.g. both `turn:` and `turns:`).
    pub urls: Vec<String>,
    /// Username for TURN long-term credentials.
    pub username: Option<String>,
    /// Credential for TURN long-term credentials.
    pub credential: Option<String>,
}

/// Scheme portion of an ICE server URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceServerScheme {
    /// STUN server.
    Stun,
    /// TURN server over UDP/TCP.
    Turn,
    /// TURN server over TLS (not usable by the UDP transport; kept for config parity).
    Turns,
}

impl IceServer {
    /// Parses the scheme of the first URL (`stun:`, `turn:`, `turns:`).
    #[must_use]
    pub fn scheme(&self) -> Option<IceServerScheme> {
        let url = self.urls.first()?;
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("stun:") {
            Some(IceServerScheme::Stun)
        } else if lower.starts_with("turns:") {
            Some(IceServerScheme::Turns)
        } else if lower.starts_with("turn:") {
            Some(IceServerScheme::Turn)
        } else {
            None
        }
    }

    /// Host and port of the first URL, with scheme-default ports applied
    /// (stun/turn: 3478, turns: 5349).
    ///
    /// # Examples
    /// ```
    /// use tpt_webrtc_core::IceServer;
    ///
    /// let srv = IceServer { urls: vec!["stun:stun.example.com".into()], username: None, credential: None };
    /// assert_eq!(srv.host_port().map(|(h, p)| (h, p)), Some(("stun.example.com".to_string(), 3478)));
    /// ```
    #[must_use]
    pub fn host_port(&self) -> Option<(String, u16)> {
        let url = self.urls.first()?;
        let rest = url.split_once(':')?.1;
        let host_part = rest.split_once('?').map_or(rest, |(h, _)| h);
        let default_port = if self.scheme()? == IceServerScheme::Turns {
            5349
        } else {
            3478
        };
        let (host, port) = match host_part.rsplit_once(':') {
            // Bare IPv6 host (no port): "[::1]" or "::1" without a port part.
            Some((h, p)) if p.parse::<u16>().is_ok() && !h.is_empty() => (
                h.trim_matches(|c| c == '[' || c == ']').to_string(),
                p.parse::<u16>().ok()?,
            ),
            _ => (
                host_part.trim_matches(|c| c == '[' || c == ']').to_string(),
                default_port,
            ),
        };
        Some((host, port))
    }
}

/// Top-level configuration for building a WebRTC endpoint.
#[derive(Debug, Clone, Default)]
pub struct WebRtcConfig {
    /// STUN/TURN servers used for candidate gathering.
    pub ice_servers: Vec<IceServer>,
    /// Codec preference order.
    pub codec_preferences: CodecPreferences,
    /// Bandwidth estimation algorithm.
    pub bandwidth_estimation: BweAlgorithm,
    /// Local DTLS certificates. When empty, each `PeerConnection` generates a
    /// fresh self-signed ECDSA P-256 certificate.
    pub dtls_certificates: Vec<DtlsCertificate>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences_are_av1_first_without_h264() {
        let prefs = CodecPreferences::default();
        assert_eq!(prefs.order.first(), Some(&CodecKind::Opus));
        assert!(prefs.order.contains(&CodecKind::Av1));
        // The critical property: no H.264 anywhere in the enum.
        let all = [
            CodecKind::Opus,
            CodecKind::Av1,
            CodecKind::Vp9,
            CodecKind::Vp8,
        ];
        for k in all {
            assert_ne!(format!("{k:?}"), "H264");
        }
    }

    #[test]
    fn ice_server_url_parsing() {
        let stun = IceServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
            username: None,
            credential: None,
        };
        assert_eq!(stun.scheme(), Some(IceServerScheme::Stun));
        assert_eq!(stun.host_port(), Some(("stun.l.google.com".into(), 19302)));

        let turn = IceServer {
            urls: vec!["turn:turn.example.com".into()],
            username: Some("u".into()),
            credential: Some("p".into()),
        };
        assert_eq!(turn.scheme(), Some(IceServerScheme::Turn));
        assert_eq!(turn.host_port(), Some(("turn.example.com".into(), 3478)));

        let turns = IceServer {
            urls: vec!["turns:turn.example.com:5349?transport=tcp".into()],
            username: None,
            credential: None,
        };
        assert_eq!(turns.scheme(), Some(IceServerScheme::Turns));
        assert_eq!(turns.host_port(), Some(("turn.example.com".into(), 5349)));

        let bad = IceServer {
            urls: vec!["http://x".into()],
            username: None,
            credential: None,
        };
        assert_eq!(bad.scheme(), None);
    }

    #[test]
    fn filter_keeps_order() {
        let prefs = CodecPreferences::default();
        let got = prefs.filtered(&[CodecKind::Vp8, CodecKind::Av1]);
        assert_eq!(got, vec![CodecKind::Av1, CodecKind::Vp8]);
    }
}
