//! Shared ICE candidate type.
//!
//! Lives in the foundation crate so both `tpt-webrtc-sdp` (candidate
//! attribute) and `tpt-webrtc-ice` (agent) can use it without a cycle.

use std::net::{IpAddr, SocketAddr};

/// Where a candidate was derived from (RFC 8445 §5.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Directly bound to a local interface address.
    Host,
    /// Server-reflexive address learned from a STUN binding.
    Srflx,
    /// Peer-reflexive address discovered during connectivity checks.
    Prflx,
    /// Relayed address allocated from a TURN server.
    Relay,
}

impl CandidateType {
    /// Wire tag used in the SDP `candidate` attribute and pairing logic.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Srflx => "srflx",
            Self::Prflx => "prflx",
            Self::Relay => "relay",
        }
    }

    /// Type preference for the RFC 8445 §5.1.2.1 priority formula.
    /// Host > prflx > srflx > relay.
    #[must_use]
    pub fn type_preference(self) -> u32 {
        match self {
            Self::Host => 126,
            Self::Prflx => 110,
            Self::Srflx => 100,
            Self::Relay => 0,
        }
    }
}

impl std::fmt::Display for CandidateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CandidateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(Self::Host),
            "srflx" => Ok(Self::Srflx),
            "prflx" => Ok(Self::Prflx),
            "relay" => Ok(Self::Relay),
            other => Err(format!("unknown candidate type: {other}")),
        }
    }
}

/// A single ICE candidate (RFC 8445 §5.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceCandidate {
    /// Locally generated foundation grouping candidates with shared bases.
    pub foundation: String,
    /// Component ID (1 = RTP, 2 = RTCP). WebRTC uses component 1 with RTCP-MUX.
    pub component_id: u32,
    /// Transport protocol, `"udp"` in practice.
    pub transport: String,
    /// RFC 8445 §5.1.2.1 priority.
    pub priority: u32,
    /// Candidate transport address.
    pub address: SocketAddr,
    /// Candidate type.
    pub candidate_type: CandidateType,
    /// Base address for srflx/prflx/relay candidates (`raddr` in SDP).
    pub related_address: Option<SocketAddr>,
}

impl IceCandidate {
    /// RFC 8445 §5.1.2.1 priority formula:
    /// `2^24 * type_pref + 2^8 * local_pref + (256 - component)`.
    #[must_use]
    pub fn compute_priority(candidate_type: CandidateType, local_pref: u32, component: u32) -> u32 {
        (candidate_type.type_preference() << 24)
            + (local_pref << 8)
            + 256_u32.saturating_sub(component.min(256))
    }

    /// Renders the candidate as the value of an SDP `a=candidate:` line
    /// (without the `a=` prefix), per RFC 8839: address and port are
    /// separate tokens.
    #[must_use]
    pub fn to_sdp_value(&self) -> String {
        let mut s = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component_id,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type
        );
        if let Some(rel) = self.related_address {
            s.push_str(&format!(" raddr {} rport {}", rel.ip(), rel.port()));
        }
        s
    }

    /// Pairing key: two candidates pair only when transport and IP family
    /// match.
    #[must_use]
    pub fn pairs_with(&self, other: &IceCandidate) -> bool {
        self.component_id == other.component_id
            && self.transport.eq_ignore_ascii_case(&other.transport)
            && self.address.is_ipv4() == other.address.is_ipv4()
            && matches!(self.address.ip(), IpAddr::V4(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(ty: CandidateType, port: u16, priority: u32) -> IceCandidate {
        IceCandidate {
            foundation: "1".into(),
            component_id: 1,
            transport: "udp".into(),
            priority,
            address: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
            candidate_type: ty,
            related_address: None,
        }
    }

    #[test]
    fn priority_formula_matches_rfc8445() {
        // type 126, local 65535, comp 1 -> 126 << 24 | 65535 << 8 | 255
        let p = IceCandidate::compute_priority(CandidateType::Host, 65_535, 1);
        assert_eq!(p, (126 << 24) | (65_535 << 8) | 255);
        // Relay (0) always sorts below host for equal local prefs.
        assert!(
            IceCandidate::compute_priority(CandidateType::Host, 0, 1)
                > IceCandidate::compute_priority(CandidateType::Relay, 65_535, 1)
        );
    }

    #[test]
    fn sdp_roundtrip_value() {
        let c = cand(CandidateType::Srflx, 5000, 100);
        let s = c.to_sdp_value();
        assert!(s.starts_with("1 1 udp 100 127.0.0.1 5000 typ srflx"), "{s}");
    }

    #[test]
    fn candidate_type_parse() {
        assert_eq!(
            "host".parse::<CandidateType>().unwrap(),
            CandidateType::Host
        );
        assert!("bogus".parse::<CandidateType>().is_err());
    }

    #[test]
    fn pairing_requires_same_component_and_family() {
        let mut c2 = cand(CandidateType::Host, 5001, 100);
        assert!(cand(CandidateType::Host, 5000, 100).pairs_with(&c2));
        c2.component_id = 2;
        assert!(!cand(CandidateType::Host, 5000, 100).pairs_with(&c2));
    }
}
