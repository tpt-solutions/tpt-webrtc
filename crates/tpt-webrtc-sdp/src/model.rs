//! SDP data model (RFC 8866 + WebRTC extensions).

use std::fmt;

use tpt_webrtc_core::IceCandidate;

/// `m=` line media type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Data channel ("application" with the `webrtc-datachannel` format).
    Application,
    /// Text media (rarely used in WebRTC).
    Text,
    /// Message media (rarely used in WebRTC).
    Message,
    /// Any other media type token.
    Other(String),
}

impl MediaType {
    /// Token used on the `m=` line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Application => "application",
            Self::Text => "text",
            Self::Message => "message",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for MediaType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "audio" => Self::Audio,
            "video" => Self::Video,
            "application" => Self::Application,
            "text" => Self::Text,
            "message" => Self::Message,
            other => Self::Other(other.to_string()),
        })
    }
}

/// `o=` line origin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    /// Usually `"-"` for WebRTC.
    pub username: String,
    /// Globally unique session id (kept as string; can exceed u64 in the wild).
    pub sess_id: String,
    /// Session version, bumped on every modification.
    pub sess_version: String,
    /// `"IN"`.
    pub net_type: String,
    /// `"IP4"` / `"IP6"`.
    pub addr_type: String,
    /// Originating address (WebRTC convention: `127.0.0.1` / `::`).
    pub address: String,
}

impl Origin {
    /// Builds an origin from numeric id/version using WebRTC conventions.
    #[must_use]
    pub fn from_ids(username: &str, sess_id: u64, sess_version: u64) -> Self {
        Self {
            username: username.to_string(),
            sess_id: sess_id.to_string(),
            sess_version: sess_version.to_string(),
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: "127.0.0.1".into(),
        }
    }
}

/// `t=` line timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Timing {
    /// Start (NTP seconds); 0 for WebRTC ("permanent").
    pub start: u64,
    /// Stop; 0 for WebRTC.
    pub stop: u64,
}

/// `c=` connection line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Connection {
    /// `"IN"`.
    pub net_type: String,
    /// `"IP4"` / `"IP6"`.
    pub addr_type: String,
    /// Address or multicast base.
    pub address: String,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: "0.0.0.0".into(),
        }
    }
}

/// Media direction (WebRTC always carries one per media section).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// `a=sendrecv`
    SendRecv,
    /// `a=sendonly`
    SendOnly,
    /// `a=recvonly`
    RecvOnly,
    /// `a=inactive`
    Inactive,
}

impl Direction {
    /// Attribute token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }
}

impl std::str::FromStr for Direction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sendrecv" => Ok(Self::SendRecv),
            "sendonly" => Ok(Self::SendOnly),
            "recvonly" => Ok(Self::RecvOnly),
            "inactive" => Ok(Self::Inactive),
            other => Err(format!("unknown direction: {other}")),
        }
    }
}

/// `a=setup` role (RFC 5763 / RFC 4145).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetupRole {
    /// `actpass` — offered role choice (offers only).
    ActPass,
    /// `active` — DTLS client.
    Active,
    /// `passive` — DTLS server.
    Passive,
    /// `holdconn` — hold the connection.
    HoldConn,
}

impl SetupRole {
    /// Attribute token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActPass => "actpass",
            Self::Active => "active",
            Self::Passive => "passive",
            Self::HoldConn => "holdconn",
        }
    }
}

impl std::str::FromStr for SetupRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "actpass" => Ok(Self::ActPass),
            "active" => Ok(Self::Active),
            "passive" => Ok(Self::Passive),
            "holdconn" => Ok(Self::HoldConn),
            other => Err(format!("unknown setup role: {other}")),
        }
    }
}

/// `a=simulcast` configuration (RFC 8851): each direction carries a list of
/// alternative *groups* (separated by `;`), each group a list of RIDs
/// separated by `,`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SimulcastConfig {
    /// `send` groups: e.g. `[[1], [2, 3]]` for `send 1;2,3`.
    pub send: Vec<Vec<String>>,
    /// `recv` groups.
    pub recv: Vec<Vec<String>>,
}

/// `a=ssrc` attribute: an SSRC id plus optional `attribute[:value]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsrcAttribute {
    /// SSRC identifier.
    pub id: u32,
    /// Attribute name (e.g. `cname`, `msid`).
    pub attribute: Option<String>,
    /// Attribute value.
    pub value: Option<String>,
}

/// `a=ssrc-group` attribute.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsrcGroupAttribute {
    /// Group semantics (e.g. `FID`, `SIM`).
    pub semantics: String,
    /// Member SSRCs.
    pub ssrcs: Vec<u32>,
}

/// A single SDP attribute, session- or media-level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Attribute {
    /// `a=rtpmap:<pt> <codec>/<clock>[/<channels>]`
    RtpMap {
        /// Payload type the mapping applies to.
        payload_type: u8,
        /// Encoding name, e.g. `OPUS` / `AV1` / `VP8`.
        codec: String,
        /// Clock rate in Hz.
        clock_rate: u32,
        /// Channel count (audio only).
        channels: Option<u32>,
    },
    /// `a=fmtp:<pt> <params>`
    Fmtp {
        /// Payload type.
        payload_type: u8,
        /// Raw parameter string.
        parameters: String,
    },
    /// `a=ice-ufrag:<value>`
    IceUfrag(String),
    /// `a=ice-pwd:<value>`
    IcePwd(String),
    /// `a=candidate:...` (RFC 8839)
    IceCandidate(IceCandidate),
    /// `a=fingerprint:<alg> <hex>` (RFC 8122)
    Fingerprint {
        /// Hash algorithm, e.g. `sha-256`.
        hash_algorithm: String,
        /// Digest bytes.
        fingerprint: Vec<u8>,
    },
    /// `a=setup:<role>`
    Setup(SetupRole),
    /// `a=mid:<value>`
    Mid(String),
    /// `a=bundle` — media-level marker that the section is bundle-able.
    Bundle,
    /// `a=rtcp-mux`
    RtcpMux,
    /// `a=simulcast:...`
    Simulcast(SimulcastConfig),
    /// `a=extmap:<id>[ <uri>]`
    ExtMap {
        /// Header extension id.
        id: u32,
        /// Extension URI.
        uri: String,
    },
    /// `a=ssrc:<id>[ <attr>[:<value>]]`
    Ssrc(SsrcAttribute),
    /// `a=ssrc-group:<semantics> <ssrcs...>`
    SsrcGroup(SsrcGroupAttribute),
    /// `a=sendrecv` / `sendonly` / `recvonly` / `inactive`
    Direction(Direction),
    /// Any other `a=<name>[:<value>]` (preserved for round-tripping).
    Custom(String, Option<String>),
}

impl Attribute {
    /// Attribute name token (used when generating `a=<name>:<value>`).
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::RtpMap { .. } => "rtpmap",
            Self::Fmtp { .. } => "fmtp",
            Self::IceUfrag(_) => "ice-ufrag",
            Self::IcePwd(_) => "ice-pwd",
            Self::IceCandidate(_) => "candidate",
            Self::Fingerprint { .. } => "fingerprint",
            Self::Setup(_) => "setup",
            Self::Mid(_) => "mid",
            Self::Bundle => "bundle",
            Self::RtcpMux => "rtcp-mux",
            Self::Simulcast(_) => "simulcast",
            Self::ExtMap { .. } => "extmap",
            Self::Ssrc(_) => "ssrc",
            Self::SsrcGroup(_) => "ssrc-group",
            Self::Direction(d) => d.as_str(),
            Self::Custom(name, _) => name,
        }
    }

    /// Renders the attribute value (the part after `a=<name>:`), or `None`
    /// for property attributes rendered as bare `a=<name>`.
    #[must_use]
    pub fn value_string(&self) -> Option<String> {
        match self {
            Self::RtpMap {
                payload_type,
                codec,
                clock_rate,
                channels,
            } => Some(match channels {
                Some(ch) => format!("{payload_type} {codec}/{clock_rate}/{ch}"),
                None => format!("{payload_type} {codec}/{clock_rate}"),
            }),
            Self::Fmtp {
                payload_type,
                parameters,
            } => Some(format!("{payload_type} {parameters}")),
            Self::IceUfrag(v) | Self::IcePwd(v) | Self::Mid(v) => Some(v.clone()),
            Self::IceCandidate(c) => Some(c.to_sdp_value()),
            Self::Fingerprint {
                hash_algorithm,
                fingerprint,
            } => {
                let hex = fingerprint
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":");
                Some(format!("{hash_algorithm} {hex}"))
            }
            Self::Setup(role) => Some(role.as_str().to_string()),
            Self::Simulcast(cfg) => {
                let groups = |gs: &[Vec<String>]| -> String {
                    gs.iter().map(|g| g.join(",")).collect::<Vec<_>>().join(";")
                };
                let mut parts = Vec::new();
                if !cfg.send.is_empty() {
                    parts.push(format!("send {}", groups(&cfg.send)));
                }
                if !cfg.recv.is_empty() {
                    parts.push(format!("recv {}", groups(&cfg.recv)));
                }
                Some(parts.join(" "))
            }
            Self::ExtMap { id, uri } => Some(format!("{id} {uri}")),
            Self::Ssrc(s) => Some(match (&s.attribute, &s.value) {
                (Some(a), Some(v)) => format!("{} {a}:{v}", s.id),
                (Some(a), None) => format!("{} {a}", s.id),
                _ => format!("{}", s.id),
            }),
            Self::SsrcGroup(g) => Some(format!(
                "{} {}",
                g.semantics,
                g.ssrcs
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
            Self::Direction(_) => None,
            Self::Bundle | Self::RtcpMux => None,
            Self::Custom(_, value) => value.clone(),
        }
    }
}

/// A `m=` media section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaDescription {
    /// Media type.
    pub media_type: MediaType,
    /// Port (WebRTC convention: 9).
    pub port: u16,
    /// Protocol, e.g. `UDP/TLS/RTP/SAVPF` or `UDP/DTLS/SCTP`.
    pub protocol: String,
    /// Format list: payload types or the datachannel format token.
    pub formats: Vec<String>,
    /// Media-level `c=` line when present.
    pub connection: Option<Connection>,
    /// Media-level attributes in order.
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    /// First attribute matching `name` (case-insensitive), for Custom attrs.
    #[must_use]
    pub fn attr_named(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
    }

    /// All `a=rtpmap` mappings in order.
    #[must_use]
    pub fn rtpmaps(&self) -> Vec<(u8, String, u32, Option<u32>)> {
        self.attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::RtpMap {
                    payload_type,
                    codec,
                    clock_rate,
                    channels,
                } => Some((*payload_type, codec.clone(), *clock_rate, *channels)),
                _ => None,
            })
            .collect()
    }

    /// The `mid` value of this section.
    #[must_use]
    pub fn mid(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Mid(m) => Some(m.as_str()),
            _ => None,
        })
    }

    /// Direction of this section (defaults to `sendrecv` when absent).
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Direction(d) => Some(*d),
                _ => None,
            })
            .unwrap_or(Direction::SendRecv)
    }
}

/// A parsed SDP session description.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SdpSession {
    /// Protocol version (`v=`); must be 0.
    pub version: u32,
    /// `o=` origin.
    pub origin: Origin,
    /// `s=` session name.
    pub session_name: String,
    /// Session-level `c=` line when present.
    pub connection: Option<Connection>,
    /// `t=` timing.
    pub timing: Timing,
    /// Session-level attributes in order.
    pub attributes: Vec<Attribute>,
    /// Media sections in order.
    pub media_descriptions: Vec<MediaDescription>,
}

impl SdpSession {
    /// Session-level attribute lookup by name.
    #[must_use]
    pub fn attr_named(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.name().eq_ignore_ascii_case(name))
    }

    /// The BUNDLE group mids from `a=group:BUNDLE ...`, if any.
    #[must_use]
    pub fn bundle_group(&self) -> Option<Vec<String>> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Custom(name, Some(value)) if name.eq_ignore_ascii_case("group") => {
                let mut parts = value.split_whitespace();
                if parts.next()?.eq_ignore_ascii_case("BUNDLE") {
                    Some(parts.map(str::to_string).collect())
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    /// ICE username fragment: media-level first, then session-level.
    #[must_use]
    pub fn ice_ufrag(&self, media: Option<&MediaDescription>) -> Option<String> {
        let find = |attrs: &[Attribute]| {
            attrs.iter().find_map(|a| match a {
                Attribute::IceUfrag(v) => Some(v.clone()),
                _ => None,
            })
        };
        media
            .and_then(|m| find(&m.attributes))
            .or_else(|| find(&self.attributes))
    }

    /// ICE password: media-level first, then session-level.
    #[must_use]
    pub fn ice_pwd(&self, media: Option<&MediaDescription>) -> Option<String> {
        let find = |attrs: &[Attribute]| {
            attrs.iter().find_map(|a| match a {
                Attribute::IcePwd(v) => Some(v.clone()),
                _ => None,
            })
        };
        media
            .and_then(|m| find(&m.attributes))
            .or_else(|| find(&self.attributes))
    }

    /// DTLS fingerprint: media-level first, then session-level.
    #[must_use]
    pub fn fingerprint(&self, media: Option<&MediaDescription>) -> Option<(String, Vec<u8>)> {
        let find = |attrs: &[Attribute]| {
            attrs.iter().find_map(|a| match a {
                Attribute::Fingerprint {
                    hash_algorithm,
                    fingerprint,
                } => Some((hash_algorithm.clone(), fingerprint.clone())),
                _ => None,
            })
        };
        media
            .and_then(|m| find(&m.attributes))
            .or_else(|| find(&self.attributes))
    }

    /// Whether any media section offers the SCTP data channel.
    #[must_use]
    pub fn has_data_channel(&self) -> bool {
        self.media_descriptions.iter().any(|m| {
            m.media_type == MediaType::Application
                && m.formats.iter().any(|f| f == "webrtc-datachannel")
        })
    }
}
