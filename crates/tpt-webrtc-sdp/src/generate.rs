//! SDP generator (inverse of [`crate::parse_sdp`]).

use crate::model::SdpSession;

/// Generates the SDP text for `session` with `\r\n` line endings per
/// RFC 8866 (a trailing CRLF is emitted after the last line).
///
/// # Errors
/// Returns [`crate::SdpError::Semantic`] when mandatory fields are empty
/// (e.g. an `o=` line whose fields contain whitespace).
pub fn generate_sdp(session: &SdpSession) -> Result<String, crate::SdpError> {
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push_str("\r\n");
    };

    line(format!("v={}", session.version));
    let o = &session.origin;
    for field in [
        &o.username,
        &o.sess_id,
        &o.sess_version,
        &o.net_type,
        &o.addr_type,
        &o.address,
    ] {
        if field.is_empty() || field.contains(char::is_whitespace) {
            return Err(crate::SdpError::Semantic(format!(
                "invalid o= field {field:?}"
            )));
        }
    }
    line(format!(
        "o={} {} {} {} {} {}",
        o.username, o.sess_id, o.sess_version, o.net_type, o.addr_type, o.address
    ));
    line(format!("s={}", session.session_name));
    if let Some(c) = &session.connection {
        line(format!("c={} {} {}", c.net_type, c.addr_type, c.address));
    }
    line(format!(
        "t={} {}",
        session.timing.start, session.timing.stop
    ));
    for attr in &session.attributes {
        push_attr(&mut line, attr);
    }
    for media in &session.media_descriptions {
        line(format!(
            "m={} {} {} {}",
            media.media_type,
            media.port,
            media.protocol,
            media.formats.join(" ")
        ));
        if let Some(c) = &media.connection {
            line(format!("c={} {} {}", c.net_type, c.addr_type, c.address));
        }
        for attr in &media.attributes {
            push_attr(&mut line, attr);
        }
    }
    Ok(out)
}

fn push_attr(line: &mut dyn FnMut(String), attr: &crate::model::Attribute) {
    match attr.value_string() {
        Some(value) => line(format!("a={}:{}", attr.name(), value)),
        None => line(format!("a={}", attr.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::parse_sdp;
    use std::net::SocketAddr;
    use tpt_webrtc_core::{CandidateType, IceCandidate};

    fn sample() -> SdpSession {
        SdpSession {
            version: 0,
            origin: Origin::from_ids("-", 1234, 2),
            session_name: "-".into(),
            connection: Some(Connection::default()),
            timing: Timing::default(),
            attributes: vec![
                Attribute::Custom("group".into(), Some("BUNDLE 0 1".into())),
                Attribute::IceUfrag("EsAw".into()),
                Attribute::IcePwd("P2uYro0UCOQ4zxjKXaWCBui1".into()),
            ],
            media_descriptions: vec![
                MediaDescription {
                    media_type: MediaType::Audio,
                    port: 9,
                    protocol: "UDP/TLS/RTP/SAVPF".into(),
                    formats: vec!["111".into()],
                    connection: None,
                    attributes: vec![
                        Attribute::Mid("0".into()),
                        Attribute::Direction(Direction::SendRecv),
                        Attribute::RtpMap {
                            payload_type: 111,
                            codec: "opus".into(),
                            clock_rate: 48_000,
                            channels: Some(2),
                        },
                        Attribute::IceCandidate(IceCandidate {
                            foundation: "1".into(),
                            component_id: 1,
                            transport: "udp".into(),
                            priority: 2_133_070_431,
                            address: "127.0.0.1:4000".parse::<SocketAddr>().unwrap(),
                            candidate_type: CandidateType::Host,
                            related_address: None,
                        }),
                    ],
                },
                MediaDescription {
                    media_type: MediaType::Application,
                    port: 9,
                    protocol: "UDP/DTLS/SCTP".into(),
                    formats: vec!["webrtc-datachannel".into()],
                    connection: None,
                    attributes: vec![
                        Attribute::Mid("1".into()),
                        Attribute::Custom("sctp-port".into(), Some("5000".into())),
                    ],
                },
            ],
        }
    }

    #[test]
    fn round_trip_via_parse() {
        let s = sample();
        let text = generate_sdp(&s).unwrap();
        assert!(text.contains("\r\n"));
        assert_eq!(parse_sdp(&text).unwrap(), s);
    }

    #[test]
    fn reject_whitespace_in_origin() {
        let mut s = sample();
        s.origin.username = "bad user".into();
        assert!(generate_sdp(&s).is_err());
    }
}
