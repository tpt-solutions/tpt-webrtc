//! SDP parser (RFC 8866 subset + WebRTC attribute grammar).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use tpt_webrtc_core::{CandidateType, IceCandidate};

use crate::model::{
    Attribute, Connection, Direction, MediaDescription, MediaType, Origin, SdpSession, SetupRole,
    SimulcastConfig, SsrcAttribute, SsrcGroupAttribute, Timing,
};
use crate::SdpError;

/// Parses an SDP session description (both `\r\n` and `\n` line endings are
/// accepted, RFC 8866 recommends `\r\n`).
///
/// # Errors
/// Returns [`SdpError::Syntax`] for malformed lines, [`SdpError::Missing`]
/// for missing mandatory lines, [`SdpError::Semantic`] for bad values.
pub fn parse_sdp(input: &str) -> Result<SdpSession, SdpError> {
    let mut version: Option<u32> = None;
    let mut origin: Option<Origin> = None;
    let mut session_name: Option<String> = None;
    let mut connection: Option<Connection> = None;
    let mut timing: Option<Timing> = None;
    let mut session_attrs: Vec<Attribute> = Vec::new();
    let mut media: Vec<MediaDescription> = Vec::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let mut chars = line.chars();
        let (type_char, value) = match (chars.next(), chars.next()) {
            (Some(t), Some('=')) => (t, &line[2..]),
            _ => {
                return Err(SdpError::Syntax {
                    line: line_no,
                    reason: format!("expected `<type>=<value>`, got {line:?}"),
                })
            }
        };

        // Attributes attach to the most recent media section, if any.
        let in_media = media.last_mut();

        match (type_char, value) {
            ('v', v) => {
                version = Some(v.parse().map_err(|_| SdpError::Syntax {
                    line: line_no,
                    reason: format!("bad protocol version {v:?}"),
                })?);
            }
            ('o', v) => {
                let parts: Vec<&str> = v.split_whitespace().collect();
                if parts.len() != 6 {
                    return Err(SdpError::Syntax {
                        line: line_no,
                        reason: "o= needs 6 fields".into(),
                    });
                }
                origin = Some(Origin {
                    username: parts[0].into(),
                    sess_id: parts[1].into(),
                    sess_version: parts[2].into(),
                    net_type: parts[3].into(),
                    addr_type: parts[4].into(),
                    address: parts[5].into(),
                });
            }
            ('s', v) => session_name = Some(v.into()),
            ('t', v) => {
                let parts: Vec<&str> = v.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(SdpError::Syntax {
                        line: line_no,
                        reason: "t= needs 2 fields".into(),
                    });
                }
                timing = Some(Timing {
                    start: parts[0].parse().map_err(|_| SdpError::Syntax {
                        line: line_no,
                        reason: "bad t= start".into(),
                    })?,
                    stop: parts[1].parse().map_err(|_| SdpError::Syntax {
                        line: line_no,
                        reason: "bad t= stop".into(),
                    })?,
                });
            }
            ('c', v) => {
                let conn = parse_connection(v, line_no)?;
                if let Some(m) = in_media {
                    m.connection = Some(conn);
                } else {
                    connection = Some(conn);
                }
            }
            ('m', v) => {
                let desc = parse_media_line(v, line_no)?;
                media.push(desc);
            }
            ('a', v) => {
                let attr = parse_attribute(v, line_no)?;
                if let Some(m) = in_media {
                    m.attributes.push(attr);
                } else {
                    session_attrs.push(attr);
                }
            }
            // Informational / legacy lines we deliberately ignore:
            // e=, p= (contact), b= (bandwidth), u=, r=, z=, k=.
            ('e' | 'p' | 'b' | 'u' | 'r' | 'z' | 'k', _) => {}
            (t, _) => {
                return Err(SdpError::Syntax {
                    line: line_no,
                    reason: format!("unknown line type {t:?}"),
                })
            }
        }
    }

    Ok(SdpSession {
        version: version.ok_or_else(|| SdpError::Missing("v= line".into()))?,
        origin: origin.ok_or_else(|| SdpError::Missing("o= line".into()))?,
        session_name: session_name.ok_or_else(|| SdpError::Missing("s= line".into()))?,
        connection,
        timing: timing.unwrap_or(Timing { start: 0, stop: 0 }),
        attributes: session_attrs,
        media_descriptions: media,
    })
}

fn syntax(line: usize, reason: impl Into<String>) -> SdpError {
    SdpError::Syntax {
        line,
        reason: reason.into(),
    }
}

fn parse_connection(v: &str, line: usize) -> Result<Connection, SdpError> {
    let parts: Vec<&str> = v.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(syntax(line, "c= needs 3 fields"));
    }
    Ok(Connection {
        net_type: parts[0].into(),
        addr_type: parts[1].into(),
        address: parts[2].into(),
    })
}

fn parse_media_line(v: &str, line: usize) -> Result<MediaDescription, SdpError> {
    let parts: Vec<&str> = v.split_whitespace().collect();
    if parts.len() < 4 {
        return Err(syntax(line, "m= needs at least 4 fields"));
    }
    Ok(MediaDescription {
        media_type: MediaType::from_str(parts[0]).map_err(|e| syntax(line, e))?,
        port: parts[1].parse().map_err(|_| syntax(line, "bad m= port"))?,
        protocol: parts[2].into(),
        formats: parts[3..].iter().map(|s| (*s).to_string()).collect(),
        connection: None,
        attributes: Vec::new(),
    })
}

fn parse_attribute(v: &str, line: usize) -> Result<Attribute, SdpError> {
    let (name, value) = match v.split_once(':') {
        Some((n, rest)) => (n, Some(rest)),
        None => (v, None),
    };

    let attr = match name.to_ascii_lowercase().as_str() {
        "rtpmap" => {
            let v = value.ok_or_else(|| syntax(line, "rtpmap needs a value"))?;
            let mut parts = v.splitn(2, ' ');
            let pt: u8 = parts
                .next()
                .unwrap_or("")
                .parse()
                .map_err(|_| syntax(line, "bad rtpmap payload type"))?;
            let enc = parts
                .next()
                .ok_or_else(|| syntax(line, "rtpmap missing encoding"))?;
            let mut enc_parts = enc.split('/');
            let codec = enc_parts.next().unwrap_or("").trim().to_string();
            let clock_rate: u32 = enc_parts
                .next()
                .unwrap_or("")
                .parse()
                .map_err(|_| syntax(line, "bad rtpmap clock rate"))?;
            let channels = enc_parts.next().and_then(|c| c.trim().parse().ok());
            Attribute::RtpMap {
                payload_type: pt,
                codec,
                clock_rate,
                channels,
            }
        }
        "fmtp" => {
            let v = value.ok_or_else(|| syntax(line, "fmtp needs a value"))?;
            let (pt, params) = v
                .split_once(' ')
                .ok_or_else(|| syntax(line, "fmtp needs <pt> <params>"))?;
            Attribute::Fmtp {
                payload_type: pt
                    .parse()
                    .map_err(|_| syntax(line, "bad fmtp payload type"))?,
                parameters: params.trim().to_string(),
            }
        }
        "ice-ufrag" => Attribute::IceUfrag(
            value
                .ok_or_else(|| syntax(line, "ice-ufrag needs a value"))?
                .to_string(),
        ),
        "ice-pwd" => Attribute::IcePwd(
            value
                .ok_or_else(|| syntax(line, "ice-pwd needs a value"))?
                .to_string(),
        ),
        "candidate" => {
            let v = value.ok_or_else(|| syntax(line, "candidate needs a value"))?;
            Attribute::IceCandidate(parse_candidate(v, line)?)
        }
        "fingerprint" => {
            let v = value.ok_or_else(|| syntax(line, "fingerprint needs a value"))?;
            let (alg, hex) = v
                .split_once(' ')
                .ok_or_else(|| syntax(line, "fingerprint needs <alg> <hex>"))?;
            let hex = hex.replace(':', "");
            let mut fingerprint = Vec::with_capacity(hex.len() / 2);
            let bytes = hex.as_bytes();
            if bytes.len() % 2 != 0 {
                return Err(syntax(line, "odd-length fingerprint hex"));
            }
            for pair in bytes.chunks(2) {
                let s = std::str::from_utf8(pair).expect("ascii input");
                fingerprint.push(
                    u8::from_str_radix(s, 16).map_err(|_| syntax(line, "bad fingerprint hex"))?,
                );
            }
            Attribute::Fingerprint {
                hash_algorithm: alg.to_ascii_lowercase(),
                fingerprint,
            }
        }
        "setup" => Attribute::Setup(
            SetupRole::from_str(value.ok_or_else(|| syntax(line, "setup needs a value"))?)
                .map_err(|e| syntax(line, e))?,
        ),
        "mid" => Attribute::Mid(
            value
                .ok_or_else(|| syntax(line, "mid needs a value"))?
                .to_string(),
        ),
        "bundle" => Attribute::Bundle,
        "rtcp-mux" => Attribute::RtcpMux,
        "simulcast" => {
            let v = value.ok_or_else(|| syntax(line, "simulcast needs a value"))?;
            Attribute::Simulcast(parse_simulcast(v, line)?)
        }
        "extmap" => {
            let v = value.ok_or_else(|| syntax(line, "extmap needs a value"))?;
            let (id, uri) = v
                .split_once(' ')
                .ok_or_else(|| syntax(line, "extmap needs <id> <uri>"))?;
            // Strip an optional "/direction" suffix from the id.
            let id_tok = id.split('/').next().unwrap_or(id);
            Attribute::ExtMap {
                id: id_tok.parse().map_err(|_| syntax(line, "bad extmap id"))?,
                uri: uri.trim().to_string(),
            }
        }
        "ssrc" => {
            let v = value.ok_or_else(|| syntax(line, "ssrc needs a value"))?;
            let (id, rest) = v.split_once(' ').map_or((v, None), |(i, r)| (i, Some(r)));
            let (attribute, attr_value) = match rest {
                Some(r) => match r.split_once(':') {
                    Some((a, val)) => (Some(a.to_string()), Some(val.to_string())),
                    None => (Some(r.to_string()), None),
                },
                None => (None, None),
            };
            Attribute::Ssrc(SsrcAttribute {
                id: id.parse().map_err(|_| syntax(line, "bad ssrc id"))?,
                attribute,
                value: attr_value,
            })
        }
        "ssrc-group" => {
            let v = value.ok_or_else(|| syntax(line, "ssrc-group needs a value"))?;
            let mut parts = v.split_whitespace();
            let semantics = parts
                .next()
                .ok_or_else(|| syntax(line, "ssrc-group missing semantics"))?
                .to_string();
            let ssrcs = parts
                .map(|p| {
                    p.parse::<u32>()
                        .map_err(|_| syntax(line, "bad ssrc in group"))
                })
                .collect::<Result<_, _>>()?;
            Attribute::SsrcGroup(SsrcGroupAttribute { semantics, ssrcs })
        }
        "sendrecv" | "sendonly" | "recvonly" | "inactive" => {
            Attribute::Direction(Direction::from_str(name).expect("matched above"))
        }
        _ => Attribute::Custom(name.to_string(), value.map(str::to_string)),
    };
    Ok(attr)
}

fn parse_candidate(v: &str, line: usize) -> Result<IceCandidate, SdpError> {
    let mut parts = v.split_whitespace();
    let mut next = |what: &str| {
        parts
            .next()
            .ok_or_else(|| syntax(line, format!("candidate missing {what}")))
    };

    let foundation = next("foundation")?.to_string();
    let component_id: u32 = next("component")?
        .parse()
        .map_err(|_| syntax(line, "bad candidate component"))?;
    let transport = next("transport")?.to_string();
    let priority: u32 = next("priority")?
        .parse()
        .map_err(|_| syntax(line, "bad candidate priority"))?;
    let addr: IpAddr = next("address")?
        .parse()
        .map_err(|_| syntax(line, "bad candidate address"))?;
    let port: u16 = next("port")?
        .parse()
        .map_err(|_| syntax(line, "bad candidate port"))?;
    let mut candidate = IceCandidate {
        foundation,
        component_id,
        transport,
        priority,
        address: SocketAddr::new(addr, port),
        candidate_type: CandidateType::Host,
        related_address: None,
    };

    // Trailing key/value pairs: typ, raddr, rport, generation, ufrag, ...
    let mut pairs: Vec<(&str, Option<&str>)> = Vec::new();
    while let Some(key) = parts.next() {
        pairs.push((key, parts.next()));
    }
    let get = |key: &str| pairs.iter().find(|(k, _)| *k == key).and_then(|(_, v)| *v);
    if let Some(ty) = get("typ") {
        candidate.candidate_type = ty.parse::<CandidateType>().map_err(|e| syntax(line, e))?;
    }
    if let (Some(raddr), Some(rport)) = (get("raddr"), get("rport")) {
        let addr: IpAddr = raddr.parse().map_err(|_| syntax(line, "bad raddr"))?;
        let port: u16 = rport.parse().map_err(|_| syntax(line, "bad rport"))?;
        candidate.related_address = Some(SocketAddr::new(addr, port));
    }
    Ok(candidate)
}

fn parse_simulcast(v: &str, line: usize) -> Result<SimulcastConfig, SdpError> {
    let mut cfg = SimulcastConfig::default();
    let mut rest = v.trim();
    while !rest.is_empty() {
        let (dir, remainder) = rest
            .split_once(' ')
            .ok_or_else(|| syntax(line, "simulcast needs a direction"))?;
        let (list, tail) = match remainder.split_once(' ') {
            Some((l, t)) if !t.is_empty() => (l, t.trim()),
            _ => (remainder, ""),
        };
        let groups = list
            .split(';')
            .map(|g| g.split(',').map(str::to_string).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        match dir {
            "send" => cfg.send = groups,
            "recv" => cfg.recv = groups,
            other => {
                return Err(syntax(
                    line,
                    format!("unknown simulcast direction {other:?}"),
                ))
            }
        }
        rest = tail;
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_OFFER: &str = "\
v=0\r\n\
o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1 2\r\n\
a=extmap-allow-mixed\r\n\
a=msid-semantic: WMS stream\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=rtcp:9 IN IP4 0.0.0.0\r\n\
a=ice-ufrag:EsAw\r\n\
a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1\r\n\
a=ice-options:trickle\r\n\
a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=ssrc:3428185634 cname:CxRb3clVeffqC9IA\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 45 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:EsAw\r\n\
a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1\r\n\
a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtcp-rsize\r\n\
a=rtpmap:45 AV1/90000\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=simulcast:send q;h,f\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:EsAw\r\n\
a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1\r\n\
a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\n\
a=setup:actpass\r\n\
a=mid:2\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n";

    #[test]
    fn parse_chrome_like_offer() {
        let sdp = parse_sdp(CHROME_OFFER).unwrap();
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.sess_id, "4611731400430051336");
        assert_eq!(sdp.session_name, "-");
        assert_eq!(sdp.bundle_group().unwrap(), vec!["0", "1", "2"]);
        assert_eq!(sdp.media_descriptions.len(), 3);

        let audio = &sdp.media_descriptions[0];
        assert_eq!(audio.media_type, MediaType::Audio);
        assert_eq!(audio.mid().unwrap(), "0");
        assert_eq!(sdp.ice_ufrag(Some(audio)).unwrap(), "EsAw");
        assert_eq!(
            sdp.ice_pwd(Some(audio)).unwrap(),
            "P2uYro0UCOQ4zxjKXaWCBui1"
        );
        let (alg, fp) = sdp.fingerprint(Some(audio)).unwrap();
        assert_eq!(alg, "sha-256");
        assert_eq!(fp.len(), 32);
        assert_eq!(audio.rtpmaps(), vec![(111, "opus".into(), 48000, Some(2))]);
        assert_eq!(audio.direction(), Direction::SendRecv);

        let video = &sdp.media_descriptions[1];
        assert_eq!(video.rtpmaps().len(), 2);
        assert!(matches!(
            video.attr_named("simulcast"),
            Some(Attribute::Simulcast(SimulcastConfig { send, .. }))
                if *send == vec![vec!["q".to_string()], vec!["h".to_string(), "f".to_string()]]
        ));
        assert!(video.attr_named("rtcp-rsize").is_some());

        let app = &sdp.media_descriptions[2];
        assert_eq!(app.media_type, MediaType::Application);
        assert_eq!(app.formats, vec!["webrtc-datachannel"]);
        assert!(matches!(
            app.attr_named("sctp-port"),
            Some(Attribute::Custom(n, Some(v))) if n == "sctp-port" && v == "5000"
        ));
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            parse_sdp("hello"),
            Err(SdpError::Syntax { line: 1, .. })
        ));
        assert!(matches!(parse_sdp("v=0\r\n"), Err(SdpError::Missing(_))));
        assert!(matches!(
            parse_sdp("v=zero\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\n"),
            Err(SdpError::Syntax { line: 1, .. })
        ));
    }

    #[test]
    fn parse_candidate_attribute() {
        let attr = parse_attribute(
            "candidate:842163049 1 udp 1677729535 192.168.1.4 54321 typ host generation 0 ufrag EsAw network-id 1",
            1,
        )
        .unwrap();
        let Attribute::IceCandidate(c) = attr else {
            panic!("not a candidate")
        };
        assert_eq!(c.foundation, "842163049");
        assert_eq!(c.component_id, 1);
        assert_eq!(c.priority, 1_677_729_535);
        assert_eq!(c.address.to_string(), "192.168.1.4:54321");
        assert_eq!(c.candidate_type, CandidateType::Host);

        let srflx = parse_attribute(
            "candidate:842163049 1 udp 1677729535 203.0.113.4 54321 typ srflx raddr 192.168.1.4 rport 54321",
            1,
        )
        .unwrap();
        let Attribute::IceCandidate(c) = srflx else {
            panic!("not a candidate")
        };
        assert_eq!(c.candidate_type, CandidateType::Srflx);
        assert_eq!(c.related_address.unwrap().to_string(), "192.168.1.4:54321");
    }

    #[test]
    fn parse_fingerprint_case_insensitive_hex() {
        let attr = parse_attribute("fingerprint:sha-1 d2:fa:0e", 1).unwrap();
        let Attribute::Fingerprint {
            hash_algorithm,
            fingerprint,
        } = attr
        else {
            panic!("not a fingerprint")
        };
        assert_eq!(hash_algorithm, "sha-1");
        assert_eq!(fingerprint, vec![0xD2, 0xFA, 0x0E]);
    }
}
