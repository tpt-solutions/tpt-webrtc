//! Offer/answer model built on [`tpt_webrtc_core::WebRtcConfig`].

use tpt_webrtc_core::crypto;
use tpt_webrtc_core::{CodecKind, WebRtcConfig};

use crate::model::{
    Attribute, Direction, MediaDescription, MediaType, Origin, SdpSession, SetupRole, Timing,
};

/// Builder for WebRTC offers, answers and codec negotiation.
#[derive(Debug, Clone, Copy, Default)]
pub struct OfferAnswerModel;

/// A codec that survived negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCodec {
    /// Payload type to use towards the remote peer.
    pub payload_type: u8,
    /// Encoding name (canonical case from the remote offer/answer).
    pub codec: String,
    /// Clock rate.
    pub clock_rate: u32,
    /// Channels (audio).
    pub channels: Option<u32>,
    /// Format parameters string, when present.
    pub fmtp: Option<String>,
}

/// Result of codec negotiation between two session descriptions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodecNegotiation {
    /// Negotiated audio codecs.
    pub audio_codecs: Vec<NegotiatedCodec>,
    /// Negotiated video codecs.
    pub video_codecs: Vec<NegotiatedCodec>,
    /// Whether both sides offered the SCTP data channel.
    pub data_channels: bool,
}

/// Payload type assignments used when creating offers (WebRTC conventions).
const PT_OPUS: u8 = 111;
const PT_AV1: u8 = 45;
const PT_VP9: u8 = 98;
const PT_VP8: u8 = 96;

/// Standard header extensions offered for RTP media sections.
const MEDIA_EXTMAPS: &[(&str, &str)] = &[
    (
        "2",
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    ),
    (
        "3",
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
];

/// Video codecs this stack can support, in enum order (never H.264).
const VIDEO_CODECS: &[(CodecKind, u8, &str)] = &[
    (CodecKind::Av1, PT_AV1, "AV1"),
    (CodecKind::Vp9, PT_VP9, "VP9"),
    (CodecKind::Vp8, PT_VP8, "VP8"),
];

fn ice_random_string(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = vec![0u8; len];
    crypto::random_bytes(&mut buf).expect("system rng");
    buf.iter()
        .map(|&b| ALPHABET[b as usize % ALPHABET.len()] as char)
        .collect()
}

fn new_origin() -> Origin {
    let sess_id = crypto::random_u64().unwrap_or(1);
    Origin::from_ids("-", sess_id, 1)
}

fn has_codec(prefs: &[CodecKind], kind: CodecKind) -> bool {
    prefs.contains(&kind)
}

impl OfferAnswerModel {
    /// Builds a WebRTC offer from configuration: audio (Opus), video (AV1 /
    /// VP9 / VP8, per `config.codec_preferences`) and the SCTP data channel.
    ///
    /// ICE credentials are freshly generated; the DTLS fingerprint is taken
    /// from `config.dtls_certificates` when one is configured and omitted
    /// otherwise (the application layer must then supply one).
    ///
    /// # Errors
    /// Returns [`SdpError`] only on internal generation failures.
    pub fn create_offer(config: &WebRtcConfig) -> Result<SdpSession, crate::SdpError> {
        let prefs = &config.codec_preferences.order;
        let mut session = SdpSession {
            version: 0,
            origin: new_origin(),
            session_name: "-".into(),
            connection: Some(crate::model::Connection::default()),
            timing: Timing::default(),
            attributes: vec![
                Attribute::Custom("msid-semantic".into(), Some(" WMS".into())),
                Attribute::IceUfrag(ice_random_string(16)),
                Attribute::IcePwd(ice_random_string(24)),
            ],
            media_descriptions: Vec::new(),
        };

        if let Some(cert) = config.dtls_certificates.first() {
            let fp = cert.fingerprint().map_err(|_| {
                crate::SdpError::Semantic("could not fingerprint certificate".into())
            })?;
            session.attributes.push(Attribute::Fingerprint {
                hash_algorithm: fp.hash_algorithm,
                fingerprint: fp.value,
            });
        }

        let mut mids: Vec<String> = Vec::new();
        let mut mid_index = 0u32;

        if has_codec(prefs, CodecKind::Opus) {
            let mut attrs = vec![
                Attribute::Mid(mid_index.to_string()),
                Attribute::Direction(Direction::SendRecv),
                Attribute::RtpMap {
                    payload_type: PT_OPUS,
                    codec: "opus".into(),
                    clock_rate: 48_000,
                    channels: Some(2),
                },
                Attribute::Fmtp {
                    payload_type: PT_OPUS,
                    parameters: "minptime=10;useinbandfec=1".into(),
                },
                Attribute::RtcpMux,
            ];
            attrs.extend(MEDIA_EXTMAPS.iter().map(|(id, uri)| Attribute::ExtMap {
                id: id.parse().expect("static extmap id"),
                uri: (*uri).into(),
            }));
            session.media_descriptions.push(MediaDescription {
                media_type: MediaType::Audio,
                port: 9,
                protocol: "UDP/TLS/RTP/SAVPF".into(),
                formats: vec![PT_OPUS.to_string()],
                connection: None,
                attributes: attrs,
            });
            mids.push(mid_index.to_string());
            mid_index += 1;
        }

        let video: Vec<_> = VIDEO_CODECS
            .iter()
            .filter(|(kind, _, _)| has_codec(prefs, *kind))
            .collect();
        if !video.is_empty() {
            let mut attrs = vec![
                Attribute::Mid(mid_index.to_string()),
                Attribute::Direction(Direction::SendRecv),
                Attribute::RtcpMux,
            ];
            for (_, pt, name) in &video {
                attrs.push(Attribute::RtpMap {
                    payload_type: *pt,
                    codec: (*name).into(),
                    clock_rate: 90_000,
                    channels: None,
                });
            }
            // VP9 defaults to profile 0.
            attrs.push(Attribute::Fmtp {
                payload_type: PT_VP9,
                parameters: "profile-id=0".into(),
            });
            attrs.extend(MEDIA_EXTMAPS.iter().map(|(id, uri)| Attribute::ExtMap {
                id: id.parse().expect("static extmap id"),
                uri: (*uri).into(),
            }));
            session.media_descriptions.push(MediaDescription {
                media_type: MediaType::Video,
                port: 9,
                protocol: "UDP/TLS/RTP/SAVPF".into(),
                formats: video.iter().map(|(_, pt, _)| pt.to_string()).collect(),
                connection: None,
                attributes: attrs,
            });
            mids.push(mid_index.to_string());
            mid_index += 1;
        }

        // Data channel section (SCTP over DTLS, RFC 8831/8841).
        session.media_descriptions.push(MediaDescription {
            media_type: MediaType::Application,
            port: 9,
            protocol: "UDP/DTLS/SCTP".into(),
            formats: vec!["webrtc-datachannel".into()],
            connection: None,
            attributes: vec![
                Attribute::Mid(mid_index.to_string()),
                Attribute::Custom("sctp-port".into(), Some("5000".into())),
            ],
        });
        mids.push(mid_index.to_string());

        session.attributes.insert(
            0,
            Attribute::Custom("group".into(), Some(format!("BUNDLE {}", mids.join(" ")))),
        );

        Ok(session)
    }

    /// Answers `offer` given local configuration: keeps only codecs this
    /// stack supports, mirrors BUNDLE / RTCP-MUX / mid, picks the DTLS
    /// `active` role when allowed, and answers the data channel when
    /// offered. Unsupported media sections get `port 0`.
    ///
    /// # Errors
    /// Returns [`SdpError`] when the offer lacks a parsable `o=`/mid or has
    /// no media sections.
    pub fn create_answer(
        offer: &SdpSession,
        config: &WebRtcConfig,
    ) -> Result<SdpSession, crate::SdpError> {
        if offer.media_descriptions.is_empty() {
            return Err(crate::SdpError::Missing(
                "no media sections in offer".into(),
            ));
        }
        let prefs = &config.codec_preferences.order;
        let mut answer = SdpSession {
            version: 0,
            origin: new_origin(),
            session_name: "-".into(),
            connection: offer.connection.clone(),
            timing: offer.timing,
            attributes: vec![
                Attribute::IceUfrag(ice_random_string(16)),
                Attribute::IcePwd(ice_random_string(24)),
            ],
            media_descriptions: Vec::new(),
        };
        if let Some(cert) = config.dtls_certificates.first() {
            let fp = cert.fingerprint().map_err(|_| {
                crate::SdpError::Semantic("could not fingerprint certificate".into())
            })?;
            answer.attributes.push(Attribute::Fingerprint {
                hash_algorithm: fp.hash_algorithm,
                fingerprint: fp.value,
            });
        }
        if let Some(group) = offer.bundle_group() {
            answer.attributes.push(Attribute::Custom(
                "group".into(),
                Some(format!("BUNDLE {}", group.join(" "))),
            ));
        }

        // Answer setup role: active whenever the offer allows it.
        let offered_setup = offer.media_descriptions.first().and_then(|m| {
            m.attributes.iter().find_map(|a| match a {
                Attribute::Setup(r) => Some(*r),
                _ => None,
            })
        });
        let answer_setup = match offered_setup {
            Some(SetupRole::Active) => SetupRole::Passive,
            Some(SetupRole::HoldConn) => SetupRole::HoldConn,
            _ => SetupRole::Active, // actpass or passive -> we take active
        };

        for media in &offer.media_descriptions {
            let mut attrs = vec![
                Attribute::Mid(media.mid().unwrap_or_default().to_string()),
                Attribute::Setup(answer_setup),
                Attribute::Direction(Direction::SendRecv),
            ];
            let formats: Vec<String> = match &media.media_type {
                MediaType::Audio => media
                    .rtpmaps()
                    .into_iter()
                    .filter(|(_, codec, _, _)| {
                        codec.eq_ignore_ascii_case("opus") && has_codec(prefs, CodecKind::Opus)
                    })
                    .map(|(pt, codec, clock, ch)| {
                        attrs.push(Attribute::RtpMap {
                            payload_type: pt,
                            codec: codec.clone(),
                            clock_rate: clock,
                            channels: ch,
                        });
                        if let Some(fmtp) = media.attributes.iter().find_map(|a| match a {
                            Attribute::Fmtp {
                                payload_type,
                                parameters,
                            } if *payload_type == pt => Some(parameters.clone()),
                            _ => None,
                        }) {
                            attrs.push(Attribute::Fmtp {
                                payload_type: pt,
                                parameters: fmtp,
                            });
                        }
                        pt.to_string()
                    })
                    .collect(),
                MediaType::Video => media
                    .rtpmaps()
                    .into_iter()
                    .filter(|(_, codec, _, _)| {
                        VIDEO_CODECS.iter().any(|(kind, _, name)| {
                            codec.eq_ignore_ascii_case(name) && has_codec(prefs, *kind)
                        })
                    })
                    .map(|(pt, codec, clock, ch)| {
                        attrs.push(Attribute::RtpMap {
                            payload_type: pt,
                            codec: codec.clone(),
                            clock_rate: clock,
                            channels: ch,
                        });
                        pt.to_string()
                    })
                    .collect(),
                MediaType::Application => {
                    attrs.push(Attribute::Custom("sctp-port".into(), Some("5000".into())));
                    vec!["webrtc-datachannel".into()]
                }
                _ => Vec::new(),
            };

            if media
                .attributes
                .iter()
                .any(|a| matches!(a, Attribute::RtcpMux))
            {
                attrs.push(Attribute::RtcpMux);
            }

            let port = u16::from(!formats.is_empty());
            answer.media_descriptions.push(MediaDescription {
                media_type: media.media_type.clone(),
                port,
                protocol: media.protocol.clone(),
                formats,
                connection: None,
                attributes: attrs,
            });
        }
        Ok(answer)
    }

    /// Intersects the codecs of two session descriptions.
    ///
    /// The payload type in the result is the **remote** side's (the one to
    /// use when sending towards it). Matching is by codec name
    /// (case-insensitive), clock rate and channel count.
    ///
    /// # Errors
    /// Never currently; kept fallible per the spec signature.
    pub fn negotiate_codecs(
        local: &SdpSession,
        remote: &SdpSession,
    ) -> Result<CodecNegotiation, crate::SdpError> {
        let mut result = CodecNegotiation::default();

        let audio = local
            .media_descriptions
            .iter()
            .find(|m| m.media_type == MediaType::Audio)
            .map(|m| m.rtpmaps())
            .unwrap_or_default();
        for m in remote
            .media_descriptions
            .iter()
            .filter(|m| m.media_type == MediaType::Audio)
        {
            for (pt, codec, clock, ch) in m.rtpmaps() {
                if audio.iter().any(|(_, lc, lclk, lch)| {
                    codec.eq_ignore_ascii_case(lc) && *lclk == clock && lch == &ch
                }) && !result
                    .audio_codecs
                    .iter()
                    .any(|c| c.codec.eq_ignore_ascii_case(&codec))
                {
                    let fmtp = m.attributes.iter().find_map(|a| match a {
                        Attribute::Fmtp {
                            payload_type,
                            parameters,
                        } if *payload_type == pt => Some(parameters.clone()),
                        _ => None,
                    });
                    result.audio_codecs.push(NegotiatedCodec {
                        payload_type: pt,
                        codec,
                        clock_rate: clock,
                        channels: ch,
                        fmtp,
                    });
                }
            }
        }

        let video = local
            .media_descriptions
            .iter()
            .find(|m| m.media_type == MediaType::Video)
            .map(|m| m.rtpmaps())
            .unwrap_or_default();
        for m in remote
            .media_descriptions
            .iter()
            .filter(|m| m.media_type == MediaType::Video)
        {
            for (pt, codec, clock, ch) in m.rtpmaps() {
                if video.iter().any(|(_, lc, lclk, lch)| {
                    codec.eq_ignore_ascii_case(lc) && *lclk == clock && lch == &ch
                }) && !result
                    .video_codecs
                    .iter()
                    .any(|c| c.codec.eq_ignore_ascii_case(&codec))
                {
                    let fmtp = m.attributes.iter().find_map(|a| match a {
                        Attribute::Fmtp {
                            payload_type,
                            parameters,
                        } if *payload_type == pt => Some(parameters.clone()),
                        _ => None,
                    });
                    result.video_codecs.push(NegotiatedCodec {
                        payload_type: pt,
                        codec,
                        clock_rate: clock,
                        channels: ch,
                        fmtp,
                    });
                }
            }
        }

        result.data_channels = local.has_data_channel() && remote.has_data_channel();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Connection;
    use tpt_webrtc_core::DtlsCertificate;

    fn config() -> WebRtcConfig {
        WebRtcConfig {
            dtls_certificates: vec![DtlsCertificate::generate().unwrap()],
            ..WebRtcConfig::default()
        }
    }

    #[test]
    fn offer_contains_expected_sections() {
        let offer = OfferAnswerModel::create_offer(&config()).unwrap();
        assert_eq!(offer.media_descriptions.len(), 3); // audio + video + app
        assert_eq!(offer.bundle_group().unwrap().len(), 3);
        assert!(offer.fingerprint(None).is_some());
        assert!(offer.ice_ufrag(None).unwrap().len() == 16);
        assert!(offer.ice_pwd(None).unwrap().len() == 24);

        let audio = &offer.media_descriptions[0];
        assert_eq!(audio.rtpmaps(), vec![(111, "opus".into(), 48_000, Some(2))]);
        let video = &offer.media_descriptions[1];
        let names: Vec<_> = video
            .rtpmaps()
            .iter()
            .map(|(_, c, _, _)| c.clone())
            .collect();
        assert_eq!(names, vec!["AV1", "VP9", "VP8"]);
        assert!(offer.media_descriptions[2]
            .formats
            .contains(&"webrtc-datachannel".to_string()));
    }

    #[test]
    fn offer_answer_negotiation_round_trip() {
        let cfg = config();
        let offer = OfferAnswerModel::create_offer(&cfg).unwrap();
        let answer = OfferAnswerModel::create_answer(&offer, &cfg).unwrap();

        // Audio: opus kept with the offer's payload type.
        let audio = &answer.media_descriptions[0];
        assert_eq!(audio.rtpmaps(), vec![(111, "opus".into(), 48_000, Some(2))]);
        assert_eq!(audio.port, 1);
        assert!(matches!(
            audio
                .attributes
                .iter()
                .find(|a| matches!(a, Attribute::Setup(_))),
            Some(Attribute::Setup(SetupRole::Active))
        ));

        // Video: all three offered codecs are supported.
        assert_eq!(answer.media_descriptions[1].rtpmaps().len(), 3);
        // Data channel answered.
        assert_eq!(
            answer.media_descriptions[2].formats,
            vec!["webrtc-datachannel"]
        );
        assert_eq!(answer.bundle_group().unwrap().len(), 3);

        let negotiation = OfferAnswerModel::negotiate_codecs(&offer, &answer).unwrap();
        assert_eq!(negotiation.audio_codecs.len(), 1);
        assert_eq!(negotiation.audio_codecs[0].codec, "opus");
        assert_eq!(negotiation.audio_codecs[0].payload_type, 111);
        assert_eq!(negotiation.video_codecs.len(), 3);
        assert!(negotiation.data_channels);
    }

    #[test]
    fn answer_rejects_unsupported_codecs() {
        let cfg = WebRtcConfig::default();
        // Hand-build an offer offering H.264 (as a browser would) and VP8.
        let mut offer = OfferAnswerModel::create_offer(&cfg).unwrap();
        offer.media_descriptions[1]
            .attributes
            .push(Attribute::RtpMap {
                payload_type: 127,
                codec: "H264".into(),
                clock_rate: 90_000,
                channels: None,
            });
        offer.media_descriptions[1].formats.push("127".into());
        let answer = OfferAnswerModel::create_answer(&offer, &cfg).unwrap();
        let codecs: Vec<_> = answer.media_descriptions[1]
            .rtpmaps()
            .iter()
            .map(|(_, c, _, _)| c.to_ascii_uppercase())
            .collect();
        assert!(
            !codecs.iter().any(|c| c == "H264"),
            "H.264 must never be answered"
        );
        assert!(codecs.contains(&"AV1".to_string()));
    }

    #[test]
    fn answer_setup_passive_when_offer_active() {
        let cfg = config();
        let mut offer = OfferAnswerModel::create_offer(&cfg).unwrap();
        for m in &mut offer.media_descriptions {
            m.attributes.retain(|a| !matches!(a, Attribute::Setup(_)));
            m.attributes.push(Attribute::Setup(SetupRole::Active));
        }
        let answer = OfferAnswerModel::create_answer(&offer, &cfg).unwrap();
        assert!(matches!(
            answer.media_descriptions[0]
                .attributes
                .iter()
                .find(|a| matches!(a, Attribute::Setup(_))),
            Some(Attribute::Setup(SetupRole::Passive))
        ));
    }

    #[test]
    fn empty_offer_is_an_error() {
        let empty = SdpSession {
            version: 0,
            origin: Origin::from_ids("-", 1, 1),
            session_name: "-".into(),
            connection: Some(Connection::default()),
            timing: Timing::default(),
            attributes: Vec::new(),
            media_descriptions: Vec::new(),
        };
        assert!(OfferAnswerModel::create_answer(&empty, &config()).is_err());
    }
}
