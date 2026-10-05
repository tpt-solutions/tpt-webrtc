//! RTCP packet codec (RFC 3550 §6) with the feedback messages the stack
//! uses: NACK + TWCC (RFC 4585 transport-layer, RFC 8888 TWCC) and
//! PLI/FIR/REMB (payload-specific, REMB per the de-facto vendor spec).

pub mod feedback;

pub use feedback::{FullIntraRequest, Nack, Remb, TransportWideCongestionControl};

use tpt_webrtc_core::RtpError;

/// RTCP packet types.
pub mod packet_type {
    /// Sender Report.
    pub const SR: u8 = 200;
    /// Receiver Report.
    pub const RR: u8 = 201;
    /// Source Description.
    pub const SDES: u8 = 202;
    /// Goodbye.
    pub const BYE: u8 = 203;
    /// Transport-Layer Feedback.
    pub const TLF: u8 = 205;
    /// Payload-Specific Feedback.
    pub const PSFB: u8 = 206;
}

/// One reception report block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportBlock {
    /// Source SSRC the report is about.
    pub ssrc: u32,
    /// Fraction lost, 8.8 fixed point (0..=255).
    pub fraction_lost: u8,
    /// Cumulative packets lost.
    pub cumulative_lost: u32,
    /// Highest sequence number received (extended).
    pub highest_sequence: u32,
    /// Interarrival jitter estimate.
    pub jitter: u32,
    /// Last SR timestamp (LSR).
    pub last_sr: u32,
    /// Delay since last SR, 1/65536 s units.
    pub delay_since_last_sr: u32,
}

/// Sender Report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SenderReport {
    /// Sender SSRC.
    pub ssrc: u32,
    /// NTP timestamp (64-bit, MSW/LSW).
    pub ntp_timestamp: u64,
    /// RTP timestamp.
    pub rtp_timestamp: u32,
    /// Packets sent.
    pub packet_count: u32,
    /// Octets sent.
    pub octet_count: u32,
    /// Reception report blocks.
    pub reports: Vec<ReportBlock>,
}

/// Receiver Report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiverReport {
    /// Sender SSRC (reporter).
    pub ssrc: u32,
    /// Reception report blocks.
    pub reports: Vec<ReportBlock>,
}

/// SDES chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    /// Source SSRC.
    pub ssrc: u32,
    /// Text items (type byte + string), e.g. (1, "cname").
    pub items: Vec<(u8, String)>,
}

/// Source Description.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceDescription {
    /// SDES chunks.
    pub chunks: Vec<SdesChunk>,
}

/// Goodbye.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Goodbye {
    /// SSRCs leaving.
    pub ssrcs: Vec<u32>,
    /// Optional reason.
    pub reason: Option<String>,
}

/// A parsed RTCP packet (the first in a compound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    /// Sender Report (200).
    SenderReport(SenderReport),
    /// Receiver Report (201).
    ReceiverReport(ReceiverReport),
    /// Source Description (202).
    SourceDescription(SourceDescription),
    /// Goodbye (203).
    Goodbye(Goodbye),
    /// Transport-Layer Feedback (205).
    TransportLayerFeedback(feedback::TransportLayerFeedback),
    /// Payload-Specific Feedback (206).
    PayloadSpecificFeedback(feedback::PayloadSpecificFeedback),
}

impl RtcpPacket {
    /// The RTCP packet type byte.
    #[must_use]
    pub fn packet_type(&self) -> u8 {
        match self {
            Self::SenderReport(_) => packet_type::SR,
            Self::ReceiverReport(_) => packet_type::RR,
            Self::SourceDescription(_) => packet_type::SDES,
            Self::Goodbye(_) => packet_type::BYE,
            Self::TransportLayerFeedback(_) => packet_type::TLF,
            Self::PayloadSpecificFeedback(_) => packet_type::PSFB,
        }
    }

    /// Parses the FIRST RTCP packet of a compound.
    ///
    /// # Errors
    /// [`RtpError::MalformedRtcpPacket`] on truncated/invalid input.
    pub fn parse(data: &[u8]) -> Result<Self, RtpError> {
        if data.len() < 8 {
            return Err(RtpError::MalformedRtcpPacket);
        }
        let pt = data[1];
        // RFC 3550: length counts 32-bit words minus one, i.e. the whole
        // packet spans (length + 1) * 4 bytes including the header.
        let length_words = u16::from_be_bytes([data[2], data[3]]) as usize;
        let end = ((length_words + 1) * 4).min(data.len());
        let body = &data[4..end];
        match pt {
            packet_type::SR => {
                if body.len() < 24 {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                let ssrc = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let ntp = u64::from_be_bytes(body[4..12].try_into().unwrap());
                let rtp_ts = u32::from_be_bytes(body[12..16].try_into().unwrap());
                let pkt = u32::from_be_bytes(body[16..20].try_into().unwrap());
                let oct = u32::from_be_bytes(body[20..24].try_into().unwrap());
                let rc = usize::from(data[0] & 0x1F);
                let mut reports = Vec::with_capacity(rc);
                let mut i = 24;
                for _ in 0..rc {
                    if i + 24 > body.len() {
                        break;
                    }
                    reports.push(parse_report_block(&body[i..i + 24]));
                    i += 24;
                }
                Ok(Self::SenderReport(SenderReport {
                    ssrc,
                    ntp_timestamp: ntp,
                    rtp_timestamp: rtp_ts,
                    packet_count: pkt,
                    octet_count: oct,
                    reports,
                }))
            }
            packet_type::RR => {
                if body.len() < 4 {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                let ssrc = u32::from_be_bytes(body[0..4].try_into().unwrap());
                let rc = usize::from(data[0] & 0x1F);
                let mut reports = Vec::with_capacity(rc);
                let mut i = 4;
                for _ in 0..rc {
                    if i + 24 > body.len() {
                        break;
                    }
                    reports.push(parse_report_block(&body[i..i + 24]));
                    i += 24;
                }
                Ok(Self::ReceiverReport(ReceiverReport { ssrc, reports }))
            }
            packet_type::SDES => {
                let mut chunks = Vec::new();
                let mut i = 0;
                while i + 5 <= body.len() {
                    let ssrc = u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
                    i += 4;
                    let mut items = Vec::new();
                    while i < body.len() && body[i] != 0 {
                        let ty = body[i];
                        let len = usize::from(body[i + 1]);
                        if i + 2 + len > body.len() {
                            break;
                        }
                        items.push((
                            ty,
                            String::from_utf8_lossy(&body[i + 2..i + 2 + len]).into_owned(),
                        ));
                        i += 2 + len;
                    }
                    chunks.push(SdesChunk { ssrc, items });
                    i += 1; // null terminator
                }
                Ok(Self::SourceDescription(SourceDescription { chunks }))
            }
            packet_type::BYE => {
                let rc = usize::from(data[0] & 0x1F);
                let mut ssrcs = Vec::with_capacity(rc);
                let mut i = 0;
                for _ in 0..rc {
                    if i + 4 > body.len() {
                        break;
                    }
                    ssrcs.push(u32::from_be_bytes(body[i..i + 4].try_into().unwrap()));
                    i += 4;
                }
                let reason = if i < body.len() {
                    let len = usize::from(body[i]);
                    i += 1;
                    if i + len <= body.len() {
                        Some(String::from_utf8_lossy(&body[i..i + len]).into_owned())
                    } else {
                        None
                    }
                } else {
                    None
                };
                Ok(Self::Goodbye(Goodbye { ssrcs, reason }))
            }
            packet_type::TLF => Ok(Self::TransportLayerFeedback(
                feedback::parse_transport_layer(data[0] & 0x1F, body)?,
            )),
            packet_type::PSFB => Ok(Self::PayloadSpecificFeedback(
                feedback::parse_payload_specific(data[0] & 0x1F, body)?,
            )),
            _ => Err(RtpError::MalformedRtcpPacket),
        }
    }

    /// Serializes the packet (with padding-free length).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::SenderReport(sr) => {
                let rc = sr.reports.len();
                out.push(0x80 | u8::try_from(rc).unwrap_or(31) & 0x1F);
                out.push(packet_type::SR);
                // 4 header + 24 sr + 24*rc
                let words = (24 + 24 * rc) / 4; // total/4 - 1: SR body + report blocks
                out.extend_from_slice(&(words as u16).to_be_bytes());
                out.extend_from_slice(&sr.ssrc.to_be_bytes());
                out.extend_from_slice(&sr.ntp_timestamp.to_be_bytes());
                out.extend_from_slice(&sr.rtp_timestamp.to_be_bytes());
                out.extend_from_slice(&sr.packet_count.to_be_bytes());
                out.extend_from_slice(&sr.octet_count.to_be_bytes());
                for r in &sr.reports {
                    out.extend_from_slice(&serialize_report_block(r));
                }
            }
            Self::ReceiverReport(rr) => {
                let rc = rr.reports.len();
                out.push(0x80 | u8::try_from(rc).unwrap_or(31) & 0x1F);
                out.push(packet_type::RR);
                let words = 1 + 24 * rc / 4; // total/4 - 1: reporter SSRC + blocks
                out.extend_from_slice(&(words as u16).to_be_bytes());
                out.extend_from_slice(&rr.ssrc.to_be_bytes());
                for r in &rr.reports {
                    out.extend_from_slice(&serialize_report_block(r));
                }
            }
            Self::SourceDescription(sd) => {
                out.push(0x81);
                out.push(packet_type::SDES);
                let mut body = Vec::new();
                for chunk in &sd.chunks {
                    body.extend_from_slice(&chunk.ssrc.to_be_bytes());
                    for (ty, text) in &chunk.items {
                        body.push(*ty);
                        body.push(text.len() as u8);
                        body.extend_from_slice(text.as_bytes());
                    }
                    body.push(0);
                }
                while body.len() % 4 != 0 {
                    body.push(0);
                }
                out.extend_from_slice(&((body.len() / 4) as u16).to_be_bytes());
                out.extend_from_slice(&body);
            }
            Self::Goodbye(bye) => {
                let rc = bye.ssrcs.len();
                out.push(0x80 | u8::try_from(rc).unwrap_or(31) & 0x1F);
                out.push(packet_type::BYE);
                let reason_len = bye.reason.as_ref().map_or(0, |r| r.len() + 1);
                let padded = reason_len.next_multiple_of(4);
                out.extend_from_slice(&(((4 * rc + padded) / 4) as u16).to_be_bytes());
                for s in &bye.ssrcs {
                    out.extend_from_slice(&s.to_be_bytes());
                }
                if let Some(reason) = &bye.reason {
                    out.push(reason.len() as u8);
                    out.extend_from_slice(reason.as_bytes());
                    while out.len() % 4 != 0 {
                        out.push(0);
                    }
                }
            }
            Self::TransportLayerFeedback(f) => {
                let (count, payload_body) = f.serialize_body();
                out.push(0x80 | count & 0x1F);
                out.push(packet_type::TLF);
                out.extend_from_slice(&(((8 + payload_body.len()) / 4) as u16).to_be_bytes());
                out.extend_from_slice(&f.sender_ssrc().to_be_bytes());
                out.extend_from_slice(&f.media_ssrc().to_be_bytes());
                out.extend_from_slice(&payload_body);
            }
            Self::PayloadSpecificFeedback(f) => {
                let (count, payload_body) = f.serialize_body();
                out.push(0x80 | count & 0x1F);
                out.push(packet_type::PSFB);
                out.extend_from_slice(&(((8 + payload_body.len()) / 4) as u16).to_be_bytes());
                out.extend_from_slice(&f.sender_ssrc().to_be_bytes());
                out.extend_from_slice(&f.media_ssrc().to_be_bytes());
                out.extend_from_slice(&payload_body);
            }
        }
        out
    }
}

fn parse_report_block(b: &[u8]) -> ReportBlock {
    ReportBlock {
        ssrc: u32::from_be_bytes(b[0..4].try_into().unwrap()),
        fraction_lost: b[4],
        cumulative_lost: u32::from_be_bytes([0, b[5], b[6], b[7]]),
        highest_sequence: u32::from_be_bytes(b[8..12].try_into().unwrap()),
        jitter: u32::from_be_bytes(b[12..16].try_into().unwrap()),
        last_sr: u32::from_be_bytes(b[16..20].try_into().unwrap()),
        delay_since_last_sr: u32::from_be_bytes(b[20..24].try_into().unwrap()),
    }
}

fn serialize_report_block(r: &ReportBlock) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&r.ssrc.to_be_bytes());
    out.push(r.fraction_lost);
    out.extend_from_slice(&r.cumulative_lost.to_be_bytes()[1..4]);
    out.extend_from_slice(&r.highest_sequence.to_be_bytes());
    out.extend_from_slice(&r.jitter.to_be_bytes());
    out.extend_from_slice(&r.last_sr.to_be_bytes());
    out.extend_from_slice(&r.delay_since_last_sr.to_be_bytes());
    out
}

/// Parses a compound RTCP datagram into its packets.
///
/// # Errors
/// [`RtpError::MalformedRtcpPacket`] when any element fails to parse.
pub fn parse_compound(data: &[u8]) -> Result<Vec<RtcpPacket>, RtpError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let length_words = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let len = (length_words + 1) * 4;
        out.push(RtcpPacket::parse(&data[i..(i + len).min(data.len())])?);
        i += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use feedback::{FullIntraRequest, PictureLossIndication};

    #[test]
    fn sender_report_roundtrip() {
        let sr = SenderReport {
            ssrc: 0xCAFE,
            ntp_timestamp: 0x12345678_9ABCDEF0,
            rtp_timestamp: 90_000,
            packet_count: 42,
            octet_count: 12_345,
            reports: vec![ReportBlock {
                ssrc: 1,
                fraction_lost: 5,
                cumulative_lost: 17,
                highest_sequence: 0x1234,
                jitter: 9,
                last_sr: 77,
                delay_since_last_sr: 3,
            }],
        };
        let wire = RtcpPacket::SenderReport(sr.clone()).serialize();
        let parsed = RtcpPacket::parse(&wire).unwrap();
        assert_eq!(parsed, RtcpPacket::SenderReport(sr));
    }

    #[test]
    fn receiver_report_roundtrip() {
        let rr = ReceiverReport {
            ssrc: 7,
            reports: vec![],
        };
        let wire = RtcpPacket::ReceiverReport(rr.clone()).serialize();
        assert_eq!(
            RtcpPacket::parse(&wire).unwrap(),
            RtcpPacket::ReceiverReport(rr)
        );
    }

    #[test]
    fn sdes_roundtrip() {
        let sdes = SourceDescription {
            chunks: vec![SdesChunk {
                ssrc: 5,
                items: vec![(1, "my-cname".into())],
            }],
        };
        let wire = RtcpPacket::SourceDescription(sdes.clone()).serialize();
        assert_eq!(
            RtcpPacket::parse(&wire).unwrap(),
            RtcpPacket::SourceDescription(sdes)
        );
    }

    #[test]
    fn bye_roundtrip() {
        let bye = Goodbye {
            ssrcs: vec![1, 2, 3],
            reason: Some("done".into()),
        };
        let wire = RtcpPacket::Goodbye(bye.clone()).serialize();
        assert_eq!(RtcpPacket::parse(&wire).unwrap(), RtcpPacket::Goodbye(bye));
    }

    #[test]
    fn compound_parse() {
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 7,
            reports: vec![],
        })
        .serialize();
        let bye = RtcpPacket::Goodbye(Goodbye {
            ssrcs: vec![9],
            reason: None,
        })
        .serialize();
        let mut compound = rr;
        compound.extend_from_slice(&bye);
        let parsed = parse_compound(&compound).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[1],
            RtcpPacket::Goodbye(Goodbye {
                ssrcs: vec![9],
                reason: None
            })
        );
    }

    #[test]
    fn pli_and_nack_roundtrip() {
        let pli = RtcpPacket::PayloadSpecificFeedback(feedback::PayloadSpecificFeedback::Pli(
            PictureLossIndication { media_ssrc: 42 },
        ));
        let wire = pli.serialize();
        assert_eq!(RtcpPacket::parse(&wire).unwrap(), pli);

        let nack =
            RtcpPacket::TransportLayerFeedback(feedback::TransportLayerFeedback::Nack(Nack {
                media_ssrc: 42,
                sequence_numbers: vec![100, 101, 103],
            }));
        let wire = nack.serialize();
        let parsed = RtcpPacket::parse(&wire).unwrap();
        assert_eq!(
            parsed,
            RtcpPacket::TransportLayerFeedback(feedback::TransportLayerFeedback::Nack(Nack {
                media_ssrc: 42,
                sequence_numbers: vec![100, 101, 103],
            }))
        );
    }

    #[test]
    fn fir_remb_roundtrip() {
        let fir = RtcpPacket::PayloadSpecificFeedback(feedback::PayloadSpecificFeedback::Fir(
            FullIntraRequest {
                media_ssrc: 1,
                sequence_number: 9,
            },
        ));
        let wire = fir.serialize();
        assert_eq!(RtcpPacket::parse(&wire).unwrap(), fir);

        let remb =
            RtcpPacket::PayloadSpecificFeedback(feedback::PayloadSpecificFeedback::Remb(Remb {
                bitrate_bps: 2_500_000,
                ssrcs: vec![1, 2],
            }));
        let wire = remb.serialize();
        assert_eq!(RtcpPacket::parse(&wire).unwrap(), remb);
    }

    #[test]
    fn twcc_roundtrip() {
        let twcc = RtcpPacket::TransportLayerFeedback(feedback::TransportLayerFeedback::Twcc(
            TransportWideCongestionControl {
                media_ssrc: 0,
                feedback_sequence: 7,
                sequence_base: 1000,
                received: vec![Some(10_000), None, Some(25_000)],
            },
        ));
        let wire = twcc.serialize();
        let parsed = RtcpPacket::parse(&wire).unwrap();
        assert_eq!(
            parsed,
            RtcpPacket::TransportLayerFeedback(feedback::TransportLayerFeedback::Twcc(
                TransportWideCongestionControl {
                    media_ssrc: 0,
                    feedback_sequence: 7,
                    sequence_base: 1000,
                    received: vec![Some(10_000), None, Some(25_000)],
                }
            ))
        );
    }
}
