//! RTCP feedback messages: NACK (RFC 4585), TWCC (RFC 8888), PLI/FIR
//! (RFC 5104) and REMB (de-facto standard).

use tpt_webrtc_core::RtpError;

/// FCI format for NACK within transport-layer feedback.
const RTPFB_NACK: u8 = 1;
/// FCI format for PLI within payload-specific feedback.
const PSFB_PLI: u8 = 1;
/// FCI format for FIR within payload-specific feedback.
const PSFB_FIR: u8 = 4;
/// FCI format for REMB (vendor extension).
const PSFB_REMB: u8 = 15;
/// RTPFB format used by TWCC in practice.
const RTPFB_TWCC: u8 = 15;

/// Generic loss NACK: generic NACK (RFC 4585 §6.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nack {
    /// SSRC of the stream being requested.
    pub media_ssrc: u32,
    /// Missing sequence numbers (decoded from PID + BLP bitmaps).
    pub sequence_numbers: Vec<u16>,
}

/// Transport-wide congestion control feedback (RFC 8888).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportWideCongestionControl {
    /// Always 0 per the spec.
    pub media_ssrc: u32,
    /// Sequence number of this feedback packet.
    pub feedback_sequence: u16,
    /// First transport-wide sequence number covered.
    pub sequence_base: u16,
    /// Per-packet arrival time in microseconds (`None` = not received),
    /// in `sequence_base` order.
    pub received: Vec<Option<u32>>,
}

/// Picture Loss Indication (RFC 4585 §6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PictureLossIndication {
    /// SSRC to re-issue an I-frame for.
    pub media_ssrc: u32,
}

/// Full Intra Request (RFC 5104 §4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullIntraRequest {
    /// SSRC to re-issue an I-frame for.
    pub media_ssrc: u32,
    /// Command sequence number.
    pub sequence_number: u8,
}

/// Receiver Estimated Maximum Bitrate (draft-alvestrand-rmcat-remb).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remb {
    /// Estimated maximum bitrate in bits per second.
    pub bitrate_bps: u32,
    /// SSRCs the estimate applies to.
    pub ssrcs: Vec<u32>,
}

/// Transport-layer feedback variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportLayerFeedback {
    /// Generic NACK.
    Nack(Nack),
    /// TWCC report.
    Twcc(TransportWideCongestionControl),
}

/// Payload-specific feedback variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSpecificFeedback {
    /// Picture Loss Indication.
    Pli(PictureLossIndication),
    /// Full Intra Request.
    Fir(FullIntraRequest),
    /// REMB.
    Remb(Remb),
}

impl TransportLayerFeedback {
    /// Sender SSRC (the feedback sender).
    #[must_use]
    pub fn sender_ssrc(&self) -> u32 {
        0
    }

    /// Media SSRC the feedback targets (0 for TWCC).
    #[must_use]
    pub fn media_ssrc(&self) -> u32 {
        match self {
            Self::Nack(n) => n.media_ssrc,
            Self::Twcc(t) => t.media_ssrc,
        }
    }

    /// FCI count/format byte and the FCI payload.
    #[must_use]
    pub fn serialize_body(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Nack(n) => {
                let mut body = Vec::new();
                let mut seqs = n.sequence_numbers.clone();
                seqs.sort_unstable();
                let mut i = 0;
                while i < seqs.len() {
                    let pid = seqs[i];
                    let mut blp = 0u16;
                    for &s in &seqs[i + 1..] {
                        let delta = s.wrapping_sub(pid);
                        if (1..=16).contains(&delta) {
                            blp |= 1 << (delta - 1);
                        }
                    }
                    body.extend_from_slice(&pid.to_be_bytes());
                    body.extend_from_slice(&blp.to_be_bytes());
                    // Skip everything covered by this PID+BLP entry.
                    i += 1 + blp.count_ones() as usize;
                }
                (RTPFB_NACK, body)
            }
            Self::Twcc(t) => {
                let mut body = Vec::new();
                body.extend_from_slice(&t.sequence_base.to_be_bytes());
                body.extend_from_slice(&(t.received.len() as u16).to_be_bytes());
                // Reference time: 24-bit; use the first delta's base 0.
                body.extend_from_slice(&[0, 0, 0]);
                body.push(t.feedback_sequence as u8); // sender's TWCC counter
                                                      // Run-length/status chunks, T=0 S=0: seven 2-bit symbols
                                                      // per chunk (01 = received with 1-byte delta, 00 = not
                                                      // received), deltas in 250 us units.
                let mut chunk = 0u16;
                let mut slots = 7;
                let mut deltas = Vec::new();
                for r in &t.received {
                    if slots == 0 {
                        body.extend_from_slice(&chunk.to_be_bytes());
                        chunk = 0;
                        slots = 7;
                    }
                    slots -= 1;
                    if let Some(us) = r {
                        chunk |= 0b01 << (slots * 2);
                        deltas.push((*us / 250).clamp(0, 255) as u8);
                    }
                }
                // The final chunk is always emitted (padded with zeros).
                body.extend_from_slice(&chunk.to_be_bytes());
                body.extend_from_slice(&deltas);
                (RTPFB_TWCC, body)
            }
        }
    }

    /// Parses a transport-layer feedback FCI.
    ///
    /// # Errors
    /// [`RtpError::MalformedRtcpPacket`] on malformed input.
    pub fn parse(count: u8, body: &[u8]) -> Result<Self, RtpError> {
        if body.len() < 8 {
            return Err(RtpError::MalformedRtcpPacket);
        }
        let _sender = u32::from_be_bytes(body[0..4].try_into().unwrap());
        let media_ssrc = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let fci = &body[8..];
        match count {
            RTPFB_NACK => {
                let mut sequence_numbers = Vec::new();
                let mut i = 0;
                while i + 4 <= fci.len() {
                    let pid = u16::from_be_bytes([fci[i], fci[i + 1]]);
                    let blp = u16::from_be_bytes([fci[i + 2], fci[i + 3]]);
                    sequence_numbers.push(pid);
                    for bit in 0..16u16 {
                        if blp & (1 << bit) != 0 {
                            sequence_numbers.push(pid.wrapping_add(bit + 1));
                        }
                    }
                    i += 4;
                }
                sequence_numbers.sort_unstable();
                sequence_numbers.dedup();
                Ok(Self::Nack(Nack {
                    media_ssrc,
                    sequence_numbers,
                }))
            }
            // TWCC arrives with FMT 15 in practice; treat anything else as
            // TWCC-shaped and parse defensively.
            _ => {
                if fci.len() < 8 {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                let sequence_base = u16::from_be_bytes([fci[0], fci[1]]);
                let status_count = u16::from_be_bytes([fci[2], fci[3]]) as usize;
                let feedback_sequence = fci[7];
                let mut received = Vec::with_capacity(status_count);
                // FCI layout: 8 fixed bytes, then the status chunks, then
                // the 1-byte deltas.
                let fci = &body[8..];
                if fci.len() < 8 {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                let chunks_total = status_count.div_ceil(7);
                let mut deltas = &fci[8 + 2 * chunks_total..];
                let mut done = 0;
                let mut chunk_index = 0;
                while done < status_count {
                    // Chunks start at FCI offset 8 (after base/count/reftime/fbcount).
                    let chunk_pos = 16 + 2 * chunk_index;
                    if chunk_pos + 2 > body.len() {
                        break;
                    }
                    let chunk = u16::from_be_bytes([body[chunk_pos], body[chunk_pos + 1]]);
                    chunk_index += 1;
                    if chunk & 0x8000 != 0 {
                        // Status vector chunk (T=1): 14 one-bit symbols
                        // (1 = received without delta info).
                        for slot in 0..14u16 {
                            if done >= status_count {
                                break;
                            }
                            let sym = (chunk >> (13 - slot)) & 1;
                            received.push(if sym == 1 { Some(0) } else { None });
                            done += 1;
                        }
                    } else {
                        // Status vector chunk (T=0 S=0): 7 two-bit symbols
                        // with 1-byte deltas in 250 us units.
                        for slot in 0..7u16 {
                            if done >= status_count {
                                break;
                            }
                            let sym = (chunk >> ((6 - slot) * 2)) & 0b11;
                            if sym == 0b01 && !deltas.is_empty() {
                                received.push(Some(u32::from(deltas[0]) * 250));
                                deltas = &deltas[1..];
                            } else {
                                received.push(None);
                            }
                            done += 1;
                        }
                    }
                }
                Ok(Self::Twcc(TransportWideCongestionControl {
                    media_ssrc: 0,
                    feedback_sequence: u16::from(feedback_sequence),
                    sequence_base,
                    received,
                }))
            }
        }
    }
}

impl PayloadSpecificFeedback {
    /// Sender SSRC.
    #[must_use]
    pub fn sender_ssrc(&self) -> u32 {
        0
    }

    /// Media SSRC.
    #[must_use]
    pub fn media_ssrc(&self) -> u32 {
        match self {
            Self::Pli(p) => p.media_ssrc,
            Self::Fir(f) => f.media_ssrc,
            Self::Remb(r) => r.ssrcs.first().copied().unwrap_or(0),
        }
    }

    /// FCI count/format byte and payload.
    #[must_use]
    pub fn serialize_body(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Pli(p) => (PSFB_PLI, p.media_ssrc.to_be_bytes().to_vec()),
            Self::Fir(f) => {
                let mut body = f.media_ssrc.to_be_bytes().to_vec();
                body.push(f.sequence_number);
                body.extend_from_slice(&[0, 0, 0]);
                (PSFB_FIR, body)
            }
            Self::Remb(r) => {
                let mut body = b"REMB".to_vec();
                // 6-bit exponent + 18-bit mantissa, as libwebrtc puts it on
                // the wire: byte 4 = exp<<2 | mantissa MSBs, bytes 5-6 =
                // rest, byte 7 unused (0); SSRC entries follow.
                let mut exp = 0u8;
                let mut mantissa = r.bitrate_bps;
                while mantissa > 0x3FFFF {
                    mantissa >>= 1;
                    exp += 1;
                }
                body.push((exp << 2) | ((mantissa >> 16) as u8 & 0x03));
                body.push((mantissa >> 8) as u8);
                body.push(mantissa as u8);
                body.push(0);
                for s in &r.ssrcs {
                    body.extend_from_slice(&s.to_be_bytes());
                }
                (PSFB_REMB, body)
            }
        }
    }

    /// Parses a payload-specific feedback FCI.
    ///
    /// # Errors
    /// [`RtpError::MalformedRtcpPacket`] on malformed input.
    pub fn parse(count: u8, body: &[u8]) -> Result<Self, RtpError> {
        if body.len() < 8 {
            return Err(RtpError::MalformedRtcpPacket);
        }
        let media_ssrc = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let fci = &body[8..];
        match count {
            PSFB_PLI => Ok(Self::Pli(PictureLossIndication { media_ssrc })),
            PSFB_FIR => {
                if fci.len() < 8 {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                Ok(Self::Fir(FullIntraRequest {
                    media_ssrc: u32::from_be_bytes(fci[0..4].try_into().unwrap()),
                    sequence_number: fci[4],
                }))
            }
            PSFB_REMB => {
                if fci.len() < 8 || &fci[0..4] != b"REMB" {
                    return Err(RtpError::MalformedRtcpPacket);
                }
                let exp = u32::from(fci[4]) >> 2;
                let mut mantissa =
                    (u32::from(fci[4]) & 0x03) << 16 | u32::from(fci[5]) << 8 | u32::from(fci[6]);
                mantissa <<= exp;
                let mut ssrcs = Vec::new();
                let mut i = 8;
                while i + 4 <= fci.len() {
                    ssrcs.push(u32::from_be_bytes(fci[i..i + 4].try_into().unwrap()));
                    i += 4;
                }
                Ok(Self::Remb(Remb {
                    bitrate_bps: mantissa,
                    ssrcs,
                }))
            }
            _ => Err(RtpError::MalformedRtcpPacket),
        }
    }
}

/// Parses a transport-layer feedback FCI (count/format byte + body).
///
/// # Errors
/// See [`TransportLayerFeedback::parse`].
pub fn parse_transport_layer(count: u8, body: &[u8]) -> Result<TransportLayerFeedback, RtpError> {
    TransportLayerFeedback::parse(count, body)
}

/// Parses a payload-specific feedback FCI (count/format byte + body).
///
/// # Errors
/// See [`PayloadSpecificFeedback::parse`].
pub fn parse_payload_specific(count: u8, body: &[u8]) -> Result<PayloadSpecificFeedback, RtpError> {
    PayloadSpecificFeedback::parse(count, body)
}
