//! SCTP wire codec: common header (RFC 4960 §3.1) and the chunk types the
//! data-channel profile needs.

use tpt_webrtc_core::SctpError;

/// SCTP chunk types (RFC 4960 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    /// Payload Data (0).
    Data,
    /// Initiation (1).
    Init,
    /// Initiation Acknowledgement (2).
    InitAck,
    /// Selective Acknowledgement (3).
    Sack,
    /// Heartbeat (4).
    Heartbeat,
    /// Heartbeat Acknowledgement (5).
    HeartbeatAck,
    /// Abort (6).
    Abort,
    /// Shutdown (7).
    Shutdown,
    /// Shutdown Acknowledgement (8).
    ShutdownAck,
    /// Operation Error (9).
    OperationError,
    /// Cookie Echo (10).
    CookieEcho,
    /// Cookie Acknowledgement (11).
    CookieAck,
    /// Unknown chunk (raw).
    Unknown(u8),
}

impl ChunkType {
    /// Wire value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Init => 1,
            Self::InitAck => 2,
            Self::Sack => 3,
            Self::Heartbeat => 4,
            Self::HeartbeatAck => 5,
            Self::Abort => 6,
            Self::Shutdown => 7,
            Self::ShutdownAck => 8,
            Self::OperationError => 9,
            Self::CookieEcho => 10,
            Self::CookieAck => 11,
            Self::Unknown(v) => v,
        }
    }

    /// From wire value.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Data,
            1 => Self::Init,
            2 => Self::InitAck,
            3 => Self::Sack,
            4 => Self::Heartbeat,
            5 => Self::HeartbeatAck,
            6 => Self::Abort,
            7 => Self::Shutdown,
            8 => Self::ShutdownAck,
            9 => Self::OperationError,
            10 => Self::CookieEcho,
            11 => Self::CookieAck,
            other => Self::Unknown(other),
        }
    }
}

/// A parsed SCTP chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Chunk type.
    pub chunk_type: ChunkType,
    /// Chunk flags.
    pub flags: u8,
    /// Chunk value (the variable part, padding stripped).
    pub value: Vec<u8>,
}

/// SCTP common header + one or more chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Verification tag.
    pub verification_tag: u32,
    /// Chunks in the packet.
    pub chunks: Vec<Chunk>,
}

impl Packet {
    /// Serializes the packet with a zero checksum (the DTLS layer provides
    /// integrity, so the CRC32c is left as 0 — matching the common
    /// DTLS-SRTP shortcut; RFC 4960 receivers on the open internet must
    /// verify, but SCTP-over-DTLS explicitly skips it, RFC 8260 §4).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.verification_tag.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]); // checksum (skipped over DTLS)
        for chunk in &self.chunks {
            out.push(chunk.chunk_type.to_u8());
            out.push(chunk.flags);
            let len = chunk.value.len() + 4;
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.extend_from_slice(&chunk.value);
            while out.len() % 4 != 0 {
                out.push(0); // chunk padding
            }
        }
        out
    }

    /// Parses a packet (all chunks).
    ///
    /// # Errors
    /// [`SctpError::MalformedChunk`] on truncated input.
    pub fn parse(data: &[u8]) -> Result<Self, SctpError> {
        if data.len() < 12 {
            return Err(SctpError::MalformedChunk);
        }
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let verification_tag = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let mut chunks = Vec::new();
        let mut i = 12;
        while i + 4 <= data.len() {
            let chunk_type = ChunkType::from_u8(data[i]);
            let flags = data[i + 1];
            let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            if len < 4 || i + len > data.len() {
                return Err(SctpError::MalformedChunk);
            }
            chunks.push(Chunk {
                chunk_type,
                flags,
                value: data[i + 4..i + len].to_vec(),
            });
            i += (len + 3) & !3; // skip padding
        }
        Ok(Self {
            src_port,
            dst_port,
            verification_tag,
            chunks,
        })
    }
}

/// INIT / INIT-ACK parameters this stack negotiates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitPeerInfo {
    /// Peer's initial TSN.
    pub initial_tsn: u32,
    /// Peer's OS (outbound streams).
    pub outbound_streams: u16,
    /// Peer's MIS (inbound streams).
    pub inbound_streams: u16,
    /// Peer's tie-tag (random, for INIT collision resolution).
    pub tie_tag: u32,
}

/// Parses the INIT / INIT-ACK body: `tag(4) a_rwnd(4) OS(2) MIS(2) TSN(4)`
/// plus optional TLV parameters (we read the random/tie-tag).
///
/// # Errors
/// [`SctpError::MalformedChunk`] on truncated input.
pub fn parse_init(body: &[u8]) -> Result<(u32, InitPeerInfo), SctpError> {
    if body.len() < 16 {
        return Err(SctpError::MalformedChunk);
    }
    let init_tag = u32::from_be_bytes(body[0..4].try_into().unwrap());
    let _a_rwnd = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let outbound_streams = u16::from_be_bytes(body[8..10].try_into().unwrap());
    let inbound_streams = u16::from_be_bytes(body[10..12].try_into().unwrap());
    let initial_tsn = u32::from_be_bytes(body[12..16].try_into().unwrap());
    let mut tie_tag = 0;
    let mut i = 16;
    while i + 4 <= body.len() {
        let ty = u16::from_be_bytes([body[i], body[i + 1]]);
        let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        if len < 4 || i + len > body.len() {
            break;
        }
        if ty == 0x8002 && len >= 12 {
            // SSCRC: random(4) + sender's local tie tag(4) + peer tie(4);
            // the sender's local tie is what the remote peer needs.
            tie_tag = u32::from_be_bytes(body[i + len - 8..i + len - 4].try_into().unwrap());
        }
        i += (len + 3) & !3;
    }
    Ok((
        init_tag,
        InitPeerInfo {
            initial_tsn,
            outbound_streams,
            inbound_streams,
            tie_tag,
        },
    ))
}

/// Serializes an INIT / INIT-ACK body with our SSCRC tie-tag parameter.
#[must_use]
pub fn serialize_init(
    init_tag: u32,
    initial_tsn: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    tie_tag: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&init_tag.to_be_bytes());
    body.extend_from_slice(&1_048_576u32.to_be_bytes()); // a_rwnd
    body.extend_from_slice(&outbound_streams.to_be_bytes());
    body.extend_from_slice(&inbound_streams.to_be_bytes());
    body.extend_from_slice(&initial_tsn.to_be_bytes());
    // SSCRC TLV (type 0x8002): random(4) + local tie(4) + peer tie(4).
    let param_len = 4 + 4 + 4 + 4;
    body.extend_from_slice(&0x8002u16.to_be_bytes());
    body.extend_from_slice(&(param_len as u16).to_be_bytes());
    body.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // random
    body.extend_from_slice(&tie_tag.to_be_bytes()); // local tie tag
    body.extend_from_slice(&[0, 0, 0, 0]); // peer tie tag (unknown at INIT)
    body
}

/// Parses a SACK body: `cumulative_tsn(4) a_rwnd(4) gaps(2) dup_tsns(2)`
/// followed by gap blocks.
///
/// # Errors
/// [`SctpError::MalformedChunk`] on truncated input.
pub fn parse_sack(body: &[u8]) -> Result<(u32, Vec<(u16, u16)>), SctpError> {
    if body.len() < 12 {
        return Err(SctpError::MalformedChunk);
    }
    let cumulative = u32::from_be_bytes(body[0..4].try_into().unwrap());
    let gaps = u16::from_be_bytes(body[8..10].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(gaps);
    let mut i = 12;
    for _ in 0..gaps {
        if i + 4 > body.len() {
            break;
        }
        let start = u16::from_be_bytes(body[i..i + 2].try_into().unwrap());
        let end = u16::from_be_bytes(body[i + 2..i + 4].try_into().unwrap());
        out.push((start, end));
        i += 4;
    }
    Ok((cumulative, out))
}

/// Serializes a SACK body.
#[must_use]
pub fn serialize_sack(cumulative_tsn: u32, gaps: &[(u16, u16)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&cumulative_tsn.to_be_bytes());
    body.extend_from_slice(&1_048_576u32.to_be_bytes()); // a_rwnd
    body.extend_from_slice(&(gaps.len() as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // dup TSNS
    for (start, end) in gaps {
        body.extend_from_slice(&start.to_be_bytes());
        body.extend_from_slice(&end.to_be_bytes());
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip_multi_chunk() {
        let pkt = Packet {
            src_port: 5000,
            dst_port: 5000,
            verification_tag: 0xDEAD_BEEF,
            chunks: vec![
                Chunk {
                    chunk_type: ChunkType::Data,
                    flags: 0x03,
                    value: vec![1, 2, 3, 4, 5],
                },
                Chunk {
                    chunk_type: ChunkType::CookieEcho,
                    flags: 0,
                    value: vec![9; 8],
                },
            ],
        };
        let wire = pkt.serialize();
        // 12 header + (4+5 padded to 12) + (4+8) = 36
        assert_eq!(wire.len(), 36);
        let parsed = Packet::parse(&wire).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn init_roundtrip() {
        let body = serialize_init(0x1111_2222, 100, 1024, 65535, 0x3333_4444);
        let (tag, info) = parse_init(&body).unwrap();
        assert_eq!(tag, 0x1111_2222);
        assert_eq!(info.initial_tsn, 100);
        assert_eq!(info.outbound_streams, 1024);
        assert_eq!(info.inbound_streams, 65535);
        assert_eq!(info.tie_tag, 0x3333_4444);
    }

    #[test]
    fn sack_roundtrip_with_gaps() {
        let body = serialize_sack(50, &[(2, 3), (5, 5)]);
        let (cum, gaps) = parse_sack(&body).unwrap();
        assert_eq!(cum, 50);
        assert_eq!(gaps, vec![(2, 3), (5, 5)]);
    }

    #[test]
    fn truncated_inputs_error() {
        assert!(Packet::parse(&[0u8; 5]).is_err());
        let mut wire = Packet {
            src_port: 1,
            dst_port: 2,
            verification_tag: 3,
            chunks: vec![Chunk {
                chunk_type: ChunkType::Data,
                flags: 0,
                value: vec![1, 2],
            }],
        }
        .serialize();
        // Declare a chunk length beyond the datagram.
        wire[14] = 0x7F;
        wire[15] = 0xFF;
        assert!(Packet::parse(&wire).is_err());
    }
}
