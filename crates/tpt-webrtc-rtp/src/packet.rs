//! RTP packet codec (RFC 3550 §5.1) with header extensions (RFC 8285).

use tpt_webrtc_core::RtpError;

/// An RTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// Version (always 2).
    pub version: u8,
    /// Padding present.
    pub padding: bool,
    /// Header extension present.
    pub extension: bool,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Media timestamp.
    pub timestamp: u32,
    /// Synchronization source.
    pub ssrc: u32,
    /// Contributing sources.
    pub csrc: Vec<u32>,
    /// One-byte header extensions: (id, data) with profile `0xBEDE`.
    pub extensions: Vec<(u8, Vec<u8>)>,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Default for RtpPacket {
    fn default() -> Self {
        Self {
            version: 2,
            padding: false,
            extension: false,
            marker: false,
            payload_type: 0,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrc: Vec::new(),
            extensions: Vec::new(),
            payload: Vec::new(),
        }
    }
}

impl RtpPacket {
    /// Parses an RTP packet.
    ///
    /// # Errors
    /// [`RtpError::MalformedPacket`] on truncated or invalid input.
    pub fn parse(data: &[u8]) -> Result<Self, RtpError> {
        if data.len() < 12 {
            return Err(RtpError::MalformedPacket);
        }
        let version = data[0] >> 6;
        if version != 2 {
            return Err(RtpError::MalformedPacket);
        }
        let padding = data[0] & 0x20 != 0;
        let extension = data[0] & 0x10 != 0;
        let csrc_count = usize::from(data[0] & 0x0F);
        let marker = data[1] & 0x80 != 0;
        let payload_type = data[1] & 0x7F;
        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut i = 12;
        if data.len() < i + 4 * csrc_count {
            return Err(RtpError::MalformedPacket);
        }
        let mut csrc = Vec::with_capacity(csrc_count);
        for _ in 0..csrc_count {
            csrc.push(u32::from_be_bytes([
                data[i],
                data[i + 1],
                data[i + 2],
                data[i + 3],
            ]));
            i += 4;
        }

        let mut extensions = Vec::new();
        if extension {
            if data.len() < i + 4 {
                return Err(RtpError::MalformedPacket);
            }
            let profile = u16::from_be_bytes([data[i], data[i + 1]]);
            let ext_len_words = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            i += 4;
            if data.len() < i + 4 * ext_len_words {
                return Err(RtpError::MalformedPacket);
            }
            if profile == 0xBEDE {
                // RFC 8285 one-byte header: id in the top nibble, length-1
                // in the bottom nibble.
                let ext = &data[i..i + 4 * ext_len_words];
                let mut j = 0;
                while j < ext.len() {
                    let b = ext[j];
                    if b == 0 {
                        break; // padding
                    }
                    let id = b >> 4;
                    let len = usize::from(b & 0x0F) + 1;
                    if id == 0 || id == 15 || j + 1 + len > ext.len() {
                        break;
                    }
                    extensions.push((id, ext[j + 1..j + 1 + len].to_vec()));
                    j += 1 + len;
                }
            }
            i += 4 * ext_len_words;
        }

        let end = data.len()
            - if padding {
                usize::from(*data.last().ok_or(RtpError::MalformedPacket)?)
            } else {
                0
            };
        if i > end {
            return Err(RtpError::MalformedPacket);
        }
        Ok(Self {
            version,
            padding,
            extension,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            extensions,
            payload: data[i..end].to_vec(),
        })
    }

    /// Serializes the packet.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_len());
        let mut first = 2u8 << 6;
        if self.padding {
            first |= 0x20;
        }
        let has_ext = !self.extensions.is_empty();
        if has_ext {
            first |= 0x10;
        }
        first |= u8::try_from(self.csrc.len()).unwrap_or(0x0F) & 0x0F;
        out.push(first);
        out.push(if self.marker { 0x80 } else { 0 } | (self.payload_type & 0x7F));
        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for c in &self.csrc {
            out.extend_from_slice(&c.to_be_bytes());
        }
        if has_ext {
            out.extend_from_slice(&0xBEDEu16.to_be_bytes());
            // Pack one-byte extensions into 32-bit words.
            let mut body = Vec::new();
            for (id, data) in &self.extensions {
                body.push((id << 4) | (data.len() as u8 - 1));
                body.extend_from_slice(data);
            }
            while body.len() % 4 != 0 {
                body.push(0);
            }
            out.extend_from_slice(&((body.len() / 4) as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Serialized size in bytes.
    #[must_use]
    pub fn serialized_len(&self) -> usize {
        let ext = if self.extensions.is_empty() {
            0
        } else {
            let body: usize = self.extensions.iter().map(|(_, d)| 1 + d.len()).sum();
            4 + body.next_multiple_of(4)
        };
        12 + 4 * self.csrc.len() + ext + self.payload.len()
    }

    /// Payload size in bytes.
    #[must_use]
    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }

    /// Media timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RtpPacket {
        RtpPacket {
            extension: true,
            marker: true,
            payload_type: 96,
            sequence_number: 0x1234,
            timestamp: 90_000,
            ssrc: 0xDEADBEEF,
            csrc: vec![1, 2],
            extensions: vec![(1, vec![0xAB]), (3, vec![1, 2, 3])],
            payload: vec![0u8; 40],
            ..RtpPacket::default()
        }
    }

    #[test]
    fn roundtrip_with_extensions() {
        let p = sample();
        let wire = p.serialize();
        assert_eq!(wire.len(), p.serialized_len());
        let parsed = RtpPacket::parse(&wire).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.payload_size(), 40);
        assert_eq!(parsed.timestamp(), 90_000);
    }

    #[test]
    fn plain_packet_roundtrip() {
        let p = RtpPacket {
            sequence_number: 7,
            payload: vec![1, 2, 3],
            ..RtpPacket::default()
        };
        assert_eq!(RtpPacket::parse(&p.serialize()).unwrap(), p);
    }

    #[test]
    fn rejects_garbage() {
        assert!(RtpPacket::parse(&[0u8; 5]).is_err());
        let mut wire = sample().serialize();
        wire[0] = 1 << 6; // version 1
        assert!(RtpPacket::parse(&wire).is_err());
        let mut short = sample().serialize();
        short.truncate(15);
        assert!(RtpPacket::parse(&short).is_err());
    }
}
