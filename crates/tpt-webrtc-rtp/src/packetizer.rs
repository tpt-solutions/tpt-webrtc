//! Payload-specific packetizers: the [`Packetizer`] trait plus AV1, VP8,
//! VP9 and Opus implementations.
//!
//! Video packetizers need sequence-number continuity across frames, so the
//! [`Packetizer::packetize`] signature carries a mutable
//! [`VideoPacketizerContext`] (the caller keeps one per outbound SSRC).

use crate::media::MediaFrame;
use crate::RtpPacket;
use tpt_webrtc_core::PacketizerError;

/// RTP clock rates per media kind.
pub mod clock {
    /// Video (all codecs).
    pub const VIDEO: u32 = 90_000;
    /// Opus.
    pub const OPUS: u32 = 48_000;
}

/// Per-outgoing-stream state for video packetizers.
#[derive(Debug, Clone, Default)]
pub struct VideoPacketizerContext {
    /// Next RTP sequence number to emit.
    pub sequence_number: u16,
    /// SSRC of the outgoing stream.
    pub ssrc: u32,
    /// Payload type.
    pub payload_type: u8,
}

impl VideoPacketizerContext {
    /// Consumes the next sequence number.
    fn next_seq(&mut self) -> u16 {
        let seq = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        seq
    }
}

/// Splits [`MediaFrame`]s into RTP packets and reassembles them.
pub trait Packetizer {
    /// Splits `frame` into RTP packets of at most `mtu` bytes each.
    ///
    /// # Errors
    /// [`PacketizerError::Packetize`] when the frame cannot be packetized
    /// for this codec (e.g. an Opus packet larger than the MTU).
    fn packetize(
        &mut self,
        ctx: &mut VideoPacketizerContext,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<RtpPacket>, PacketizerError>;

    /// Reassembles a frame from one frame's packets (in order).
    ///
    /// # Errors
    /// [`PacketizerError::Depacketize`] on invalid payload structure.
    fn depacketize(&self, packets: &[RtpPacket]) -> Result<MediaFrame, PacketizerError>;
}

/// Builds a video RTP packet with common header fields.
fn video_packet(
    ctx: &mut VideoPacketizerContext,
    frame: &MediaFrame,
    marker: bool,
    payload: Vec<u8>,
) -> RtpPacket {
    RtpPacket {
        marker,
        payload_type: ctx.payload_type,
        sequence_number: ctx.next_seq(),
        timestamp: frame.rtp_timestamp(clock::VIDEO),
        ssrc: ctx.ssrc,
        payload,
        ..RtpPacket::default()
    }
}

/// Splits a slice into `mtu`-bounded chunks, returning `(chunk, is_first,
/// is_last)` triples.
fn chunk_payload(payload: &[u8], mtu: usize, overhead: usize) -> Vec<(&[u8], bool, bool)> {
    let per_packet = mtu.saturating_sub(overhead).max(1);
    if payload.len() <= per_packet {
        return vec![(payload, true, true)];
    }
    let mut out = Vec::new();
    let mut rest = payload;
    loop {
        let n = per_packet.min(rest.len());
        out.push((&rest[..n], out.is_empty(), n == rest.len()));
        rest = &rest[n..];
        if rest.is_empty() {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Opus (RFC 7587): one Opus packet per RTP packet, no fragmentation.
// ---------------------------------------------------------------------------

/// Opus packetizer: an Opus packet is the RTP payload, unfragmented.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpusPacketizer;

impl Packetizer for OpusPacketizer {
    fn packetize(
        &mut self,
        ctx: &mut VideoPacketizerContext,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<RtpPacket>, PacketizerError> {
        let MediaFrame::Audio(audio) = frame else {
            return Err(PacketizerError::Packetize(
                "OpusPacketizer requires MediaFrame::Audio".into(),
            ));
        };
        if audio.data.len() > mtu {
            return Err(PacketizerError::Packetize(format!(
                "opus packet of {} bytes exceeds MTU {mtu}",
                audio.data.len()
            )));
        }
        let mut pkt = video_packet(ctx, frame, true, audio.data.clone());
        pkt.timestamp = frame.rtp_timestamp(clock::OPUS);
        Ok(vec![pkt])
    }

    fn depacketize(&self, packets: &[RtpPacket]) -> Result<MediaFrame, PacketizerError> {
        let Some(first) = packets.first() else {
            return Err(PacketizerError::Depacketize("no packets".into()));
        };
        let mut data = Vec::new();
        for p in packets {
            data.extend_from_slice(&p.payload);
        }
        Ok(MediaFrame::Audio(crate::media::AudioFrame {
            data,
            timestamp: std::time::Duration::from_secs_f64(
                f64::from(first.timestamp) / f64::from(clock::OPUS),
            ),
        }))
    }
}

// ---------------------------------------------------------------------------
// VP8 (RFC 7741): 1-octet payload descriptor, minimal.
// ---------------------------------------------------------------------------

/// VP8 packetizer (minimal RFC 7741 payload descriptor: S/E/PID, no
/// PictureID).
#[derive(Debug, Clone, Copy, Default)]
pub struct Vp8Packetizer;

impl Packetizer for Vp8Packetizer {
    fn packetize(
        &mut self,
        ctx: &mut VideoPacketizerContext,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<RtpPacket>, PacketizerError> {
        let MediaFrame::Video(_) = frame else {
            return Err(PacketizerError::Packetize(
                "Vp8Packetizer requires MediaFrame::Video".into(),
            ));
        };
        const OVERHEAD: usize = 1; // descriptor octet
        let mut out = Vec::new();
        for (chunk, first, last) in chunk_payload(frame.data(), mtu, OVERHEAD) {
            // X=0 R=0 N=0 S E R PID=0
            let descriptor = u8::from(first) << 4 | u8::from(last) << 3;
            out.push(video_packet(
                ctx,
                frame,
                last,
                std::iter::once(descriptor)
                    .chain(chunk.iter().copied())
                    .collect(),
            ));
        }
        Ok(out)
    }

    fn depacketize(&self, packets: &[RtpPacket]) -> Result<MediaFrame, PacketizerError> {
        let Some(first) = packets.first() else {
            return Err(PacketizerError::Depacketize("no packets".into()));
        };
        let mut data = Vec::new();
        for p in packets {
            if p.payload.is_empty() {
                return Err(PacketizerError::Depacketize("empty VP8 payload".into()));
            }
            let pid = p.payload[0] & 0x07;
            if pid != 0 && !data.is_empty() {
                return Err(PacketizerError::Depacketize(
                    "non-zero PID unsupported".into(),
                ));
            }
            data.extend_from_slice(&p.payload[1..]);
        }
        Ok(MediaFrame::Video(crate::media::VideoFrame {
            keyframe: first.payload.len() > 1 && is_vp8_keyframe(&first.payload[1..]),
            data,
            timestamp: std::time::Duration::from_secs_f64(
                f64::from(first.timestamp) / f64::from(clock::VIDEO),
            ),
            width: 0,
            height: 0,
        }))
    }
}

/// VP8 keyframe detection: the first uncompressed data partition's P-frame
/// bit (bit 4 of the first octet, after the 3-bit common prefix 0b010...).
fn is_vp8_keyframe(payload: &[u8]) -> bool {
    // First partition starts with the frame tag; bit 4 = frame type
    // (0 = key). The tag's top 9 bits carry the size; frame type is bit 4
    // of the first byte only when the sync code follows. We check the
    // practical marker: keyframes embed the 3-byte start code 9d 01 2a at
    // offset 3..6 of the first partition.
    payload.len() >= 6 && payload[3..6] == [0x9D, 0x01, 0x2A]
}

// ---------------------------------------------------------------------------
// VP9 (draft-ietf-payload-rtp-vp9): flexible-mode 1-octet descriptor.
// ---------------------------------------------------------------------------

/// VP9 packetizer (flexible mode, no PictureID: F=1, B/E bits).
#[derive(Debug, Clone, Copy, Default)]
pub struct Vp9Packetizer;

impl Packetizer for Vp9Packetizer {
    fn packetize(
        &mut self,
        ctx: &mut VideoPacketizerContext,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<RtpPacket>, PacketizerError> {
        let MediaFrame::Video(_) = frame else {
            return Err(PacketizerError::Packetize(
                "Vp9Packetizer requires MediaFrame::Video".into(),
            ));
        };
        const OVERHEAD: usize = 1;
        let mut out = Vec::new();
        for (chunk, first, last) in chunk_payload(frame.data(), mtu, OVERHEAD) {
            // I=0 P=0 L=0 F=1 B E V=0 R=0
            let descriptor = 0x10 | u8::from(first) << 3 | u8::from(last) << 2;
            out.push(video_packet(
                ctx,
                frame,
                last,
                std::iter::once(descriptor)
                    .chain(chunk.iter().copied())
                    .collect(),
            ));
        }
        Ok(out)
    }

    fn depacketize(&self, packets: &[RtpPacket]) -> Result<MediaFrame, PacketizerError> {
        let Some(first) = packets.first() else {
            return Err(PacketizerError::Depacketize("no packets".into()));
        };
        let mut data = Vec::new();
        for p in packets {
            if p.payload.is_empty() {
                return Err(PacketizerError::Depacketize("empty VP9 payload".into()));
            }
            let descriptor = p.payload[0];
            if descriptor & 0x10 == 0 {
                return Err(PacketizerError::Depacketize(
                    "non-flexible VP9 unsupported".into(),
                ));
            }
            let mut extra = 1; // the descriptor octet itself
            if descriptor & 0x80 != 0 {
                extra += 1; // I: picture id (1 byte, short form)
            }
            if descriptor & 0x40 != 0 {
                extra += 1; // P: reference indices (compact, 1 byte here)
            }
            if descriptor & 0x20 != 0 {
                extra += 2; // L: layer indices
            }
            data.extend_from_slice(&p.payload[extra..]);
        }
        // VP9 flexible-mode descriptors carry no keyframe flag; the
        // application tracks it via PLI/RPSI instead.
        Ok(MediaFrame::Video(crate::media::VideoFrame {
            keyframe: false,
            data,
            timestamp: std::time::Duration::from_secs_f64(
                f64::from(first.timestamp) / f64::from(clock::VIDEO),
            ),
            width: 0,
            height: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// AV1 (RFC for RTP payload format for AV1): leb128-OBU aggregation.
// ---------------------------------------------------------------------------

/// AV1 packetizer: splits the temporal unit into OBUs (leb128 length
/// prefixed, as libaom/rav1e emit them) and aggregates up to three OBUs
/// per RTP packet; oversized OBUs are fragmented with the Z/Y bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct Av1Packetizer;

/// Reads a leb128 value; returns `(value, bytes_consumed)`.
fn read_leb128(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &b) in data.iter().enumerate().take(8) {
        value |= u64::from(b & 0x7F) << (i * 7);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Writes a leb128 value (minimal length).
fn write_leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Splits a temporal unit into OBUs. Each OBU keeps its 1-byte header as
/// the first byte of `data` (the leb128 length prefix is dropped).
fn split_obus(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        // Layout per OBU: obu_header(1) + obu_size(leb128, header excluded)
        // + obu_body. The parsed OBU keeps header + body only.
        let header = data[i];
        i += 1;
        let Some((size, prefix)) = read_leb128(&data[i..]) else {
            break;
        };
        i += prefix;
        let end = (i + size as usize).min(data.len());
        let mut obu = Vec::with_capacity(1 + (end - i));
        obu.push(header);
        obu.extend_from_slice(&data[i..end]);
        out.push(obu);
        i = end;
    }
    out
}

impl Packetizer for Av1Packetizer {
    fn packetize(
        &mut self,
        ctx: &mut VideoPacketizerContext,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<RtpPacket>, PacketizerError> {
        let MediaFrame::Video(_) = frame else {
            return Err(PacketizerError::Packetize(
                "Av1Packetizer requires MediaFrame::Video".into(),
            ));
        };
        const OVERHEAD: usize = 1; // aggregation header
        let obus = split_obus(frame.data());
        if obus.is_empty() {
            return Err(PacketizerError::Packetize(
                "no OBUs in temporal unit".into(),
            ));
        }

        let mut out = Vec::new();
        let mut consumed = 0usize;
        while consumed < obus.len() {
            let remaining = &obus[consumed..];
            // Aggregate whole OBUs while at most 3 fit (W is 2 bits) and
            // the sizes + payload stay under the MTU.
            let mut count = 0usize;
            let mut payload = Vec::new();
            for obu in remaining.iter().take(3) {
                // Wire size field: obu_size excludes the 1-byte header.
                let size_prefix = write_leb128(obu.len() as u64 - 1);
                if payload.len() + 1 + size_prefix.len() + obu.len() + OVERHEAD > mtu {
                    break;
                }
                payload.extend_from_slice(&size_prefix);
                payload.extend_from_slice(obu);
                count += 1;
            }
            if count == 0 {
                // A single OBU larger than the MTU: fragment it across
                // packets (W=0, Z/Y continuation bits). The leb128 size
                // prefix rides on the first fragment.
                let obu = &remaining[0];
                let with_size = {
                    let mut v = write_leb128(obu.len() as u64 - 1);
                    v.extend_from_slice(obu);
                    v
                };
                for (chunk, first, last) in chunk_payload(&with_size, mtu, OVERHEAD) {
                    let y = !last || remaining.len() > 1;
                    let agg = u8::from(!first) << 2 | u8::from(y) << 1;
                    let marker = last && remaining.len() == 1;
                    out.push(video_packet(
                        ctx,
                        frame,
                        marker,
                        std::iter::once(agg).chain(chunk.iter().copied()).collect(),
                    ));
                }
                consumed += 1;
                continue;
            }
            let is_last = consumed + count == obus.len();
            let w = count - 1; // 0..=2
            let agg_header = (w as u8) << 6; // N=0 Z=0 Y=0
            let mut body = vec![agg_header];
            body.extend_from_slice(&payload);
            out.push(video_packet(ctx, frame, is_last, body));
            consumed += count;
        }
        if let Some(last) = out.last_mut() {
            last.marker = true;
        }
        Ok(out)
    }

    fn depacketize(&self, packets: &[RtpPacket]) -> Result<MediaFrame, PacketizerError> {
        let Some(first) = packets.first() else {
            return Err(PacketizerError::Depacketize("no packets".into()));
        };
        // Rebuild the temporal unit: [obu_header][leb128(body)][body] per
        // OBU. Aggregated entries (W>0) carry size+OBU; fragments (W=0)
        // concatenate into the same size+OBU stream (size prefix rides on
        // the first fragment).
        let mut obus: Vec<Vec<u8>> = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let drain = |pending: &mut Vec<u8>, obus: &mut Vec<Vec<u8>>| {
            while !pending.is_empty() {
                let Some((size, prefix)) = read_leb128(pending) else {
                    break;
                };
                let end = prefix + 1 + size as usize; // size excludes header
                if pending.len() < end {
                    break; // more fragments coming
                }
                obus.push(pending[prefix..end].to_vec());
                pending.drain(..end);
            }
        };
        for p in packets {
            if p.payload.is_empty() {
                return Err(PacketizerError::Depacketize("empty AV1 payload".into()));
            }
            let agg = p.payload[0];
            let w = usize::from(agg >> 6);
            if w == 0 {
                pending.extend_from_slice(&p.payload[1..]);
                drain(&mut pending, &mut obus);
                continue;
            }
            let mut j = 1;
            for _ in 0..w + 1 {
                let Some((size, prefix)) = read_leb128(&p.payload[j..]) else {
                    return Err(PacketizerError::Depacketize("bad leb128".into()));
                };
                let end = j + prefix + 1 + size as usize;
                if end > p.payload.len() {
                    return Err(PacketizerError::Depacketize("OBU overruns payload".into()));
                }
                obus.push(p.payload[j + prefix..end].to_vec());
                j = end;
            }
        }
        if !pending.is_empty() {
            return Err(PacketizerError::Depacketize(
                "truncated OBU fragments".into(),
            ));
        }
        let mut tu = Vec::new();
        for obu in &obus {
            let header = obu[0];
            let body = &obu[1..];
            tu.push(header);
            tu.extend_from_slice(&write_leb128(body.len() as u64));
            tu.extend_from_slice(body);
        }
        Ok(MediaFrame::Video(crate::media::VideoFrame {
            keyframe: first.marker,
            data: tu,
            timestamp: std::time::Duration::from_secs_f64(
                f64::from(first.timestamp) / f64::from(clock::VIDEO),
            ),
            width: 0,
            height: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ctx() -> VideoPacketizerContext {
        VideoPacketizerContext {
            sequence_number: 100,
            ssrc: 42,
            payload_type: 96,
        }
    }

    fn video_frame(len: usize, key: bool) -> MediaFrame {
        MediaFrame::Video(crate::media::VideoFrame {
            data: (0..len).map(|i| (i % 251) as u8).collect(),
            timestamp: Duration::from_millis(33),
            keyframe: key,
            width: 1280,
            height: 720,
        })
    }

    fn audio_frame(len: usize) -> MediaFrame {
        MediaFrame::Audio(crate::media::AudioFrame {
            data: vec![7u8; len],
            timestamp: Duration::from_millis(20),
        })
    }

    #[test]
    fn opus_single_packet() {
        let mut p = OpusPacketizer;
        let mut c = ctx();
        let out = p.packetize(&mut c, &audio_frame(120), 1200).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].marker);
        assert_eq!(out[0].timestamp(), 960); // 20ms at 48kHz
        let back = p.depacketize(&out).unwrap();
        assert_eq!(back.data(), &[7u8; 120]);
    }

    #[test]
    fn opus_rejects_oversize() {
        let mut p = OpusPacketizer;
        let mut c = ctx();
        assert!(p.packetize(&mut c, &audio_frame(2000), 1200).is_err());
    }

    #[test]
    fn vp8_fragmentation_reassembly() {
        let mut p = Vp8Packetizer;
        let mut c = ctx();
        let frame = video_frame(5000, true);
        let out = p.packetize(&mut c, &frame, 1200).unwrap();
        assert!(out.len() >= 5, "must fragment across packets");
        assert!(!out[0].marker);
        assert!(out.last().unwrap().marker);
        // S bit set on the first packet only.
        assert!(out[0].payload[0] & 0x10 != 0);
        assert!(out[1].payload[0] & 0x10 == 0);
        let back = p.depacketize(&out).unwrap();
        assert_eq!(back.data(), frame.data());
        assert_eq!(c.sequence_number, 100 + out.len() as u16);
    }

    #[test]
    fn vp9_flexible_reassembly() {
        let mut p = Vp9Packetizer;
        let mut c = ctx();
        let frame = video_frame(3000, false);
        let out = p.packetize(&mut c, &frame, 1200).unwrap();
        assert!(out.len() >= 3);
        // F=1 flexible bit on every packet.
        assert!(out.iter().all(|p| p.payload[0] & 0x10 != 0));
        let back = p.depacketize(&out).unwrap();
        assert_eq!(back.data(), frame.data());
    }

    #[test]
    fn av1_whole_obus_roundtrip() {
        let mut p = Av1Packetizer;
        let mut c = ctx();
        // Build a temporal unit of 4 OBUs (header + leb128 size + body).
        let mut tu = Vec::new();
        for i in 0..4u8 {
            tu.push(0x08 | i); // OBU header (sequence header etc.)
            let body_len = 100u64;
            tu.extend_from_slice(&write_leb128(body_len));
            tu.extend(std::iter::repeat_n(i, body_len as usize));
        }
        let frame = MediaFrame::Video(crate::media::VideoFrame {
            data: tu.clone(),
            timestamp: Duration::from_millis(33),
            keyframe: true,
            width: 0,
            height: 0,
        });
        let out = p.packetize(&mut c, &frame, 1200).unwrap();
        // 4 OBUs of ~101 bytes each: packets carry up to 3 OBUs each.
        assert_eq!(out.len(), 2);
        assert!(out.last().unwrap().marker);
        let back = p.depacketize(&out).unwrap();
        assert_eq!(back.data(), &tu, "temporal unit must round-trip");
    }

    #[test]
    fn av1_fragmented_large_obu_roundtrip() {
        let mut p = Av1Packetizer;
        let mut c = ctx();
        // One OBU far larger than the MTU.
        let mut tu = vec![0x0A];
        tu.extend_from_slice(&write_leb128(4000 - 1));
        tu.extend(vec![5u8; 4000 - 1]);
        let frame = MediaFrame::Video(crate::media::VideoFrame {
            data: tu.clone(),
            timestamp: Duration::from_millis(33),
            keyframe: true,
            width: 0,
            height: 0,
        });
        let out = p.packetize(&mut c, &frame, 1200).unwrap();
        assert!(out.len() >= 4);
        for p in out.iter().take(out.len() - 1) {
            assert!(!p.marker);
        }
        assert!(out.last().unwrap().marker);
        let back = p.depacketize(&out).unwrap();
        assert_eq!(back.data(), &tu);
    }

    #[test]
    fn leb128_helpers() {
        assert_eq!(read_leb128(&[0x7F]), Some((127, 1)));
        assert_eq!(read_leb128(&[0xFF, 0x7F]), Some((0x3FFF, 2)));
        assert_eq!(write_leb128(127), vec![0x7F]);
        assert_eq!(write_leb128(0x3FFF), vec![0xFF, 0x7F]);
    }

    #[test]
    fn wrong_media_kind_rejected() {
        let mut p = Vp8Packetizer;
        let mut c = ctx();
        assert!(p.packetize(&mut c, &audio_frame(10), 1200).is_err());
    }
}
