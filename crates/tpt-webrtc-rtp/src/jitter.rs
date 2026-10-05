//! Jitter buffer: reorders RTP packets per (SSRC, sequence number) and
//! releases contiguous frames (up to the marker bit).

use std::collections::BTreeMap;
use std::time::Duration;

use crate::RtpPacket;

/// Reorder/decode buffer for one or more RTP streams.
#[derive(Debug, Default)]
pub struct JitterBuffer {
    packets: BTreeMap<(u32, u16), RtpPacket>,
    target_delay: Duration,
    max_delay: Duration,
}

impl JitterBuffer {
    /// New buffer with the given playout delays (informational for this
    /// reorder-only implementation).
    #[must_use]
    pub fn new(target_delay: Duration, max_delay: Duration) -> Self {
        Self {
            packets: BTreeMap::new(),
            target_delay,
            max_delay,
        }
    }

    /// Configured target delay.
    #[must_use]
    pub fn target_delay(&self) -> Duration {
        self.target_delay
    }

    /// Configured maximum delay.
    #[must_use]
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Inserts a packet (reorder by (SSRC, seq)); duplicates are dropped.
    pub fn insert(&mut self, packet: RtpPacket) {
        self.packets
            .entry((packet.ssrc, packet.sequence_number))
            .or_insert(packet);
    }

    /// Pops the next complete frame for `ssrc`: the contiguous run of
    /// packets from the oldest buffered sequence number through the packet
    /// with the marker bit (or through the buffer if no marker arrived).
    #[must_use]
    pub fn get_frame(&mut self, ssrc: u32) -> Option<Vec<RtpPacket>> {
        let first = self.packets.keys().find(|(s, _)| *s == ssrc).copied()?;
        let mut frame = Vec::new();
        let mut seq = first.1;
        while let Some(p) = self.packets.remove(&(ssrc, seq)) {
            let marker = p.marker;
            frame.push(p);
            if marker {
                break;
            }
            seq = seq.wrapping_add(1);
        }
        Some(frame)
    }

    /// Number of buffered packets (all streams).
    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether the buffer holds no packets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Drops every buffered packet.
    pub fn flush(&mut self) {
        self.packets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(ssrc: u32, seq: u16, marker: bool) -> RtpPacket {
        RtpPacket {
            ssrc,
            sequence_number: seq,
            marker,
            payload: vec![seq as u8],
            ..RtpPacket::default()
        }
    }

    #[test]
    fn reorders_out_of_order_arrivals() {
        let mut jb = JitterBuffer::new(Duration::from_millis(60), Duration::from_millis(200));
        jb.insert(packet(1, 3, true));
        jb.insert(packet(1, 1, false));
        jb.insert(packet(1, 2, false));
        assert_eq!(jb.len(), 3);
        let frame = jb.get_frame(1).unwrap();
        assert_eq!(frame.len(), 3);
        assert_eq!(frame[0].sequence_number, 1);
        assert!(frame[2].marker);
        assert!(jb.is_empty());
    }

    #[test]
    fn waits_for_missing_packet() {
        let mut jb = JitterBuffer::new(Duration::from_millis(60), Duration::from_millis(200));
        jb.insert(packet(1, 1, false));
        jb.insert(packet(1, 3, true));
        // 1 alone is contiguous but has no marker -> still released as a
        // partial frame (buffer drained), 3 waits for 2.
        let frame = jb.get_frame(1).unwrap();
        assert_eq!(frame.len(), 1);
        assert_eq!(jb.len(), 1);
        jb.insert(packet(1, 2, false));
        let frame = jb.get_frame(1).unwrap();
        assert_eq!(frame.len(), 2);
        assert!(frame[1].marker);
    }

    #[test]
    fn drops_duplicates_and_separates_ssrcs() {
        let mut jb = JitterBuffer::new(Duration::from_millis(60), Duration::from_millis(200));
        jb.insert(packet(1, 1, true));
        jb.insert(packet(1, 1, true));
        jb.insert(packet(2, 1, true));
        assert_eq!(jb.len(), 2);
        assert!(jb.get_frame(2).is_some());
        assert_eq!(jb.len(), 1);
        jb.flush();
        assert!(jb.is_empty());
    }

    #[test]
    fn empty_stream_is_none() {
        let mut jb = JitterBuffer::new(Duration::from_millis(60), Duration::from_millis(200));
        assert!(jb.get_frame(99).is_none());
    }
}
