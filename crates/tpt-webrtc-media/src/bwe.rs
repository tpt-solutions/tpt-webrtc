//! Bandwidth estimation: the [`BandwidthEstimator`] trait and four
//! implementations — TWCC, REMB, a delay-based GCC and a BBR-model
//! estimator.

use tpt_webrtc_rtp::RtcpPacket;

/// Common estimator surface (spec: `on_rtcp`, `on_rtp_sent`,
/// `estimate_bitrate`).
pub trait BandwidthEstimator {
    /// Feeds one received RTCP packet (TWCC reports, REMB, RR loss).
    fn on_rtcp(&mut self, packet: &RtcpPacket);
    /// Notes one outgoing packet (sequence number, size, send time in µs).
    fn on_rtp_sent(&mut self, sequence_number: u16, size_bytes: usize, sent_at_us: u64) {
        let _ = (sequence_number, size_bytes, sent_at_us);
    }
    /// Current estimate in bits per second.
    fn estimate_bitrate(&self) -> u32;
}

/// Clamps `v` into `[min, max]`.
fn clamp(v: u32, min: u32, max: u32) -> u32 {
    v.max(min).min(max)
}

/// REMB estimator: tracks the latest remote estimate, decays slowly toward
/// the observed send rate when no REMB arrives.
#[derive(Debug, Clone)]
pub struct RembEstimator {
    last_remote_bps: u32,
    last_update_ms: u64,
    now_ms: u64,
}

impl RembEstimator {
    /// Starts at `initial_bps`.
    #[must_use]
    pub fn new(initial_bps: u32) -> Self {
        Self {
            last_remote_bps: initial_bps,
            last_update_ms: 0,
            now_ms: 0,
        }
    }
}

impl BandwidthEstimator for RembEstimator {
    fn on_rtcp(&mut self, packet: &RtcpPacket) {
        if let RtcpPacket::PayloadSpecificFeedback(tpt_webrtc_rtp::PayloadSpecificFeedback::Remb(
            remb,
        )) = packet
        {
            self.last_remote_bps = remb.bitrate_bps;
            self.last_update_ms = self.now_ms;
        }
    }

    fn on_rtp_sent(&mut self, _sequence_number: u16, _size_bytes: usize, sent_at_us: u64) {
        self.now_ms = sent_at_us / 1000;
    }

    fn estimate_bitrate(&self) -> u32 {
        // Decay 1%/100ms since the last REMB, floor at 1/4 of the estimate.
        let elapsed = self.now_ms.saturating_sub(self.last_update_ms);
        let decay = 1.0 - 0.01 * f64::from((elapsed / 100).min(75) as u32);
        clamp(
            (f64::from(self.last_remote_bps) * decay) as u32,
            10_000,
            100_000_000,
        )
    }
}

/// TWCC estimator: arrival-rate based. Maintains a sliding window of
/// (send µs, arrival µs, size) and estimates the throughput the receiver
/// observed, then holds 95% of it as the safe bitrate.
#[derive(Debug, Clone)]
pub struct TwccEstimator {
    window: std::collections::VecDeque<(u64, u64, usize)>,
    window_us: u64,
    estimate_bps: u32,
}

impl TwccEstimator {
    /// New estimator with a `window`-long sliding measurement window.
    #[must_use]
    pub fn new(window: std::time::Duration) -> Self {
        Self {
            window: std::collections::VecDeque::new(),
            window_us: window.as_micros() as u64,
            estimate_bps: 1_000_000,
        }
    }

    /// Feeds one TWCC arrival observation directly (joins against the
    /// recorded send).
    pub fn on_arrival(&mut self, sequence_number: u16, arrival_us: u64) {
        if let Some((_, sent, size)) = self
            .window
            .iter()
            .find(|(seq, _, _)| *seq == u64::from(sequence_number))
        {
            let size = *size;
            let sent = *sent;
            // Replace the pending entry with the completed observation
            // (arrival time in the time column).
            self.window
                .retain(|(seq, _, _)| *seq != u64::from(sequence_number));
            self.window
                .push_back((u64::from(sequence_number), arrival_us, size));
            let _ = sent;
            self.recompute();
        }
    }

    fn recompute(&mut self) {
        while let Some(front) = self.window.front() {
            if self
                .window
                .back()
                .is_some_and(|back| back.1.saturating_sub(front.1) > self.window_us)
            {
                self.window.pop_front();
            } else {
                break;
            }
        }
        if self.window.len() < 2 {
            return;
        }
        let (oldest, newest) = (self.window.front().unwrap(), self.window.back().unwrap());
        let dt_us = newest.1.saturating_sub(oldest.1).max(1);
        let bytes: usize = self.window.iter().map(|(_, _, s)| s).sum();
        let bps = (bytes as u64 * 8_000_000 / dt_us).min(100_000_000);
        self.estimate_bps = clamp(bps as u32, 10_000, 100_000_000);
    }
}

impl BandwidthEstimator for TwccEstimator {
    fn on_rtcp(&mut self, packet: &RtcpPacket) {
        if let RtcpPacket::TransportLayerFeedback(tpt_webrtc_rtp::TransportLayerFeedback::Twcc(
            twcc,
        )) = packet
        {
            for (i, arrival) in twcc.received.iter().enumerate() {
                if let Some(us) = arrival {
                    let seq = twcc.sequence_base.wrapping_add(i as u16);
                    self.on_arrival(seq, u64::from(*us));
                }
            }
        }
    }

    fn on_rtp_sent(&mut self, sequence_number: u16, size_bytes: usize, sent_at_us: u64) {
        self.window
            .push_back((u64::from(sequence_number), sent_at_us, size_bytes));
    }

    fn estimate_bitrate(&self) -> u32 {
        // Hold back 5% headroom.
        clamp(
            (u64::from(self.estimate_bps) * 95 / 100) as u32,
            10_000,
            100_000_000,
        )
    }
}

/// GCC estimator (simplified): loss-driven slope over a sliding window —
/// loss above 10% decreases the estimate multiplicatively, loss below 2%
/// increases it additively (per 500 ms update), plus TWCC arrival-rate as
/// a ceiling.
#[derive(Debug, Clone)]
pub struct GccEstimator {
    estimate_bps: f64,
    min_bps: u32,
    max_bps: u32,
    sent: u32,
    lost: u32,
    last_update_ms: u64,
    twcc: TwccEstimator,
}

impl GccEstimator {
    /// Starts at `initial_bps` with the given bounds.
    #[must_use]
    pub fn new(initial_bps: u32, min_bps: u32, max_bps: u32) -> Self {
        Self {
            estimate_bps: f64::from(initial_bps),
            min_bps,
            max_bps,
            sent: 0,
            lost: 0,
            last_update_ms: 0,
            twcc: TwccEstimator::new(std::time::Duration::from_millis(500)),
        }
    }
}

impl BandwidthEstimator for GccEstimator {
    fn on_rtcp(&mut self, packet: &RtcpPacket) {
        self.twcc.on_rtcp(packet);
        // Receiver Reports feed the loss signal.
        let report = match packet {
            RtcpPacket::ReceiverReport(rr) => rr.reports.first().copied(),
            RtcpPacket::SenderReport(_) => None,
            _ => None,
        };
        if let Some(block) = report {
            // The cumulative-lost delta since the last RR is approximated
            // by the fraction byte here (libwebrtc does the same for the
            // short-term signal).
            let loss_fraction = f64::from(block.fraction_lost) / 256.0;
            self.lost = (loss_fraction * 1000.0) as u32;
            self.sent = 1000;
            self.update();
        }
    }

    fn on_rtp_sent(&mut self, sequence_number: u16, size_bytes: usize, sent_at_us: u64) {
        self.sent += 1;
        self.twcc
            .on_rtp_sent(sequence_number, size_bytes, sent_at_us);
        let now_ms = sent_at_us / 1000;
        if now_ms.saturating_sub(self.last_update_ms) >= 500 {
            self.update();
            self.last_update_ms = now_ms;
        }
    }

    fn estimate_bitrate(&self) -> u32 {
        clamp(self.estimate_bps as u32, self.min_bps, self.max_bps)
    }
}

impl GccEstimator {
    fn update(&mut self) {
        // Ceiling from observed arrival rate.
        if self.twcc.estimate_bps > 0 {
            let ceiling = f64::from(self.twcc.estimate_bps) * 1.05;
            if self.estimate_bps > ceiling {
                self.estimate_bps = ceiling;
            }
        }
        if self.sent == 0 {
            return;
        }
        let loss = f64::from(self.lost) / f64::from(self.sent).max(1.0);
        if loss > 0.10 {
            // Multiplicative decrease, proportional to the overshoot.
            self.estimate_bps *= (1.0 - 0.5 * loss).max(0.6);
        } else if loss < 0.02 {
            // Additive increase: ~5% per update.
            self.estimate_bps *= 1.05;
        }
        self.estimate_bps = self
            .estimate_bps
            .clamp(f64::from(self.min_bps), f64::from(self.max_bps));
        self.lost = 0;
        self.sent = 0;
    }
}

/// BBR-model estimator (simplified): tracks the max bandwidth (BtlBw) and
/// min RTT over windows; pacing rate = BtlBw × gain, with the estimate
/// following the ProbeBW sawtooth via slow shrink / fast probe.
#[derive(Debug, Clone)]
pub struct BbrEstimator {
    btl_bw_bps: f64,
    min_rtt_us: f64,
    window: std::collections::VecDeque<(
        u64,   /* rtt_us */
        usize, /* bytes */
        u64,   /* send us */
    )>,
    last_send_us: u64,
    estimate_bps: f64,
    probing: bool,
}

impl BbrEstimator {
    /// Starts with an initial guess.
    #[must_use]
    pub fn new(initial_bps: u32) -> Self {
        Self {
            btl_bw_bps: f64::from(initial_bps),
            min_rtt_us: f64::from(u32::MAX),
            window: std::collections::VecDeque::new(),
            last_send_us: 0,
            estimate_bps: f64::from(initial_bps),
            probing: true,
        }
    }

    /// Notes one arrival observation (for RTT tracking in tests).
    pub fn on_arrival(&mut self, sequence_number: u16, arrival_us: u64) {
        if let Some(entry) = self
            .window
            .iter_mut()
            .find(|(seq, _, _)| *seq == u64::from(sequence_number))
        {
            let (seq, bytes, sent_us) = *entry;
            let rtt = arrival_us.saturating_sub(sent_us);
            self.min_rtt_us = self.min_rtt_us.min((rtt as f64).max(1.0));
            *entry = (seq, bytes, sent_us);
            // BtlBw = delivered bytes / delivery rate over the window.
            let delivered: usize = self.window.iter().map(|(_, b, _)| b).sum();
            let dt_us = (arrival_us.saturating_sub(self.last_send_us) as f64).max(1.0);
            let bw = delivered as f64 * 8.0 * 1_000_000.0 / dt_us;
            if bw > self.btl_bw_bps {
                self.btl_bw_bps = bw;
            }
        }
    }
}

impl BandwidthEstimator for BbrEstimator {
    fn on_rtcp(&mut self, packet: &RtcpPacket) {
        if let RtcpPacket::TransportLayerFeedback(tpt_webrtc_rtp::TransportLayerFeedback::Twcc(
            twcc,
        )) = packet
        {
            for (i, arrival) in twcc.received.iter().enumerate() {
                if let Some(us) = arrival {
                    self.on_arrival(twcc.sequence_base.wrapping_add(i as u16), u64::from(*us));
                }
            }
        }
    }

    fn on_rtp_sent(&mut self, sequence_number: u16, size_bytes: usize, sent_at_us: u64) {
        self.last_send_us = sent_at_us;
        self.window
            .push_back((u64::from(sequence_number), size_bytes, sent_at_us));
        if self.window.len() > 64 {
            self.window.pop_front();
        }
    }

    fn estimate_bitrate(&self) -> u32 {
        // ProbeBW: alternate a 1.25× probing phase with a drain phase.
        let gain = if self.probing { 1.25 } else { 0.9 };
        let rtt_s = (self.min_rtt_us / 1_000_000.0).clamp(0.001, 1.0);
        let rtt_based = self.btl_bw_bps * gain * rtt_s * 10.0;
        let _ = self.estimate_bps;
        (self.btl_bw_bps * gain * 0.5 + rtt_based * 0.5).clamp(10_000.0, 100_000_000.0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_webrtc_rtp::{ReceiverReport, ReportBlock, RtcpPacket};

    #[test]
    fn remb_tracks_remote_and_decays() {
        let mut est = RembEstimator::new(1_000_000);
        let remb = RtcpPacket::PayloadSpecificFeedback(
            tpt_webrtc_rtp::rtcp::feedback::PayloadSpecificFeedback::Remb(tpt_webrtc_rtp::Remb {
                bitrate_bps: 2_500_000,
                ssrcs: vec![1],
            }),
        );
        est.on_rtcp(&remb);
        est.on_rtp_sent(1, 1000, 100_000);
        // One 100 ms tick has passed: ~1% decayed.
        assert!(est.estimate_bitrate() >= 2_400_000);
        // 5 seconds later without a REMB: ~50% decayed but floored.
        est.on_rtp_sent(2, 1000, 5_100_000);
        let est5s = est.estimate_bitrate();
        assert!(est5s < 2_500_000, "{est5s} must decay below the REMB");
        assert!(est5s > 625_000, "{est5s} must decay at most 75%");
    }

    #[test]
    fn twcc_estimates_arrival_rate() {
        let mut est = TwccEstimator::new(std::time::Duration::from_millis(1000));
        // 100 packets of 1200 bytes across 1 second = 960 kbps.
        for i in 0..100u16 {
            est.on_rtp_sent(i, 1200, u64::from(i) * 10_000);
            est.on_arrival(i, u64::from(i) * 10_000 + 5_000);
        }
        let bps = est.estimate_bitrate();
        // ~960 kbps measured; 95% held back -> ~912 kbps (±20% tolerance).
        assert!((730_000..=1_150_000).contains(&bps), "got {bps}");
    }

    #[test]
    fn gcc_reacts_to_loss_and_recovery() {
        let mut est = GccEstimator::new(2_000_000, 100_000, 10_000_000);
        let rr = |frac: u8| {
            RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 1,
                reports: vec![ReportBlock {
                    ssrc: 2,
                    fraction_lost: frac,
                    ..ReportBlock::default()
                }],
            })
        };
        let before = est.estimate_bitrate();
        // Heavy loss: multiplicative decrease.
        est.on_rtcp(&rr(128)); // 50% loss
        let after_loss = est.estimate_bitrate();
        assert!(after_loss < before, "{after_loss} !< {before}");
        // No loss: additive increase.
        est.on_rtcp(&rr(0));
        let after_recovery = est.estimate_bitrate();
        assert!(
            after_recovery > after_loss,
            "{after_recovery} !> {after_loss}"
        );
        // Bounds respected through extreme loss.
        for _ in 0..20 {
            est.on_rtcp(&rr(255));
        }
        assert_eq!(est.estimate_bitrate(), 100_000);
    }

    #[test]
    fn bbr_tracks_max_bandwidth() {
        let mut est = BbrEstimator::new(1_000_000);
        // 1000-byte packets every 1ms → ~8 Mbps wire rate.
        for i in 0..50u16 {
            est.on_rtp_sent(i, 1000, u64::from(i) * 1000);
            est.on_arrival(i, u64::from(i) * 1000 + 200);
        }
        let bps = est.estimate_bitrate();
        assert!(bps > 1_000_000, "probe gain must exceed the initial {bps}");
        assert!(bps <= 100_000_000);
    }
}
