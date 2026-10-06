//! Network adaptation: couples a [`BandwidthEstimator`] to encoder bitrate
//! control (`set_bitrate`), the Phase 5 congestion-response loop.

use crate::bwe::BandwidthEstimator;

/// Applies a computed target bitrate to an encoder.
pub trait BitrateControl {
    /// Sets the encoder's target bitrate.
    ///
    /// # Errors
    /// Implementation-defined (e.g. reconfiguration failure).
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), String>;
}

/// Couples bandwidth estimation to bitrate control: feed it RTCP feedback
/// and send-time observations, and it pushes `set_bitrate` updates to the
/// attached encoder whenever the target moves by more than the hysteresis
/// threshold (default 10%).
#[derive(Debug)]
pub struct CongestionController<E: BandwidthEstimator> {
    estimator: E,
    min_bps: u32,
    max_bps: u32,
    /// Relative change required before a `set_bitrate` call is issued.
    hysteresis: f64,
    last_applied: u32,
}

impl<E: BandwidthEstimator> CongestionController<E> {
    /// Wraps `estimator` with bitrate bounds and hysteresis.
    #[must_use]
    pub fn new(estimator: E, min_bps: u32, max_bps: u32, hysteresis: f64) -> Self {
        Self {
            estimator,
            min_bps,
            max_bps,
            hysteresis: hysteresis.clamp(0.01, 0.9),
            last_applied: min_bps,
        }
    }

    /// Access the inner estimator (for direct feedback injection).
    #[must_use]
    pub fn estimator_mut(&mut self) -> &mut E {
        &mut self.estimator
    }

    /// Recomputes the estimate and, if it moved beyond the hysteresis
    /// band, pushes `set_bitrate` to the control target.
    ///
    /// Returns the bitrate currently applied.
    pub fn on_tick<C: BitrateControl>(&mut self, control: &mut C) -> u32 {
        let target = self
            .estimator
            .estimate_bitrate()
            .clamp(self.min_bps, self.max_bps);
        let delta = (target as f64 - f64::from(self.last_applied)).abs()
            / f64::from(self.last_applied).max(1.0);
        if delta >= self.hysteresis {
            let _ = control.set_bitrate(target);
            self.last_applied = target;
        }
        self.last_applied
    }

    /// Last bitrate pushed to the encoder.
    #[must_use]
    pub fn applied_bitrate(&self) -> u32 {
        self.last_applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bwe::{BandwidthEstimator, RembEstimator};
    use std::cell::Cell;

    struct RecordingControl {
        last: Cell<u32>,
    }

    impl BitrateControl for RecordingControl {
        fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), String> {
            self.last.set(bitrate_bps);
            Ok(())
        }
    }

    #[test]
    fn congestion_loop_applies_and_holds() {
        let est = RembEstimator::new(1_000_000);
        let mut cc = CongestionController::new(est, 100_000, 10_000_000, 0.10);
        let mut ctrl = RecordingControl { last: Cell::new(0) };

        // First tick: last_applied starts at min → 1 Mbps is a 10x jump.
        let applied = cc.on_tick(&mut ctrl);
        assert_eq!(applied, 1_000_000);
        assert_eq!(ctrl.last.get(), 1_000_000);

        // Small movement within hysteresis: no new set_bitrate.
        let same = cc.on_tick(&mut ctrl);
        assert_eq!(same, 1_000_000);
        assert_eq!(ctrl.last.get(), 1_000_000);
    }

    #[test]
    fn estimator_feedback_drives_control() {
        let est = RembEstimator::new(1_000_000);
        let mut cc = CongestionController::new(est, 100_000, 10_000_000, 0.10);
        let mut ctrl = RecordingControl { last: Cell::new(0) };
        cc.on_tick(&mut ctrl);

        // Remote reports 3 Mbps.
        let remb = tpt_webrtc_rtp::RtcpPacket::PayloadSpecificFeedback(
            tpt_webrtc_rtp::PayloadSpecificFeedback::Remb(tpt_webrtc_rtp::Remb {
                bitrate_bps: 3_000_000,
                ssrcs: vec![1],
            }),
        );
        cc.estimator_mut().on_rtcp(&remb);
        let applied = cc.on_tick(&mut ctrl);
        assert_eq!(applied, 3_000_000);
        assert_eq!(ctrl.last.get(), 3_000_000);
    }
}
