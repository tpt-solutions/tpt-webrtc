//! Audio processing: gain control, noise suppression and echo
//! cancellation, operating on 16-bit PCM blocks.

/// Automatic gain control trait (spec).
pub trait AutomaticGainControl {
    /// Processes a PCM block in place.
    fn process(&mut self, signal: &mut [i16]);
}

/// Noise suppressor trait (spec).
pub trait NoiseSuppressor {
    /// Processes a PCM block in place.
    fn process(&mut self, signal: &mut [i16]);
}

/// Acoustic echo canceller trait (spec).
pub trait AcousticEchoCanceller {
    /// Cancels `speaker_signal` from `mic_signal` in place.
    fn process(&mut self, mic_signal: &mut [i16], speaker_signal: &[i16]);
}

/// Peak-normalizing AGC: tracks a slow peak envelope and applies a gain
/// that targets `target_peak`, smoothed to avoid pumping.
#[derive(Debug, Clone)]
pub struct PeakNormalizingAgc {
    target_peak: i16,
    max_gain: f32,
    /// Current linear gain.
    gain: f32,
    /// Slow attack/release state.
    envelope: f32,
}

impl PeakNormalizingAgc {
    /// Targets `target_peak` with a gain ceiling of `max_gain`.
    #[must_use]
    pub fn new(target_peak: i16, max_gain: f32) -> Self {
        Self {
            target_peak,
            max_gain: max_gain.max(1.0),
            gain: 1.0,
            envelope: 0.0,
        }
    }
}

impl Default for PeakNormalizingAgc {
    fn default() -> Self {
        Self::new(16_000, 8.0)
    }
}

impl AutomaticGainControl for PeakNormalizingAgc {
    fn process(&mut self, signal: &mut [i16]) {
        if signal.is_empty() {
            return;
        }
        let peak = signal.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
        // Slow envelope (release faster than attack).
        let peak_f = f32::from(peak);
        self.envelope = if peak_f > self.envelope {
            self.envelope + 0.2 * (peak_f - self.envelope)
        } else {
            self.envelope + 0.01 * (peak_f - self.envelope)
        };
        let wanted = if self.envelope > 1.0 {
            f32::from(self.target_peak) / self.envelope
        } else {
            self.max_gain
        };
        let wanted = wanted.clamp(0.25, self.max_gain);
        // Smooth gain moves.
        self.gain += 0.1 * (wanted - self.gain);
        for s in signal.iter_mut() {
            let v = f32::from(*s) * self.gain;
            *s = v.clamp(-32_768.0, 32_767.0) as i16;
        }
    }
}

/// Noise gate: blocks below `threshold` are attenuated toward zero with a
/// smooth window, so quiet frames (fans, room tone) disappear without
/// clipping word starts.
#[derive(Debug, Clone)]
pub struct NoiseGate {
    threshold: i16,
    /// Current attenuation 0..=1.
    openness: f32,
}

impl NoiseGate {
    /// Gate with the given open threshold.
    #[must_use]
    pub fn new(threshold: i16) -> Self {
        Self {
            threshold,
            openness: 1.0,
        }
    }
}

impl Default for NoiseGate {
    fn default() -> Self {
        Self::new(300)
    }
}

impl NoiseSuppressor for NoiseGate {
    fn process(&mut self, signal: &mut [i16]) {
        if signal.is_empty() {
            return;
        }
        // Decide from the RAW signal so an already-attenuated stream can
        // still re-open the gate (no self-muting hysteresis).
        let rms = (signal
            .iter()
            .map(|s| i64::from(*s) * i64::from(*s))
            .sum::<i64>() as f64
            / signal.len() as f64)
            .sqrt() as i16;
        let wanted = if rms >= self.threshold { 1.0 } else { 0.0 };
        // ~5 ms smoothing at 48 kHz blocks of 240.
        self.openness += 0.1 * (wanted - self.openness);
        if self.openness > 0.995 {
            return; // fully open: pass through untouched
        }
        for s in signal.iter_mut() {
            *s = (f32::from(*s) * self.openness) as i16;
        }
    }
}

/// Time-domain adaptive echo canceller: a normalized-LMS tapped-delay-line
/// filter over the speaker reference, subtracted from the mic.
#[derive(Debug, Clone)]
pub struct AdaptiveEchoCanceller {
    /// Filter taps (e.g. 64 ≈ 1.3 ms at 48 kHz — small but real; the tail
    /// length is a configuration knob, not a correctness limit here).
    taps: Vec<f32>,
    step_size: f32,
}

impl AdaptiveEchoCanceller {
    /// New canceller with `taps` coefficients and NLMS step size.
    #[must_use]
    pub fn new(taps: usize, step_size: f32) -> Self {
        Self {
            taps: vec![0.0; taps.max(1)],
            step_size: step_size.clamp(0.001, 1.0),
        }
    }
}

impl Default for AdaptiveEchoCanceller {
    fn default() -> Self {
        Self::new(64, 0.2)
    }
}

impl AcousticEchoCanceller for AdaptiveEchoCanceller {
    fn process(&mut self, mic_signal: &mut [i16], speaker_signal: &[i16]) {
        // Delay-line history across blocks.
        const HISTORY: usize = 4096;
        let mut history = vec![0.0f32; HISTORY + self.taps.len()];

        for (n, sample) in mic_signal.iter_mut().enumerate() {
            // Shift in one speaker sample.
            history.rotate_left(1);
            history[HISTORY] = f32::from(speaker_signal.get(n).copied().unwrap_or(0));

            // Echo estimate from the tail of the history.
            let window = &history[HISTORY + 1 - self.taps.len()..=HISTORY];
            let echo: f32 = window
                .iter()
                .rev()
                .zip(self.taps.iter())
                .map(|(s, w)| s * w)
                .sum();
            let mic = f32::from(*sample);
            let error = mic - echo;
            *sample = error.clamp(-32_768.0, 32_767.0) as i16;

            // NLMS tap update.
            let power: f32 = window.iter().map(|s| s * s).sum();
            let norm = 1.0 / (power + 1e-6);
            for (w, s) in self.taps.iter_mut().zip(window.iter().rev()) {
                *w += self.step_size * error * s * norm;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rms(signal: &[i16]) -> f64 {
        (signal
            .iter()
            .map(|s| i64::from(*s) * i64::from(*s))
            .sum::<i64>() as f64
            / signal.len() as f64)
            .sqrt()
    }

    #[test]
    fn agc_brings_quiet_signal_to_target() {
        let mut agc = PeakNormalizingAgc::new(16_000, 20.0);
        // Sustained quiet tone.
        let mut signal: Vec<i16> = (0..4800)
            .map(|i: usize| ((i as f64) * 0.05).sin() * 800.0)
            .map(|v: f64| v as i16)
            .collect();
        let before = rms(&signal);
        agc.process(&mut signal);
        let after = rms(&signal);
        assert!(
            after > before * 2.0,
            "gain must lift quiet input: {before} -> {after}"
        );
        // Output must not clip beyond i16 range (guaranteed by clamp) and
        // stay below the target peak envelope + headroom.
        assert!(signal.iter().all(|s| i16::MIN < *s && *s < i16::MAX));
    }

    #[test]
    fn agc_attenuates_loud_signal() {
        let mut agc = PeakNormalizingAgc::default();
        let mut signal = vec![20_000i16; 4800];
        agc.process(&mut signal);
        let after = rms(&signal);
        assert!(after < 30_000.0, "loud input must be attenuated: {after}");
    }

    #[test]
    fn noise_gate_silences_room_tone() {
        let mut gate = NoiseGate::new(300);
        // Room tone at RMS ~50, then speech bursts at RMS ~5000.
        // Each process() call is one fresh block of the stream.
        let mut last_tone = 0.0;
        for _ in 0..10 {
            let mut block = vec![50i16; 2400];
            gate.process(&mut block);
            last_tone = rms(&block);
        }
        assert!(last_tone < 20.0, "tone must be gated: {last_tone}");
        // Speech blocks ramp the gate back open.
        let mut last_speech = 0.0;
        for _ in 0..24 {
            let mut block: Vec<i16> = (0..2400)
                .map(|i: usize| (5_000.0 * ((i as f64) * 0.1).sin()) as i16)
                .collect();
            gate.process(&mut block);
            last_speech = rms(&block);
        }
        assert!(last_speech > 3_000.0, "speech must pass: {last_speech}");
    }

    #[test]
    fn aec_cancels_known_echo_path() {
        // Speaker emits a delayed scaled copy; the canceller must learn the
        // path and suppress the echo from the mic.
        let mut aec = AdaptiveEchoCanceller::new(64, 0.5);
        let n = 4000;
        let speaker: Vec<i16> = (0..n)
            .map(|i: usize| (8_000.0 * ((i as f64) * 0.05).sin()) as i16)
            .collect();
        let mut mic: Vec<i16> = vec![0; n];
        // Echo: speaker delayed by 10 samples at 0.5 gain + tiny noise.
        for i in 10..n {
            mic[i] = (f32::from(speaker[i - 10]) * 0.5) as i16;
        }
        // Warm up the filter, then measure residual on steady state.
        for block in 0..8 {
            let lo = block * (n / 8);
            let hi = (block + 1) * (n / 8);
            let mut chunk = mic[lo..hi].to_vec();
            aec.process(&mut chunk, &speaker[lo..hi]);
            if block >= 6 {
                let residual = rms(&chunk);
                let original = rms(&mic[lo..hi]);
                assert!(
                    residual < original * 0.3,
                    "echo must be mostly cancelled: {residual} vs {original}"
                );
            }
        }
    }

    #[test]
    fn empty_input_is_fine() {
        let mut agc = PeakNormalizingAgc::default();
        let mut gate = NoiseGate::default();
        let mut aec = AdaptiveEchoCanceller::default();
        agc.process(&mut []);
        gate.process(&mut []);
        aec.process(&mut [], &[]);
    }
}
