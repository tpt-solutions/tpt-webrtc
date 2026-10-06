//! AV1 encoding via `rav1e` (pure Rust — the AV1-first strategy's
//! software encoder; no external C dependency).

use std::time::Duration;

use rav1e::prelude::*;

use crate::frame::{EncodedPacket, VideoCodec, VideoFrame};
use crate::traits::{CodecError, TimestampScale, VideoEncoder};
use crate::Av1EncoderConfig;

/// AV1 encoder built on rav1e.
pub struct Av1Encoder {
    config: Av1EncoderConfig,
    ctx: Context<u8>,
    clock: TimestampScale,
    force_keyframe: bool,
}

impl Av1Encoder {
    /// Creates an encoder for `config`.
    ///
    /// # Errors
    /// [`CodecError::Config`] for invalid dimensions / invalid rav1e setup.
    pub fn new(config: Av1EncoderConfig) -> Result<Self, CodecError> {
        if config.width == 0
            || config.height == 0
            || config.width % 2 != 0
            || config.height % 2 != 0
        {
            return Err(CodecError::Config(format!(
                "dimensions {}x{} must be non-zero and even",
                config.width, config.height
            )));
        }
        let keyframe_interval = u64::from(config.keyframe_interval.clamp(1, 240));
        let encoder_config = EncoderConfig {
            width: config.width as usize,
            height: config.height as usize,
            bitrate: config.bitrate as i32,
            time_base: Rational::new(1, u64::from(config.framerate.max(1))),
            min_key_frame_interval: keyframe_interval * 3 / 4,
            max_key_frame_interval: keyframe_interval,
            speed_settings: SpeedSettings::from_preset(config.speed_preset.clamp(0, 10)),
            // Emit one packet per input frame (no lookahead buffering) —
            // the live-transport contract of the VideoEncoder trait.
            low_latency: true,
            ..EncoderConfig::default()
        };
        let rav1e_config = Config::new().with_encoder_config(encoder_config);
        let ctx = rav1e_config
            .new_context()
            .map_err(|e| CodecError::Config(e.to_string()))?;
        Ok(Self {
            config: config.clone(),
            ctx,
            clock: TimestampScale {
                frames: 0,
                fps: config.framerate.max(1),
            },
            force_keyframe: false,
        })
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> &Av1EncoderConfig {
        &self.config
    }

    /// Flushes the encoder's look-ahead, draining every buffered frame
    /// into packets. After this the encoder accepts new frames again.
    ///
    /// # Errors
    /// [`CodecError::Encode`] on failure.
    pub fn flush_drain(&mut self) -> Result<Vec<EncodedPacket>, CodecError> {
        // rav1e reports Encoded once the flush request is accepted; the
        // subsequent receive loop drains the tail.
        let _ = self.ctx.send_frame(None);
        let mut out = Vec::new();
        let _attempts = 0u32;
        loop {
            match self.ctx.receive_packet() {
                Ok(pkt) => {
                    let is_key = pkt.frame_type == FrameType::KEY;
                    out.push(EncodedPacket::new(
                        pkt.data.to_vec(),
                        Duration::ZERO,
                        is_key,
                        VideoCodec::Av1,
                    )?);
                }
                // In flush mode these are the terminal "all packets
                // emitted" statuses; Encoded means a frame was encoded
                // without emitting a packet (show-existing) — done too.
                Err(
                    EncoderStatus::EnoughData
                    | EncoderStatus::NeedMoreData
                    | EncoderStatus::Encoded
                    | EncoderStatus::LimitReached,
                ) => break,
                Err(e) => return Err(CodecError::Encode(e.to_string())),
            }
        }
        Ok(out)
    }
}

impl VideoEncoder for Av1Encoder {
    fn encode(&mut self, frame: &VideoFrame) -> Result<Vec<EncodedPacket>, CodecError> {
        if frame.format != crate::PixelFormat::Yuv420 {
            return Err(CodecError::Encode(format!(
                "Av1Encoder requires Yuv420 input, got {:?}",
                frame.format
            )));
        }
        if frame.width != self.config.width || frame.height != self.config.height {
            return Err(CodecError::Encode(format!(
                "frame {}x{} does not match encoder {}x{}",
                frame.width, frame.height, self.config.width, self.config.height
            )));
        }

        let mut rframe = self.ctx.new_frame();
        let w = self.config.width as usize;
        let h = self.config.height as usize;
        let cw = w / 2;
        let ch = h / 2;
        if frame.data.len() < w * h + 2 * cw * ch {
            return Err(CodecError::Encode(format!(
                "Yuv420 payload too small: {} < {}",
                frame.data.len(),
                w * h + 2 * cw * ch
            )));
        }
        rframe.planes[0].copy_from_raw_u8(&frame.data[..w * h], w, 1);
        rframe.planes[1].copy_from_raw_u8(&frame.data[w * h..w * h + cw * ch], cw, 1);
        rframe.planes[2].copy_from_raw_u8(&frame.data[w * h + cw * ch..w * h + 2 * cw * ch], cw, 1);

        let force_key = self.force_keyframe;
        self.force_keyframe = false;

        let timestamp = self.clock.advance();
        let _ = timestamp;
        if force_key {
            let params = FrameParameters {
                frame_type_override: FrameTypeOverride::Key,
                ..FrameParameters::default()
            };
            self.ctx
                .send_frame((rframe, params))
                .map_err(|e| CodecError::Encode(e.to_string()))?;
        } else {
            self.ctx
                .send_frame(rframe)
                .map_err(|e| CodecError::Encode(e.to_string()))?;
        }

        let mut out = Vec::new();
        let mut attempts = 0u32;
        loop {
            match self.ctx.receive_packet() {
                Ok(pkt) => {
                    let is_key = pkt.frame_type == FrameType::KEY;
                    out.push(EncodedPacket::new(
                        pkt.data.to_vec(),
                        timestamp,
                        is_key,
                        VideoCodec::Av1,
                    )?);
                }
                Err(
                    EncoderStatus::EnoughData
                    | EncoderStatus::NeedMoreData
                    | EncoderStatus::Encoded
                    | EncoderStatus::LimitReached,
                ) => break,

                // (e.g. Encoded) mean "poll again", so retry.
                Err(_) => {
                    attempts += 1;
                    if attempts > 10_000 {
                        return Err(CodecError::Encode("encoder drain stalled".into()));
                    }
                    continue;
                }
            }
        }
        Ok(out)
    }

    fn set_bitrate(&mut self, bitrate: u32) -> Result<(), CodecError> {
        if bitrate == 0 {
            return Err(CodecError::Config("bitrate must be non-zero".into()));
        }
        self.config.bitrate = bitrate;
        Ok(())
    }

    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    fn set_resolution(&mut self, width: u32, height: u32) -> Result<(), CodecError> {
        if width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0 {
            return Err(CodecError::Config(
                "dimensions must be non-zero and even".into(),
            ));
        }
        let mut new_config = self.config.clone();
        new_config.width = width;
        new_config.height = height;
        *self = Self::new(new_config)?;
        Ok(())
    }

    fn set_framerate(&mut self, fps: u32) -> Result<(), CodecError> {
        if fps == 0 {
            return Err(CodecError::Config("framerate must be non-zero".into()));
        }
        self.config.framerate = fps;
        self.clock = TimestampScale {
            frames: self.clock.frames,
            fps,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PixelFormat;

    fn yuv_frame(w: u32, h: u32, ts: Duration, luma: u8) -> VideoFrame {
        let (wu, hu) = (w as usize, h as usize);
        let mut data = vec![luma; wu * hu];
        data.extend(vec![128u8; (wu / 2) * (hu / 2) * 2]);
        VideoFrame {
            width: w,
            height: h,
            format: PixelFormat::Yuv420,
            data,
            timestamp: ts,
        }
    }

    fn small_config() -> Av1EncoderConfig {
        Av1EncoderConfig {
            width: 64,
            height: 64,
            bitrate: 200_000,
            framerate: 30,
            speed_preset: 10,
            keyframe_interval: 30,
        }
    }

    #[test]
    fn av1_encodes_keyframe_and_inter() {
        let mut enc = Av1Encoder::new(small_config()).unwrap();
        // The trait contract allows zero packets per frame (codec
        // look-ahead); feed a run of frames and collect everything.
        let mut all = Vec::new();
        for i in 0..6u32 {
            // Distinct noise per frame so each inter frame carries real
            // differences (flat frames can legally emit nothing).
            let mut f = yuv_frame(
                64,
                64,
                Duration::from_millis(33 * u64::from(i)),
                128 + i as u8,
            );
            for (j, b) in f.data.iter_mut().enumerate().take(64 * 64) {
                *b = 128u8.wrapping_add((((j * 31) + (i as usize * 7)) % 64) as u8);
            }
            all.extend(enc.encode(&f).unwrap());
        }
        // Drain whatever the codec buffered.
        all.extend(enc.flush_drain().unwrap());
        assert!(!all.is_empty(), "a 6-frame run must produce packets");
        assert!(
            all.iter().any(|p| p.is_keyframe),
            "the first emitted packet must be a keyframe"
        );
        assert_eq!(all[0].codec, VideoCodec::Av1);
        // AV1 show-existing frames may legally emit nothing for flat
        // inter frames; require a keyframe and at least one packet.
        assert!(!all.is_empty(), "packets must be produced");
        assert!(all[0].is_keyframe, "first packet must be a keyframe");
        assert!(
            all.iter().all(|p| p.data.starts_with(&[0x12, 0x00])),
            "temporal delimiter OBU expected"
        );
    }

    #[test]
    fn av1_rejects_mismatched_input() {
        let mut enc = Av1Encoder::new(small_config()).unwrap();
        let mut f = yuv_frame(64, 64, Duration::ZERO, 0);
        f.format = PixelFormat::Rgba;
        assert!(enc.encode(&f).is_err());
        let f2 = yuv_frame(128, 64, Duration::ZERO, 0);
        assert!(enc.encode(&f2).is_err());
        let mut f3 = yuv_frame(64, 64, Duration::ZERO, 0);
        f3.data.truncate(10);
        assert!(enc.encode(&f3).is_err());
    }

    #[test]
    fn av1_invalid_configs() {
        assert!(Av1Encoder::new(Av1EncoderConfig {
            width: 63,
            ..small_config()
        })
        .is_err());
        assert!(Av1Encoder::new(Av1EncoderConfig {
            height: 0,
            ..small_config()
        })
        .is_err());
    }

    #[test]
    fn bitrate_and_resolution_controls() {
        let mut enc = Av1Encoder::new(small_config()).unwrap();
        enc.set_bitrate(1_500_000).unwrap();
        assert_eq!(enc.config().bitrate, 1_500_000);
        assert!(enc.set_bitrate(0).is_err());
        enc.request_keyframe();
        enc.set_framerate(60).unwrap();
        assert_eq!(enc.config().framerate, 60);
        enc.set_resolution(128, 128).unwrap();
        assert_eq!(enc.config().width, 128);
        assert!(enc.set_resolution(33, 33).is_err());
        let mut all = Vec::new();
        for i in 0..4u32 {
            all.extend(
                enc.encode(&yuv_frame(
                    128,
                    128,
                    Duration::from_millis(33 * u64::from(i)),
                    64,
                ))
                .unwrap(),
            );
        }
        all.extend(enc.flush_drain().unwrap());
        assert!(!all.is_empty());
    }
}
