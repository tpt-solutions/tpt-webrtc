//! Simulcast fan-out: one input frame scaled into N layers. Encoders are
//! injected as closures so the crate stays codec-agnostic (the codecs
//! crate plugs its encoders in here).

use crate::video::{bilinear_resize_yuv420, Yuv420Frame};

/// One simulcast layer description (spec: rid, dimensions, bitrate cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulcastLayer {
    /// RID (restriction id) from the SDP simulcast attribute.
    pub rid: String,
    /// Layer width.
    pub width: u32,
    /// Layer height.
    pub height: u32,
    /// Maximum bitrate for the layer.
    pub max_bitrate: u32,
}

/// Scales one input frame into all configured layers; per-layer encoding
/// is delegated to the caller-supplied closure (which owns the actual
/// encoders from `tpt-webrtc-codecs`).
#[derive(Debug, Clone)]
pub struct SimulcastScaler {
    layers: Vec<SimulcastLayer>,
}

/// One layer's scaled frame, ready for its encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayeredFrame {
    /// Layer the frame belongs to.
    pub rid: String,
    /// Scaled frame.
    pub frame: Yuv420Frame,
}

impl SimulcastScaler {
    /// Fan-out over `layers`.
    #[must_use]
    pub fn new(layers: Vec<SimulcastLayer>) -> Self {
        Self { layers }
    }

    /// Configured layers.
    #[must_use]
    pub fn layers(&self) -> &[SimulcastLayer] {
        &self.layers
    }

    /// Scales `frame` once per layer.
    #[must_use]
    pub fn scale(&self, frame: &Yuv420Frame) -> Vec<LayeredFrame> {
        self.layers
            .iter()
            .map(|layer| LayeredFrame {
                rid: layer.rid.clone(),
                frame: bilinear_resize_yuv420(frame, layer.width, layer.height),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fan_out_scales_every_layer() {
        let scaler = SimulcastScaler::new(vec![
            SimulcastLayer {
                rid: "q".into(),
                width: 320,
                height: 180,
                max_bitrate: 150_000,
            },
            SimulcastLayer {
                rid: "h".into(),
                width: 640,
                height: 360,
                max_bitrate: 500_000,
            },
            SimulcastLayer {
                rid: "f".into(),
                width: 1280,
                height: 720,
                max_bitrate: 2_500_000,
            },
        ]);
        let src = Yuv420Frame::new(1280, 720);
        let out = scaler.scale(&src);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].rid, "q");
        assert_eq!(out[0].frame.width, 320);
        assert_eq!(out[2].frame.width, 1280);
        assert_eq!(out[2].frame, src, "full layer is a copy");
    }
}
