//! Video processing: YUV420 bilinear scaling and RGBA ↔ YUV420 color
//! conversion (BT.601 limited range), plus the pipeline types.

/// A planar YUV420 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Yuv420Frame {
    /// Width in pixels (even).
    pub width: u32,
    /// Height in pixels (even).
    pub height: u32,
    /// Y plane, `width * height` bytes.
    pub y: Vec<u8>,
    /// U plane, `(width/2) * (height/2)` bytes.
    pub u: Vec<u8>,
    /// V plane, `(width/2) * (height/2)` bytes.
    pub v: Vec<u8>,
}

impl Yuv420Frame {
    /// Allocates a black frame.
    #[must_use]
    pub fn new(width: u32, height: u32) -> Self {
        let (w, h) = (width as usize, height as usize);
        Self {
            y: vec![16; w * h],
            u: vec![128; (w / 2) * (h / 2)],
            v: vec![128; (w / 2) * (h / 2)],
            width,
            height,
        }
    }

    /// Chroma dimensions.
    #[must_use]
    pub fn chroma_size(&self) -> (usize, usize) {
        (self.width as usize / 2, self.height as usize / 2)
    }
}

/// Bilinear YUV420 scaler: luma at full resolution, chroma at half
/// resolution; each plane resampled independently with a bilinear kernel.
///
/// # Panics
/// Never; malformed plane sizes are treated as all-neutral.
#[must_use]
pub fn bilinear_resize_yuv420(src: &Yuv420Frame, dst_w: u32, dst_h: u32) -> Yuv420Frame {
    let resize = |plane: &[u8], sw: u32, sh: u32, dw: u32, dh: u32| -> Vec<u8> {
        let mut out = vec![0u8; (dw * dh) as usize];
        if sw == 0 || sh == 0 {
            return out;
        }
        let (sw, sh, dw, dh) = (f64::from(sw), f64::from(sh), f64::from(dw), f64::from(dh));
        for dy in 0..dh as usize {
            let sy = (dy as f64 + 0.5) * sh / dh - 0.5;
            let y0 = sy.floor().max(0.0) as usize;
            let y1 = (y0 + 1).min(sh as usize - 1);
            let fy = (sy - y0 as f64).clamp(0.0, 1.0);
            for dx in 0..dw as usize {
                let sx = (dx as f64 + 0.5) * sw / dw - 0.5;
                let x0 = sx.floor().max(0.0) as usize;
                let x1 = (x0 + 1).min(sw as usize - 1);
                let fx = (sx - x0 as f64).clamp(0.0, 1.0);
                let p00 = f64::from(plane[y0 * sw as usize + x0]);
                let p01 = f64::from(plane[y0 * sw as usize + x1]);
                let p10 = f64::from(plane[y1 * sw as usize + x0]);
                let p11 = f64::from(plane[y1 * sw as usize + x1]);
                let top = p00 * (1.0 - fx) + p01 * fx;
                let bottom = p10 * (1.0 - fx) + p11 * fx;
                out[dy * dw as usize + dx] = (top * (1.0 - fy) + bottom * fy).round() as u8;
            }
        }
        out
    };

    let (cw, ch) = (src.width / 2, src.height / 2);
    let (dcw, dch) = (dst_w / 2, dst_h / 2);
    let min_y = src.y.len().min((src.width * src.height) as usize);
    let min_u = src.u.len().min((cw * ch) as usize);
    let min_v = src.v.len().min((cw * ch) as usize);
    Yuv420Frame {
        width: dst_w,
        height: dst_h,
        y: resize(&src.y[..min_y], src.width, src.height, dst_w, dst_h),
        u: resize(&src.u[..min_u], cw, ch, dcw, dch),
        v: resize(&src.v[..min_v], cw, ch, dcw, dch),
    }
}

/// Convenience wrapper matching the spec's `VideoScaler` name.
#[derive(Debug, Clone, Copy, Default)]
pub struct VideoScaler;

impl VideoScaler {
    /// Scales `src` to `(width, height)`.
    #[must_use]
    pub fn scale(&self, src: &Yuv420Frame, width: u32, height: u32) -> Yuv420Frame {
        bilinear_resize_yuv420(src, width, height)
    }
}

/// Converts RGBA8 (packed, row-major) to planar YUV420 (BT.601 limited
/// range). Width/height must be even for the chroma subsample.
#[must_use]
pub fn rgba_to_yuv420(rgba: &[u8], width: u32, height: u32) -> Yuv420Frame {
    let mut frame = Yuv420Frame::new(width, height);
    let w = width as usize;
    for y in 0..height as usize {
        for x in 0..w {
            let i = (y * w + x) * 4;
            let (r, g, b) = (
                f64::from(rgba[i]),
                f64::from(rgba[i + 1]),
                f64::from(rgba[i + 2]),
            );
            let yv = (0.257 * r + 0.504 * g + 0.098 * b + 16.0).round();
            frame.y[y * w + x] = yv.clamp(16.0, 235.0) as u8;
            if y % 2 == 0 && x % 2 == 0 {
                let (cy, cx) = (y / 2, x / 2);
                let cw = w / 2;
                let u = (-0.148 * r - 0.291 * g + 0.439 * b + 128.0).round();
                let v = (0.439 * r - 0.368 * g - 0.071 * b + 128.0).round();
                frame.u[cy * cw + cx] = u.clamp(16.0, 240.0) as u8;
                frame.v[cy * cw + cx] = v.clamp(16.0, 240.0) as u8;
            }
        }
    }
    frame
}

/// Converts planar YUV420 back to RGBA8 (BT.601 limited range).
#[must_use]
pub fn yuv420_to_rgba(frame: &Yuv420Frame) -> Vec<u8> {
    let w = frame.width as usize;
    let h = frame.height as usize;
    let mut out = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let yv = f64::from(frame.y[y * w + x]) - 16.0;
            let cw = w / 2;
            let u = f64::from(frame.u[(y / 2) * cw + x / 2]) - 128.0;
            let v = f64::from(frame.v[(y / 2) * cw + x / 2]) - 128.0;
            let r = 1.164 * yv + 1.596 * v;
            let g = 1.164 * yv - 0.391 * u - 0.813 * v;
            let b = 1.164 * yv + 2.018 * u;
            let i = (y * w + x) * 4;
            out[i] = r.clamp(0.0, 255.0) as u8;
            out[i + 1] = g.clamp(0.0, 255.0) as u8;
            out[i + 2] = b.clamp(0.0, 255.0) as u8;
            out[i + 3] = 255;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_same_size_is_identity() {
        let mut src = Yuv420Frame::new(64, 64);
        for (i, b) in src.y.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let out = bilinear_resize_yuv420(&src, 64, 64);
        assert_eq!(out.y, src.y, "identity resample must not change luma");
    }

    #[test]
    fn scale_down_up_preserves_structure() {
        let mut src = Yuv420Frame::new(64, 64);
        for (i, b) in src.y.iter_mut().enumerate() {
            *b = if i < 64 * 32 { 30 } else { 220 }; // top / bottom halves
        }
        let down = bilinear_resize_yuv420(&src, 32, 32);
        assert_eq!(down.y.len(), 32 * 32);
        let back = bilinear_resize_yuv420(&down, 64, 64);
        assert_eq!(back.y.len(), 64 * 64);
        // The top half stays dark, bottom stays bright (sampled centers).
        assert!(back.y[10 * 64 + 32] < 120);
        assert!(back.y[50 * 64 + 32] > 150);
    }

    #[test]
    fn rgba_yuv_roundtrip_approximate() {
        // Solid colors survive the limited-range round trip closely.
        for (r, g, b) in [(255u8, 0, 0), (0, 255, 0), (0, 0, 255), (128, 128, 128)] {
            let rgba = vec![[r, g, b, 255u8]; 64 * 64 * 4].concat();
            let yuv = rgba_to_yuv420(&rgba, 64, 64);
            let back = yuv420_to_rgba(&yuv);
            for px in back.chunks_exact(4) {
                assert!(
                    (i16::from(px[0]) - i16::from(r)).abs() <= 12,
                    "r {} -> {}",
                    px[0],
                    r
                );
                assert!((i16::from(px[1]) - i16::from(g)).abs() <= 12, "g");
                assert!((i16::from(px[2]) - i16::from(b)).abs() <= 12, "b");
            }
        }
    }

    #[test]
    fn scaler_trait() {
        let src = Yuv420Frame::new(128, 96);
        let out = VideoScaler.scale(&src, 640, 480);
        assert_eq!((out.width, out.height), (640, 480));
        assert_eq!(out.y.len(), 640 * 480);
        assert_eq!(out.u.len(), 320 * 240);
    }
}
