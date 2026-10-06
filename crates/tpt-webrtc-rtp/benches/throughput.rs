//! Micro-benchmarks for the media transport hot paths (std-timed, no
//! criterion dependency). Run: `cargo bench -p tpt-webrtc-rtp`.

use std::time::{Duration, Instant};

use tpt_webrtc_dtls::{Direction, SrtpCipher, SrtpKeys, SrtpSession};
use tpt_webrtc_rtp::VideoFrame as RtpVideoFrame;
use tpt_webrtc_rtp::{
    Av1Packetizer, MediaFrame, OpusPacketizer, Packetizer, RtpPacket, VideoPacketizerContext,
};

fn timed<F: FnMut()>(name: &str, mut f: F) {
    // Warmup.
    for _ in 0..100 {
        f();
    }
    let iters = 10_000u64;
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    println!(
        "{name:<44} {:>10.1} ns/iter  ({:.0} M/s)",
        elapsed.as_nanos() as f64 / iters as f64,
        f64::from(iters as u32) / (elapsed.as_secs_f64() * 1_000_000.0),
    );
}

fn video_frame(len: usize) -> MediaFrame {
    MediaFrame::Video(RtpVideoFrame {
        data: vec![7u8; len],
        timestamp: Duration::from_millis(33),
        keyframe: true,
        width: 1280,
        height: 720,
    })
}

fn srtp_pair() -> (SrtpSession, SrtpSession) {
    let mut export = vec![0u8; 60];
    for (i, b) in export.iter_mut().enumerate() {
        *b = (i * 13 + 1) as u8;
    }
    let keys = SrtpKeys::from_export(&export);
    (
        SrtpSession::new(
            keys.clone(),
            true,
            Direction::Protect,
            SrtpCipher::Aes128CmHmacSha1_80,
        )
        .unwrap(),
        SrtpSession::new(
            keys,
            false,
            Direction::Unprotect,
            SrtpCipher::Aes128CmHmacSha1_80,
        )
        .unwrap(),
    )
}

trait FromExport {
    fn from_export(export: &[u8]) -> Self;
}

impl FromExport for SrtpKeys {
    fn from_export(export: &[u8]) -> Self {
        // 60-byte export split: 16+16 key / 14+14 salt.
        SrtpKeys {
            client_key: export[0..16].to_vec(),
            server_key: export[16..32].to_vec(),
            client_salt: export[32..46].to_vec(),
            server_salt: export[46..60].to_vec(),
        }
    }
}

fn main() {
    println!("== tpt-webrtc-rtp micro-benchmarks ==\n");

    // RTP packetize/depacketize.
    let mut av1 = Av1Packetizer;
    let mut ctx = VideoPacketizerContext {
        sequence_number: 0,
        ssrc: 1,
        payload_type: 96,
    };
    let frame = video_frame(4000);
    timed("AV1 packetize 4 KB (OBU-aggregated)", || {
        let _ = av1.packetize(&mut ctx, &frame, 1200).unwrap();
    });

    let opus_packets = {
        let mut p = OpusPacketizer;
        let mut c = VideoPacketizerContext {
            sequence_number: 0,
            ssrc: 2,
            payload_type: 111,
        };
        let audio = MediaFrame::Audio(tpt_webrtc_rtp::AudioFrame {
            data: vec![3u8; 400],
            timestamp: Duration::from_millis(20),
        });
        p.packetize(&mut c, &audio, 1200).unwrap()
    };
    timed("Opus packetize 400 B", || {
        let _ = OpusPacketizer
            .packetize(
                &mut VideoPacketizerContext {
                    sequence_number: 0,
                    ssrc: 2,
                    payload_type: 111,
                },
                &MediaFrame::Audio(tpt_webrtc_rtp::AudioFrame {
                    data: vec![3u8; 400],
                    timestamp: Duration::from_millis(20),
                }),
                1200,
            )
            .unwrap();
    });
    timed("Opus depacketize 1 packet", || {
        let _ = OpusPacketizer.depacketize(&opus_packets).unwrap();
    });

    // RTP serialize/parse.
    let rtp = RtpPacket {
        marker: true,
        payload_type: 111,
        sequence_number: 42,
        timestamp: 960,
        ssrc: 0xDEADBEEF,
        payload: vec![0u8; 400],
        ..RtpPacket::default()
    };
    let wire = rtp.serialize();
    timed("RTP serialize 400 B", || {
        let _ = rtp.serialize();
    });
    timed("RTP parse 400 B", || {
        let _ = RtpPacket::parse(&wire).unwrap();
    });

    // SRTP protect/unprotect (CM-HMAC-SHA1-80).
    let (mut tx, mut rx) = srtp_pair();
    let plain = rtp.serialize();
    let protected = tx.protect_rtp(&plain).unwrap();
    timed("SRTP protect 400 B (CM+SHA1-80)", || {
        let _ = tx.protect_rtp(&plain).unwrap();
    });
    timed("SRTP unprotect 400 B (CM+SHA1-80)", || {
        let _ = rx.unprotect_rtp(&protected).unwrap();
    });

    println!("\nnote: debug-build numbers are order-of-magnitude only; use --release");
}
