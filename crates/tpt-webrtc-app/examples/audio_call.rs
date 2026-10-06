//! Example: audio-only call — A sends three Opus-shaped audio frames to B
//! over the SRTP path.

use std::time::Duration;

use tpt_webrtc_app::{MediaStreamTrack, PeerConnection, PeerConnectionConfig, TrackKind};
use tpt_webrtc_rtp::MediaFrame;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut a = PeerConnection::new(config()).unwrap();
    let mut b = PeerConnection::new(config()).unwrap();

    a.add_track(MediaStreamTrack {
        id: "audio-0".into(),
        kind: TrackKind::Audio,
    });
    b.add_remote_track(MediaStreamTrack {
        id: "audio-0".into(),
        kind: TrackKind::Audio,
    });

    let offer = a.create_offer().await.unwrap();
    a.set_local_description(&offer).unwrap();
    b.set_remote_description(&offer).unwrap();
    let answer = b.create_answer(&offer).await.unwrap();
    b.set_local_description(&answer).unwrap();
    a.set_remote_description(&answer).unwrap();

    let connect = async {
        tokio::join!(
            a.connect(Duration::from_secs(30)),
            b.connect(Duration::from_secs(30))
        )
        .0
    };
    tokio::time::timeout(Duration::from_secs(30), connect)
        .await
        .expect("connect timed out")
        .unwrap();
    println!("call established (ice+dtls+srtp keys exported)");

    // A 440 Hz "tone" as three 20 ms frames.
    let mut received = 0usize;
    for i in 0..3u32 {
        let mut samples = Vec::with_capacity(480);
        for j in 0..480 {
            let t = f64::from(i * 960 + j as u32) / 48_000.0;
            samples.push((3_000.0 * (2.0 * std::f64::consts::PI * 440.0 * t).sin()) as i16);
        }
        let frame = MediaFrame::Audio(tpt_webrtc_rtp::AudioFrame {
            data: samples.into_iter().flat_map(i16::to_le_bytes).collect(),
            timestamp: Duration::from_millis(u64::from(i) * 20),
        });
        a.send_media_frame(&frame).unwrap();
        for _ in 0..200 {
            a.poll(Duration::from_millis(5)).await;
            b.poll(Duration::from_millis(5)).await;
            if b.recv_media_frame().is_some() {
                received += 1;
                break;
            }
        }
    }
    println!("received {received}/3 audio frames on B");
    a.close();
    b.close();
}

fn config() -> PeerConnectionConfig {
    PeerConnectionConfig {
        local_addresses: vec![std::net::IpAddr::from([127, 0, 0, 1])],
        ..PeerConnectionConfig::default()
    }
}
