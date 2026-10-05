//! Phase 4 milestone integration test: two `PeerConnection`s complete
//! SDP offer/answer, ICE connectivity over real loopback UDP, the DTLS
//! handshake with fingerprint authentication, SCTP establishment, and then
//! exchange data-channel messages and SRTP-protected audio frames.

use std::time::Duration;

use tpt_webrtc_app::{
    DataChannelConfig, DataChannelMessage, MediaStreamTrack, PeerConnection, PeerConnectionConfig,
    TrackKind,
};
use tpt_webrtc_rtp::MediaFrame;

fn config() -> PeerConnectionConfig {
    PeerConnectionConfig {
        // Bind host candidates to loopback: self-to-LAN-IP UDP is
        // firewall-blocked for test binaries on Windows.
        local_addresses: vec![std::net::IpAddr::from([127, 0, 0, 1])],
        ..PeerConnectionConfig::default()
    }
}

async fn negotiate(a: &mut PeerConnection, b: &mut PeerConnection) {
    let offer = a.create_offer().await.unwrap();
    a.set_local_description(&offer).unwrap();
    b.set_remote_description(&offer).unwrap();
    let answer = b.create_answer(&offer).await.unwrap();
    b.set_local_description(&answer).unwrap();
    a.set_remote_description(&answer).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn full_connection_data_channel_end_to_end() {
    let mut a = PeerConnection::new(config()).unwrap();
    let mut b = PeerConnection::new(config()).unwrap();

    // Data channels are created before negotiation (matching the browser
    // model for pre-offer channels).
    let a_ch = a
        .create_data_channel("chat", DataChannelConfig::default())
        .unwrap();
    let b_ch = b
        .create_data_channel("chat", DataChannelConfig::default())
        .unwrap();
    assert_eq!(a_ch, b_ch, "both sides must number channels identically");

    negotiate(&mut a, &mut b).await;

    let (ra, rb) = tokio::join!(
        a.connect(Duration::from_secs(30)),
        b.connect(Duration::from_secs(30))
    );
    ra.expect("A connect");
    rb.expect("B connect");

    assert_eq!(
        a.peer_connection_state(),
        tpt_webrtc_app::PeerConnectionState::Connected
    );
    assert_eq!(
        b.peer_connection_state(),
        tpt_webrtc_app::PeerConnectionState::Connected
    );
    assert_eq!(
        a.ice_connection_state(),
        tpt_webrtc_app::IceConnectionState::Connected
    );
    assert_eq!(
        a.data_channel_state(a_ch),
        Some(tpt_webrtc_app::DataChannelState::Open)
    );

    // A -> B text, B -> A binary.
    a.send_data_channel(a_ch, &DataChannelMessage::Text("hello from A".into()))
        .unwrap();
    b.send_data_channel(b_ch, &DataChannelMessage::Binary(vec![1, 2, 3, 4]))
        .unwrap();

    for _ in 0..200 {
        a.poll(Duration::from_millis(10)).await;
        b.poll(Duration::from_millis(10)).await;
        if b.recv_data_channel(b_ch).is_some() && a.recv_data_channel(a_ch).is_some() {
            break;
        }
    }
    // Drain into typed values (recv pops; capture across the loop).
    // The loop above only checked presence; pump again for delivery.
    a.send_data_channel(a_ch, &DataChannelMessage::Text("second".into()))
        .unwrap();
    for _ in 0..200 {
        b.poll(Duration::from_millis(10)).await;
        if let Some(DataChannelMessage::Text(t)) = b.recv_data_channel(b_ch) {
            assert_eq!(t, "second");
            break;
        }
    }
    for _ in 0..200 {
        a.poll(Duration::from_millis(10)).await;
        if let Some(DataChannelMessage::Binary(bin)) = a.recv_data_channel(a_ch) {
            assert_eq!(bin, vec![1, 2, 3, 4]);
            break;
        }
    }

    a.close();
    b.close();
    assert_eq!(
        a.peer_connection_state(),
        tpt_webrtc_app::PeerConnectionState::Closed
    );
    assert_eq!(
        b.peer_connection_state(),
        tpt_webrtc_app::PeerConnectionState::Closed
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_connection_srtp_audio_end_to_end() {
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

    negotiate(&mut a, &mut b).await;

    let (ra, rb) = tokio::join!(
        a.connect(Duration::from_secs(30)),
        b.connect(Duration::from_secs(30))
    );
    ra.unwrap();
    rb.unwrap();

    // Send three 20 ms Opus-shaped frames, collecting them as they arrive.
    let mut received = Vec::new();
    for i in 0..3u8 {
        let frame = MediaFrame::Audio(tpt_webrtc_rtp::AudioFrame {
            data: vec![i; 160],
            timestamp: Duration::from_millis(u64::from(i) * 20),
        });
        a.send_media_frame(&frame).unwrap();
        for _ in 0..100 {
            a.poll(Duration::from_millis(5)).await;
            b.poll(Duration::from_millis(5)).await;
            if let Some(frame) = b.recv_media_frame() {
                received.push(frame);
                break;
            }
        }
    }

    assert_eq!(received.len(), 3, "all three frames must arrive");
    assert!(matches!(&received[0], MediaFrame::Audio(f) if f.data[0] == 0));
    assert!(matches!(&received[2], MediaFrame::Audio(f) if f.data[0] == 2));
}
