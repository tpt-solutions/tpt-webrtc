//! Example: data-channel ping-pong between two `PeerConnection`s over
//! real loopback UDP.
//!
//! Run with: `cargo run -p tpt-webrtc-app --example data_channel_pingpong`

use std::time::Duration;

use tpt_webrtc_app::{DataChannelConfig, DataChannelMessage, PeerConnection, PeerConnectionConfig};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger_compat();

    let mut a = PeerConnection::new(config()).unwrap();
    let mut b = PeerConnection::new(config()).unwrap();
    let ch = a
        .create_data_channel("demo", DataChannelConfig::default())
        .unwrap();
    b.create_data_channel("demo", DataChannelConfig::default())
        .unwrap();

    // Signaling (here: direct function calls; any SignalingTransport works).
    let offer = a.create_offer().await.unwrap();
    a.set_local_description(&offer).unwrap();
    b.set_remote_description(&offer).unwrap();
    let answer = b.create_answer(&offer).await.unwrap();
    b.set_local_description(&answer).unwrap();
    a.set_remote_description(&answer).unwrap();
    println!("signaling complete");

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
    println!("peer connection established: ice+dtls+sctp up");

    for round in 0..3u32 {
        a.send_data_channel(ch, &DataChannelMessage::Text(format!("ping {round}")))
            .unwrap();
        // B polls until the ping arrives, then echoes a pong back.
        let got = wait_for_text(&mut a, &mut b, ch, &format!("ping {round}")).await;
        println!("round {round}: B received {got:?}");
        b.send_data_channel(ch, &DataChannelMessage::Text(format!("pong {round}")))
            .unwrap();
        let pong = wait_for_text(&mut b, &mut a, ch, &format!("pong {round}")).await;
        println!("round {round}: A received {pong:?}");
    }
    a.close();
    b.close();
    println!("closed");
}

/// Polls both peers until `ch` on `receiver` delivers `needle` (the
/// sender's outbox only flushes when its own poll runs).
async fn wait_for_text(
    sender: &mut PeerConnection,
    receiver: &mut PeerConnection,
    ch: u16,
    needle: &str,
) -> Option<String> {
    for _ in 0..600 {
        sender.poll(Duration::from_millis(5)).await;
        receiver.poll(Duration::from_millis(5)).await;
        if let Some(DataChannelMessage::Text(t)) = receiver.recv_data_channel(ch) {
            if t.contains(needle) {
                return Some(t);
            }
        }
    }
    None
}

fn config() -> PeerConnectionConfig {
    PeerConnectionConfig {
        local_addresses: vec![std::net::IpAddr::from([127, 0, 0, 1])],
        ..PeerConnectionConfig::default()
    }
}

fn env_logger_compat() {
    // Placeholder so the example compiles without extra deps.
}
