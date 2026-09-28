//! Phase 1 milestone integration test: two in-process `IceAgent`s complete
//! candidate gathering (host + server-reflexive via a local STUN server),
//! connectivity checks and nomination over loopback UDP.

use std::net::SocketAddr;
use std::time::Duration;

use tpt_webrtc_core::{IceCandidate, IceServer};
use tpt_webrtc_ice::{IceAgent, IceConfig, IceState, StunAttribute, StunMessage, StunMessageType};

/// A minimal STUN server that answers binding requests, echoing the
/// transaction id and mapping the client to a fake public address
/// (203.0.113.99, TEST-NET-3) so server-reflexive gathering is
/// deterministic even over loopback.
async fn spawn_stun_server() -> SocketAddr {
    use tokio::net::UdpSocket;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(req) = StunMessage::parse(&buf[..n]) else {
                continue;
            };
            if req.message_type != StunMessageType::BindingRequest {
                continue;
            }
            let mut resp = StunMessage::new(StunMessageType::BindingResponse)
                .with(StunAttribute::XorMappedAddress(SocketAddr::new(
                    std::net::IpAddr::from([203, 0, 113, 99]),
                    src.port(),
                )))
                .with(StunAttribute::Fingerprint(0));
            resp.transaction_id = req.transaction_id;
            let _ = socket.send_to(&resp.serialize(), src).await;
        }
    });
    addr
}

fn stun_server_config(addr: SocketAddr) -> Vec<IceServer> {
    vec![IceServer {
        urls: vec![format!("stun:{addr}")],
        username: None,
        credential: None,
    }]
}

/// Simulates signaling: crosses candidates and ICE credentials over.
fn signal(a: &mut IceAgent, b: &mut IceAgent) {
    a.set_remote_credentials(b.ufrag().to_string(), b.pwd().to_string());
    b.set_remote_credentials(a.ufrag().to_string(), a.pwd().to_string());
    for c in a.local_candidates().to_vec() {
        b.add_remote_candidate(c);
    }
    for c in b.local_candidates().to_vec() {
        a.add_remote_candidate(c);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_agents_connect_over_loopback_with_local_stun() {
    let stun_addr = spawn_stun_server().await;
    let servers = stun_server_config(stun_addr);

    let mut a = IceAgent::new(IceConfig::new(true)); // controlling (offerer)
    let mut b = IceAgent::new(IceConfig::new(false)); // controlled (answerer)

    let a_cands = a.gather_candidates(&servers).await.unwrap();
    let _b_cands = b.gather_candidates(&servers).await.unwrap();
    assert_eq!(a.state(), IceState::Waiting);
    assert_eq!(b.state(), IceState::Waiting);

    // Host candidate plus the server-reflexive one from our mini STUN
    // server (which maps us to the fake NAT address 203.0.113.99).
    assert!(a_cands.len() >= 2, "expected host + srflx, got {a_cands:?}");
    let srflx = a_cands
        .iter()
        .find(|c: &&IceCandidate| c.candidate_type == tpt_webrtc_core::CandidateType::Srflx)
        .expect("srflx candidate from STUN server");
    assert!(
        srflx.address.to_string().starts_with("203.0.113.99:"),
        "{srflx:?}"
    );
    assert_eq!(srflx.related_address, Some(a_cands[0].address));

    signal(&mut a, &mut b);
    assert!(!a.remote_candidates().is_empty());

    let (ra, rb) = tokio::join!(
        a.check_connectivity(Duration::from_secs(10)),
        b.check_connectivity(Duration::from_secs(10))
    );
    ra.expect("agent A connectivity");
    rb.expect("agent B connectivity");

    assert_eq!(a.state(), IceState::Completed);
    assert_eq!(b.state(), IceState::Completed);

    let na = a.nominated_pair().expect("A nominated");
    let nb = b.nominated_pair().expect("B nominated");
    assert!(na.nominated && nb.nominated);
    // A's local/remote addresses mirror B's remote/local addresses.
    assert_eq!(na.local.address, nb.remote.address);
    assert_eq!(na.remote.address, nb.local.address);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_credentials_fail_connectivity() {
    let mut a = IceAgent::new(IceConfig::new(true));
    let mut b = IceAgent::new(IceConfig::new(false));
    let a_cands = a.gather_candidates(&[]).await.unwrap();
    for c in a_cands {
        b.add_remote_candidate(c);
    }
    let b_cands = b.gather_candidates(&[]).await.unwrap();
    for c in b_cands {
        a.add_remote_candidate(c);
    }
    // Deliberately WRONG remote password on A.
    a.set_remote_credentials(b.ufrag().to_string(), "totally-wrong-password".to_string());
    b.set_remote_credentials(a.ufrag().to_string(), a.pwd().to_string());

    let (ra, rb) = tokio::join!(
        a.check_connectivity(Duration::from_millis(800)),
        b.check_connectivity(Duration::from_millis(800))
    );
    assert!(ra.is_err(), "checks with a bad password must fail");
    // B cannot complete either: A's requests fail integrity at B, so no
    // USE-CANDIDATE ever arrives.
    assert!(rb.is_err());
    assert_eq!(a.state(), IceState::Failed);
}

#[tokio::test]
async fn checking_without_remote_candidates_errors() {
    let mut a = IceAgent::new(IceConfig::new(true));
    a.gather_candidates(&[]).await.unwrap();
    let err = a
        .check_connectivity(Duration::from_millis(100))
        .await
        .unwrap_err();
    assert_eq!(err, tpt_webrtc_core::IceError::NoCandidatesAvailable);
}

#[tokio::test]
async fn double_gather_is_invalid_state() {
    let mut a = IceAgent::new(IceConfig::new(true));
    a.gather_candidates(&[]).await.unwrap();
    assert_eq!(
        a.gather_candidates(&[]).await.unwrap_err(),
        tpt_webrtc_core::IceError::InvalidState
    );
}
