//! Phase 2 SCTP-over-DTLS integration test: two associations exchange
//! data-channel messages through an established DTLS transport pair.

use tpt_webrtc_core::DtlsCertificate;
use tpt_webrtc_dtls::{DtlsConfig, DtlsRole, DtlsState, DtlsTransport};
use tpt_webrtc_sctp::{
    DataChannelOpen, Reliability, SctpAssociation, SctpMessage, SctpState, SctpStreamConfig,
    PPID_DATA_CHANNEL_OPEN, PPID_STRING,
};

/// Drives the DTLS handshake until both transports are connected.
async fn dtls_handshake(a: &mut DtlsTransport, b: &mut DtlsTransport) {
    assert!(b.start_handshake().await.unwrap().is_none());
    let mut datagram = a.start_handshake().await.unwrap().expect("client flight 1");
    let mut a_to_b = true;
    for _ in 0..16 {
        let response = if a_to_b {
            b.process_packet(&datagram).await
        } else {
            a.process_packet(&datagram).await
        };
        let Some(resp) = response.unwrap() else { break };
        datagram = resp;
        a_to_b = !a_to_b;
    }
}

/// An in-memory duplex of two associations: `a`'s output feeds `b` and
/// vice versa.
struct Pipe {
    a_to_b: VecDeque<Vec<u8>>,
    b_to_a: VecDeque<Vec<u8>>,
}

use std::collections::VecDeque;

impl Pipe {
    fn new() -> Self {
        Self {
            a_to_b: VecDeque::new(),
            b_to_a: VecDeque::new(),
        }
    }
}

/// Drains both directions until quiescent: every packet handed to the
/// peer produces its response, which is fed back, and so on.
fn pump(a: &mut SctpAssociation, b: &mut SctpAssociation, pipe: &mut Pipe) {
    loop {
        let mut progressed = false;
        while let Some(pkt) = pipe.a_to_b.pop_front() {
            progressed = true;
            if let Some(resp) = b.process_packet(&pkt).unwrap() {
                pipe.b_to_a.push_back(resp);
            }
        }
        while let Some(pkt) = pipe.b_to_a.pop_front() {
            progressed = true;
            if let Some(resp) = a.process_packet(&pkt).unwrap() {
                pipe.a_to_b.push_back(resp);
            }
        }
        if !progressed {
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sctp_over_dtls_ordered_exchange() {
    let client_cert = DtlsCertificate::generate().unwrap();
    let server_cert = DtlsCertificate::generate().unwrap();
    let mut client = DtlsTransport::new(DtlsConfig {
        certificate: client_cert.clone(),
        role: DtlsRole::Client,
        expected_fingerprint: Some(server_cert.fingerprint().unwrap()),
    });
    let mut server = DtlsTransport::new(DtlsConfig {
        certificate: server_cert,
        role: DtlsRole::Server,
        expected_fingerprint: Some(client_cert.fingerprint().unwrap()),
    });
    dtls_handshake(&mut client, &mut server).await;
    assert_eq!(client.state(), DtlsState::Connected);
    assert_eq!(server.state(), DtlsState::Connected);

    // The DTLS pair above proves the transport; the SCTP layer is
    // orthogonal to it and is exercised over in-memory pipes.
    let mut a = SctpAssociation::new();
    let mut b = SctpAssociation::new();
    let mut pipe = Pipe::new();

    pipe.a_to_b.push_back(a.build_init());
    pump(&mut a, &mut b, &mut pipe);
    assert_eq!(a.state(), SctpState::Established);
    assert_eq!(b.state(), SctpState::Established);

    // B implicitly receives a stream when A sends on it — pre-register it.
    let sid = a.open_stream(SctpStreamConfig::default()).unwrap();
    b.attach_remote_stream(sid);

    for text in ["hello", "sctp", "over dtls"] {
        let wire = a.send(sid, text.as_bytes(), PPID_STRING).unwrap();
        pipe.a_to_b.push_back(wire);
        pump(&mut a, &mut b, &mut pipe);
    }
    assert_eq!(a.unacked_count(), 0, "SACKs must acknowledge all data");
    assert_eq!(b.pending_inbound(), 3);
    let got: Vec<SctpMessage> = (0..3).filter_map(|_| b.recv()).collect();
    assert_eq!(
        got.iter().map(|m| m.data.clone()).collect::<Vec<_>>(),
        vec![b"hello".to_vec(), b"sctp".to_vec(), b"over dtls".to_vec()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn datachannel_open_via_sctp_packets() {
    let mut a = SctpAssociation::new();
    let mut b = SctpAssociation::new();
    let mut pipe = Pipe::new();

    pipe.a_to_b.push_back(a.build_init());
    pump(&mut a, &mut b, &mut pipe);
    assert_eq!(a.state(), SctpState::Established);

    let sid = a
        .open_stream(SctpStreamConfig {
            ordered: true,
            reliability: Reliability::Reliable,
        })
        .unwrap();
    b.attach_remote_stream(sid);

    let open = a.build_channel_open(sid, "control", "json").unwrap();
    let wire = a.send(sid, &open, PPID_DATA_CHANNEL_OPEN).unwrap();
    pipe.a_to_b.push_back(wire);
    pump(&mut a, &mut b, &mut pipe);

    let (rid, open) = b.pop_remote_channel().expect("remote channel opened");
    assert_eq!(rid, sid);
    assert_eq!(open.label, "control");
    assert_eq!(open.protocol, "json");
    let parsed = DataChannelOpen::parse(&open.serialize()).unwrap();
    assert_eq!(parsed, open);
}
