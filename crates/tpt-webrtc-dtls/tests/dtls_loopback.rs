//! Phase 2 DTLS integration test: a full client/server DTLS 1.2 handshake
//! (cookie exchange, ECDHE-ECDSA, encrypted Finished flights) over an
//! in-memory datagram pipe, with matching DTLS-SRTP key export and
//! protected application data on top.

use tpt_webrtc_core::DtlsCertificate;
use tpt_webrtc_dtls::{DtlsConfig, DtlsRole, DtlsState, DtlsTransport};

/// Drives the flight exchange until both transports are connected.
async fn handshake(a: &mut DtlsTransport, b: &mut DtlsTransport) {
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

fn client_config(cert: &DtlsCertificate, server_fp: Option<tpt_webrtc_core::Fingerprint>) -> DtlsConfig {
    DtlsConfig {
        certificate: cert.clone(),
        role: DtlsRole::Client,
        expected_fingerprint: server_fp,
    }
}

fn server_config(cert: &DtlsCertificate, client_fp: Option<tpt_webrtc_core::Fingerprint>) -> DtlsConfig {
    DtlsConfig {
        certificate: cert.clone(),
        role: DtlsRole::Server,
        expected_fingerprint: client_fp,
    }
}

#[tokio::test]
async fn full_handshake_exports_matching_srtp_keys() {
    let client_cert = DtlsCertificate::generate().unwrap();
    let server_cert = DtlsCertificate::generate().unwrap();

    let mut client = DtlsTransport::new(client_config(
        &client_cert,
        Some(server_cert.fingerprint().unwrap()),
    ));
    let mut server = DtlsTransport::new(server_config(
        &server_cert,
        Some(client_cert.fingerprint().unwrap()),
    ));

    handshake(&mut client, &mut server).await;

    assert_eq!(client.state(), DtlsState::Connected);
    assert_eq!(server.state(), DtlsState::Connected);

    // The whole point of DTLS-SRTP: identical key material on both sides.
    let ck = client.srtp_keys().expect("client srtp keys");
    let sk = server.srtp_keys().expect("server srtp keys");
    assert_eq!(ck, sk);
    assert_eq!(ck.client_key.len(), 16);
    assert_eq!(ck.client_salt.len(), 14);

    // Peer certificates landed on both sides.
    assert!(client.peer_certificate().is_some());
    assert!(server.peer_certificate().is_some());
}

#[tokio::test]
async fn application_data_roundtrip() {
    let client_cert = DtlsCertificate::generate().unwrap();
    let server_cert = DtlsCertificate::generate().unwrap();
    let mut client = DtlsTransport::new(client_config(&client_cert, Some(server_cert.fingerprint().unwrap())));
    let mut server = DtlsTransport::new(server_config(&server_cert, Some(client_cert.fingerprint().unwrap())));
    handshake(&mut client, &mut server).await;
    assert_eq!(client.state(), DtlsState::Connected);

    let msg = b"hello over DTLS";
    let wire = client.send_application_data(msg).await.unwrap();
    assert_ne!(&wire[13..], msg, "application data must be encrypted");
    server.process_packet(&wire).await.unwrap();
    assert_eq!(server.recv_application_data(), Some(msg.to_vec()));

    let reply = server.send_application_data(b"ack").await.unwrap();
    client.process_packet(&reply).await.unwrap();
    assert_eq!(client.recv_application_data(), Some(b"ack".to_vec()));
}

#[tokio::test]
async fn wrong_fingerprint_is_rejected() {
    let client_cert = DtlsCertificate::generate().unwrap();
    let server_cert = DtlsCertificate::generate().unwrap();
    let other = DtlsCertificate::generate().unwrap();

    let mut client = DtlsTransport::new(client_config(&client_cert, Some(other.fingerprint().unwrap())));
    let mut server = DtlsTransport::new(server_config(&server_cert, None));
    let mut datagram = client.start_handshake().await.unwrap().unwrap();

    // Drive until the client sees the server certificate.
    let mut a_to_b = true;
    let mut result: Option<Result<Option<Vec<u8>>, tpt_webrtc_core::DtlsError>> = None;
    for _ in 0..16 {
        let response = if a_to_b {
            server.process_packet(&datagram).await
        } else {
            client.process_packet(&datagram).await
        };
        let is_err = response.is_err();
        result = Some(response);
        if is_err {
            break;
        }
        let Some(resp) = result.as_ref().unwrap().as_ref().unwrap() else { break };
        datagram = resp.clone();
        a_to_b = !a_to_b;
    }
    assert_eq!(
        result.unwrap().err(),
        Some(tpt_webrtc_core::DtlsError::CertificateVerificationFailed),
        "a mismatched SDP fingerprint must abort the handshake"
    );
    assert_eq!(client.state(), DtlsState::Connecting);
}

#[tokio::test]
async fn handshake_without_fingerprint_expectation_succeeds() {
    let client_cert = DtlsCertificate::generate().unwrap();
    let server_cert = DtlsCertificate::generate().unwrap();
    let mut client = DtlsTransport::new(client_config(&client_cert, None));
    let mut server = DtlsTransport::new(server_config(&server_cert, None));
    handshake(&mut client, &mut server).await;
    assert_eq!(client.state(), DtlsState::Connected);
    assert_eq!(server.state(), DtlsState::Connected);
}

#[test]
fn srtp_sessions_protect_rtp_end_to_end() {
    use tpt_webrtc_dtls::{Direction, SrtpCipher, SrtpSession};

    // Simulate keys exported from a completed handshake.
    let mut export = vec![0u8; 60];
    for (i, b) in export.iter_mut().enumerate() {
        *b = (i * 11 + 5) as u8;
    }
    let keys = tpt_webrtc_dtls::prf::srtp_keys_from_export(&export).unwrap();

    let mut tx = SrtpSession::new(keys.clone(), true, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
    let mut rx = SrtpSession::new(keys.clone(), true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();

    let mut rtp = vec![0x80, 0x60, 0, 42, 0, 0, 1, 0, 1, 2, 3, 4];
    rtp.extend_from_slice(b"media payload");
    let protected = tx.protect_rtp(&rtp).unwrap();
    assert_eq!(rx.unprotect_rtp(&protected).unwrap(), rtp);

    // Server-protected (client-unprotect) direction uses the other key pair.
    let mut srv = SrtpSession::new(keys.clone(), false, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
    let mut cli = SrtpSession::new(keys, true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
    let protected = srv.protect_rtp(&rtp).unwrap();
    assert_eq!(cli.unprotect_rtp(&protected).unwrap(), rtp);
}
