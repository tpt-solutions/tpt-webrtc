//! The DTLS transport: drives the WebRTC-profile DTLS 1.2 handshake
//! flight-by-flight over a datagram pump, then carries application data and
//! exports DTLS-SRTP keys.
//!
//! Simplifications (documented, per the todo scope):
//! - one cipher suite: `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`;
//! - handshake messages are not fragmented (our largest message, the
//!   certificate, stays far below the MTU);
//! - no client `CertificateVerify` — authentication is the SDP
//!   fingerprint of the peer certificate, checked in both directions.

use std::collections::VecDeque;

use ring::agreement;
use ring::rand::SystemRandom;

use crate::handshake::{
    self, CertificateMessage, ClientKeyExchange, Finished, HandshakeHeader, HandshakeType, Hello, HelloVerifyRequest, ServerKeyExchange,
};
use crate::prf;
use crate::record::{content_type, RecordLayer};
use tpt_webrtc_core::{DtlsCertificate, DtlsError, Fingerprint};

/// DTLS role. The application picks explicit roles (the SDP `setup`
/// attribute decides in WebRTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DtlsRole {
    /// DTLS client (sends ClientHello).
    #[default]
    Client,
    /// DTLS server (waits for ClientHello).
    Server,
}

/// Transport states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DtlsState {
    /// Freshly constructed.
    #[default]
    New,
    /// Handshake in flight.
    Connecting,
    /// Handshake completed; SRTP keys exported.
    Connected,
    /// Handshake failed.
    Failed,
    /// Closed by the application.
    Closed,
}

/// Transport configuration.
#[derive(Debug)]
pub struct DtlsConfig {
    /// Local certificate (self-signed, generated or loaded).
    pub certificate: DtlsCertificate,
    /// Explicit role.
    pub role: DtlsRole,
    /// Expected peer certificate fingerprint (from SDP). When `Some`, the
    /// peer certificate must match — this is WebRTC's authentication.
    pub expected_fingerprint: Option<Fingerprint>,
}

/// A DTLS 1.2 transport for one WebRTC connection.
pub struct DtlsTransport {
    config: DtlsConfig,
    state: DtlsState,
    record: RecordLayer,
    client_random: [u8; 32],
    server_random: [u8; 32],
    transcript: Vec<u8>,
    ecdhe: Option<agreement::EphemeralPrivateKey>,
    ecdhe_public: Vec<u8>,
    master_secret: Option<Vec<u8>>,
    expected_cookie: Option<Vec<u8>>,
    next_message_seq: u16,
    peer_cert_der: Option<Vec<u8>>,
    /// Server-side accumulation of the client flight's handshake bytes
    /// before the master secret exists (Certificate before CKE).
    srtp_keys: Option<crate::SrtpKeys>,
    inbound_app: VecDeque<Vec<u8>>,
}

impl std::fmt::Debug for DtlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsTransport")
            .field("state", &self.state)
            .field("role", &self.config.role)
            .field("has_srtp_keys", &self.srtp_keys.is_some())
            .finish()
    }
}

impl DtlsTransport {
    /// Creates a transport in [`DtlsState::New`].
    #[must_use]
    pub fn new(config: DtlsConfig) -> Self {
        Self {
            config,
            state: DtlsState::New,
            record: RecordLayer::new(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            transcript: Vec::new(),
            ecdhe: None,
            ecdhe_public: Vec::new(),
            master_secret: None,
            expected_cookie: None,
            next_message_seq: 0,
            peer_cert_der: None,
            srtp_keys: None,
            inbound_app: VecDeque::new(),
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> DtlsState {
        self.state
    }

    /// Exported DTLS-SRTP keys (available once [`DtlsState::Connected`]).
    #[must_use]
    pub fn srtp_keys(&self) -> Option<&crate::SrtpKeys> {
        self.srtp_keys.as_ref()
    }

    /// The local certificate fingerprint to advertise in SDP.
    ///
    /// # Errors
    /// Propagates hashing failure (never in practice).
    pub fn local_fingerprint(&self) -> Result<Fingerprint, DtlsError> {
        self.config.certificate.fingerprint()
    }

    /// The peer certificate's DER, once received.
    #[must_use]
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_cert_der.as_deref()
    }

    fn take_seq(&mut self) -> u16 {
        let seq = self.next_message_seq;
        self.next_message_seq += 1;
        seq
    }

    fn record_transcript(&mut self, msg: &[u8]) {
        self.transcript.extend_from_slice(msg);
    }

    /// Starts the handshake. For the client role this builds flight 1
    /// (ClientHello); for the server role it transitions to
    /// [`DtlsState::Connecting`] and waits for `process_packet`.
    ///
    /// Returns the outgoing datagram, if any.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] when already handshaking/connected, or
    /// crypto failures while building the flight.
    pub async fn start_handshake(&mut self) -> Result<Option<Vec<u8>>, DtlsError> {
        if self.state != DtlsState::New {
            return Err(DtlsError::InvalidState);
        }
        self.state = DtlsState::Connecting;
        if self.config.role == DtlsRole::Client {
            return Ok(Some(self.build_client_hello()?));
        }
        Ok(None)
    }

    fn build_client_hello(&mut self) -> Result<Vec<u8>, DtlsError> {
        prf::random(&mut self.client_random)?;
        let (priv_key, pub_key) = generate_ecdhe()?;
        self.ecdhe = Some(priv_key);
        self.ecdhe_public = pub_key;
        let hello = Hello {
            random: self.client_random,
            session_id: Vec::new(),
            cookie: self.expected_cookie.clone().unwrap_or_default(),
            cipher_suites: handshake::default_cipher_suites(),
            compression: vec![0],
            extensions: Hello::client_extensions(),
        };
        let body = hello.serialize(true);
        let seq = self.take_seq();
        let msg = handshake::wrap(HandshakeType::ClientHello, seq, &body);
        if self.expected_cookie.is_some() {
            self.replace_transcript_client_hello(&msg);
        } else {
            self.record_transcript(&msg);
        }
        Ok(RecordLayer::plaintext_record(content_type::HANDSHAKE, &msg))
    }

    fn replace_transcript_client_hello(&mut self, msg: &[u8]) {
        if let Ok(h) = HandshakeHeader::parse(&self.transcript) {
            if h.msg_type == HandshakeType::ClientHello.to_u8() {
                let total = handshake::HANDSHAKE_HEADER_LEN + h.fragment_length as usize;
                self.transcript.splice(0..total, msg.iter().copied());
            }
        }
    }

    /// Feeds one received datagram (which may contain several records);
    /// returns the outgoing datagram, if the state machine produces one.
    /// Received application data is queued and retrieved via
    /// [`recv_application_data`](Self::recv_application_data).
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] after close,
    /// [`DtlsError::CertificateVerificationFailed`] on fingerprint
    /// mismatch, [`DtlsError::HandshakeFailed`] on protocol violations,
    /// [`DtlsError::DecryptionFailed`] for bad records.
    pub async fn process_packet(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, DtlsError> {
        if !matches!(self.state, DtlsState::Connecting | DtlsState::Connected) {
            return Err(DtlsError::InvalidState);
        }
        let mut out = Vec::new();
        let mut offset = 0;
        while offset + 13 <= data.len() {
            let len = u16::from_be_bytes([data[offset + 11], data[offset + 12]]) as usize;
            if offset + 13 + len > data.len() {
                return Err(DtlsError::InvalidState);
            }
            let record = &data[offset..offset + 13 + len];
            offset += 13 + len;

            let ctype = record[0];
            let epoch = u16::from_be_bytes([record[2], record[3]]);
            let (_, _, plain) = self.record.unprotect(record)?;
            match ctype {
                content_type::HANDSHAKE => {
                    self.on_handshake(&plain, epoch, &mut out)?;
                }
                content_type::CHANGE_CIPHER_SPEC => {}
                content_type::APPLICATION_DATA => {
                    self.inbound_app.push_back(plain);
                }
                content_type::ALERT => return Err(DtlsError::HandshakeFailed),
                _ => return Err(DtlsError::InvalidState),
            }
        }
        Ok(if out.is_empty() { None } else { Some(out) })
    }

    fn on_handshake(&mut self, plain: &[u8], epoch: u16, out: &mut Vec<u8>) -> Result<(), DtlsError> {
        let header = HandshakeHeader::parse(plain)?;
        let msg_type = HandshakeType::from_u8(header.msg_type);
        let body = plain[handshake::HANDSHAKE_HEADER_LEN..].to_vec();

        if epoch == 0 {
            match (self.config.role, msg_type) {
                (DtlsRole::Server, HandshakeType::ClientHello) => {
                    self.server_on_client_hello(&body, out)?;
                }
                (DtlsRole::Client, HandshakeType::HelloVerifyRequest) => {
                    let hvr = HelloVerifyRequest::parse(&body)?;
                    self.expected_cookie = Some(hvr.cookie);
                    let datagram = self.build_client_hello()?;
                    out.extend_from_slice(&datagram);
                }
                (DtlsRole::Client, HandshakeType::ServerHello) => {
                    let hello = Hello::parse(&body, false)?;
                    if hello.cipher_suites.first() != Some(&crate::CIPHER_SUITE) {
                        return Err(DtlsError::HandshakeFailed);
                    }
                    self.server_random = hello.random;
                    self.record_transcript(plain);
                }
                (DtlsRole::Client, HandshakeType::Certificate) => {
                    let cert = CertificateMessage::parse(&body)?;
                    let der = cert
                        .certificates
                        .first()
                        .cloned()
                        .ok_or(DtlsError::HandshakeFailed)?;
                    if let Some(want) = &self.config.expected_fingerprint {
                        let got = Fingerprint::sha256(&der)?;
                        if got != *want {
                            return Err(DtlsError::CertificateVerificationFailed);
                        }
                    }
                    self.peer_cert_der = Some(der);
                    self.record_transcript(plain);
                }
                (DtlsRole::Client, HandshakeType::ServerKeyExchange) => {
                    let ske = ServerKeyExchange::parse(&body)?;
                    let peer_cert = self.peer_cert_der.as_ref().ok_or(DtlsError::HandshakeFailed)?;
                    // Signature over client_random || server_random || params,
                    // verified with the peer certificate's public key (the
                    // fingerprint in SDP is the actual authentication).
                    let mut signed = Vec::with_capacity(64 + ske.signed_params().len());
                    signed.extend_from_slice(&self.client_random);
                    signed.extend_from_slice(&self.server_random);
                    signed.extend_from_slice(&ske.signed_params());
                    let point = tpt_webrtc_core::p256_point_from_der_cert(peer_cert)?;
                    tpt_webrtc_core::verify_with_p256_point(&point, &signed, &ske.signature)?;
                    // Compute the shared secret and derive the master secret.
                    let shared = self.ecdhe_agree(&ske.point)?;
                    let master =
                        prf::master_secret(&shared, &self.client_random, &self.server_random);
                    self.master_secret = Some(master);
                    self.activate_keys();
                    self.record_transcript(plain);
                }
                (DtlsRole::Client, HandshakeType::ServerHelloDone) => {
                    self.record_transcript(plain);
                    self.client_send_flight(out)?;
                }
                (DtlsRole::Server, HandshakeType::Certificate) => {
                    let cert = CertificateMessage::parse(&body)?;
                    let der = cert
                        .certificates
                        .first()
                        .cloned()
                        .ok_or(DtlsError::HandshakeFailed)?;
                    if let Some(want) = &self.config.expected_fingerprint {
                        let got = Fingerprint::sha256(&der)?;
                        if got != *want {
                            return Err(DtlsError::CertificateVerificationFailed);
                        }
                    }
                    self.peer_cert_der = Some(der);
                    self.record_transcript(plain);
                }
                (DtlsRole::Server, HandshakeType::ClientKeyExchange) => {
                    let cke = ClientKeyExchange::parse(&body)?;
                    self.record_transcript(plain);
                    let shared = self.ecdhe_agree(&cke.point)?;
                    let master =
                        prf::master_secret(&shared, &self.client_random, &self.server_random);
                    self.master_secret = Some(master);
                    self.activate_keys();
                }
                _ => return Err(DtlsError::HandshakeFailed),
            }
        } else {
            // Encrypted handshake: Finished only.
            if msg_type != HandshakeType::Finished {
                return Err(DtlsError::HandshakeFailed);
            }
            let finished = Finished::parse(&body)?;
            let label: &[u8] = if self.config.role == DtlsRole::Client {
                b"server finished"
            } else {
                b"client finished"
            };
            let master = self
                .master_secret
                .clone()
                .ok_or(DtlsError::HandshakeFailed)?;
            let hash = tpt_webrtc_core::sha256(&self.transcript);
            let want = prf::prf_sha256(&master, label, &hash, 12);
            if finished.verify_data != want {
                return Err(DtlsError::HandshakeFailed);
            }
            self.record_transcript(plain);

            if self.config.role == DtlsRole::Client {
                self.export_srtp_keys()?;
                self.state = DtlsState::Connected;
            } else {
                // Server: send CCS + its own (encrypted) Finished.
                out.extend_from_slice(&RecordLayer::plaintext_record(
                    content_type::CHANGE_CIPHER_SPEC,
                    &[1],
                ));
                let seq = self.take_seq();
                let verify = prf::prf_sha256(&master, b"server finished", &hash, 12);
                let fin =
                    handshake::wrap(
                        HandshakeType::Finished,
                        seq,
                        &Finished { verify_data: verify }.serialize(),
                    );
                self.record_transcript(&fin);
                let encrypted = self.record.protect(content_type::HANDSHAKE, &fin)?;
                out.extend_from_slice(&encrypted);
                self.export_srtp_keys()?;
                self.state = DtlsState::Connected;
            }
        }
        Ok(())
    }

    fn server_on_client_hello(&mut self, body: &[u8], out: &mut Vec<u8>) -> Result<(), DtlsError> {
        let hello = Hello::parse(body, true)?;
        let cookie_ok = self
            .expected_cookie
            .as_ref()
            .is_some_and(|want| !hello.cookie.is_empty() && want == &hello.cookie);
        if !cookie_ok {
            let mut cookie = vec![0u8; 16];
            prf::random(&mut cookie)?;
            self.expected_cookie = Some(cookie.clone());
            let hvr_body = HelloVerifyRequest { cookie }.serialize();
            let seq = self.take_seq();
            let msg = handshake::wrap(HandshakeType::HelloVerifyRequest, seq, &hvr_body);
            out.extend_from_slice(&RecordLayer::plaintext_record(content_type::HANDSHAKE, &msg));
            return Ok(());
        }

        if self.transcript.is_empty() {
            self.record_transcript(
                // The transcript uses the received CH as-is; rebuild the
                // full message bytes from the caller-provided slice.
                &{
                    let header = HandshakeHeader {
                        msg_type: HandshakeType::ClientHello.to_u8(),
                        length: body.len() as u32,
                        message_seq: 1,
                        fragment_offset: 0,
                        fragment_length: body.len() as u32,
                    };
                    let mut m = header.serialize();
                    m.extend_from_slice(body);
                    m
                },
            );
        }
        prf::random(&mut self.server_random)?;
        let (priv_key, pub_key) = generate_ecdhe()?;
        self.ecdhe = Some(priv_key);
        self.ecdhe_public = pub_key.clone();

        let server_hello = Hello {
            random: self.server_random,
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: vec![crate::CIPHER_SUITE],
            compression: vec![0],
            extensions: vec![handshake::Extension::UseSrtp {
                profiles: vec![crate::SRTP_AES128_CM_HMAC_SHA1_80],
                mki: Vec::new(),
            }],
        };
        let ske = ServerKeyExchange {
            point: pub_key.clone(),
            signature: self.config.certificate.sign(&self.ske_signature_input(&pub_key))?,
        };
        for (ty, msg_body) in [
            (HandshakeType::ServerHello, server_hello.serialize(false)),
            (
                HandshakeType::Certificate,
                CertificateMessage {
                    certificates: vec![self.config.certificate.der().to_vec()],
                }
                .serialize(),
            ),
            (HandshakeType::ServerKeyExchange, ske.serialize()),
            (HandshakeType::ServerHelloDone, Vec::new()),
        ] {
            let seq = self.take_seq();
            let m = handshake::wrap(ty, seq, &msg_body);
            self.record_transcript(&m);
            out.extend_from_slice(&RecordLayer::plaintext_record(content_type::HANDSHAKE, &m));
        }
        Ok(())
    }

    fn ske_signature_input(&self, pub_key: &[u8]) -> Vec<u8> {
        let ske = ServerKeyExchange {
            point: pub_key.to_vec(),
            signature: Vec::new(),
        };
        let mut input = Vec::with_capacity(64 + ske.signed_params().len());
        input.extend_from_slice(&self.client_random);
        input.extend_from_slice(&self.server_random);
        input.extend_from_slice(&ske.signed_params());
        input
    }

    /// Client flight: Certificate + ClientKeyExchange + CCS + Finished.
    fn client_send_flight(&mut self, out: &mut Vec<u8>) -> Result<(), DtlsError> {
        let cert_body = CertificateMessage {
            certificates: vec![self.config.certificate.der().to_vec()],
        }
        .serialize();
        let seq = self.take_seq();
        let cert_msg = handshake::wrap(HandshakeType::Certificate, seq, &cert_body);
        self.record_transcript(&cert_msg);
        out.extend_from_slice(&RecordLayer::plaintext_record(content_type::HANDSHAKE, &cert_msg));

        let cke_body = ClientKeyExchange {
            point: self.ecdhe_public.clone(),
        }
        .serialize();
        let seq = self.take_seq();
        let cke_msg = handshake::wrap(HandshakeType::ClientKeyExchange, seq, &cke_body);
        self.record_transcript(&cke_msg);
        out.extend_from_slice(&RecordLayer::plaintext_record(content_type::HANDSHAKE, &cke_msg));

        out.extend_from_slice(&RecordLayer::plaintext_record(
            content_type::CHANGE_CIPHER_SPEC,
            &[1],
        ));

        let master = self
            .master_secret
            .clone()
            .ok_or(DtlsError::HandshakeFailed)?;
        let hash = tpt_webrtc_core::sha256(&self.transcript);
        let verify = prf::prf_sha256(&master, b"client finished", &hash, 12);
        let seq = self.take_seq();
        let fin = handshake::wrap(
                        HandshakeType::Finished,
                        seq,
                        &Finished { verify_data: verify }.serialize(),
                    );
        self.record_transcript(&fin);
        let encrypted = self.record.protect(content_type::HANDSHAKE, &fin)?;
        out.extend_from_slice(&encrypted);
        Ok(())
    }

    fn activate_keys(&mut self) {
        let master = self.master_secret.clone().expect("keys after master secret");
        let keys = prf::key_block(&master, &self.client_random, &self.server_random);
        self.record.activate(self.config.role == DtlsRole::Client, &keys);
    }

    fn export_srtp_keys(&mut self) -> Result<(), DtlsError> {
        let master = self
            .master_secret
            .clone()
            .ok_or(DtlsError::HandshakeFailed)?;
        let exporter =
            prf::exporter_master_secret(&master, &self.client_random, &self.server_random);
        let export = prf::export_keying_material(
            &exporter,
            b"EXTRACTOR-dtls_srtp",
            &self.client_random,
            &self.server_random,
            60,
        );
        self.srtp_keys = Some(prf::srtp_keys_from_export(&export)?);
        Ok(())
    }

    fn ecdhe_agree(&mut self, peer_point: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let private = self.ecdhe.take().ok_or(DtlsError::HandshakeFailed)?;
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_point);
        agreement::agree_ephemeral(private, &peer, |shared| shared.to_vec())
            .map_err(|_| DtlsError::HandshakeFailed)
    }

    /// Sends application data once connected. Returns the encrypted
    /// datagram to transmit.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] before the handshake completed.
    pub async fn send_application_data(&mut self, data: &[u8]) -> Result<Vec<u8>, DtlsError> {
        if self.state != DtlsState::Connected {
            return Err(DtlsError::InvalidState);
        }
        self.record.protect(content_type::APPLICATION_DATA, data)
    }

    /// Pops one queued application-data message.
    #[must_use]
    pub fn recv_application_data(&mut self) -> Option<Vec<u8>> {
        self.inbound_app.pop_front()
    }

    /// Closes the transport.
    pub fn close(&mut self) {
        self.state = DtlsState::Closed;
    }
}

fn generate_ecdhe() -> Result<(agreement::EphemeralPrivateKey, Vec<u8>), DtlsError> {
    let rng = SystemRandom::new();
    let private =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| DtlsError::Crypto)?;
    let public = private
        .compute_public_key()
        .map_err(|_| DtlsError::Crypto)?;
    Ok((private, public.as_ref().to_vec()))
}
