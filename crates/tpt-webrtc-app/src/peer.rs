//! The `PeerConnection`: negotiation, the ICE/DTLS/SCTP event loop and the
//! data/media path.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tpt_webrtc_core::{IceCandidate, IceError, IceServer, SdpError, WebRtcError};
use tpt_webrtc_dtls::{DtlsConfig, DtlsRole, DtlsState, DtlsTransport};
use tpt_webrtc_ice::{IceAgent, IceConfig, IceState};
use tpt_webrtc_rtp::MediaFrame;
use tpt_webrtc_sctp::{Reliability, SctpAssociation, SctpState};
use tpt_webrtc_sdp::{Attribute, OfferAnswerModel, SdpSession, SetupRole};

use crate::config::PeerConnectionConfig;
use crate::data_channel::{DataChannel, DataChannelConfig, DataChannelMessage, DataChannelState};
use crate::media::{srtp_pair, MediaStreamTrack, RtpReceiver, RtpSender};
use crate::{classify_datagram, DatagramKind, POLL_STEP};

/// Signaling states (W3C subset used by the stack).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignalingState {
    /// Stable; next event is an offer or answer.
    #[default]
    Stable,
    /// Local offer applied.
    HaveLocalOffer,
    /// Remote offer applied.
    HaveRemoteOffer,
    /// Closed.
    Closed,
}

/// ICE connection states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IceConnectionState {
    /// No candidates yet.
    #[default]
    New,
    /// Checks running.
    Checking,
    /// A pair is nominated.
    Connected,
    /// Checks failed.
    Failed,
    /// Closed.
    Closed,
}

/// Aggregate peer states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerConnectionState {
    /// Freshly created.
    #[default]
    New,
    /// ICE/DTLS/SCTP in progress.
    Connecting,
    /// Data path usable.
    Connected,
    /// Terminal failure.
    Failed,
    /// Closed.
    Closed,
}

/// A high-level WebRTC connection.
pub struct PeerConnection {
    config: PeerConnectionConfig,
    /// Local DTLS certificate (generated when not configured).
    certificate: tpt_webrtc_core::DtlsCertificate,
    ice: IceAgent,
    dtls: DtlsTransport,
    sctp: SctpAssociation,
    signaling_state: SignalingState,
    ice_state: IceConnectionState,
    peer_state: PeerConnectionState,
    /// DTLS client role (from the SDP setup attribute once negotiated).
    dtls_client: bool,
    dtls_started: bool,
    /// SRTP sessions (created at DTLS connect).
    srtp_tx: Option<tpt_webrtc_dtls::SrtpSession>,
    srtp_rx: Option<tpt_webrtc_dtls::SrtpSession>,
    /// Locally created data channels keyed by stream id.
    data_channels: VecDeque<DataChannel>,
    /// Streams waiting for SCTP establishment.
    pending_streams: VecDeque<(u16, tpt_webrtc_sctp::SctpStreamConfig)>,
    /// Sender/receiver for the (single) audio media section.
    sender: Option<RtpSender>,
    receiver: Option<RtpReceiver>,
    /// Gathered local candidates (attached to the SDP we generate).
    local_candidates: Vec<IceCandidate>,
    /// Negotiated: whether we are the offerer.
    is_offerer: bool,
    outbox: VecDeque<Vec<u8>>,
    /// Last DTLS flight we sent (for quiet-time retransmission).
    last_dtls_flight: Option<Vec<u8>>,
}

impl PeerConnection {
    /// Creates a connection in [`PeerConnectionState::New`].
    ///
    /// # Errors
    /// Propagates DTLS certificate generation failure.
    pub fn new(mut config: PeerConnectionConfig) -> Result<Self, WebRtcError> {
        let certificate = match config.dtls_certificates.pop() {
            Some(cert) => cert,
            None => tpt_webrtc_core::DtlsCertificate::generate().map_err(WebRtcError::from)?,
        };
        let dtls = DtlsTransport::new(DtlsConfig {
            certificate: certificate.clone(),
            role: DtlsRole::Client,
            expected_fingerprint: None,
        });
        let mut ice_config = IceConfig::new(true);
        ice_config.local_addresses = config.local_addresses.clone();
        Ok(Self {
            ice: IceAgent::new(ice_config),
            dtls,
            sctp: SctpAssociation::new(),
            config: PeerConnectionConfig {
                dtls_certificates: Vec::new(),
                ..config
            },
            certificate,
            signaling_state: SignalingState::Stable,
            ice_state: IceConnectionState::New,
            peer_state: PeerConnectionState::New,
            dtls_client: false,
            dtls_started: false,
            srtp_tx: None,
            srtp_rx: None,
            data_channels: VecDeque::new(),
            pending_streams: VecDeque::new(),
            sender: None,
            receiver: None,
            local_candidates: Vec::new(),
            is_offerer: true,
            outbox: VecDeque::new(),
            last_dtls_flight: None,
        })
    }

    /// Aggregate state.
    #[must_use]
    pub fn peer_connection_state(&self) -> PeerConnectionState {
        self.peer_state
    }

    /// ICE state.
    #[must_use]
    pub fn ice_connection_state(&self) -> IceConnectionState {
        self.ice_state
    }

    /// Signaling state.
    #[must_use]
    pub fn signaling_state(&self) -> SignalingState {
        self.signaling_state
    }

    /// The local DTLS fingerprint advertised in SDP.
    ///
    /// # Errors
    /// Propagates hashing failure.
    pub fn local_fingerprint(&self) -> Result<String, WebRtcError> {
        let fp = self.certificate.fingerprint()?;
        Ok(format!("{} {}", fp.hash_algorithm, fp.to_sdp_value()))
    }

    /// ICE servers in use (from config).
    #[must_use]
    pub fn ice_servers(&self) -> &[IceServer] {
        &self.config.ice_servers
    }

    /// Creates an offer: media sections per codec preferences, the data
    /// channel section, ICE credentials and the local fingerprint.
    /// Also gathers local candidates (non-trickle: they ride in the SDP).
    ///
    /// # Errors
    /// SDP generation or gathering failure.
    pub async fn create_offer(&mut self) -> Result<SdpSession, WebRtcError> {
        if self.signaling_state != SignalingState::Stable {
            return Err(WebRtcError::Sdp(SdpError::Semantic(
                "create_offer outside stable state".into(),
            )));
        }
        self.is_offerer = true;
        let mut sdp = OfferAnswerModel::create_offer(&tpt_webrtc_core::WebRtcConfig {
            ice_servers: self.config.ice_servers.clone(),
            codec_preferences: self.config.codec_preferences.clone(),
            bandwidth_estimation: self.config.bandwidth_estimation,
            dtls_certificates: vec![self.certificate.clone()],
        })?;
        self.add_ice_attributes(&mut sdp).await?;
        Ok(sdp)
    }

    /// Creates an answer for a received offer (setup: active — we take the
    /// DTLS client role after the offerer's actpass).
    ///
    /// # Errors
    /// SDP generation or gathering failure.
    pub async fn create_answer(&mut self, offer: &SdpSession) -> Result<SdpSession, WebRtcError> {
        if self.signaling_state != SignalingState::HaveRemoteOffer {
            return Err(WebRtcError::Sdp(SdpError::Semantic(
                "create_answer requires set_remote_description first".into(),
            )));
        }
        self.is_offerer = false;
        self.dtls_client = true; // actpass → active
        let mut sdp = OfferAnswerModel::create_answer(
            offer,
            &tpt_webrtc_core::WebRtcConfig {
                ice_servers: self.config.ice_servers.clone(),
                codec_preferences: self.config.codec_preferences.clone(),
                bandwidth_estimation: self.config.bandwidth_estimation,
                dtls_certificates: vec![self.certificate.clone()],
            },
        )?;
        self.add_ice_attributes(&mut sdp).await?;
        Ok(sdp)
    }

    async fn add_ice_attributes(&mut self, sdp: &mut SdpSession) -> Result<(), WebRtcError> {
        // ICE credentials are the agent's. `OfferAnswerModel` plants
        // placeholder credentials of its own; replace them so the SDP
        // carries exactly the credentials the checks are signed with.
        let ufrag = self.ice.ufrag().to_string();
        let pwd = self.ice.pwd().to_string();
        sdp.attributes
            .retain(|a| !matches!(a, Attribute::IceUfrag(_) | Attribute::IcePwd(_)));
        sdp.attributes.push(Attribute::IceUfrag(ufrag));
        sdp.attributes.push(Attribute::IcePwd(pwd));
        if self.local_candidates.is_empty() {
            self.local_candidates = self
                .ice
                .gather_candidates(&self.config.ice_servers)
                .await
                .map_err(WebRtcError::from)?;
        }
        if let Some(media) = sdp.media_descriptions.first_mut() {
            for c in &self.local_candidates {
                media.attributes.push(Attribute::IceCandidate(c.clone()));
            }
        }
        Ok(())
    }

    /// Applies a locally created description.
    ///
    /// # Errors
    /// [`WebRtcError::Sdp`] on invalid state transitions.
    pub fn set_local_description(&mut self, _sdp: &SdpSession) -> Result<(), WebRtcError> {
        match self.signaling_state {
            SignalingState::Stable if self.is_offerer => {
                self.signaling_state = SignalingState::HaveLocalOffer;
                Ok(())
            }
            SignalingState::HaveRemoteOffer => {
                self.signaling_state = SignalingState::Stable;
                Ok(())
            }
            _ => Err(WebRtcError::Sdp(SdpError::Semantic(
                "set_local_description in unexpected state".into(),
            ))),
        }
    }

    /// Applies the remote description: extracts ICE credentials, the DTLS
    /// fingerprint and candidates.
    ///
    /// # Errors
    /// [`WebRtcError::Sdp`] when the description lacks mandatory attributes.
    pub fn set_remote_description(&mut self, sdp: &SdpSession) -> Result<(), WebRtcError> {
        let ufrag = sdp
            .ice_ufrag(sdp.media_descriptions.first())
            .ok_or_else(|| WebRtcError::Sdp(SdpError::Missing("ice-ufrag".into())))?;
        let pwd = sdp
            .ice_pwd(sdp.media_descriptions.first())
            .ok_or_else(|| WebRtcError::Sdp(SdpError::Missing("ice-pwd".into())))?;
        self.ice.set_remote_credentials(ufrag, pwd);

        let (alg, fp) = sdp
            .fingerprint(sdp.media_descriptions.first())
            .ok_or_else(|| WebRtcError::Sdp(SdpError::Missing("fingerprint".into())))?;
        // RFC 5763 setup semantics, read from the REMOTE description:
        // remote `active`/`actpass` → we take the server/client role
        // respectively; remote `passive` → we are the client.
        let offered_setup = sdp.media_descriptions.first().and_then(|m| {
            m.attributes.iter().find_map(|a| match a {
                Attribute::Setup(r) => Some(*r),
                _ => None,
            })
        });
        let role = match offered_setup {
            Some(SetupRole::Passive) => DtlsRole::Client,
            Some(SetupRole::Active) => DtlsRole::Server,
            _ => DtlsRole::Client, // actpass offer: we answer active
        };
        self.dtls_client = role == DtlsRole::Client;
        self.dtls = DtlsTransport::new(DtlsConfig {
            certificate: self.certificate.clone(),
            role,
            expected_fingerprint: Some(tpt_webrtc_core::Fingerprint {
                hash_algorithm: alg,
                value: fp,
            }),
        });
        self.dtls_started = false;

        for media in &sdp.media_descriptions {
            for attr in &media.attributes {
                if let Attribute::IceCandidate(c) = attr {
                    self.ice.add_remote_candidate(c.clone());
                }
            }
        }

        if self.signaling_state == SignalingState::Stable {
            self.signaling_state = SignalingState::HaveRemoteOffer;
        } else if self.signaling_state == SignalingState::HaveLocalOffer {
            self.signaling_state = SignalingState::Stable;
        }
        Ok(())
    }

    /// Adds a remote candidate (trickle path).
    pub fn add_ice_candidate(&mut self, candidate: IceCandidate) {
        self.ice.add_remote_candidate(candidate);
    }

    /// Adds a local audio track and returns the sender.
    pub fn add_track(&mut self, track: MediaStreamTrack) -> &RtpSender {
        self.sender = Some(RtpSender::new_audio(track, 0));
        self.sender.as_ref().expect("just set")
    }

    /// Arms the receiver (remote track).
    pub fn add_remote_track(&mut self, track: MediaStreamTrack) {
        self.receiver = Some(RtpReceiver::new_audio(track));
    }

    /// Creates a data channel and returns its handle data.
    ///
    /// # Errors
    /// [`WebRtcError::Sctp`] when the channel cannot be registered.
    pub fn create_data_channel(
        &mut self,
        label: &str,
        config: DataChannelConfig,
    ) -> Result<u16, WebRtcError> {
        let id = self.data_channels.back().map_or(0, |c| c.stream_id + 1);
        let mut channel = DataChannel::new(label.to_string(), id, config);
        let sctp_config = tpt_webrtc_sctp::SctpStreamConfig {
            ordered: channel.config.ordered,
            reliability: channel.config.reliability.clone(),
        };
        if self.sctp.state() == SctpState::Established {
            let _ = self.sctp.open_stream(sctp_config);
            channel.mark_open();
        } else {
            // Opening is deferred to the SCTP establishment; keep state
            // Connecting until the association is up.
            channel.set_state(DataChannelState::Connecting);
            self.pending_streams.push_back((id, sctp_config));
        }
        self.data_channels.push_back(channel);
        Ok(id)
    }

    /// Sends bytes on a data channel.
    ///
    /// # Errors
    /// [`WebRtcError::Sctp`] when the association/stream is not ready.
    pub fn send_data_channel(
        &mut self,
        stream_id: u16,
        message: &DataChannelMessage,
    ) -> Result<(), WebRtcError> {
        if self.sctp.state() != SctpState::Established {
            return Err(WebRtcError::Sctp(tpt_webrtc_core::SctpError::InvalidState));
        }
        let (ppid, payload) = match message {
            DataChannelMessage::Text(t) => (tpt_webrtc_sctp::PPID_STRING, t.clone().into_bytes()),
            DataChannelMessage::Binary(b) => (tpt_webrtc_sctp::PPID_BINARY, b.clone()),
        };
        let wire = self
            .sctp
            .send(stream_id, &payload, ppid)
            .map_err(WebRtcError::from)?;
        self.outbox.push_back(wire);
        Ok(())
    }

    /// Pops one inbound data-channel message.
    #[must_use]
    pub fn recv_data_channel(&mut self, stream_id: u16) -> Option<DataChannelMessage> {
        self.data_channels
            .iter_mut()
            .find(|c| c.stream_id == stream_id)
            .and_then(|c| c.recv())
    }

    /// Marks a channel open and registers its SCTP stream (called once
    /// the association is established, and afterwards for late channels).
    fn open_local_channels(&mut self) {
        while let Some((_, config)) = self.pending_streams.pop_front() {
            let _ = self.sctp.open_stream(config);
        }
        for channel in &mut self.data_channels {
            if channel.state() == DataChannelState::Connecting {
                channel.mark_open();
            }
        }
    }

    /// Sends one media frame on the sender's track (SRTP over ICE).
    ///
    /// # Errors
    /// Media-path failures.
    pub fn send_media_frame(&mut self, frame: &MediaFrame) -> Result<(), WebRtcError> {
        let Some(mut sender) = self.sender.take() else {
            return Err(WebRtcError::Codec(
                tpt_webrtc_core::CodecError::Unsupported("no track added".into()),
            ));
        };
        let Some(mut tx) = self.srtp_tx.take() else {
            self.sender = Some(sender);
            return Err(WebRtcError::Dtls(tpt_webrtc_core::DtlsError::InvalidState));
        };
        let wires = sender.send(&mut tx, frame, 1200).map_err(|e| {
            WebRtcError::Rtp(tpt_webrtc_core::RtpError::Packetization(e.to_string()))
        })?;
        self.sender = Some(sender);
        self.srtp_tx = Some(tx);
        for w in wires {
            self.outbox.push_back(w);
        }
        Ok(())
    }

    /// Pops one received media frame.
    #[must_use]
    pub fn recv_media_frame(&mut self) -> Option<MediaFrame> {
        self.receiver.as_mut().and_then(|r| r.recv_frame())
    }

    /// Drives the connection for up to `dur`: receives datagrams on the
    /// ICE pair, demultiplexes (RFC 7983), advances ICE/DTLS/SCTP and
    /// flushes the outbox. Call repeatedly until
    /// [`peer_connection_state`](Self::peer_connection_state) is
    /// [`PeerConnectionState::Connected`], then continue polling to
    /// service the data/media path.
    pub async fn poll(&mut self, dur: Duration) {
        let deadline = Instant::now() + dur;
        // 1. Outbox first (checks, DTLS flights, SCTP, media).
        self.flush_outbox().await;
        // 2. Receive loop.
        while Instant::now() < deadline {
            let Some((data, _src)) = self.ice.recv_raw(POLL_STEP).await else {
                break;
            };
            self.handle_datagram(&data).await;
        }
        // 3. Late outgoing responses from the receive loop.
        self.flush_outbox().await;
        self.refresh_states();
    }

    async fn flush_outbox(&mut self) {
        while let Some(data) = self.outbox.pop_front() {
            if self.ice.send_raw(&data).await.is_err() {
                break; // socket gone; state refresh will report it
            }
        }
    }

    async fn handle_datagram(&mut self, data: &[u8]) {
        match classify_datagram(data) {
            DatagramKind::Stun => { /* consumed inside recv_raw */ }
            DatagramKind::Dtls => {
                if let Ok(Some(response)) = self.dtls.process_packet(data).await {
                    self.last_dtls_flight = Some(response.clone());
                    self.outbox.push_back(response);
                }
                if self.dtls.state() == DtlsState::Connected && self.srtp_tx.is_none() {
                    if let Some(keys) = self.dtls.srtp_keys().cloned() {
                        let (tx, rx) = srtp_pair(keys, self.dtls_client);
                        self.srtp_tx = Some(tx);
                        self.srtp_rx = Some(rx);
                        // Start SCTP: the answerer (DTLS client) initiates.
                        if !self.is_offerer {
                            let init = self.sctp.build_init();
                            if let Ok(wire) = self.dtls.send_application_data(&init).await {
                                self.outbox.push_back(wire);
                            }
                        }
                    }
                }
                // DTLS app data (SCTP) may now be queued.
                while let Some(app) = self.dtls.recv_application_data() {
                    if let Ok(Some(response)) = self.sctp.process_packet(&app) {
                        if let Ok(wire) = self.dtls.send_application_data(&response).await {
                            self.outbox.push_back(wire);
                        }
                    }
                    // Remotely opened channels become local handles.
                    while let Some((stream_id, open)) = self.sctp.pop_remote_channel() {
                        let mut channel = DataChannel::new(
                            open.label.clone(),
                            stream_id,
                            DataChannelConfig {
                                ordered: open.channel_type & 128 == 0,
                                reliability: Reliability::Reliable,
                                protocol: open.protocol.clone(),
                            },
                        );
                        channel.mark_open();
                        self.data_channels.push_back(channel);
                    }
                    // Deliver user messages to their data channels.
                    while let Some(msg) = self.sctp.recv() {
                        if let Some(channel) = self
                            .data_channels
                            .iter_mut()
                            .find(|c| c.stream_id == msg.stream_id)
                        {
                            if let Ok(m) = DataChannel::message_from_sctp(&msg) {
                                channel.queue_inbound(m);
                            }
                        }
                    }
                }
                if self.dtls.state() == DtlsState::Connected
                    && self.sctp.state() == SctpState::Established
                {
                    self.open_local_channels();
                }
            }
            DatagramKind::Rtp => {
                if let Some(mut rx) = self.receiver.take() {
                    if let Some(mut session) = self.srtp_rx.take() {
                        let _ = rx.receive(&mut session, data);
                        self.srtp_rx = Some(session);
                    }
                    self.receiver = Some(rx);
                }
            }
            DatagramKind::Unknown => {}
        }
    }

    async fn start_dtls_if_needed(&mut self) -> Result<(), WebRtcError> {
        if self.dtls_started || self.ice_state != IceConnectionState::Connected {
            return Ok(());
        }
        self.dtls_started = true;
        // Both roles must arm: the client gets flight 1 (ClientHello), the
        // server transitions to Connecting so process_packet accepts it.
        if let Some(flight) = self
            .dtls
            .start_handshake()
            .await
            .map_err(WebRtcError::from)?
        {
            self.last_dtls_flight = Some(flight.clone());
            self.outbox.push_back(flight);
        }
        Ok(())
    }

    fn refresh_states(&mut self) {
        self.ice_state = match self.ice.state() {
            IceState::New => IceConnectionState::New,
            IceState::Gathering | IceState::Waiting | IceState::Checking => {
                IceConnectionState::Checking
            }
            IceState::Connected | IceState::Completed => IceConnectionState::Connected,
            IceState::Failed | IceState::Disconnected => IceConnectionState::Failed,
            IceState::Closed => IceConnectionState::Closed,
        };
        if self.peer_state == PeerConnectionState::New && self.ice_state != IceConnectionState::New
        {
            self.peer_state = PeerConnectionState::Connecting;
        }
        if self.sctp.state() == SctpState::Established {
            self.open_local_channels();
        }
        if self.ice.has_nominated_pair()
            && self.dtls.state() == DtlsState::Connected
            && self.sctp.state() == SctpState::Established
        {
            self.peer_state = PeerConnectionState::Connected;
            if self.signaling_state == SignalingState::HaveLocalOffer
                || self.signaling_state == SignalingState::HaveRemoteOffer
            {
                self.signaling_state = SignalingState::Stable;
            }
        }
        if self.ice_state == IceConnectionState::Failed {
            self.peer_state = PeerConnectionState::Failed;
        }
    }

    /// Runs ICE checks and then pumps the DTLS/SCTP handshake until the
    /// data path is fully up (or `timeout` elapses). Convenience wrapper
    /// around repeated [`poll`](Self::poll) calls.
    ///
    /// # Errors
    /// [`WebRtcError::Ice`] when checks fail.
    pub async fn connect(&mut self, timeout: Duration) -> Result<(), WebRtcError> {
        let deadline = Instant::now() + timeout;
        self.ice
            .check_connectivity(timeout)
            .await
            .map_err(WebRtcError::from)?;
        // Quiet-time retransmission: DTLS flights and the SCTP INIT go out
        // unreliably; when no state progress happens within 500 ms, resend
        // the last flight (and/or the INIT) until progress or deadline.
        let mut last_snapshot = (self.dtls.state(), self.sctp.state());
        let mut last_activity = Instant::now();
        while Instant::now() < deadline {
            self.poll(POLL_STEP).await;
            self.start_dtls_if_needed().await?;
            if self.peer_state == PeerConnectionState::Connected {
                return Ok(());
            }
            if self.peer_state == PeerConnectionState::Failed {
                return Err(WebRtcError::Ice(IceError::ConnectivityCheckFailed));
            }
            let snapshot = (self.dtls.state(), self.sctp.state());
            if snapshot != last_snapshot {
                last_snapshot = snapshot;
                last_activity = Instant::now();
            } else if last_activity.elapsed() >= Duration::from_millis(500) {
                last_activity = Instant::now();
                if self.dtls.state() == DtlsState::Connecting {
                    if let Some(flight) = &self.last_dtls_flight {
                        self.outbox.push_back(flight.clone());
                    }
                }
                if self.dtls.state() == DtlsState::Connected
                    && self.sctp.state() != SctpState::Established
                    && !self.is_offerer
                {
                    let init = self.sctp.build_init();
                    if let Ok(wire) = self.dtls.send_application_data(&init).await {
                        self.outbox.push_back(wire);
                    }
                }
            }
        }
        Err(WebRtcError::Ice(IceError::NominationTimeout))
    }

    /// SCTP association state (data-channel readiness).
    #[must_use]
    pub fn sctp_state(&self) -> SctpState {
        self.sctp.state()
    }

    /// DTLS state.
    #[must_use]
    pub fn dtls_state(&self) -> DtlsState {
        self.dtls.state()
    }

    /// Data channel count.
    #[must_use]
    pub fn data_channel_count(&self) -> usize {
        self.data_channels.len()
    }

    /// Data channel state by stream id.
    #[must_use]
    pub fn data_channel_state(&self, stream_id: u16) -> Option<DataChannelState> {
        self.data_channels
            .iter()
            .find(|c| c.stream_id == stream_id)
            .map(DataChannel::state)
    }

    /// Closes the connection.
    pub fn close(&mut self) {
        self.sctp.shutdown();
        self.dtls.close();
        self.ice.close();
        for c in &mut self.data_channels {
            c.set_state(DataChannelState::Closed);
        }
        self.signaling_state = SignalingState::Closed;
        self.peer_state = PeerConnectionState::Closed;
    }
}
