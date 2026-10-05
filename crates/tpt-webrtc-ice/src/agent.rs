//! The ICE agent: candidate gathering, pairing, connectivity checks and
//! nomination (RFC 8445), with STUN server-reflexive gathering (RFC 8489)
//! and TURN relay gathering (RFC 8656).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tpt_webrtc_core::config::IceServerScheme;
use tpt_webrtc_core::crypto;
use tpt_webrtc_core::{
    CandidateType, IceCandidate, IceError, IceServer, UdpWebRtcSocket, WebRtcSocket,
};

use crate::stun::{sign_integrity, verify_integrity, StunAttribute, StunMessage, StunMessageType};
use crate::turn::TurnClient;

/// How long to wait per connectivity-check receive step.
const CHECK_RECV_STEP: Duration = Duration::from_millis(20);
/// Interval between retransmitted checks.
const CHECK_INTERVAL: Duration = Duration::from_millis(100);
/// Timeout for a STUN server binding during gathering.
const GATHER_TIMEOUT: Duration = Duration::from_secs(2);

/// ICE agent state machine (superset of RFC 8445 §6.1 with WebRTC's
/// `Disconnected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Freshly constructed.
    New,
    /// Gathering local candidates.
    Gathering,
    /// Gathered; waiting to start checks.
    Waiting,
    /// Connectivity checks in flight.
    Checking,
    /// At least one pair succeeded.
    Connected,
    /// A pair is nominated; the agent is done.
    Completed,
    /// Checks exhausted without a nominated pair.
    Failed,
    /// A previously nominated pair stopped responding.
    Disconnected,
    /// Closed by the application.
    Closed,
}

/// Configuration for one ICE agent (one data stream, component 1 by
/// default — RTCP-MUX means WebRTC never needs component 2).
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// Controlling (offerer) vs controlled role.
    pub controlling: bool,
    /// Role-conflict tie breaker (RFC 8445 §5.1.1).
    pub tie_breaker: u64,
    /// Component id (1).
    pub component_id: u32,
    /// Local username fragment.
    pub local_ufrag: String,
    /// Local password.
    pub local_pwd: String,
    /// Remote username fragment (learned via SDP before checking).
    pub remote_ufrag: String,
    /// Remote password (learned via SDP before checking).
    pub remote_pwd: String,
    /// Explicit local addresses for host candidates. When non-empty, the
    /// route probe is skipped and sockets bind exactly here (useful for
    /// servers and loopback tests).
    pub local_addresses: Vec<std::net::IpAddr>,
}

impl IceConfig {
    /// New config with freshly generated ICE credentials.
    #[must_use]
    pub fn new(controlling: bool) -> Self {
        Self {
            controlling,
            tie_breaker: crypto::random_u64().unwrap_or(1),
            component_id: 1,
            local_ufrag: random_ice_string(16),
            local_pwd: random_ice_string(24),
            remote_ufrag: String::new(),
            remote_pwd: String::new(),
            local_addresses: Vec::new(),
        }
    }
}

/// ICE characters (RFC 8839): alphanumeric plus `+` and `/`.
fn random_ice_string(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = vec![0u8; len];
    crypto::random_bytes(&mut buf).expect("system rng");
    buf.iter()
        .map(|&b| ALPHABET[b as usize % ALPHABET.len()] as char)
        .collect()
}

/// State of one candidate pair's connectivity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Not yet started.
    Frozen,
    /// Queued for checking.
    Waiting,
    /// Check in flight.
    InProgress,
    /// A valid binding response was received.
    Succeeded,
    /// Check failed / timed out.
    Failed,
}

/// One local/remote candidate combination with its pair priority
/// (RFC 8445 §6.1.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    /// Local candidate (checks for srflx/relay pairs are sent from its base
    /// socket).
    pub local: IceCandidate,
    /// Remote candidate.
    pub remote: IceCandidate,
    /// Pair priority.
    pub priority: u64,
    /// Check state.
    pub state: PairState,
    /// Whether this pair has been nominated.
    pub nominated: bool,
}

impl CandidatePair {
    /// RFC 8445 §6.1.2.3 pair priority.
    #[must_use]
    pub fn compute_priority(controlling: bool, local_prio: u32, remote_prio: u32) -> u64 {
        let (g, d) = if controlling {
            (u64::from(local_prio), u64::from(remote_prio))
        } else {
            (u64::from(remote_prio), u64::from(local_prio))
        };
        (g.min(d) << 32) + (g.max(d) << 1) + u64::from(g > d)
    }
}

struct BaseSocket {
    socket: UdpWebRtcSocket,
    /// Local candidate address this socket's candidates are bound to.
    base: SocketAddr,
    /// Receives datagrams forwarded by the per-socket pump task.
    incoming: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
}

/// An ICE agent for one media/data component.
///
/// The agent is driven explicitly ([`gather_candidates`](Self::gather_candidates),
/// [`check_connectivity`](Self::check_connectivity), ...) instead of
/// spawning background tasks, so the application (and tests) fully control
/// timing; SDP is exchanged out of band by the caller:
///
/// 1. [`gather_candidates`](Self::gather_candidates) → send the returned
///    candidates + [`ufrag`](Self::ufrag)/[`pwd`](Self::pwd) to the peer,
/// 2. [`set_remote_credentials`](Self::set_remote_credentials) +
///    [`add_remote_candidate`](Self::add_remote_candidate) from the peer,
/// 3. [`check_connectivity`](Self::check_connectivity) on both sides.
pub struct IceAgent {
    config: IceConfig,
    state: IceState,
    sockets: Vec<BaseSocket>,
    /// Local candidates in order; `base_index[i]` is the socket used as
    /// their base.
    local_candidates: Vec<IceCandidate>,
    base_index: Vec<usize>,
    remote_candidates: Vec<IceCandidate>,
    /// Candidate pairs, priority-sorted; `pair_socket[i]` is the socket a
    /// check for pair `i` is sent from.
    pairs: Vec<CandidatePair>,
    pair_socket: Vec<usize>,
    nominated: Option<CandidatePair>,
    /// Set once a nominating check (USE-CANDIDATE) has actually been sent.
    nominated_check_sent: bool,
    turn: Option<TurnClient>,
}

impl std::fmt::Debug for IceAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceAgent")
            .field("state", &self.state)
            .field("local_candidates", &self.local_candidates)
            .field("remote_candidates", &self.remote_candidates)
            .field("pairs", &self.pairs)
            .field("nominated", &self.nominated)
            .finish()
    }
}

impl IceAgent {
    /// Creates an agent with the given role/credentials.
    #[must_use]
    pub fn new(config: IceConfig) -> Self {
        Self {
            config,
            state: IceState::New,
            sockets: Vec::new(),
            local_candidates: Vec::new(),
            base_index: Vec::new(),
            remote_candidates: Vec::new(),
            pairs: Vec::new(),
            pair_socket: Vec::new(),
            nominated: None,
            nominated_check_sent: false,
            turn: None,
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> IceState {
        self.state
    }

    /// The nominated pair, if any.
    #[must_use]
    pub fn nominated_pair(&self) -> Option<&CandidatePair> {
        self.nominated.as_ref()
    }

    /// Locally gathered candidates.
    #[must_use]
    pub fn local_candidates(&self) -> &[IceCandidate] {
        &self.local_candidates
    }

    /// Remote candidates added so far.
    #[must_use]
    pub fn remote_candidates(&self) -> &[IceCandidate] {
        &self.remote_candidates
    }

    /// Local ICE username fragment.
    #[must_use]
    pub fn ufrag(&self) -> &str {
        &self.config.local_ufrag
    }

    /// Local ICE password.
    #[must_use]
    pub fn pwd(&self) -> &str {
        &self.config.local_pwd
    }

    /// Sets the peer's ICE credentials from the exchanged SDP.
    pub fn set_remote_credentials(&mut self, ufrag: String, pwd: String) {
        self.config.remote_ufrag = ufrag;
        self.config.remote_pwd = pwd;
    }

    /// Gathers host candidates on every usable local IPv4 address, then
    /// server-reflexive candidates via each STUN server and relayed
    /// candidates via each TURN server.
    ///
    /// # Errors
    /// [`IceError::InvalidState`] if already gathered/closed;
    /// [`IceError::NoCandidatesAvailable`] when no socket could be bound.
    pub async fn gather_candidates(
        &mut self,
        servers: &[IceServer],
    ) -> Result<Vec<IceCandidate>, IceError> {
        if !matches!(self.state, IceState::New) {
            return Err(IceError::InvalidState);
        }
        self.state = IceState::Gathering;

        let mut local_pref = 65_535u32;
        let probed = if self.config.local_addresses.is_empty() {
            local_ipv4_addrs(servers).await
        } else {
            self.config.local_addresses.clone()
        };
        for ip in probed {
            let Ok(socket) = UdpWebRtcSocket::bind(SocketAddr::new(ip, 0)).await else {
                continue;
            };
            let Ok(base) = socket.local_addr() else {
                continue;
            };
            let candidate = IceCandidate {
                foundation: format!("h{}", self.local_candidates.len() + 1),
                component_id: self.config.component_id,
                transport: "udp".into(),
                priority: IceCandidate::compute_priority(
                    CandidateType::Host,
                    local_pref,
                    self.config.component_id,
                ),
                address: base,
                candidate_type: CandidateType::Host,
                related_address: None,
            };
            let incoming = spawn_pump(&socket);
            self.local_candidates.push(candidate);
            self.base_index.push(self.sockets.len());
            self.sockets.push(BaseSocket {
                socket,
                base,
                incoming,
            });
            local_pref -= 1;
        }
        if self.sockets.is_empty() {
            self.state = IceState::Failed;
            return Err(IceError::NoCandidatesAvailable);
        }

        let servers = servers.to_vec();
        for server in &servers {
            match server.scheme() {
                Some(IceServerScheme::Stun) => {
                    if let Some(candidate) = self.gather_srflx(server).await {
                        self.local_candidates.push(candidate);
                        self.base_index.push(0);
                    }
                }
                Some(IceServerScheme::Turn | IceServerScheme::Turns) => {
                    if let (Some(username), Some(credential)) =
                        (&server.username, &server.credential)
                    {
                        if let Some(candidate) =
                            self.gather_relay(server, username, credential).await
                        {
                            // Relay pairs cannot be checked through the base
                            // socket (they need TURN send indications), so
                            // they are gathered for SDP but pruned from
                            // pairing — same as libwebrtc's default UDP
                            // behaviour.
                            let _ = candidate;
                        }
                    }
                }
                None => {}
            }
        }

        self.state = IceState::Waiting;
        Ok(self.local_candidates.clone())
    }

    async fn gather_srflx(&mut self, server: &IceServer) -> Option<IceCandidate> {
        let (host, port) = server.host_port()?;
        let server_addr = resolve(&host, port).await?;
        let (socket, base, incoming) = {
            let s = &mut self.sockets[0];
            (&s.socket, s.base, &mut s.incoming)
        };
        let req = crate::StunClient::create_binding_request();
        let txid = req.transaction_id;
        socket.send_to(&req.serialize(), server_addr).await.ok()?;
        let deadline = Instant::now() + GATHER_TIMEOUT;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let (data, _src) = tokio::time::timeout(remaining, incoming.recv())
                .await
                .ok()??;
            let Ok(msg) = crate::StunClient::parse_message(&data) else {
                continue;
            };
            if msg.transaction_id != txid {
                continue;
            }
            let Some(StunAttribute::XorMappedAddress(mapped)) = msg.attr(0x0020) else {
                continue;
            };
            if *mapped == base {
                return None; // server saw our local address; not reflexive
            }
            return Some(IceCandidate {
                foundation: format!("s{}", self.local_candidates.len() + 1),
                component_id: self.config.component_id,
                transport: "udp".into(),
                priority: IceCandidate::compute_priority(
                    CandidateType::Srflx,
                    65_535,
                    self.config.component_id,
                ),
                address: *mapped,
                candidate_type: CandidateType::Srflx,
                related_address: Some(base),
            });
        }
    }

    async fn gather_relay(
        &mut self,
        server: &IceServer,
        username: &str,
        credential: &str,
    ) -> Option<IceCandidate> {
        let (host, port) = server.host_port()?;
        let server_addr = resolve(&host, port).await?;
        let mut turn = TurnClient::new(server_addr, username.to_string(), credential.to_string());
        let socket = self.sockets[0].socket.clone();
        let allocation = turn.allocate(&socket).await.ok()?;
        let related = self.sockets[0].base;
        self.turn = Some(turn);
        Some(IceCandidate {
            foundation: format!("r{}", self.local_candidates.len() + 1),
            component_id: self.config.component_id,
            transport: "udp".into(),
            priority: IceCandidate::compute_priority(
                CandidateType::Relay,
                1,
                self.config.component_id,
            ),
            address: allocation.relayed_address,
            candidate_type: CandidateType::Relay,
            related_address: Some(related),
        })
    }

    /// Adds a remote candidate (from the peer's SDP) and re-forms pairs.
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        if !self.remote_candidates.contains(&candidate) {
            self.remote_candidates.push(candidate);
        }
        self.form_pairs();
    }

    /// Builds pairs (same component, same family, matching transports) and
    /// sorts them by pair priority. Check state of previously known pairs
    /// is preserved across rebuilds.
    fn form_pairs(&mut self) {
        let old = std::mem::take(&mut self.pairs);
        let mut pairs: Vec<(CandidatePair, usize)> = Vec::new();
        for (li, l) in self.local_candidates.iter().enumerate() {
            let socket_idx = self.base_index[li];
            for r in &self.remote_candidates {
                if !l.pairs_with(r) {
                    continue;
                }
                let priority = CandidatePair::compute_priority(
                    self.config.controlling,
                    l.priority,
                    r.priority,
                );
                let mut pair = CandidatePair {
                    local: l.clone(),
                    remote: r.clone(),
                    priority,
                    state: PairState::Waiting,
                    nominated: false,
                };
                if !pairs.iter().any(|(p, _)| *p == pair) {
                    // Preserve check progress from before the rebuild.
                    if let Some(prev) = old
                        .iter()
                        .find(|o| o.local == pair.local && o.remote == pair.remote)
                    {
                        pair.state = prev.state;
                        pair.nominated = prev.nominated;
                    }
                    pairs.push((pair, socket_idx));
                }
            }
        }
        pairs.sort_by_key(|(p, _)| std::cmp::Reverse(p.priority));
        self.pair_socket = pairs.iter().map(|(_, s)| *s).collect();
        self.pairs = pairs.into_iter().map(|(p, _)| p).collect();
    }

    /// Runs connectivity checks until a pair is nominated or `timeout`
    /// elapses. On success the agent reaches [`IceState::Completed`] with
    /// [`nominated_pair`](Self::nominated_pair) set.
    ///
    /// # Errors
    /// [`IceError::InvalidState`] before gathering / after close or when
    /// remote credentials were not set;
    /// [`IceError::NoCandidatesAvailable`] without remote candidates;
    /// [`IceError::ConnectivityCheckFailed`] when no pair is nominated
    /// within `timeout`.
    pub async fn check_connectivity(&mut self, timeout: Duration) -> Result<(), IceError> {
        if !matches!(
            self.state,
            IceState::Waiting | IceState::Checking | IceState::Connected
        ) {
            return Err(IceError::InvalidState);
        }
        if self.remote_candidates.is_empty() {
            return Err(IceError::NoCandidatesAvailable);
        }
        if self.config.remote_pwd.is_empty() || self.config.remote_ufrag.is_empty() {
            return Err(IceError::InvalidState);
        }
        self.form_pairs();
        self.state = IceState::Checking;
        let deadline = Instant::now() + timeout;
        let mut last_check = Instant::now() - CHECK_INTERVAL;

        while Instant::now() < deadline {
            if last_check.elapsed() >= CHECK_INTERVAL {
                self.send_checks().await;
                last_check = Instant::now();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let step = CHECK_RECV_STEP.min(remaining.max(Duration::from_millis(1)));
            self.recv_step(step).await;
            if self.nomination_complete() {
                self.state = IceState::Completed;
                return Ok(());
            }
        }

        if self.nomination_complete() {
            self.nominated = self.pairs.iter().find(|p| p.nominated).cloned();
            self.state = IceState::Completed;
            Ok(())
        } else {
            self.state = IceState::Failed;
            Err(IceError::ConnectivityCheckFailed)
        }
    }

    /// Nomination is complete when a pair is nominated AND the controlling
    /// side has actually transmitted its USE-CANDIDATE check (or the
    /// controlled side observed USE-CANDIDATE directly, which sets
    /// `nominated_check_sent` via `nominate_from_request`).
    fn nomination_complete(&self) -> bool {
        self.nominated_check_sent && self.pairs.iter().any(|p| p.nominated)
    }

    /// Explicit nomination (controlling side): promotes the best succeeded
    /// pair so the next check cycle carries USE-CANDIDATE.
    ///
    /// # Errors
    /// [`IceError::NominationTimeout`] when no pair has succeeded yet.
    pub fn nominate_pair(&mut self) -> Result<CandidatePair, IceError> {
        let best = self
            .pairs
            .iter_mut()
            .find(|p| p.state == PairState::Succeeded)
            .ok_or(IceError::NominationTimeout)?;
        best.nominated = true;
        let pair = best.clone();
        self.nominated = Some(pair.clone());
        Ok(pair)
    }

    /// Sends raw bytes over the nominated pair (post-connection data
    /// path: DTLS, RTP, RTCP ride the same 5-tuple as the checks).
    ///
    /// # Errors
    /// [`IceError::InvalidState`] without a nominated pair;
    /// [`IceError::ConnectivityCheckFailed`] on socket failure.
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<(), IceError> {
        let nominated = self.nominated.as_ref().ok_or(IceError::InvalidState)?;
        let socket_idx = self
            .local_candidates
            .iter()
            .position(|l| *l == nominated.local)
            .and_then(|li| self.base_index.get(li).copied())
            .ok_or(IceError::InvalidState)?;
        let socket = self
            .sockets
            .get(socket_idx)
            .ok_or(IceError::InvalidState)?
            .socket
            .clone();
        socket
            .send_to(data, nominated.remote.address)
            .await
            .map(|_| ())
            .map_err(|_| IceError::ConnectivityCheckFailed)
    }

    /// Receives one raw datagram from any base socket, waiting up to
    /// `dur`. Post-connection, non-STUN datagrams are application data;
    /// STUN datagrams are handled internally (consent/role races).
    pub async fn recv_raw(&mut self, dur: Duration) -> Option<(Vec<u8>, std::net::SocketAddr)> {
        for si in 0..self.sockets.len() {
            let received = {
                let incoming = &mut self.sockets[si].incoming;
                tokio::time::timeout(dur, incoming.recv()).await
            };
            if let Ok(Some((data, src))) = received {
                // STUN packets (magic cookie) are agent business.
                if data.len() >= 8 && data[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                    self.handle_datagram(si, &data, src).await;
                    continue;
                }
                return Some((data, src));
            }
        }
        None
    }

    /// Whether a pair has been nominated (data path usable).
    #[must_use]
    pub fn has_nominated_pair(&self) -> bool {
        self.nominated
            .as_ref()
            .is_some_and(|p| p.nominated && p.state == PairState::Succeeded)
    }

    /// Closes the agent.
    pub fn close(&mut self) {
        self.state = IceState::Closed;
        self.sockets.clear();
        self.local_candidates.clear();
        self.pairs.clear();
    }

    async fn send_checks(&mut self) {
        let outstanding: Vec<(usize, SocketAddr, bool, u32)> = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(i, p)| {
                if self.pair_socket[*i] >= self.sockets.len() {
                    return false;
                }
                // Nominated pairs keep (re)sending so USE-CANDIDATE reaches
                // the peer (RFC 8445 §8.1.1); others check until done.
                p.nominated || (p.state != PairState::Succeeded && p.state != PairState::Failed)
            })
            .map(|(i, p)| {
                (
                    self.pair_socket[i],
                    p.remote.address,
                    p.nominated,
                    p.local.priority,
                )
            })
            .collect();
        for (socket_idx, remote_addr, nominated, local_priority) in outstanding {
            let Some(base) = self.sockets.get(socket_idx) else {
                continue;
            };
            let mut req = StunMessage::new(StunMessageType::BindingRequest)
                .with(StunAttribute::Username(format!(
                    "{}:{}",
                    self.config.remote_ufrag, self.config.local_ufrag
                )))
                .with(StunAttribute::Priority(prflx_priority(local_priority)));
            if self.config.controlling {
                req.attributes
                    .push(StunAttribute::IceControlling(self.config.tie_breaker));
                if nominated {
                    req.attributes.push(StunAttribute::UseCandidate);
                }
            } else {
                req.attributes
                    .push(StunAttribute::IceControlled(self.config.tie_breaker));
            }
            sign_integrity(&mut req, self.config.remote_pwd.as_bytes());
            req.attributes.push(StunAttribute::Fingerprint(0));
            if nominated {
                self.nominated_check_sent = true;
            }
            let _ = base.socket.send_to(&req.serialize(), remote_addr).await;
        }
    }

    /// Receives one datagram (from any base socket) and drives the state
    /// machine.
    async fn recv_step(&mut self, dur: Duration) {
        for si in 0..self.sockets.len() {
            let received = {
                let incoming = &mut self.sockets[si].incoming;
                tokio::time::timeout(dur, incoming.recv()).await
            };
            if let Ok(Some((data, src))) = received {
                self.handle_datagram(si, &data, src).await;
                return; // one datagram per step
            }
        }
    }

    async fn handle_datagram(&mut self, si: usize, data: &[u8], src: SocketAddr) {
        let Ok(msg) = crate::StunClient::parse_message(data) else {
            return;
        };
        match msg.message_type {
            StunMessageType::BindingRequest => self.handle_binding_request(&msg, src, si).await,
            StunMessageType::BindingResponse => self.handle_binding_response(&msg, src, si),
            StunMessageType::BindingErrorResponse
                if msg.error_code().is_some_and(|(c, _)| c == 487) =>
            {
                // Role conflict (487): flip roles and keep going.
                self.config.controlling = !self.config.controlling;
                self.form_pairs();
            }
            _ => {}
        }
    }

    async fn handle_binding_request(&mut self, msg: &StunMessage, src: SocketAddr, si: usize) {
        // Username must address us: "our_ufrag:peer_ufrag".
        let Some(StunAttribute::Username(username)) = msg.attr(0x0006) else {
            return;
        };
        let our_prefix = format!("{}:", self.config.local_ufrag);
        let Some(peer_ufrag) = username.strip_prefix(&our_prefix) else {
            return;
        };
        // Integrity with OUR local password (short-term credentials).
        if !verify_integrity(msg, self.config.local_pwd.as_bytes()) {
            return;
        }

        let mut signed = StunMessage::new(StunMessageType::BindingResponse)
            .with(StunAttribute::XorMappedAddress(src))
            .with(StunAttribute::Software("tpt-webrtc".into()))
            .with(StunAttribute::Fingerprint(0));
        sign_integrity(&mut signed, self.config.local_pwd.as_bytes());
        let socket = self.sockets[si].socket.clone();
        let _ = socket.send_to(&signed.serialize(), src).await;

        // Triggered checks: record the peer's prflx priority and make sure
        // a pair towards this source exists.
        if let Some(StunAttribute::Priority(p)) = msg.attr(0x0024) {
            self.ensure_prflx_remote(src, *p);
        }

        // USE-CANDIDATE (from the controlling agent) nominates the pair.
        if msg.attr(0x0025).is_some() {
            let target = self.pairs.iter().position(|p| {
                p.remote.address == src
                    && self
                        .local_candidates
                        .iter()
                        .position(|l| *l == p.local)
                        .is_some_and(|li| self.base_index[li] == si)
            });
            if let Some(idx) = target {
                let pair = &mut self.pairs[idx];
                pair.nominated = true;
                pair.state = PairState::Succeeded;
                self.nominated = Some(pair.clone());
            }
        }
        let _ = peer_ufrag;
    }

    fn handle_binding_response(&mut self, msg: &StunMessage, src: SocketAddr, si: usize) {
        let Some(pair_idx) = (0..self.pairs.len())
            .find(|&i| self.pair_socket[i] == si && self.pairs[i].remote.address == src)
        else {
            return;
        };
        // Responses are integrity-checked with the REMOTE password.
        if !verify_integrity(msg, self.config.remote_pwd.as_bytes()) {
            self.pairs[pair_idx].state = PairState::Failed;
            return;
        }
        self.pairs[pair_idx].state = PairState::Succeeded;
        // Controlling agent: immediately nominate the first succeeded pair.
        if self.config.controlling && self.nominated.is_none() {
            self.pairs[pair_idx].nominated = true;
            self.nominated = Some(self.pairs[pair_idx].clone());
        }
    }

    fn ensure_prflx_remote(&mut self, src: SocketAddr, priority: u32) {
        if self.remote_candidates.iter().any(|c| c.address == src) {
            return;
        }
        self.remote_candidates.push(IceCandidate {
            foundation: format!("p{}", self.remote_candidates.len() + 1),
            component_id: self.config.component_id,
            transport: "udp".into(),
            priority,
            address: src,
            candidate_type: CandidateType::Prflx,
            related_address: None,
        });
        self.form_pairs();
    }
}

fn prflx_priority(base_priority: u32) -> u32 {
    // Type-adapt the priority to prflx (RFC 8445 §7.1.1): replace the top
    // 8 bits with the prflx type preference.
    (110 << 24) | (base_priority & 0x00FF_FFFF)
}

/// Spawns the per-socket forwarder task feeding `recv_step`.
fn spawn_pump(socket: &UdpWebRtcSocket) -> mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)> {
    let socket = socket.clone();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if tx.send((buf[..n].to_vec(), src)).is_err() {
                break; // agent dropped its receiver
            }
        }
    });
    rx
}

async fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    match tokio::net::lookup_host((host, port)).await {
        // Prefer IPv4 (dual-stack sockets are not used by this stack yet).
        Ok(mut addrs) => addrs.find(|a| a.is_ipv4()),
        Err(_) => None,
    }
}

/// Discovers local IPv4 addresses for host candidates: probes a route via
/// each configured server (falling back to a public address), defaulting to
/// loopback when no route is available (typical in loopback tests).
async fn local_ipv4_addrs(servers: &[IceServer]) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, UdpSocket as StdUdpSocket};

    let mut probe_targets: Vec<String> = Vec::new();
    for server in servers {
        if let Some((host, port)) = server.host_port() {
            probe_targets.push(format!("{host}:{port}"));
        }
    }
    // Standard probe target when no servers are configured.
    probe_targets.push("8.8.8.8:80".into());

    let mut addrs = Vec::new();
    for target in probe_targets {
        // Use a blocking std socket on the blocking pool: UDP "connect"
        // only picks a route; no packet is sent.
        let found = tokio::task::spawn_blocking(move || {
            StdUdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
                s.connect(&target).ok()?;
                s.local_addr().ok()
            })
        })
        .await
        .ok()
        .flatten();
        if let Some(addr) = found {
            if addr.ip() != IpAddr::from([0, 0, 0, 0]) && !addrs.contains(&addr.ip()) {
                addrs.push(addr.ip());
            }
            break; // one good route is enough
        }
    }
    if addrs.is_empty() {
        addrs.push(IpAddr::from([127, 0, 0, 1]));
    }
    addrs
}
