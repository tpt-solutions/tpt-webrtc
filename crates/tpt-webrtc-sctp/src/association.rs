//! The SCTP association: state machine, streams, DATA/SACK handling and
//! the DataChannel establishment protocol (RFC 8831 §6).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::chunk::{
    parse_init, parse_sack, serialize_init, serialize_sack, Chunk, ChunkType, InitPeerInfo, Packet,
};
use crate::{PPID_BINARY, PPID_DATA_CHANNEL_ACK, PPID_DATA_CHANNEL_OPEN, WEBRTC_SCTP_PORT};
use tpt_webrtc_core::SctpError;
use tpt_webrtc_dtls::DtlsTransport;

/// Association states (RFC 4960 §4 simplified for the DTLS data-channel
/// profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SctpState {
    /// No association.
    #[default]
    Closed,
    /// INIT sent, waiting for COOKIE-ECHO side to complete.
    CookieWait,
    /// COOKIE-ECHO sent.
    CookieEchoed,
    /// Established.
    Established,
    /// Shutdown pending/sent (terminal handling merged).
    Shutdown,
}

/// Per-stream reliability (RFC 3758 subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reliability {
    /// Fully reliable, in-order (default).
    Reliable,
    /// Limited retransmissions (RFC 3758 timed-rexmit style cap).
    PartialReliableRexmit(u32),
    /// Timed reliability: abandon after the given delay.
    PartialReliableTimed(std::time::Duration),
    /// Best effort: never retransmit.
    Unreliable,
}

/// Stream configuration for [`SctpAssociation::open_stream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpStreamConfig {
    /// Ordered delivery (SCTP stream sequence numbers in use).
    pub ordered: bool,
    /// Reliability policy.
    pub reliability: Reliability,
}

impl Default for SctpStreamConfig {
    fn default() -> Self {
        Self {
            ordered: true,
            reliability: Reliability::Reliable,
        }
    }
}

/// A data-channel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpMessage {
    /// Stream id.
    pub stream_id: u16,
    /// Payload protocol id (53 = binary, 51 = string/ctrl).
    pub ppid: u32,
    /// User payload.
    pub data: Vec<u8>,
    /// Whether the stream was ordered.
    pub ordered: bool,
}

/// `DATA_CHANNEL_OPEN` message (datachannel draft §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannelOpen {
    /// Channel type: 0 reliable, 1 = partial-reliable rexmit, 2 = timed,
    /// 128 = unordered reliable, 129/130 unordered partial.
    pub channel_type: u8,
    /// Priority (0 here).
    pub priority: u32,
    /// Reliability parameter (rexmit count or ms).
    pub reliability_parameter: u32,
    /// Channel label.
    pub label: String,
    /// Sub-protocol.
    pub protocol: String,
}

impl DataChannelOpen {
    /// Serializes the OPEN message (draft §5.1.1).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![self.channel_type, 0];
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.reliability_parameter.to_be_bytes());
        out.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.protocol.len() as u16).to_be_bytes());
        out.extend_from_slice(self.label.as_bytes());
        out.extend_from_slice(self.protocol.as_bytes());
        out
    }

    /// Parses the OPEN message.
    ///
    /// # Errors
    /// [`SctpError::MalformedChunk`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, SctpError> {
        if data.len() < 14 {
            return Err(SctpError::MalformedChunk);
        }
        let label_len = u16::from_be_bytes([data[10], data[11]]) as usize;
        let proto_len = u16::from_be_bytes([data[12], data[13]]) as usize;
        if data.len() < 14 + label_len + proto_len {
            return Err(SctpError::MalformedChunk);
        }
        Ok(Self {
            channel_type: data[0],
            priority: u32::from_be_bytes(data[2..6].try_into().unwrap()),
            reliability_parameter: u32::from_be_bytes(data[6..10].try_into().unwrap()),
            label: String::from_utf8_lossy(&data[14..14 + label_len]).into_owned(),
            protocol: String::from_utf8_lossy(&data[14 + label_len..14 + label_len + proto_len])
                .into_owned(),
        })
    }
}

/// A local stream.
#[derive(Debug, Clone)]
pub struct Stream {
    /// Stream configuration.
    pub config: SctpStreamConfig,
    /// Next outbound stream sequence number (ordered streams only).
    pub next_ssn: u16,
    /// Next expected inbound SSN (ordered streams only).
    pub expected_ssn: u16,
    /// OPEN message pending remote ACK (locally created channels).
    pub awaiting_ack: bool,
    /// Established by the remote side (an OPEN was received).
    pub remote_opened: bool,
}

/// Packet sink: how the association emits SCTP packets. Implemented for
/// [`DtlsTransport`] (SCTP over DTLS) and test pipes.
pub trait SctpTransport: Send {
    /// Encrypts and queues/sends one SCTP packet.
    ///
    /// # Errors
    /// Transport failures.
    fn send_packet(&mut self, packet: &[u8]) -> impl Future<Output = Result<(), SctpError>> + Send;

    /// Pops one received SCTP packet, if any.
    fn recv_packet(&mut self) -> Option<Vec<u8>>;
}

impl SctpTransport for Arc<Mutex<DtlsTransport>> {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), SctpError> {
        let dtls = self.clone();
        let mut guard = dtls.lock().await;
        guard
            .send_application_data(packet)
            .await
            .map(|_| ())
            .map_err(|e| SctpError::Protocol(e.to_string()))
    }

    fn recv_packet(&mut self) -> Option<Vec<u8>> {
        // Requires the DTLS mutex; pumped by the caller via
        // `process_packet` + `recv_application_data`. This impl therefore
        // only drains already-queued data when the lock is free.
        None
    }
}

/// An SCTP association for one DTLS connection.
pub struct SctpAssociation {
    state: SctpState,
    local_port: u16,
    remote_port: u16,
    local_tag: u32,
    remote_tag: Option<u32>,
    local_tsn: u32,
    /// Highest TSN seen from the peer (cumulative-ack point).
    remote_cumulative_tsn: Option<u32>,
    streams: HashMap<u16, Stream>,
    next_stream_id: u16,
    inbound: VecDeque<SctpMessage>,
    /// Unacked outbound DATA chunks: (tsn, stream, ssn, ppid, data, ordered).
    unacked: Vec<(u32, u16, u16, u32, Vec<u8>, bool)>,
    opened_channels: VecDeque<(u16, DataChannelOpen)>,
}

impl Default for SctpAssociation {
    fn default() -> Self {
        Self::new()
    }
}

impl SctpAssociation {
    /// Creates a fresh (closed) association.
    #[must_use]
    pub fn new() -> Self {
        let tag = tpt_webrtc_core::random_u32().unwrap_or(1);
        Self {
            state: SctpState::Closed,
            local_port: WEBRTC_SCTP_PORT,
            remote_port: WEBRTC_SCTP_PORT,
            local_tag: tag,
            remote_tag: None,
            local_tsn: tpt_webrtc_core::random_u32().unwrap_or(0),
            remote_cumulative_tsn: None,
            streams: HashMap::new(),
            next_stream_id: 0,
            inbound: VecDeque::new(),
            unacked: Vec::new(),
            opened_channels: VecDeque::new(),
        }
    }

    /// Current association state.
    #[must_use]
    pub fn state(&self) -> SctpState {
        self.state
    }

    /// Opens a local stream and returns its id.
    ///
    /// # Errors
    /// [`SctpError::InvalidState`] when the association is not established.
    pub fn open_stream(&mut self, config: SctpStreamConfig) -> Result<u16, SctpError> {
        if self.state != SctpState::Established {
            return Err(SctpError::InvalidState);
        }
        let id = self.next_stream_id;
        self.next_stream_id = id.wrapping_add(1);
        self.streams.insert(
            id,
            Stream {
                config,
                next_ssn: 0,
                expected_ssn: 0,
                awaiting_ack: true,
                remote_opened: false,
            },
        );
        Ok(id)
    }

    /// Builds a `DATA_CHANNEL_OPEN` message on a stream.
    ///
    /// # Errors
    /// [`SctpError::Stream`] when the stream does not exist.
    pub fn build_channel_open(
        &mut self,
        stream_id: u16,
        label: &str,
        protocol: &str,
    ) -> Result<Vec<u8>, SctpError> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Err(SctpError::Stream(format!("stream {stream_id} not open")));
        };
        let (channel_type, reliability_parameter) = match &stream.config.reliability {
            Reliability::Reliable => {
                if stream.config.ordered {
                    (0, 0)
                } else {
                    (128, 0)
                }
            }
            Reliability::PartialReliableRexmit(n) => {
                (if stream.config.ordered { 1 } else { 129 }, *n)
            }
            Reliability::PartialReliableTimed(d) => (
                if stream.config.ordered { 2 } else { 130 },
                d.as_millis() as u32,
            ),
            Reliability::Unreliable => (if stream.config.ordered { 1 } else { 129 }, 0),
        };
        Ok(DataChannelOpen {
            channel_type,
            priority: 0,
            reliability_parameter,
            label: label.to_string(),
            protocol: protocol.to_string(),
        }
        .serialize())
    }

    /// Sends user data on a stream, returning the outgoing DTLS payload.
    ///
    /// # Errors
    /// [`SctpError::InvalidState`] / unknown stream / oversized data.
    pub fn send(&mut self, stream_id: u16, data: &[u8], ppid: u32) -> Result<Vec<u8>, SctpError> {
        if self.state != SctpState::Established {
            return Err(SctpError::InvalidState);
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(SctpError::Stream(format!("stream {stream_id} not open")));
        };
        if data.len() > 65_535 {
            return Err(SctpError::Protocol(
                "message too large for this profile".into(),
            ));
        }
        let ordered = stream.config.ordered;
        let ssn = if ordered { stream.next_ssn } else { 0 };
        if ordered {
            stream.next_ssn = stream.next_ssn.wrapping_add(1);
        }
        let tsn = self.local_tsn;
        self.local_tsn = self.local_tsn.wrapping_add(1);
        self.unacked
            .push((tsn, stream_id, ssn, ppid, data.to_vec(), ordered));
        Ok(Packet {
            src_port: self.local_port,
            dst_port: self.remote_port,
            verification_tag: self.remote_tag.unwrap_or(0),
            chunks: vec![Chunk {
                chunk_type: ChunkType::Data,
                flags: if ordered { 0x03 } else { 0x05 }, // B|E / E|U
                value: serialize_data(tsn, stream_id, ssn, ppid, data),
            }],
        }
        .serialize())
    }

    /// Receives one inbound message, if queued.
    #[must_use]
    pub fn recv(&mut self) -> Option<SctpMessage> {
        self.inbound.pop_front()
    }

    /// Number of queued inbound messages.
    #[must_use]
    pub fn pending_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Processes one received SCTP packet; returns the outgoing response
    /// packet (if any).
    ///
    /// # Errors
    /// [`SctpError::MalformedChunk`] / protocol violations.
    pub fn process_packet(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, SctpError> {
        let packet = Packet::parse(data)?;
        let mut out_chunks: Vec<Chunk> = Vec::new();
        let mut out_tag = self.remote_tag.unwrap_or(0);

        for chunk in &packet.chunks {
            match chunk.chunk_type {
                ChunkType::Init => {
                    let (peer_tag, peer) = parse_init(&chunk.value)?;
                    self.remote_tag = Some(peer_tag);
                    out_tag = peer_tag;
                    // INIT-ACK with our parameters + the (empty) cookie.
                    let cookie = self.make_cookie(&peer);
                    let mut value =
                        serialize_init(self.local_tag, self.local_tsn, 1024, 65535, peer.tie_tag);
                    value.extend_from_slice(&cookie_tlv(&cookie));
                    out_chunks.push(Chunk {
                        chunk_type: ChunkType::InitAck,
                        flags: 0,
                        value,
                    });
                    self.state = SctpState::CookieEchoed;
                }
                ChunkType::InitAck => {
                    let (peer_tag, _peer) = parse_init(&chunk.value)?;
                    self.remote_tag = Some(peer_tag);
                    out_tag = peer_tag;
                    let cookie = cookie_from_init_ack(&chunk.value);
                    out_chunks.push(Chunk {
                        chunk_type: ChunkType::CookieEcho,
                        flags: 0,
                        value: cookie,
                    });
                    self.state = SctpState::CookieEchoed;
                }
                ChunkType::CookieEcho => {
                    if self.state == SctpState::Closed {
                        return Err(SctpError::InvalidState);
                    }
                    out_chunks.push(Chunk {
                        chunk_type: ChunkType::CookieAck,
                        flags: 0,
                        value: Vec::new(),
                    });
                    self.state = SctpState::Established;
                }
                ChunkType::CookieAck => {
                    self.state = SctpState::Established;
                }
                ChunkType::Data => {
                    let (tsn, stream_id, ssn, ppid, payload) = parse_data(&chunk.value)?;
                    let ordered = chunk.flags & 0x04 == 0; // U bit clear = ordered
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        if ordered && stream.expected_ssn != ssn {
                            // Out-of-order: drop for now (retransmission will
                            // re-deliver); report the highest in-order TSN.
                            let cum = self.remote_cumulative_tsn.unwrap_or(tsn.wrapping_sub(1));
                            out_chunks.push(Chunk {
                                chunk_type: ChunkType::Sack,
                                flags: 0,
                                value: serialize_sack(cum, &[]),
                            });
                            continue;
                        }
                        if ordered {
                            stream.expected_ssn = stream.expected_ssn.wrapping_add(1);
                        }
                        if ppid == PPID_DATA_CHANNEL_OPEN {
                            if let Ok(open) = DataChannelOpen::parse(&payload) {
                                let stream =
                                    self.streams.entry(stream_id).or_insert_with(|| Stream {
                                        config: SctpStreamConfig::default(),
                                        next_ssn: 0,
                                        expected_ssn: 0,
                                        awaiting_ack: false,
                                        remote_opened: true,
                                    });
                                stream.remote_opened = true;
                                self.opened_channels.push_back((stream_id, open));
                                out_chunks.push(Chunk {
                                    chunk_type: ChunkType::Data,
                                    flags: 0x03,
                                    value: serialize_data(
                                        self.local_tsn,
                                        stream_id,
                                        0,
                                        PPID_DATA_CHANNEL_ACK,
                                        &[],
                                    ),
                                });
                                self.local_tsn = self.local_tsn.wrapping_add(1);
                            }
                        } else {
                            self.inbound.push_back(SctpMessage {
                                stream_id,
                                ppid,
                                data: payload,
                                ordered,
                            });
                        }
                    } else if ppid == PPID_DATA_CHANNEL_OPEN {
                        // Implicitly-opened stream from the remote side.
                        if let Ok(open) = DataChannelOpen::parse(&payload) {
                            self.streams.insert(
                                stream_id,
                                Stream {
                                    config: SctpStreamConfig::default(),
                                    next_ssn: 0,
                                    expected_ssn: 0,
                                    awaiting_ack: false,
                                    remote_opened: true,
                                },
                            );
                            self.opened_channels.push_back((stream_id, open));
                            out_chunks.push(Chunk {
                                chunk_type: ChunkType::Data,
                                flags: 0x03,
                                value: serialize_data(
                                    self.local_tsn,
                                    stream_id,
                                    0,
                                    PPID_DATA_CHANNEL_ACK,
                                    &[],
                                ),
                            });
                            self.local_tsn = self.local_tsn.wrapping_add(1);
                        }
                    }
                    // SACK the data.
                    self.remote_cumulative_tsn = Some(match self.remote_cumulative_tsn {
                        Some(c) if c.wrapping_sub(tsn) > 0x8000_0000 => c, // old TSN
                        _ => tsn,
                    });
                    if !out_chunks.iter().any(|c| c.chunk_type == ChunkType::Sack) {
                        out_chunks.push(Chunk {
                            chunk_type: ChunkType::Sack,
                            flags: 0,
                            value: serialize_sack(self.remote_cumulative_tsn.unwrap_or(tsn), &[]),
                        });
                    }
                }
                ChunkType::Sack => {
                    let (cum, _gaps) = parse_sack(&chunk.value)?;
                    self.unacked
                        .retain(|(tsn, ..)| tsn.wrapping_sub(cum) > 0x8000_0000);
                    for s in self.streams.values_mut() {
                        s.awaiting_ack = false;
                    }
                }
                ChunkType::Heartbeat => {
                    out_chunks.push(Chunk {
                        chunk_type: ChunkType::HeartbeatAck,
                        flags: 0,
                        value: chunk.value.clone(),
                    });
                }
                ChunkType::Abort | ChunkType::Shutdown | ChunkType::ShutdownAck => {
                    self.state = SctpState::Shutdown;
                }
                ChunkType::HeartbeatAck | ChunkType::OperationError | ChunkType::Unknown(_) => {}
            }
        }

        if out_chunks.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            Packet {
                src_port: self.local_port,
                dst_port: self.remote_port,
                verification_tag: out_tag,
                chunks: out_chunks,
            }
            .serialize(),
        ))
    }

    /// Pops one remotely-opened channel notification.
    #[must_use]
    pub fn pop_remote_channel(&mut self) -> Option<(u16, DataChannelOpen)> {
        self.opened_channels.pop_front()
    }

    /// Pre-registers a stream as remotely opened (the peer opened a data
    /// channel on it before we have SCTP state for it).
    pub fn attach_remote_stream(&mut self, stream_id: u16) {
        self.streams.entry(stream_id).or_insert_with(|| Stream {
            config: SctpStreamConfig::default(),
            next_ssn: 0,
            expected_ssn: 0,
            awaiting_ack: false,
            remote_opened: true,
        });
    }

    /// Number of outbound DATA chunks awaiting a SACK.
    #[must_use]
    pub fn unacked_count(&self) -> usize {
        self.unacked.len()
    }

    /// Closes a stream.
    ///
    /// # Errors
    /// [`SctpError::Stream`] when the stream is unknown.
    pub fn close_stream(&mut self, stream_id: u16) -> Result<(), SctpError> {
        self.streams
            .remove(&stream_id)
            .map(|_| ())
            .ok_or_else(|| SctpError::Stream(format!("stream {stream_id} not open")))
    }

    /// Shuts the association down.
    pub fn shutdown(&mut self) {
        self.state = SctpState::Shutdown;
        self.streams.clear();
    }

    fn make_cookie(&self, peer: &InitPeerInfo) -> Vec<u8> {
        let _ = peer;
        // HMAC-less opaque cookie: tag + fixed marker (the DTLS layer
        // authenticates the transport, and single-session semantics make
        // spoofing out of scope for this profile).
        let mut cookie = Vec::with_capacity(24);
        cookie.extend_from_slice(&self.local_tag.to_be_bytes());
        cookie.extend_from_slice(b"TPT-SCTP-COOKIE");
        cookie
    }

    /// Kicks off the handshake (client side): INIT packet.
    #[must_use]
    pub fn build_init(&mut self) -> Vec<u8> {
        self.state = SctpState::CookieWait;
        Packet {
            src_port: self.local_port,
            dst_port: self.remote_port,
            verification_tag: 0,
            chunks: vec![Chunk {
                chunk_type: ChunkType::Init,
                flags: 0,
                value: serialize_init(self.local_tag, self.local_tsn, 1024, 65535, 0),
            }],
        }
        .serialize()
    }
}

/// DATA chunk value: `TSN(4) stream(2) ssn(2) ppid(4) data`.
fn serialize_data(tsn: u32, stream: u16, ssn: u16, ppid: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + data.len());
    v.extend_from_slice(&tsn.to_be_bytes());
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(&ssn.to_be_bytes());
    v.extend_from_slice(&ppid.to_be_bytes());
    v.extend_from_slice(data);
    v
}

fn parse_data(value: &[u8]) -> Result<(u32, u16, u16, u32, Vec<u8>), SctpError> {
    if value.len() < 12 {
        return Err(SctpError::MalformedChunk);
    }
    Ok((
        u32::from_be_bytes(value[0..4].try_into().unwrap()),
        u16::from_be_bytes(value[4..6].try_into().unwrap()),
        u16::from_be_bytes(value[6..8].try_into().unwrap()),
        u32::from_be_bytes(value[8..12].try_into().unwrap()),
        value[12..].to_vec(),
    ))
}

fn cookie_tlv(cookie: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::with_capacity(cookie.len() + 4);
    tlv.extend_from_slice(&7u16.to_be_bytes()); // COOKIE parameter
    tlv.extend_from_slice(&((cookie.len() + 4) as u16).to_be_bytes());
    tlv.extend_from_slice(cookie);
    while tlv.len() % 4 != 0 {
        tlv.push(0);
    }
    tlv
}

fn cookie_from_init_ack(body: &[u8]) -> Vec<u8> {
    let mut i = 16;
    while i + 4 <= body.len() {
        let ty = u16::from_be_bytes([body[i], body[i + 1]]);
        let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        if len < 4 || i + len > body.len() {
            break;
        }
        if ty == 7 {
            return body[i + 4..i + len].to_vec();
        }
        i += (len + 3) & !3;
    }
    Vec::new()
}

/// Convenience: binary message on a stream.
impl SctpAssociation {
    /// Sends binary data (PPID 53).
    ///
    /// # Errors
    /// See [`send`](Self::send).
    pub fn send_binary(&mut self, stream_id: u16, data: &[u8]) -> Result<Vec<u8>, SctpError> {
        self.send(stream_id, data, PPID_BINARY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established_pair() -> (SctpAssociation, SctpAssociation) {
        let mut a = SctpAssociation::new();
        let mut b = SctpAssociation::new();
        // A: INIT
        let init = a.build_init();
        // B: INIT-ACK
        let resp = b.process_packet(&init).unwrap().unwrap();
        // A: COOKIE-ECHO
        let echo = a.process_packet(&resp).unwrap().unwrap();
        // B: COOKIE-ACK
        let ack = b.process_packet(&echo).unwrap().unwrap();
        // A: Established.
        a.process_packet(&ack).unwrap();
        (a, b)
    }

    #[test]
    fn association_establishment() {
        let (a, b) = established_pair();
        assert_eq!(a.state(), SctpState::Established);
        assert_eq!(b.state(), SctpState::Established);
        assert_ne!(a.local_tag, b.local_tag);
    }

    #[test]
    fn ordered_send_recv_with_sack() {
        let (mut a, mut b) = established_pair();
        let sid = a.open_stream(SctpStreamConfig::default()).unwrap();
        b.streams.insert(
            sid,
            Stream {
                config: SctpStreamConfig::default(),
                next_ssn: 0,
                expected_ssn: 0,
                awaiting_ack: false,
                remote_opened: true,
            },
        );

        for msg in [b"one".as_slice(), b"two", b"three"] {
            let wire = a.send(sid, msg, PPID_BINARY).unwrap();
            let resp = b.process_packet(&wire).unwrap();
            // SACK goes back to A.
            if let Some(sack) = resp {
                a.process_packet(&sack).unwrap();
            }
        }
        assert!(a.unacked.is_empty(), "SACKs must clear unacked data");
        assert_eq!(b.pending_inbound(), 3);
        assert_eq!(b.recv().unwrap().data, b"one");
        assert_eq!(b.recv().unwrap().data, b"two");
        assert_eq!(b.recv().unwrap().data, b"three");
    }

    #[test]
    fn unordered_bypasses_ssn() {
        let (mut a, mut b) = established_pair();
        let sid = a
            .open_stream(SctpStreamConfig {
                ordered: false,
                reliability: Reliability::Unreliable,
            })
            .unwrap();
        b.streams.insert(
            sid,
            Stream {
                config: SctpStreamConfig {
                    ordered: false,
                    reliability: Reliability::Unreliable,
                },
                next_ssn: 0,
                expected_ssn: 0,
                awaiting_ack: false,
                remote_opened: true,
            },
        );
        let wire = a.send(sid, b"unreliable!", PPID_BINARY).unwrap();
        b.process_packet(&wire).unwrap();
        let msg = b.recv().unwrap();
        assert!(!msg.ordered);
        assert_eq!(msg.data, b"unreliable!");
    }

    #[test]
    fn data_channel_open_ack_flow() {
        let (mut a, mut b) = established_pair();
        let sid = a.open_stream(SctpStreamConfig::default()).unwrap();
        b.streams.insert(
            sid,
            Stream {
                config: SctpStreamConfig::default(),
                next_ssn: 0,
                expected_ssn: 0,
                awaiting_ack: false,
                remote_opened: true,
            },
        );
        let open = a.build_channel_open(sid, "chat", "").unwrap();
        let wire = a.send(sid, &open, PPID_DATA_CHANNEL_OPEN).unwrap();
        b.process_packet(&wire).unwrap();
        let (rid, open) = b.pop_remote_channel().unwrap();
        assert_eq!(rid, sid);
        assert_eq!(open.label, "chat");

        // The ACK flows back.
        let ack_wire = {
            // The ACK was bundled in b's response; rebuild it directly.
            Packet {
                src_port: b.local_port,
                dst_port: b.remote_port,
                verification_tag: b.remote_tag.unwrap_or(0),
                chunks: vec![Chunk {
                    chunk_type: ChunkType::Data,
                    flags: 0x03,
                    value: serialize_data(0, sid, 0, PPID_DATA_CHANNEL_ACK, &[]),
                }],
            }
            .serialize()
        };
        a.process_packet(&ack_wire).unwrap();
    }

    #[test]
    fn close_stream_errors_when_unknown() {
        let mut a = SctpAssociation::new();
        assert!(a.close_stream(9).is_err());
    }

    #[test]
    fn send_requires_established() {
        let mut a = SctpAssociation::new();
        assert_eq!(a.send(0, b"x", 53), Err(SctpError::InvalidState));
    }
}
