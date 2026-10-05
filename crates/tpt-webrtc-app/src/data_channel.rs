//! Data channels: the user-facing handle over one SCTP stream.

use tpt_webrtc_core::SctpError;
use tpt_webrtc_sctp::{DataChannelOpen, Reliability, SctpMessage};

/// Data channel configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannelConfig {
    /// Ordered delivery (default true).
    pub ordered: bool,
    /// Reliability policy.
    pub reliability: Reliability,
    /// Protocol (sub-protocol) string.
    pub protocol: String,
}

impl Default for DataChannelConfig {
    fn default() -> Self {
        Self {
            ordered: true,
            reliability: Reliability::Reliable,
            protocol: String::new(),
        }
    }
}

/// Data channel states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataChannelState {
    /// Created locally, SCTP not established yet.
    #[default]
    Connecting,
    /// OPEN/ACK exchanged.
    Open,
    /// Closing.
    Closing,
    /// Closed.
    Closed,
}

/// Messages delivered on a data channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataChannelMessage {
    /// Binary payload (PPID 53).
    Binary(Vec<u8>),
    /// UTF-8 text payload (PPID 51).
    Text(String),
}

impl DataChannelMessage {
    /// Raw bytes of either variant.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Binary(b) => b,
            Self::Text(t) => t.into_bytes(),
        }
    }
}

/// A data channel: label + stream id + state + inbound queue. Send goes
/// through the owning [`crate::PeerConnection`] (it owns the SCTP
/// association); receive queues here.
#[derive(Debug)]
pub struct DataChannel {
    /// Channel label.
    pub label: String,
    /// SCTP stream id.
    pub stream_id: u16,
    /// Channel configuration.
    pub config: DataChannelConfig,
    state: DataChannelState,
    inbound: std::collections::VecDeque<DataChannelMessage>,
}

impl DataChannel {
    pub(crate) fn new(label: String, stream_id: u16, config: DataChannelConfig) -> Self {
        Self {
            label,
            stream_id,
            config,
            state: DataChannelState::Connecting,
            inbound: std::collections::VecDeque::new(),
        }
    }

    pub(crate) fn mark_open(&mut self) {
        self.state = DataChannelState::Open;
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> DataChannelState {
        self.state
    }

    pub(crate) fn set_state(&mut self, state: DataChannelState) {
        self.state = state;
    }

    pub(crate) fn queue_inbound(&mut self, msg: DataChannelMessage) {
        self.inbound.push_back(msg);
    }

    /// Pops one inbound message.
    #[must_use]
    pub fn recv(&mut self) -> Option<DataChannelMessage> {
        self.inbound.pop_front()
    }

    /// Number of queued messages.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.inbound.len()
    }

    /// Maps this channel's configuration onto the datachannel-draft
    /// `DATA_CHANNEL_OPEN` message.
    #[must_use]
    pub fn build_open(&self) -> DataChannelOpen {
        let (channel_type, reliability_parameter) = match &self.config.reliability {
            Reliability::Reliable => {
                if self.config.ordered {
                    (0u8, 0u32)
                } else {
                    (128, 0)
                }
            }
            Reliability::PartialReliableRexmit(n) => {
                (if self.config.ordered { 1 } else { 129 }, *n)
            }
            Reliability::PartialReliableTimed(d) => (
                if self.config.ordered { 2 } else { 130 },
                d.as_millis() as u32,
            ),
            Reliability::Unreliable => (if self.config.ordered { 1 } else { 129 }, 0),
        };
        DataChannelOpen {
            channel_type,
            priority: 0,
            reliability_parameter,
            label: self.label.clone(),
            protocol: self.config.protocol.clone(),
        }
    }

    /// Wraps an inbound SCTP message into a [`DataChannelMessage`].
    pub(crate) fn message_from_sctp(msg: &SctpMessage) -> Result<DataChannelMessage, SctpError> {
        match msg.ppid {
            51 => Ok(DataChannelMessage::Text(
                String::from_utf8_lossy(&msg.data).into_owned(),
            )),
            53 => Ok(DataChannelMessage::Binary(msg.data.clone())),
            other => Err(SctpError::Protocol(format!("unexpected PPID {other}"))),
        }
    }
}
