//! # tpt-webrtc-ice
//!
//! ICE connectivity layer (RFC 8445) with STUN (RFC 8489) and TURN
//! (RFC 8656) clients.
//!
//! - [`IceAgent`] gathers host/server-reflexive/relayed candidates, pairs
//!   them with the peer's candidates, performs connectivity checks and
//!   nominates a pair. It is driven explicitly so applications (and tests)
//!   control timing; SDP is exchanged out of band by the caller.
//! - [`StunClient`] is the stateless RFC 8489 codec facade.
//! - [`TurnClient`] implements basic TURN allocation/permission/refresh.
//!
//! # Example
//! ```
//! use tpt_webrtc_ice::{IceAgent, IceConfig};
//!
//! let agent = IceAgent::new(IceConfig::new(true));
//! assert_eq!(agent.state(), tpt_webrtc_ice::IceState::New);
//! assert_eq!(agent.ufrag().len(), 16);
//! ```

pub mod agent;
pub mod client;
pub mod stun;
pub mod turn;

pub use agent::{CandidatePair, IceAgent, IceConfig, IceState, PairState};
pub use client::StunClient;
pub use stun::{StunAttribute, StunError, StunMessage, StunMessageType};
pub use turn::{TurnAllocation, TurnClient, TurnError};

/// Re-exported error type used throughout the crate.
pub use tpt_webrtc_core::IceError;
