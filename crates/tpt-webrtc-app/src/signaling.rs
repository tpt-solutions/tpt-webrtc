//! Signaling transport abstraction.
//!
//! The stack is signaling-agnostic: offer/answer descriptions and ICE
//! candidates move over anything that can carry strings. The trait here is
//! the seam; [`LoopbackSignaling`] is the in-process implementation used by
//! tests and examples. WebSocket/HTTP bridges plug in the same trait.

use std::future::Future;

use tpt_webrtc_core::WebRtcError;

/// A bidirectional string channel for SDP and candidate exchange.
pub trait SignalingTransport: Send {
    /// Sends one text message to the remote peer.
    ///
    /// # Errors
    /// Transport failure.
    fn send(&mut self, message: &str) -> impl Future<Output = Result<(), WebRtcError>> + Send;

    /// Receives one text message from the remote peer, waiting up to
    /// `timeout`.
    fn recv(&mut self, timeout: std::time::Duration)
        -> impl Future<Output = Option<String>> + Send;
}

/// In-process loopback signaling: whatever is sent is immediately
/// available to `peer()`'s `recv`.
#[derive(Debug, Default)]
pub struct LoopbackSignaling {
    queue: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}

impl LoopbackSignaling {
    /// Creates a connected pair of transports.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let queue = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        (
            Self {
                queue: std::sync::Arc::clone(&queue),
            },
            Self { queue },
        )
    }
}

impl SignalingTransport for LoopbackSignaling {
    async fn send(&mut self, message: &str) -> Result<(), WebRtcError> {
        self.queue
            .lock()
            .expect("signaling queue poisoned")
            .push_back(message.to_string());
        Ok(())
    }

    async fn recv(&mut self, timeout: std::time::Duration) -> Option<String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(msg) = self
                .queue
                .lock()
                .expect("signaling queue poisoned")
                .pop_front()
            {
                return Some(msg);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}
