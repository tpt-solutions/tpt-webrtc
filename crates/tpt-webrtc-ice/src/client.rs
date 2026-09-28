//! The [`StunClient`] entry points required by the spec — a thin, stateless
//! facade over the [`crate::stun`] codec.

use crate::stun::{verify_integrity as codec_verify, StunError, StunMessage};

/// Stateless STUN message factory/parser (RFC 8489).
#[derive(Debug, Clone, Copy, Default)]
pub struct StunClient;

impl StunClient {
    /// A fresh binding request with a random transaction id.
    #[must_use]
    pub fn create_binding_request() -> StunMessage {
        StunMessage::new(crate::stun::StunMessageType::BindingRequest)
            .with(crate::stun::StunAttribute::Software("tpt-webrtc".into()))
    }

    /// Parses a STUN datagram (magic cookie and FINGERPRINT validated).
    ///
    /// # Errors
    /// See [`StunError`].
    pub fn parse_message(data: &[u8]) -> Result<StunMessage, StunError> {
        StunMessage::parse(data)
    }

    /// Serializes a STUN message.
    #[must_use]
    pub fn serialize_message(msg: &StunMessage) -> Vec<u8> {
        msg.serialize()
    }

    /// Verifies the MESSAGE-INTEGRITY attribute with a short-term-credential
    /// key (the peer's ICE password).
    #[must_use]
    pub fn verify_integrity(msg: &StunMessage, key: &[u8]) -> bool {
        codec_verify(msg, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{sign_integrity, StunAttribute, StunMessageType};

    #[test]
    fn binding_request_parse_verify_cycle() {
        let req = StunClient::create_binding_request();
        let mut msg = StunMessage::new(StunMessageType::BindingResponse)
            .with(StunAttribute::Software("tpt".into()))
            .with(StunAttribute::Fingerprint(0));
        msg.transaction_id = req.transaction_id;
        sign_integrity(&mut msg, b"pwd-1234567890");
        let bytes = StunClient::serialize_message(&msg);

        let parsed = StunClient::parse_message(&bytes).unwrap();
        assert_eq!(parsed.transaction_id, req.transaction_id);
        assert!(StunClient::verify_integrity(&parsed, b"pwd-1234567890"));
        assert!(!StunClient::verify_integrity(&parsed, b"other"));
    }
}
