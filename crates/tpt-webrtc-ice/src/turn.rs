//! Basic TURN client (RFC 8656): allocate / create-permission / refresh /
//! send-data indications, with long-term credential authentication.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tpt_webrtc_core::crypto::md5;
use tpt_webrtc_core::WebRtcSocket;

use crate::stun::{sign_integrity, StunAttribute, StunMessage, StunMessageType};

/// TURN client errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TurnError {
    /// The server did not answer in time.
    #[error("TURN request timed out")]
    Timeout,
    /// The message exchange failed at the codec level.
    #[error("TURN protocol error: {0}")]
    Protocol(String),
    /// The allocation was rejected (carries the STUN error code).
    #[error("TURN allocation rejected: {0}")]
    Rejected(u16),
}

/// A TURN allocation (RFC 8656 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnAllocation {
    /// The `XOR-RELAYED-ADDRESS` the server allocated for us.
    pub relayed_address: SocketAddr,
    /// Lifetime of the allocation.
    pub lifetime: Duration,
}

/// A basic TURN client speaking over an existing UDP socket (the same one
/// used for ICE checks towards the TURN server).
#[derive(Debug, Clone)]
pub struct TurnClient {
    server: SocketAddr,
    username: String,
    password: String,
    realm: Option<String>,
    nonce: Option<String>,
    allocation: Option<TurnAllocation>,
}

impl TurnClient {
    /// Creates a client for `server` with long-term credentials.
    #[must_use]
    pub fn new(server: SocketAddr, username: String, password: String) -> Self {
        Self {
            server,
            username,
            password,
            realm: None,
            nonce: None,
            allocation: None,
        }
    }

    /// The current allocation, if any.
    #[must_use]
    pub fn allocation(&self) -> Option<&TurnAllocation> {
        self.allocation.as_ref()
    }

    /// RFC 8656 §9.2.2 long-term credential key: `MD5(username:realm:password)`.
    #[must_use]
    pub fn long_term_key(&self) -> [u8; 16] {
        let realm = self.realm.as_deref().unwrap_or("");
        let input = format!("{}:{}:{}", self.username, realm, self.password);
        md5(input.as_bytes())
    }

    /// Allocates a relay address (with 401-challenge retry).
    ///
    /// # Errors
    /// [`TurnError`] on timeout / rejection / malformed responses.
    pub async fn allocate<S: WebRtcSocket>(
        &mut self,
        socket: &S,
    ) -> Result<TurnAllocation, TurnError> {
        let send_allocate = |client: &TurnClient| {
            let mut req = StunMessage::new(StunMessageType::AllocateRequest)
                .with(StunAttribute::RequestedTransport(17));
            if let (Some(realm), Some(nonce)) = (&client.realm, &client.nonce) {
                req.attributes
                    .push(StunAttribute::Username(client.username.clone()));
                req.attributes.push(StunAttribute::Realm(realm.clone()));
                req.attributes.push(StunAttribute::Nonce(nonce.clone()));
                sign_integrity(&mut req, &client.long_term_key());
            }
            req.attributes.push(StunAttribute::Fingerprint(0));
            req
        };

        let mut req = send_allocate(self);
        let txid = req.transaction_id;
        let resp = self.exchange(socket, &req, txid).await?;
        if resp.error_code().is_some_and(|(c, _)| c == 401) {
            // Challenge: capture realm/nonce and retry with integrity.
            if let Some(StunAttribute::Realm(realm)) = resp.attr(0x0014) {
                self.realm = Some(realm.clone());
            }
            if let Some(StunAttribute::Nonce(nonce)) = resp.attr(0x0015) {
                self.nonce = Some(nonce.clone());
            }
            req = send_allocate(self);
            let resp = self.exchange(socket, &req, req.transaction_id).await?;
            if let Some((code, _)) = resp.error_code() {
                return Err(TurnError::Rejected(code));
            }
            self.parse_allocation(&resp)
        } else {
            if let Some((code, _)) = resp.error_code() {
                return Err(TurnError::Rejected(code));
            }
            self.parse_allocation(&resp)
        }
    }

    /// Installs a permission for `peer` so relayed data can flow (§8).
    ///
    /// # Errors
    /// [`TurnError`] on timeout / rejection.
    pub async fn create_permission<S: WebRtcSocket>(
        &mut self,
        socket: &S,
        peer: SocketAddr,
    ) -> Result<(), TurnError> {
        let mut req = StunMessage::new(StunMessageType::CreatePermissionRequest)
            .with(StunAttribute::XorPeerAddress(peer))
            .with(StunAttribute::Username(self.username.clone()));
        if let Some(realm) = &self.realm {
            req.attributes.push(StunAttribute::Realm(realm.clone()));
        }
        if let Some(nonce) = &self.nonce {
            req.attributes.push(StunAttribute::Nonce(nonce.clone()));
        }
        sign_integrity(&mut req, &self.long_term_key());
        req.attributes.push(StunAttribute::Fingerprint(0));
        let resp = self.exchange(socket, &req, req.transaction_id).await?;
        match resp.error_code() {
            Some((code, _)) => Err(TurnError::Rejected(code)),
            None => Ok(()),
        }
    }

    /// Sends application data to `peer` via a Send indication (§11.3).
    ///
    /// # Errors
    /// [`TurnError`] on socket errors.
    pub async fn send_indication<S: WebRtcSocket>(
        &mut self,
        socket: &S,
        data: &[u8],
        peer: SocketAddr,
    ) -> Result<(), TurnError> {
        let ind = StunMessage::new(StunMessageType::SendIndication)
            .with(StunAttribute::XorPeerAddress(peer))
            .with(StunAttribute::Data(data.to_vec()))
            .with(StunAttribute::Fingerprint(0));
        socket
            .send_to(&ind.serialize(), self.server)
            .await
            .map_err(|e| TurnError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// Refreshes the allocation (default lifetime 600 s; `lifetime` of 0
    /// deletes it).
    ///
    /// # Errors
    /// [`TurnError`] on timeout / rejection.
    pub async fn refresh<S: WebRtcSocket>(
        &mut self,
        socket: &S,
        lifetime: Duration,
    ) -> Result<(), TurnError> {
        let mut req = StunMessage::new(StunMessageType::RefreshRequest)
            .with(StunAttribute::Lifetime(lifetime.as_secs() as u32))
            .with(StunAttribute::Username(self.username.clone()));
        if let Some(realm) = &self.realm {
            req.attributes.push(StunAttribute::Realm(realm.clone()));
        }
        if let Some(nonce) = &self.nonce {
            req.attributes.push(StunAttribute::Nonce(nonce.clone()));
        }
        sign_integrity(&mut req, &self.long_term_key());
        req.attributes.push(StunAttribute::Fingerprint(0));
        let resp = self.exchange(socket, &req, req.transaction_id).await?;
        match resp.error_code() {
            Some((code, _)) => Err(TurnError::Rejected(code)),
            None => Ok(()),
        }
    }

    fn parse_allocation(&mut self, resp: &StunMessage) -> Result<TurnAllocation, TurnError> {
        let Some(StunAttribute::XorRelayedAddress(relayed)) = resp.attr(0x0016) else {
            return Err(TurnError::Protocol(
                "allocation missing XOR-RELAYED-ADDRESS".into(),
            ));
        };
        let lifetime_secs = match resp.attr(0x000D) {
            Some(StunAttribute::Lifetime(l)) => *l,
            _ => 600,
        };
        let allocation = TurnAllocation {
            relayed_address: *relayed,
            lifetime: Duration::from_secs(u64::from(lifetime_secs)),
        };
        self.allocation = Some(allocation.clone());
        Ok(allocation)
    }

    /// Sends `req`, waits for the matching response (by transaction id),
    /// skipping unrelated datagrams.
    async fn exchange<S: WebRtcSocket>(
        &self,
        socket: &S,
        req: &StunMessage,
        txid: [u8; 12],
    ) -> Result<StunMessage, TurnError> {
        socket
            .send_to(&req.serialize(), self.server)
            .await
            .map_err(|e| TurnError::Protocol(e.to_string()))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or(TurnError::Timeout)?;
            let mut buf = vec![0u8; 65_536];
            let (n, src) = tokio::time::timeout(remaining, socket.recv_from(&mut buf))
                .await
                .map_err(|_| TurnError::Timeout)?
                .map_err(|e| TurnError::Protocol(e.to_string()))?;
            if src != self.server {
                continue;
            }
            let Ok(msg) = StunMessage::parse(&buf[..n]) else {
                continue;
            };
            if msg.transaction_id == txid && msg.message_type.is_response() {
                return Ok(msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_request_encodes_requested_transport() {
        let req = StunMessage::new(StunMessageType::AllocateRequest)
            .with(StunAttribute::RequestedTransport(17))
            .with(StunAttribute::Fingerprint(0));
        let bytes = req.serialize();
        let parsed = StunMessage::parse(&bytes).unwrap();
        assert_eq!(
            parsed.attr(0x0019),
            Some(&StunAttribute::RequestedTransport(17))
        );
    }

    #[test]
    fn long_term_key_is_md5_of_user_realm_pass() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user".into(),
            "pass".into(),
        );
        let mut c = client;
        c.realm = Some("example.org".into());
        // md5("user:example.org:pass")
        let key = c.long_term_key();
        assert_eq!(key, md5(b"user:example.org:pass"));
    }

    #[test]
    fn parse_synthetic_allocation_response() {
        let client = TurnClient::new(
            "127.0.0.1:3478".parse().unwrap(),
            "user".into(),
            "pass".into(),
        );
        let resp = StunMessage::new(StunMessageType::AllocateResponse)
            .with(StunAttribute::XorRelayedAddress(
                "203.0.113.9:61000".parse().unwrap(),
            ))
            .with(StunAttribute::Lifetime(540))
            .with(StunAttribute::Fingerprint(0));
        let mut c = client;
        let alloc = c.parse_allocation(&resp).unwrap();
        assert_eq!(alloc.relayed_address.to_string(), "203.0.113.9:61000");
        assert_eq!(alloc.lifetime, Duration::from_secs(540));
    }

    #[test]
    fn send_indication_roundtrip() {
        let ind = StunMessage::new(StunMessageType::SendIndication)
            .with(StunAttribute::XorPeerAddress(
                "198.51.100.2:7777".parse().unwrap(),
            ))
            .with(StunAttribute::Data(vec![1, 2, 3]))
            .with(StunAttribute::Fingerprint(0));
        let bytes = ind.serialize();
        let parsed = StunMessage::parse(&bytes).unwrap();
        assert_eq!(
            parsed.attr(0x0013),
            Some(&StunAttribute::Data(vec![1, 2, 3]))
        );
    }
}
