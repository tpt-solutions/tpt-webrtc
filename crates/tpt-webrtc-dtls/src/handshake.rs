//! DTLS handshake message codecs (RFC 6347 §4.1.2 / RFC 5246 §7.4) for the
//! WebRTC profile: ClientHello, HelloVerifyRequest, ServerHello,
//! Certificate, ServerKeyExchange / ClientKeyExchange (ECDHE P-256),
//! Finished, plus the extensions the stack negotiates.

use tpt_webrtc_core::DtlsError;

use crate::{CIPHER_SUITE, GROUP_SECP256R1, SRTP_AEAD_AES_128_GCM, SRTP_AES128_CM_HMAC_SHA1_80};

/// Handshake message types used by the stack (RFC 5246 §7.4, RFC 6347).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    /// 0 — ClientHello.
    ClientHello,
    /// 2 — ServerHello.
    ServerHello,
    /// 3 — HelloVerifyRequest (DTLS cookie exchange).
    HelloVerifyRequest,
    /// 11 — Certificate.
    Certificate,
    /// 12 — ServerKeyExchange (ECDHE params + signature).
    ServerKeyExchange,
    /// 14 — ServerHelloDone.
    ServerHelloDone,
    /// 16 — ClientKeyExchange (EC point).
    ClientKeyExchange,
    /// 20 — Finished.
    Finished,
    /// Unknown type (parsed as raw).
    Unknown(u8),
}

impl HandshakeType {
    /// Wire value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::ClientHello => 0,
            Self::ServerHello => 2,
            Self::HelloVerifyRequest => 3,
            Self::Certificate => 11,
            Self::ServerKeyExchange => 12,
            Self::ServerHelloDone => 14,
            Self::ClientKeyExchange => 16,
            Self::Finished => 20,
            Self::Unknown(v) => v,
        }
    }

    /// From wire value.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::ClientHello,
            2 => Self::ServerHello,
            3 => Self::HelloVerifyRequest,
            11 => Self::Certificate,
            12 => Self::ServerKeyExchange,
            14 => Self::ServerHelloDone,
            16 => Self::ClientKeyExchange,
            20 => Self::Finished,
            other => Self::Unknown(other),
        }
    }
}

/// Extensions negotiated by this stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// `use_srtp` (RFC 5764): the SRTP protection profiles we accept.
    UseSrtp {
        /// Offered/accepted profile ids.
        profiles: Vec<u16>,
        /// MKI, always empty here.
        mki: Vec<u8>,
    },
    /// `supported_groups`: named curves.
    SupportedGroups(Vec<u16>),
    /// `ec_point_formats`.
    EcPointFormats(Vec<u8>),
    /// `signature_algorithms` (SHA256 + ECDSA).
    SignatureAlgorithms(Vec<u16>),
    /// `extended_master_secret` (RFC 7627), offered for parity with
    /// browsers; the from-scratch stack does not require it.
    ExtendedMasterSecret,
    /// Unknown extension, preserved raw.
    Unknown(u16, Vec<u8>),
}

impl Extension {
    /// Extension type id.
    #[must_use]
    pub fn ext_type(&self) -> u16 {
        match self {
            Self::UseSrtp { .. } => 14,
            Self::SupportedGroups(_) => 10,
            Self::EcPointFormats(_) => 11,
            Self::SignatureAlgorithms(_) => 13,
            Self::ExtendedMasterSecret => 0x0017,
            Self::Unknown(t, _) => *t,
        }
    }

    fn encode_body(&self) -> Vec<u8> {
        match self {
            Self::UseSrtp { profiles, mki } => {
                let mut b = Vec::new();
                b.extend_from_slice(&((profiles.len() * 2) as u16).to_be_bytes());
                for p in profiles {
                    b.extend_from_slice(&p.to_be_bytes());
                }
                b.extend_from_slice(&(mki.len() as u8).to_be_bytes());
                b.extend_from_slice(mki);
                b
            }
            Self::SupportedGroups(groups) => {
                let mut b = Vec::new();
                b.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
                for g in groups {
                    b.extend_from_slice(&g.to_be_bytes());
                }
                b
            }
            Self::EcPointFormats(fmts) => {
                let mut b = Vec::new();
                b.push(fmts.len() as u8);
                b.extend_from_slice(fmts);
                b
            }
            Self::SignatureAlgorithms(algs) => {
                let mut b = Vec::new();
                b.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
                for a in algs {
                    b.extend_from_slice(&a.to_be_bytes());
                }
                b
            }
            Self::ExtendedMasterSecret => Vec::new(),
            Self::Unknown(_, body) => body.clone(),
        }
    }

    fn parse(ext_type: u16, body: &[u8]) -> Self {
        match ext_type {
            14 => {
                let mut profiles = Vec::new();
                if body.len() >= 2 {
                    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let end = (2 + list_len).min(body.len());
                    let mut i = 2;
                    while i + 2 <= end {
                        profiles.push(u16::from_be_bytes([body[i], body[i + 1]]));
                        i += 2;
                    }
                }
                let mki = if body.len() >= 3 {
                    let mki_len = body[body.len() - 1] as usize;
                    let start = body.len() - 1 - mki_len;
                    if start >= 2 {
                        body[start..body.len() - 1].to_vec()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                Self::UseSrtp { profiles, mki }
            }
            10 => {
                let mut groups = Vec::new();
                if body.len() >= 2 {
                    let mut i = 2;
                    while i + 2 <= body.len() {
                        groups.push(u16::from_be_bytes([body[i], body[i + 1]]));
                        i += 2;
                    }
                }
                Self::SupportedGroups(groups)
            }
            11 => Self::EcPointFormats(body.first().map_or_else(Vec::new, |n| {
                body.get(1..1 + usize::from(*n)).unwrap_or(&[]).to_vec()
            })),
            13 => {
                let mut algs = Vec::new();
                if body.len() >= 2 {
                    let mut i = 2;
                    while i + 2 <= body.len() {
                        algs.push(u16::from_be_bytes([body[i], body[i + 1]]));
                        i += 2;
                    }
                }
                Self::SignatureAlgorithms(algs)
            }
            0x0017 => Self::ExtendedMasterSecret,
            other => Self::Unknown(other, body.to_vec()),
        }
    }
}

/// The DTLS handshake record header (RFC 6347 §4.1.2): `type(1) length(3)
/// message_seq(2) fragment_offset(3) fragment_length(3)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    /// Message type.
    pub msg_type: u8,
    /// Total message length (of the un-fragmented message).
    pub length: u32,
    /// Sequence number of this handshake message (per direction).
    pub message_seq: u16,
    /// Fragment offset.
    pub fragment_offset: u32,
    /// Fragment length.
    pub fragment_length: u32,
}

pub const HANDSHAKE_HEADER_LEN: usize = 12;

impl HandshakeHeader {
    /// Serializes the header.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN);
        out.push(self.msg_type);
        out.extend_from_slice(&self.length.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.message_seq.to_be_bytes());
        out.extend_from_slice(&self.fragment_offset.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.fragment_length.to_be_bytes()[1..4]);
        out
    }

    /// Parses the header. `# Errors` on short input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.len() < HANDSHAKE_HEADER_LEN {
            return Err(DtlsError::InvalidState);
        }
        Ok(Self {
            msg_type: data[0],
            length: u32::from_be_bytes([0, data[1], data[2], data[3]]),
            message_seq: u16::from_be_bytes([data[4], data[5]]),
            fragment_offset: u32::from_be_bytes([0, data[6], data[7], data[8]]),
            fragment_length: u32::from_be_bytes([0, data[9], data[10], data[11]]),
        })
    }
}

/// A parsed handshake message: header + un-fragmented body.
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    /// Header.
    pub header: HandshakeHeader,
    /// Message body (after the header; one fragment).
    pub body: Vec<u8>,
}

/// ClientHello / ServerHello share the hello shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// 32-byte random.
    pub random: [u8; 32],
    /// Session id (always empty here).
    pub session_id: Vec<u8>,
    /// DTLS cookie (ClientHello after HelloVerifyRequest; empty otherwise).
    pub cookie: Vec<u8>,
    /// Offered (client) or selected (server) cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Compression methods (always `[0]`).
    pub compression: Vec<u8>,
    /// Extensions.
    pub extensions: Vec<Extension>,
}

impl Hello {
    /// Offers the stack's default extensions: use_srtp with both profiles,
    /// secp256r1, uncompressed points, ECDSA+SHA256.
    #[must_use]
    pub fn client_extensions() -> Vec<Extension> {
        vec![
            Extension::SupportedGroups(vec![GROUP_SECP256R1]),
            Extension::EcPointFormats(vec![0]),
            Extension::SignatureAlgorithms(vec![0x0403]), // ecdsa_secp256r1_sha256
            Extension::UseSrtp {
                profiles: vec![SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AEAD_AES_128_GCM],
                mki: Vec::new(),
            },
            Extension::ExtendedMasterSecret,
        ]
    }

    /// Serializes as a ClientHello (client) or ServerHello (server) body
    /// without the handshake header.
    ///
    /// ServerHello omits the cookie field (it is ClientHello-only per
    /// RFC 6347 §4.1.2.1).
    #[must_use]
    pub fn serialize(&self, is_client: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(0xFE); // version: DTLS 1.2 (254, 253)
        b.push(0xFD);
        b.extend_from_slice(&self.random);
        b.push(self.session_id.len() as u8);
        b.extend_from_slice(&self.session_id);
        if is_client {
            b.push(self.cookie.len() as u8);
            b.extend_from_slice(&self.cookie);
        }
        b.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            b.extend_from_slice(&cs.to_be_bytes());
        }
        b.push(self.compression.len() as u8);
        b.extend_from_slice(&self.compression);
        // extensions
        let mut ext = Vec::new();
        for e in &self.extensions {
            let body = e.encode_body();
            ext.extend_from_slice(&e.ext_type().to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(&body);
        }
        b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        b.extend_from_slice(&ext);
        b
    }

    /// Parses a hello body. `is_client` selects the cookie field.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8], is_client: bool) -> Result<Self, DtlsError> {
        let mut i = 0;
        let take = |i: &mut usize, n: usize| -> Result<&[u8], DtlsError> {
            let end = *i + n;
            if data.len() < end {
                return Err(DtlsError::InvalidState);
            }
            let s = &data[*i..end];
            *i = end;
            Ok(s)
        };
        let _ = take(&mut i, 2)?; // version
        let random: [u8; 32] = take(&mut i, 32)?.try_into().expect("32 bytes");
        let sid_len = take(&mut i, 1)?[0] as usize;
        let session_id = take(&mut i, sid_len)?.to_vec();
        let cookie = if is_client {
            let c = take(&mut i, 1)?[0] as usize;
            take(&mut i, c)?.to_vec()
        } else {
            Vec::new()
        };
        let cs_len = u16::from_be_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
        let mut cipher_suites = Vec::new();
        for _ in 0..cs_len / 2 {
            cipher_suites.push(u16::from_be_bytes(take(&mut i, 2)?.try_into().unwrap()));
        }
        let comp_len = take(&mut i, 1)?[0] as usize;
        let compression = take(&mut i, comp_len)?.to_vec();
        let mut extensions = Vec::new();
        if i + 2 <= data.len() {
            let ext_len = u16::from_be_bytes(take(&mut i, 2)?.try_into().unwrap()) as usize;
            let mut j = i;
            let end = i + ext_len;
            while j + 4 <= end {
                let ty = u16::from_be_bytes([data[j], data[j + 1]]);
                let bl = u16::from_be_bytes([data[j + 2], data[j + 3]]) as usize;
                if j + 4 + bl > data.len() {
                    return Err(DtlsError::InvalidState);
                }
                extensions.push(Extension::parse(ty, &data[j + 4..j + 4 + bl]));
                j += 4 + bl;
            }
        }
        Ok(Self {
            random,
            session_id,
            cookie,
            cipher_suites,
            compression,
            extensions,
        })
    }
}

/// `Certificate` message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMessage {
    /// DER certificates in order (single self-signed cert here).
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateMessage {
    /// Serializes the body.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let total: usize = self.certificates.iter().map(|c| c.len() + 3).sum();
        b.extend_from_slice(&(total as u32).to_be_bytes()[1..4]);
        for c in &self.certificates {
            b.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..4]);
            b.extend_from_slice(c);
        }
        b
    }

    /// Parses the body.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.len() < 3 {
            return Err(DtlsError::InvalidState);
        }
        let mut i = 3usize; // skip total length
        let mut certificates = Vec::new();
        while i + 3 <= data.len() {
            let len = u32::from_be_bytes([0, data[i], data[i + 1], data[i + 2]]) as usize;
            i += 3;
            if i + len > data.len() {
                return Err(DtlsError::InvalidState);
            }
            certificates.push(data[i..i + len].to_vec());
            i += len;
        }
        Ok(Self { certificates })
    }
}

/// `ServerKeyExchange` body: ECDHE P-256 params + ECDSA-SHA256 signature
/// over `client_random || server_random || params`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchange {
    /// Server's ephemeral EC point (uncompressed).
    pub point: Vec<u8>,
    /// DER-encoded ECDSA-SigValue over the transcript prefix.
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// Serializes the body: `curve_type(3=named) || named_group(P-256) ||
    /// point_len || point || sig_len || sig`.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(3); // curve_type: named_curve
        b.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
        b.push(self.point.len() as u8);
        b.extend_from_slice(&self.point);
        b.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.signature);
        b
    }

    /// The signed parameter block (everything before the signature).
    #[must_use]
    pub fn signed_params(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(3);
        b.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
        b.push(self.point.len() as u8);
        b.extend_from_slice(&self.point);
        b
    }

    /// Parses the body.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.len() < 4 {
            return Err(DtlsError::InvalidState);
        }
        if data[0] != 3 || u16::from_be_bytes([data[1], data[2]]) != GROUP_SECP256R1 {
            return Err(DtlsError::HandshakeFailed);
        }
        let plen = data[3] as usize;
        let mut i = 4;
        if data.len() < i + plen + 2 {
            return Err(DtlsError::InvalidState);
        }
        let point = data[i..i + plen].to_vec();
        i += plen;
        let slen = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        if data.len() < i + slen {
            return Err(DtlsError::InvalidState);
        }
        Ok(Self {
            point,
            signature: data[i..i + slen].to_vec(),
        })
    }
}

/// `ClientKeyExchange` body: the client's ephemeral EC point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyExchange {
    /// Client's ephemeral EC point (uncompressed).
    pub point: Vec<u8>,
}

impl ClientKeyExchange {
    /// Serializes the body.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(self.point.len() as u8);
        b.extend_from_slice(&self.point);
        b
    }

    /// Parses the body.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.is_empty() || data.len() < 1 + data[0] as usize {
            return Err(DtlsError::InvalidState);
        }
        Ok(Self {
            point: data[1..1 + data[0] as usize].to_vec(),
        })
    }
}

/// `Finished` body: 12-byte verify_data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// Verify data (12 bytes).
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Serializes the body.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(self.verify_data.len() as u8);
        b.extend_from_slice(&self.verify_data);
        b
    }

    /// Parses the body.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.is_empty() || data.len() < 1 + data[0] as usize {
            return Err(DtlsError::InvalidState);
        }
        Ok(Self {
            verify_data: data[1..1 + data[0] as usize].to_vec(),
        })
    }
}

/// `HelloVerifyRequest` body: `version(2) || cookie_len(1) || cookie`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// Opaque cookie to echo in the next ClientHello.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Serializes the body.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = vec![0xFE, 0xFD];
        b.push(self.cookie.len() as u8);
        b.extend_from_slice(&self.cookie);
        b
    }

    /// Parses the body.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] on malformed input.
    pub fn parse(data: &[u8]) -> Result<Self, DtlsError> {
        if data.len() < 3 {
            return Err(DtlsError::InvalidState);
        }
        let clen = data[2] as usize;
        if data.len() < 3 + clen {
            return Err(DtlsError::InvalidState);
        }
        Ok(Self {
            cookie: data[3..3 + clen].to_vec(),
        })
    }
}

/// Wraps a handshake body into a complete DTLS handshake message.
#[must_use]
pub fn wrap(msg_type: HandshakeType, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let header = HandshakeHeader {
        msg_type: msg_type.to_u8(),
        length: body.len() as u32,
        message_seq,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
    };
    let mut out = header.serialize();
    out.extend_from_slice(body);
    out
}

/// Convenience: the stack's single cipher suite as a one-element offer.
#[must_use]
pub fn default_cipher_suites() -> Vec<u16> {
    vec![CIPHER_SUITE]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let hello = Hello {
            random: [7u8; 32],
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: default_cipher_suites(),
            compression: vec![0],
            extensions: Hello::client_extensions(),
        };
        let body = hello.serialize(true);
        let msg = wrap(HandshakeType::ClientHello, 0, &body);
        let header = HandshakeHeader::parse(&msg).unwrap();
        assert_eq!(header.msg_type, 0);
        assert_eq!(header.length as usize, body.len());
        let parsed = Hello::parse(&msg[HANDSHAKE_HEADER_LEN..], true).unwrap();
        assert_eq!(parsed, hello);
    }

    #[test]
    fn client_hello_with_cookie_roundtrip() {
        let hello = Hello {
            random: [9u8; 32],
            session_id: Vec::new(),
            cookie: vec![1, 2, 3, 4, 5, 6, 7, 8],
            cipher_suites: default_cipher_suites(),
            compression: vec![0],
            extensions: Hello::client_extensions(),
        };
        let body = hello.serialize(true);
        let parsed = Hello::parse(&body, true).unwrap();
        assert_eq!(parsed, hello);
    }

    #[test]
    fn server_hello_roundtrip() {
        let hello = Hello {
            random: [3u8; 32],
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: vec![CIPHER_SUITE],
            compression: vec![0],
            extensions: vec![Extension::UseSrtp {
                profiles: vec![SRTP_AES128_CM_HMAC_SHA1_80],
                mki: Vec::new(),
            }],
        };
        let body = hello.serialize(false);
        let parsed = Hello::parse(&body, false).unwrap();
        assert_eq!(parsed, hello);
    }

    #[test]
    fn use_srtp_parse() {
        let ext = Extension::UseSrtp {
            profiles: vec![SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AEAD_AES_128_GCM],
            mki: Vec::new(),
        };
        let parsed = Extension::parse(14, &ext.encode_body());
        assert_eq!(parsed, ext);
    }

    #[test]
    fn certificate_roundtrip() {
        let cert = CertificateMessage {
            certificates: vec![vec![0x30, 0x82, 1, 2, 3, 4]],
        };
        let body = cert.serialize();
        assert_eq!(CertificateMessage::parse(&body).unwrap(), cert);
    }

    #[test]
    fn key_exchange_and_finished_roundtrip() {
        let ske = ServerKeyExchange {
            point: vec![4u8; 65],
            signature: vec![0x30, 1, 2],
        };
        let body = ske.serialize();
        assert_eq!(ServerKeyExchange::parse(&body).unwrap(), ske);
        assert_eq!(
            ServerKeyExchange::parse(&body).unwrap().signed_params(),
            ske.signed_params()
        );

        let cke = ClientKeyExchange {
            point: vec![4u8; 65],
        };
        assert_eq!(ClientKeyExchange::parse(&cke.serialize()).unwrap(), cke);

        let fin = Finished {
            verify_data: vec![0xAB; 12],
        };
        assert_eq!(Finished::parse(&fin.serialize()).unwrap(), fin);
    }

    #[test]
    fn hello_verify_request_roundtrip() {
        let hvr = HelloVerifyRequest {
            cookie: vec![9u8; 16],
        };
        let body = hvr.serialize();
        assert_eq!(HelloVerifyRequest::parse(&body).unwrap(), hvr);
    }

    #[test]
    fn truncated_inputs_error() {
        assert!(HandshakeHeader::parse(&[0u8; 5]).is_err());
        assert!(Hello::parse(&[0u8; 10], true).is_err());
        assert!(CertificateMessage::parse(&[0u8; 2]).is_err());
        assert!(ServerKeyExchange::parse(&[3, 0x00, 0x17]).is_err());
        assert!(ClientKeyExchange::parse(&[65, 1, 2]).is_err());
        assert!(HelloVerifyRequest::parse(&[0xFE, 0xFD, 9, 1]).is_err());
    }
}
