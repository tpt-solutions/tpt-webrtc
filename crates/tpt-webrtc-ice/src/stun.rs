//! STUN message codec (RFC 8489) with the ICE / TURN extensions
//! (RFC 8445, RFC 8656).

use std::net::{IpAddr, SocketAddr};

use thiserror::Error;
use tpt_webrtc_core::{constant_time_eq, crc32_ieee, hmac_sha1, random_bytes};

/// RFC 8489 magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// XOR mask applied to the FINGERPRINT CRC (`"STUN"` in ASCII).
pub const FINGERPRINT_XOR: u32 = 0x5354_554E;
/// Size of the fixed STUN header.
pub const HEADER_LEN: usize = 20;

/// STUN parse errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StunError {
    /// Not a STUN message (bad magic cookie, truncated header, ...).
    #[error("malformed STUN message: {0}")]
    Malformed(&'static str),
    /// An attribute length does not fit the message or its fixed size.
    #[error("malformed STUN attribute (type 0x{0:04x})")]
    MalformedAttribute(u16),
    /// The FINGERPRINT attribute does not match the message.
    #[error("STUN fingerprint mismatch")]
    FingerprintMismatch,
}

/// STUN message class/method combinations used by the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StunMessageType {
    /// 0x001 binding request (also ICE connectivity check).
    BindingRequest,
    /// 0x011 binding indication.
    BindingIndication,
    /// 0x101 binding success response.
    BindingResponse,
    /// 0x111 binding error response.
    BindingErrorResponse,
    /// 0x003 TURN allocate.
    AllocateRequest,
    /// 0x103 TURN allocate success.
    AllocateResponse,
    /// 0x113 TURN allocate error.
    AllocateErrorResponse,
    /// 0x004 TURN refresh.
    RefreshRequest,
    /// 0x104 TURN refresh success.
    RefreshResponse,
    /// 0x114 TURN refresh error.
    RefreshErrorResponse,
    /// 0x016 TURN send indication.
    SendIndication,
    /// 0x017 TURN data indication.
    DataIndication,
    /// 0x008 TURN create permission.
    CreatePermissionRequest,
    /// 0x108 TURN create permission success.
    CreatePermissionResponse,
    /// 0x118 TURN create permission error.
    CreatePermissionErrorResponse,
    /// Unrecognized method/class (parsed but opaque).
    Unknown(u16),
}

impl StunMessageType {
    /// Wire value.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            Self::BindingRequest => 0x0001,
            Self::BindingIndication => 0x0011,
            Self::BindingResponse => 0x0101,
            Self::BindingErrorResponse => 0x0111,
            Self::AllocateRequest => 0x0003,
            Self::AllocateResponse => 0x0103,
            Self::AllocateErrorResponse => 0x0113,
            Self::RefreshRequest => 0x0004,
            Self::RefreshResponse => 0x0104,
            Self::RefreshErrorResponse => 0x0114,
            Self::SendIndication => 0x0016,
            Self::DataIndication => 0x0017,
            Self::CreatePermissionRequest => 0x0008,
            Self::CreatePermissionResponse => 0x0108,
            Self::CreatePermissionErrorResponse => 0x0118,
            Self::Unknown(v) => v,
        }
    }

    /// From wire value.
    #[must_use]
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::BindingRequest,
            0x0011 => Self::BindingIndication,
            0x0101 => Self::BindingResponse,
            0x0111 => Self::BindingErrorResponse,
            0x0003 => Self::AllocateRequest,
            0x0103 => Self::AllocateResponse,
            0x0113 => Self::AllocateErrorResponse,
            0x0004 => Self::RefreshRequest,
            0x0104 => Self::RefreshResponse,
            0x0114 => Self::RefreshErrorResponse,
            0x0016 => Self::SendIndication,
            0x0017 => Self::DataIndication,
            0x0008 => Self::CreatePermissionRequest,
            0x0108 => Self::CreatePermissionResponse,
            0x0118 => Self::CreatePermissionErrorResponse,
            other => Self::Unknown(other),
        }
    }

    /// Whether this is a success/error response.
    #[must_use]
    pub fn is_response(self) -> bool {
        self.to_u16() & 0x0100 != 0
    }

    /// Fresh random transaction id.
    ///
    /// # Errors
    /// Propagates RNG failure as a zero id (never happens in practice).
    pub fn new_transaction_id() -> [u8; 12] {
        let mut t = [0u8; 12];
        random_bytes(&mut t).unwrap_or(());
        t
    }
}

/// A single STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS (0x0001).
    MappedAddress(SocketAddr),
    /// XOR-MAPPED-ADDRESS (0x0020).
    XorMappedAddress(SocketAddr),
    /// XOR-PEER-ADDRESS (0x0012, TURN).
    XorPeerAddress(SocketAddr),
    /// XOR-RELAYED-ADDRESS (0x0016, TURN).
    XorRelayedAddress(SocketAddr),
    /// USERNAME (0x0006).
    Username(String),
    /// MESSAGE-INTEGRITY (0x0008), 20-byte HMAC-SHA1.
    MessageIntegrity(Vec<u8>),
    /// FINGERPRINT (0x8028), CRC-32 ^ 0x5354554e. The value is recomputed
    /// on serialization and verified on parse; hand-set values are ignored.
    Fingerprint(u32),
    /// ERROR-CODE (0x0009): (code, reason).
    ErrorCode(u16, String),
    /// REALM (0x0014).
    Realm(String),
    /// NONCE (0x0015).
    Nonce(String),
    /// SOFTWARE (0x8022).
    Software(String),
    /// PRIORITY (0x0024, ICE).
    Priority(u32),
    /// USE-CANDIDATE (0x0025, ICE).
    UseCandidate,
    /// ICE-CONTROLLED (0x8029).
    IceControlled(u64),
    /// ICE-CONTROLLING (0x802A).
    IceControlling(u64),
    /// LIFETIME (0x000D, TURN).
    Lifetime(u32),
    /// REQUESTED-TRANSPORT (0x0019, TURN): protocol number (17 = UDP).
    RequestedTransport(u8),
    /// DATA (0x0013, TURN).
    Data(Vec<u8>),
    /// Unknown attribute, preserved as raw TLV for round-tripping.
    Unknown(u16, Vec<u8>),
}

impl StunAttribute {
    /// Wire attribute type.
    #[must_use]
    pub fn attr_type(&self) -> u16 {
        match self {
            Self::MappedAddress(_) => 0x0001,
            Self::XorMappedAddress(_) => 0x0020,
            Self::XorPeerAddress(_) => 0x0012,
            Self::XorRelayedAddress(_) => 0x0016,
            Self::Username(_) => 0x0006,
            Self::MessageIntegrity(_) => 0x0008,
            Self::Fingerprint(_) => 0x8028,
            Self::ErrorCode(_, _) => 0x0009,
            Self::Realm(_) => 0x0014,
            Self::Nonce(_) => 0x0015,
            Self::Software(_) => 0x8022,
            Self::Priority(_) => 0x0024,
            Self::UseCandidate => 0x0025,
            Self::IceControlled(_) => 0x8029,
            Self::IceControlling(_) => 0x802A,
            Self::Lifetime(_) => 0x000D,
            Self::RequestedTransport(_) => 0x0019,
            Self::Data(_) => 0x0013,
            Self::Unknown(t, _) => *t,
        }
    }
}

/// A STUN message.
///
/// Equality only considers the protocol-visible fields; the cached MAC input
/// captured during parsing is an implementation detail.
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Method + class.
    pub message_type: StunMessageType,
    /// 96-bit transaction id.
    pub transaction_id: [u8; 12],
    /// Attributes in wire order.
    pub attributes: Vec<StunAttribute>,
    /// MAC input captured during parse: message bytes up to the
    /// MESSAGE-INTEGRITY attribute with the header length adjusted to
    /// include it (RFC 8489 §14.5). `None` for hand-built messages.
    integrity_input: Option<Vec<u8>>,
}

impl PartialEq for StunMessage {
    fn eq(&self, other: &Self) -> bool {
        self.message_type == other.message_type
            && self.transaction_id == other.transaction_id
            && self.attributes == other.attributes
    }
}

impl Eq for StunMessage {}

impl StunMessage {
    /// New message with a fresh random transaction id.
    #[must_use]
    pub fn new(message_type: StunMessageType) -> Self {
        Self {
            message_type,
            transaction_id: StunMessageType::new_transaction_id(),
            attributes: Vec::new(),
            integrity_input: None,
        }
    }

    /// Pushes an attribute and returns `self` (builder style).
    #[must_use]
    pub fn with(mut self, attr: StunAttribute) -> Self {
        self.attributes.push(attr);
        self
    }

    /// First attribute with the given wire type.
    #[must_use]
    pub fn attr(&self, want: u16) -> Option<&StunAttribute> {
        self.attributes.iter().find(|a| a.attr_type() == want)
    }

    /// The (code, reason) of an error response, if any.
    #[must_use]
    pub fn error_code(&self) -> Option<(u16, String)> {
        self.attributes.iter().find_map(|a| match a {
            StunAttribute::ErrorCode(code, reason) => Some((*code, reason.clone())),
            _ => None,
        })
    }

    /// Serializes the message. The header length accounts for
    /// MESSAGE-INTEGRITY (RFC 8489 §14.5) and FINGERPRINT (§14.7); the
    /// FINGERPRINT value is recomputed over the serialized prefix.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut pre_mi: Vec<u8> = Vec::new();
        let mut post_mi: Vec<u8> = Vec::new();
        let mut has_mi = false;
        let mut has_fp = false;
        let mut seen_mi = false;
        for attr in &self.attributes {
            match attr {
                StunAttribute::MessageIntegrity(_) if !seen_mi => {
                    has_mi = true;
                    seen_mi = true;
                }
                StunAttribute::Fingerprint(_) => has_fp = true,
                other => {
                    let enc = encode_attr(other, &self.transaction_id);
                    if seen_mi {
                        post_mi.extend_from_slice(&enc);
                    } else {
                        pre_mi.extend_from_slice(&enc);
                    }
                }
            }
        }

        let mut header_len = pre_mi.len() + post_mi.len();
        if has_mi {
            header_len += 24;
        }
        if has_fp {
            header_len += 8;
        }

        let mut out = Vec::with_capacity(HEADER_LEN + header_len);
        out.extend_from_slice(&self.message_type.to_u16().to_be_bytes());
        out.extend_from_slice(&(header_len as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&pre_mi);

        if has_mi {
            let stored = self
                .attributes
                .iter()
                .find_map(|a| match a {
                    StunAttribute::MessageIntegrity(v) => Some(v.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| vec![0u8; 20]);
            out.extend_from_slice(&encode_attr(
                &StunAttribute::MessageIntegrity(stored),
                &self.transaction_id,
            ));
        }
        out.extend_from_slice(&post_mi);

        if has_fp {
            // CRC covers everything before FP; the header length already
            // includes the 8-byte FP attribute (RFC 5389 §15.5).
            let crc = crc32_ieee(&out) ^ FINGERPRINT_XOR;
            out.extend_from_slice(&encode_attr(
                &StunAttribute::Fingerprint(crc),
                &self.transaction_id,
            ));
        }
        out
    }

    /// Parses a datagram. Validates the magic cookie, attribute framing and
    /// — when present — the FINGERPRINT attribute.
    ///
    /// # Errors
    /// See [`StunError`].
    pub fn parse(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < HEADER_LEN {
            return Err(StunError::Malformed("shorter than header"));
        }
        if u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != MAGIC_COOKIE {
            return Err(StunError::Malformed("magic cookie"));
        }
        let message_type = StunMessageType::from_u16(u16::from_be_bytes([data[0], data[1]]));
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < HEADER_LEN + msg_len {
            return Err(StunError::Malformed("declared length exceeds datagram"));
        }
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&data[8..20]);

        let mut attributes = Vec::new();
        let mut integrity_input: Option<Vec<u8>> = None;
        let mut pos = HEADER_LEN;
        let end = HEADER_LEN + msg_len;
        while pos + 4 <= end {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let value_end = pos + 4 + attr_len;
            if value_end > end {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            let value = &data[pos + 4..value_end];

            if attr_type == 0x0008 {
                // Capture MAC input before consuming: bytes up to here with
                // the header length rewritten to include the MI attribute.
                let mut mac_input = data[..pos].to_vec();
                let adjusted = (pos - HEADER_LEN + 24) as u16;
                mac_input[2..4].copy_from_slice(&adjusted.to_be_bytes());
                integrity_input = Some(mac_input);
                if attr_len != 20 {
                    return Err(StunError::MalformedAttribute(attr_type));
                }
                attributes.push(StunAttribute::MessageIntegrity(value.to_vec()));
            } else if attr_type == 0x8028 {
                if attr_len != 4 {
                    return Err(StunError::MalformedAttribute(attr_type));
                }
                let stored = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let want = crc32_ieee(&data[..pos]) ^ FINGERPRINT_XOR;
                if stored != want {
                    return Err(StunError::FingerprintMismatch);
                }
                attributes.push(StunAttribute::Fingerprint(stored));
            } else {
                attributes.push(parse_attr(attr_type, value, &txid)?);
            }

            pos = value_end + (4 - value_end % 4) % 4; // skip padding
        }

        Ok(Self {
            message_type,
            transaction_id: txid,
            attributes,
            integrity_input,
        })
    }

    /// The captured MAC input (parse) or computes it fresh (hand-built),
    /// per RFC 8489 §14.5: message up to and including a hypothetical
    /// MESSAGE-INTEGRITY attribute, with the header length adjusted.
    /// FINGERPRINT attributes are skipped (they never precede
    /// MESSAGE-INTEGRITY on the wire).
    #[must_use]
    pub fn mac_input(&self) -> Vec<u8> {
        if let Some(captured) = &self.integrity_input {
            return captured.clone();
        }
        let mut attrs: Vec<u8> = Vec::new();
        for attr in &self.attributes {
            match attr {
                StunAttribute::MessageIntegrity(_) => break,
                StunAttribute::Fingerprint(_) => {}
                other => attrs.extend_from_slice(&encode_attr(other, &self.transaction_id)),
            }
        }
        let mut input = Vec::with_capacity(HEADER_LEN + attrs.len());
        input.extend_from_slice(&self.message_type.to_u16().to_be_bytes());
        input.extend_from_slice(&((attrs.len() + 24) as u16).to_be_bytes());
        input.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        input.extend_from_slice(&self.transaction_id);
        input.extend_from_slice(&attrs);
        input
    }
}

fn parse_attr(attr_type: u16, value: &[u8], txid: &[u8; 12]) -> Result<StunAttribute, StunError> {
    let attr = match attr_type {
        0x0001 => StunAttribute::MappedAddress(
            parse_addr(value, false, txid).ok_or(StunError::MalformedAttribute(attr_type))?,
        ),
        0x0020 => StunAttribute::XorMappedAddress(
            parse_addr(value, true, txid).ok_or(StunError::MalformedAttribute(attr_type))?,
        ),
        0x0012 => StunAttribute::XorPeerAddress(
            parse_addr(value, true, txid).ok_or(StunError::MalformedAttribute(attr_type))?,
        ),
        0x0016 => StunAttribute::XorRelayedAddress(
            parse_addr(value, true, txid).ok_or(StunError::MalformedAttribute(attr_type))?,
        ),
        0x0006 => StunAttribute::Username(String::from_utf8_lossy(value).into_owned()),
        0x0009 => {
            if value.len() < 4 {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            let code = u16::from(value[2]) * 100 + u16::from(value[3]);
            StunAttribute::ErrorCode(code, String::from_utf8_lossy(&value[4..]).into_owned())
        }
        0x0014 => StunAttribute::Realm(String::from_utf8_lossy(value).into_owned()),
        0x0015 => StunAttribute::Nonce(String::from_utf8_lossy(value).into_owned()),
        0x8022 => StunAttribute::Software(String::from_utf8_lossy(value).into_owned()),
        0x0024 => {
            if value.len() != 4 {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            StunAttribute::Priority(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
        }
        0x0025 => StunAttribute::UseCandidate,
        0x8029 | 0x802A => {
            if value.len() != 8 {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            let tie = u64::from_be_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]);
            if attr_type == 0x8029 {
                StunAttribute::IceControlled(tie)
            } else {
                StunAttribute::IceControlling(tie)
            }
        }
        0x000D => {
            if value.len() != 4 {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            StunAttribute::Lifetime(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
        }
        0x0019 => {
            if value.len() != 4 {
                return Err(StunError::MalformedAttribute(attr_type));
            }
            StunAttribute::RequestedTransport(value[0])
        }
        0x0013 => StunAttribute::Data(value.to_vec()),
        other => StunAttribute::Unknown(other, value.to_vec()),
    };
    Ok(attr)
}

fn parse_addr(body: &[u8], xor: bool, txid: &[u8; 12]) -> Option<SocketAddr> {
    if body.len() < 8 {
        return None;
    }
    let family = body[1];
    let port = u16::from_be_bytes([body[2], body[3]]);
    let ip = match family {
        0x01 => IpAddr::from([body[4], body[5], body[6], body[7]]),
        0x02 => {
            if body.len() < 20 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&body[4..20]);
            IpAddr::from(o)
        }
        _ => return None,
    };
    Some(if xor {
        let (port, ip) = xor_address(SocketAddr::new(ip, port), txid);
        SocketAddr::new(ip, port)
    } else {
        SocketAddr::new(ip, port)
    })
}

fn xor_address(addr: SocketAddr, txid: &[u8; 12]) -> (u16, IpAddr) {
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let port = addr.port() ^ u16::from_be_bytes([cookie_be[0], cookie_be[1]]);
    match addr.ip() {
        IpAddr::V4(v4) => {
            let mut o = v4.octets();
            for (i, b) in o.iter_mut().enumerate() {
                *b ^= cookie_be[i];
            }
            (port, IpAddr::from(o))
        }
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&cookie_be);
            mask[4..].copy_from_slice(txid);
            for (i, b) in o.iter_mut().enumerate() {
                *b ^= mask[i];
            }
            (port, IpAddr::from(o))
        }
    }
}

fn encode_attr(attr: &StunAttribute, txid: &[u8; 12]) -> Vec<u8> {
    let (attr_type, value): (u16, Vec<u8>) = match attr {
        StunAttribute::MappedAddress(a) => (0x0001, encode_address(false, *a, txid)),
        StunAttribute::XorMappedAddress(a) => (0x0020, encode_address(true, *a, txid)),
        StunAttribute::XorPeerAddress(a) => (0x0012, encode_address(true, *a, txid)),
        StunAttribute::XorRelayedAddress(a) => (0x0016, encode_address(true, *a, txid)),
        StunAttribute::Username(u) => (0x0006, u.as_bytes().to_vec()),
        StunAttribute::MessageIntegrity(mac) => (0x0008, mac.clone()),
        StunAttribute::Fingerprint(crc) => (0x8028, crc.to_be_bytes().to_vec()),
        StunAttribute::ErrorCode(code, reason) => {
            let mut v = vec![0, 0];
            v.push((code / 100) as u8);
            v.push((code % 100) as u8);
            v.extend_from_slice(reason.as_bytes());
            (0x0009, v)
        }
        StunAttribute::Realm(r) => (0x0014, r.as_bytes().to_vec()),
        StunAttribute::Nonce(n) => (0x0015, n.as_bytes().to_vec()),
        StunAttribute::Software(s) => (0x8022, s.as_bytes().to_vec()),
        StunAttribute::Priority(p) => (0x0024, p.to_be_bytes().to_vec()),
        StunAttribute::UseCandidate => (0x0025, Vec::new()),
        StunAttribute::IceControlled(t) => (0x8029, t.to_be_bytes().to_vec()),
        StunAttribute::IceControlling(t) => (0x802A, t.to_be_bytes().to_vec()),
        StunAttribute::Lifetime(l) => (0x000D, l.to_be_bytes().to_vec()),
        StunAttribute::RequestedTransport(proto) => (0x0019, vec![*proto, 0, 0, 0]),
        StunAttribute::Data(d) => (0x0013, d.clone()),
        StunAttribute::Unknown(t, v) => (*t, v.clone()),
    };

    let mut out = Vec::with_capacity(4 + value.len() + 3);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    while out.len() % 4 != 0 {
        out.push(0); // RFC 8489 §14.1 padding
    }
    out
}

fn encode_address(xor: bool, addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let (port, ip) = if xor {
        xor_address(addr, txid)
    } else {
        (addr.port(), addr.ip())
    };
    let mut body = Vec::with_capacity(20);
    body.push(0); // reserved
    body.push(match ip {
        IpAddr::V4(_) => 0x01,
        IpAddr::V6(_) => 0x02,
    });
    body.extend_from_slice(&port.to_be_bytes());
    match ip {
        IpAddr::V4(v4) => body.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => body.extend_from_slice(&v6.octets()),
    }
    body
}

/// Verifies the MESSAGE-INTEGRITY attribute of `msg` against `key`
/// (short-term credential: the ICE password; RFC 8489 §9.2.2 / RFC 8445).
#[must_use]
pub fn verify_integrity(msg: &StunMessage, key: &[u8]) -> bool {
    let Some(StunAttribute::MessageIntegrity(stored)) = msg.attr(0x0008) else {
        return false;
    };
    constant_time_eq(&hmac_sha1(key, &msg.mac_input()), stored)
}

/// Computes and stores the MESSAGE-INTEGRITY attribute for `msg` using the
/// short-term-credential `key`. Any existing MESSAGE-INTEGRITY is replaced
/// and the FINGERPRINT (RFC 8489 requires it last) is moved to the end.
pub fn sign_integrity(msg: &mut StunMessage, key: &[u8]) {
    let mac = hmac_sha1(key, &msg.mac_input());
    let mut had_fp = false;
    msg.attributes.retain(|a| match a {
        StunAttribute::MessageIntegrity(_) => false,
        StunAttribute::Fingerprint(_) => {
            had_fp = true;
            false
        }
        _ => true,
    });
    msg.attributes.push(StunAttribute::MessageIntegrity(mac));
    if had_fp {
        msg.attributes.push(StunAttribute::Fingerprint(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compares two messages ignoring the FINGERPRINT value, which
    /// `serialize` recomputes from the serialized bytes.
    fn assert_same_ignoring_fp(a: &StunMessage, b: &StunMessage) {
        assert_eq!(a.message_type, b.message_type);
        assert_eq!(a.transaction_id, b.transaction_id);
        let strip = |m: &StunMessage| {
            m.attributes
                .iter()
                .filter(|attr| !matches!(attr, StunAttribute::Fingerprint(_)))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(strip(a), strip(b));
        assert!(a.attr(0x8028).is_some());
        assert!(b.attr(0x8028).is_some());
    }

    #[test]
    fn binding_request_roundtrip() {
        let addr: SocketAddr = "203.0.113.5:3478".parse().unwrap();
        let msg = StunMessage::new(StunMessageType::BindingRequest)
            .with(StunAttribute::Username("EsAw:REcv".into()))
            .with(StunAttribute::Priority(1_853_824_767))
            .with(StunAttribute::XorMappedAddress(addr))
            .with(StunAttribute::Software("tpt-webrtc".into()))
            .with(StunAttribute::IceControlling(0xDEAD_BEEF_1234_5678))
            .with(StunAttribute::Fingerprint(0));
        let bytes = msg.serialize();
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            MAGIC_COOKIE
        );

        let parsed = StunMessage::parse(&bytes).unwrap();
        assert_same_ignoring_fp(&parsed, &msg);
        assert_eq!(parsed.transaction_id, msg.transaction_id);
    }

    #[test]
    fn signed_message_roundtrip_and_verify() {
        let addr: SocketAddr = "198.51.100.7:50000".parse().unwrap();
        let mut msg = StunMessage::new(StunMessageType::BindingResponse)
            .with(StunAttribute::XorMappedAddress(addr))
            .with(StunAttribute::Fingerprint(0));
        sign_integrity(&mut msg, b"secret-ice-pwd-0001");
        let bytes = msg.serialize();

        let parsed = StunMessage::parse(&bytes).unwrap();
        assert!(verify_integrity(&parsed, b"secret-ice-pwd-0001"));
        assert!(!verify_integrity(&parsed, b"wrong-pwd"));
        assert_same_ignoring_fp(&parsed, &msg);
    }

    #[test]
    fn rfc5769_test_vector_realtime() {
        // RFC 5769 §2.1 sample request (software "STUN test client",
        // username "evtj:h6vY", ICE-CONTROLLED), signed with short-term
        // credentials and FINGERPRINT.
        let bytes: Vec<u8> = [
            0x00, 0x01, 0x00, 0x58, // Binding Request, length 0x58
            0x21, 0x12, 0xA4, 0x42, // magic
            0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE, // txid
            0x80, 0x22, 0x00, 0x10, // SOFTWARE
            b'S', b'T', b'U', b'N', b' ', b't', b'e', b's', b't', b' ', b'c', b'l', b'i', b'e',
            b'n', b't', 0x00, 0x24, 0x00, 0x04, // PRIORITY
            0x6E, 0x00, 0x01, 0xFF, 0x80, 0x29, 0x00, 0x08, // ICE-CONTROLLED
            0x93, 0x2F, 0xF9, 0xB1, 0x51, 0x26, 0x3B, 0x36, 0x00, 0x06, 0x00,
            0x09, // USERNAME "evtj:h6vY" + 3 pad
            b'e', b'v', b't', b'j', b':', b'h', b'6', b'v', b'Y', 0x20, 0x20, 0x20, 0x00, 0x08,
            0x00, 0x14, // MESSAGE-INTEGRITY
            0x9A, 0xEA, 0xA7, 0x0C, 0xBF, 0xD8, 0xCB, 0x56, 0x78, 0x1E, 0xF2, 0xB5, 0xB2, 0xD3,
            0xF2, 0x49, 0xC1, 0xB5, 0x71, 0xA2, 0x80, 0x28, 0x00, 0x04, // FINGERPRINT
            0xE5, 0x7A, 0x3B, 0xCF,
        ]
        .to_vec();

        let msg = StunMessage::parse(&bytes).expect("RFC 5769 sample must parse");
        assert_eq!(msg.message_type, StunMessageType::BindingRequest);
        assert_eq!(
            msg.attr(0x0006),
            Some(&StunAttribute::Username("evtj:h6vY".into()))
        );
        assert!(matches!(
            msg.attr(0x8029),
            Some(StunAttribute::IceControlled(_))
        ));
        // Short-term credential key = SASLprep(password).
        assert!(
            verify_integrity(&msg, b"VOkJxbRl1RmTxUk/WvJxBt"),
            "MESSAGE-INTEGRITY must verify with the RFC 5769 key"
        );
    }

    #[test]
    fn truncated_and_garbage_inputs() {
        assert_eq!(
            StunMessage::parse(&[]),
            Err(StunError::Malformed("shorter than header"))
        );
        assert_eq!(
            StunMessage::parse(&[0u8; 20]),
            Err(StunError::Malformed("magic cookie"))
        );
        let mut good = StunMessage::new(StunMessageType::BindingRequest).serialize();
        good.truncate(15);
        assert!(StunMessage::parse(&good).is_err());
    }
}
