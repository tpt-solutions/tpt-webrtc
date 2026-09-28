//! Cryptographic primitives (via `ring`) shared by the protocol crates.
//!
//! Everything crypto-related in the stack funnels through this module:
//! digests, HMAC, random bytes, constant-time comparison, CRC-32 (for STUN
//! FINGERPRINT) and self-signed DTLS certificate generation (ECDSA P-256,
//! SHA-256) with RFC-correct minimal DER encoding.

use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, KeyPair};

use crate::error::DtlsError;

/// Fresh system RNG handle (cheap to construct on demand).
fn rng() -> SystemRandom {
    SystemRandom::new()
}

/// Fills `dest` with cryptographically secure random bytes.
///
/// # Errors
/// Returns [`DtlsError::Crypto`] if the system RNG fails.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), DtlsError> {
    rng().fill(dest).map_err(|_| DtlsError::Crypto)
}

/// Random `u32` (e.g. ICE tie-breakers).
///
/// # Errors
/// Returns [`DtlsError::Crypto`] if the system RNG fails.
pub fn random_u32() -> Result<u32, DtlsError> {
    let mut b = [0u8; 4];
    random_bytes(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Random `u64` (e.g. ICE tie-breakers are 64-bit).
///
/// # Errors
/// Returns [`DtlsError::Crypto`] if the system RNG fails.
pub fn random_u64() -> Result<u64, DtlsError> {
    let mut b = [0u8; 8];
    random_bytes(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

/// SHA-256 digest.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// SHA-1 digest (STUN MESSAGE-INTEGRITY, DTLS fingerprint negotiation).
#[must_use]
pub fn sha1(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec()
}

/// HMAC-SHA1 (STUN short- and long-term credential message integrity).
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// HMAC-SHA256 (TLS 1.2 PRF, finished messages).
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// MD5 digest (TURN long-term credential keys: `MD5(user:realm:pass)`,
/// RFC 8656 §9.2.2). `ring` does not expose MD5, so a compact RFC 1321
/// implementation lives here.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    // Constants from RFC 1321.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Constant-time equality (for tag / fingerprint comparison).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// CRC-32 (IEEE 802.3, reflected, poly `0xEDB88320`) — used by the STUN
/// FINGERPRINT attribute (`crc32 ^ 0x5354554e`).
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A certificate fingerprint (hash algorithm + digest), as exchanged in SDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// e.g. `"sha-256"`.
    pub hash_algorithm: String,
    /// Digest bytes.
    pub value: Vec<u8>,
}

impl Fingerprint {
    /// Computes the SHA-256 fingerprint of DER certificate data.
    ///
    /// # Errors
    /// Currently infallible; kept fallible for API stability.
    pub fn sha256(der: &[u8]) -> Result<Self, DtlsError> {
        Ok(Self {
            hash_algorithm: "sha-256".into(),
            value: sha256(der),
        })
    }

    /// RFC 8122 colon-separated hex form, e.g. `AA:BB:...` (without the
    /// `sha-256 ` prefix).
    #[must_use]
    pub fn to_sdp_value(&self) -> String {
        self.value
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

// ---------------------------------------------------------------------------
// Minimal DER encoding
// ---------------------------------------------------------------------------

/// Encodes a DER length prefix.
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Tag-length-value encoding.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// DER INTEGER from a big-endian magnitude.
fn der_integer(magnitude: &[u8]) -> Vec<u8> {
    let mut content = magnitude
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect::<Vec<_>>();
    if content.is_empty() {
        content.push(0);
    }
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

/// DER OBJECT IDENTIFIER from decimal components.
fn der_oid(components: &[u64]) -> Vec<u8> {
    let mut body = vec![(components[0] * 40 + components[1]) as u8];
    for &c in &components[2..] {
        // Base-128 groups, most significant first; all but the last carry
        // the continuation bit.
        let mut groups = Vec::new();
        let mut v = c;
        loop {
            groups.push((v & 0x7F) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for (i, g) in groups.iter().enumerate().rev() {
            if i == 0 {
                body.push(*g);
            } else {
                body.push(*g | 0x80);
            }
        }
    }
    tlv(0x06, &body)
}

const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];

/// Subject CN placed in every generated certificate.
pub const CERT_SUBJECT_CN: &str = "tpt-webrtc";

fn name(cn: &str) -> Vec<u8> {
    let cn_value = tlv(0x0C, cn.as_bytes());
    let atv = tlv(
        0x30,
        &der_oid(OID_COMMON_NAME)
            .into_iter()
            .chain(cn_value)
            .collect::<Vec<_>>(),
    );
    let rdn = tlv(0x31, &atv);
    tlv(0x30, &rdn)
}

fn utc_time(s: &str) -> Vec<u8> {
    tlv(0x17, s.as_bytes())
}

/// Converts a fixed-width (r||s, 64-byte for P-256) ECDSA signature into the
/// DER `ECDSA-SigValue` encoding used by X.509.
#[must_use]
pub fn ecdsa_fixed_to_der(fixed: &[u8]) -> Vec<u8> {
    let (r, s) = fixed.split_at(fixed.len() / 2);
    let mut content = der_integer(r);
    content.extend_from_slice(&der_integer(s));
    tlv(0x30, &content)
}

/// Parses a DER length starting at `idx`, returning `(length, content_start)`.
fn parse_der_len(data: &[u8], idx: usize) -> Option<(usize, usize)> {
    let first = *data.get(idx)?;
    if first & 0x80 == 0 {
        Some((usize::from(first), idx + 1))
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*data.get(idx + 1 + i)?);
        }
        Some((len, idx + 1 + n))
    }
}

/// Parses a DER `ECDSA-SigValue` (SEQUENCE of two INTEGERs) back into the
/// fixed-width `r||s` encoding `ring` verifies; `None` on malformed input.
#[must_use]
pub fn ecdsa_der_to_fixed(der: &[u8]) -> Option<Vec<u8>> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let (seq_len, seq_start) = parse_der_len(der, 1)?;
    let end = seq_start.checked_add(seq_len)?;
    if der.len() < end {
        return None;
    }
    let mut pos = seq_start;
    let mut out = Vec::with_capacity(64);
    for _ in 0..2 {
        if der.get(pos) != Some(&0x02) {
            return None;
        }
        let (int_len, content_start) = parse_der_len(der, pos + 1)?;
        let content_end = content_start.checked_add(int_len)?;
        if content_end > end {
            return None;
        }
        let mut mag = der[content_start..content_end].to_vec();
        while mag.first() == Some(&0) {
            mag.remove(0);
        }
        if mag.len() > 32 {
            return None;
        }
        let pad = 32 - mag.len();
        out.resize(out.len() + pad, 0);
        out.extend_from_slice(&mag);
        pos = content_end;
    }
    if pos != end {
        return None;
    }
    Some(out)
}

/// A self-signed DTLS certificate: ECDSA P-256, SHA-256, long-lived.
///
/// WebRTC does not use a PKI — the certificate's fingerprint is transported
/// in SDP and compared after the handshake — so a minimal self-signed
/// structure with no extensions beyond `basicConstraints` is sufficient.
///
/// Clones share the same immutable certificate bytes (the DER, and therefore
/// the fingerprint, is stable across clones).
#[derive(Debug, Clone)]
pub struct DtlsCertificate {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    key_pair: signature::EcdsaKeyPair,
    pkcs8: Vec<u8>,
    der: Vec<u8>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsCertificateInner")
            .field("der_len", &self.der.len())
            .finish()
    }
}

impl DtlsCertificate {
    /// DER encoding of the certificate's public key (uncompressed EC point).
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.inner.key_pair.public_key().as_ref()
    }

    /// Generates a fresh key pair and self-signed certificate.
    ///
    /// # Examples
    /// ```
    /// use tpt_webrtc_core::DtlsCertificate;
    ///
    /// let cert = DtlsCertificate::generate().unwrap();
    /// assert_eq!(cert.fingerprint().unwrap().value.len(), 32);
    /// ```
    ///
    /// # Errors
    /// Returns [`DtlsError::Crypto`] if key generation or signing fails.
    pub fn generate() -> Result<Self, DtlsError> {
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng(),
        )
        .map_err(|_| DtlsError::Crypto)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Builds a certificate around an existing PKCS#8 (unencrypted) key.
    ///
    /// # Errors
    /// Returns [`DtlsError::Crypto`] if the key cannot be parsed or signing fails.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, DtlsError> {
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            &rng(),
        )
        .map_err(|_| DtlsError::Crypto)?;
        let der = Self::build_self_signed(&key_pair)?;
        Ok(Self {
            inner: std::sync::Arc::new(Inner {
                key_pair,
                pkcs8: pkcs8.to_vec(),
                der,
            }),
        })
    }

    fn build_self_signed(key_pair: &signature::EcdsaKeyPair) -> Result<Vec<u8>, DtlsError> {
        // Deterministic serial from the public key: the same key always
        // yields the same certificate (and thus the same fingerprint).
        let mut serial = sha256(key_pair.public_key().as_ref());
        serial.truncate(16);
        serial[0] &= 0x7F; // keep the INTEGER positive

        let subject = name(CERT_SUBJECT_CN);
        let spki = {
            let alg = tlv(
                0x30,
                &der_oid(OID_EC_PUBLIC_KEY)
                    .into_iter()
                    .chain(der_oid(OID_SECP256R1))
                    .collect::<Vec<_>>(),
            );
            let point = key_pair.public_key().as_ref();
            let mut bits = vec![0u8]; // no unused bits
            bits.extend_from_slice(point);
            tlv(
                0x30,
                &alg.into_iter().chain(tlv(0x03, &bits)).collect::<Vec<_>>(),
            )
        };
        let sig_alg = tlv(0x30, &der_oid(OID_ECDSA_WITH_SHA256));
        let validity = tlv(
            0x30,
            &utc_time("250101000000Z")
                .into_iter()
                .chain(utc_time("350101000000Z"))
                .collect::<Vec<_>>(),
        );
        let basic_constraints_value = tlv(0x04, &tlv(0x30, &[]));
        let extension = tlv(
            0x30,
            &der_oid(OID_BASIC_CONSTRAINTS)
                .into_iter()
                .chain([0x01, 0x01, 0xFF]) // critical: TRUE
                .chain(basic_constraints_value)
                .collect::<Vec<_>>(),
        );
        let extensions = tlv(0xA3, &tlv(0x30, &extension));
        let version = tlv(0xA0, &der_integer(&[2]));

        let mut tbs_content = version;
        tbs_content.extend_from_slice(&der_integer(&serial));
        tbs_content.extend_from_slice(&sig_alg);
        tbs_content.extend_from_slice(&subject);
        tbs_content.extend_from_slice(&validity);
        tbs_content.extend_from_slice(&subject);
        tbs_content.extend_from_slice(&spki);
        tbs_content.extend_from_slice(&extensions);
        let tbs = tlv(0x30, &tbs_content);

        let signature_der = ecdsa_fixed_to_der(
            key_pair
                .sign(&rng(), &tbs)
                .map_err(|_| DtlsError::Crypto)?
                .as_ref(),
        );
        let mut sig_bits = vec![0u8]; // no unused bits
        sig_bits.extend_from_slice(&signature_der);
        let signature_bitstring = tlv(0x03, &sig_bits);
        Ok(tlv(
            0x30,
            &tbs.into_iter()
                .chain(sig_alg)
                .chain(signature_bitstring)
                .collect::<Vec<_>>(),
        ))
    }

    /// DER encoding of the full certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.inner.der
    }

    /// SHA-256 fingerprint of the DER certificate (what goes into SDP).
    ///
    /// # Errors
    /// Currently infallible.
    pub fn fingerprint(&self) -> Result<Fingerprint, DtlsError> {
        Fingerprint::sha256(&self.inner.der)
    }

    /// PKCS#8 private key material (for persisting the certificate).
    #[must_use]
    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.inner.pkcs8.clone()
    }

    /// Signs `msg`, returning the DER-encoded ECDSA-SigValue.
    ///
    /// # Errors
    /// Returns [`DtlsError::Crypto`] if signing fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let sig = self
            .inner
            .key_pair
            .sign(&rng(), msg)
            .map_err(|_| DtlsError::Crypto)?;
        Ok(ecdsa_fixed_to_der(sig.as_ref()))
    }

    /// Verifies a DER-encoded `ECDSA-SigValue` over `msg` against this
    /// certificate's public key.
    ///
    /// Note: `ring` verifies the fixed-width encoding, so the DER signature
    /// is converted back first.
    ///
    /// # Errors
    /// Returns [`DtlsError::Crypto`] on verification failure.
    pub fn verify(&self, msg: &[u8], der_sig: &[u8]) -> Result<(), DtlsError> {
        let fixed = ecdsa_der_to_fixed(der_sig).ok_or(DtlsError::Crypto)?;
        let pub_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            self.inner.key_pair.public_key().as_ref(),
        );
        pub_key.verify(msg, &fixed).map_err(|_| DtlsError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_ieee_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b"hello"), 0x3610_A686);
    }

    #[test]
    fn hmac_sha1_rfc2202_vector() {
        // RFC 2202 test case 2: key "Jefe", data "what do ya want for nothing?"
        let mac = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256(b"abc")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn md5_rfc1321_vectors() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(md5(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hex(md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn constant_time_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn der_oid_known_encodings() {
        let expect = |c: &[u64], hex: &str| {
            assert_eq!(
                der_oid(c)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                hex
            );
        };
        expect(OID_COMMON_NAME, "0603550403");
        expect(OID_EC_PUBLIC_KEY, "06072a8648ce3d0201");
        expect(OID_SECP256R1, "06082a8648ce3d030107");
        expect(OID_ECDSA_WITH_SHA256, "06082a8648ce3d040302");
    }

    #[test]
    fn ecdsa_der_conversion() {
        // r = 0x80.. : needs a leading zero
        let mut fixed = vec![0x80u8; 32];
        fixed.extend_from_slice(&[0x01; 32]);
        let der = ecdsa_fixed_to_der(&fixed);
        assert_eq!(der[0], 0x30);
        assert!(der.windows(4).any(|w| w == [0x02, 0x21, 0x00, 0x80]));
        assert_eq!(ecdsa_der_to_fixed(&der).unwrap(), fixed);
        assert!(ecdsa_der_to_fixed(&der[..der.len() - 1]).is_none());
        assert!(ecdsa_der_to_fixed(&[0x02, 0x00]).is_none());
    }

    #[test]
    fn certificate_generate_sign_verify_fingerprint() {
        let cert = DtlsCertificate::generate().unwrap();
        assert_eq!(cert.der()[0], 0x30);
        assert!(cert.der().len() > 200);
        assert_eq!(
            cert.der()
                .windows(CERT_SUBJECT_CN.len())
                .filter(|w| *w == CERT_SUBJECT_CN.as_bytes())
                .count(),
            2
        ); // issuer + subject

        let fp = cert.fingerprint().unwrap();
        assert_eq!(fp.hash_algorithm, "sha-256");
        assert_eq!(fp.to_sdp_value().len(), 95); // 32 bytes * 3 - 1

        let msg = b"handshake context";
        let sig = cert.sign(msg).unwrap();
        assert_eq!(sig[0], 0x30);
        cert.verify(msg, &sig).unwrap();
        let mut tampered = sig.clone();
        tampered[10] ^= 0xFF;
        // Any single-byte flip changes a parsed integer (or breaks DER
        // structure), so verification must fail.
        assert!(cert.verify(msg, &tampered).is_err());
    }

    #[test]
    fn certificate_pkcs8_roundtrip_is_deterministic() {
        let cert = DtlsCertificate::generate().unwrap();
        let pkcs8 = cert.to_pkcs8();
        let rebuilt = DtlsCertificate::from_pkcs8(&pkcs8).unwrap();
        // Same key material and same public identity (the TBS is rebuilt
        // with a fresh ECDSA nonce, so signature bytes may differ).
        assert_eq!(cert.public_key(), rebuilt.public_key());
        let msg = b"cross-sign check";
        rebuilt.verify(msg, &cert.sign(msg).unwrap()).unwrap();
    }

    #[test]
    fn two_certs_differ() {
        let a = DtlsCertificate::generate().unwrap();
        let b = DtlsCertificate::generate().unwrap();
        assert_ne!(a.der(), b.der());
    }
}
