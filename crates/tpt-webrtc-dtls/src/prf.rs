//! TLS 1.2 key schedule: pseudo-random function, master secret, key block
//! and the RFC 5705 exporter used for DTLS-SRTP.

use tpt_webrtc_core::{hmac_sha256, random_bytes};

/// `P_<hash>(secret, data)` (RFC 5246 §5): iterate HMAC-SHA256.
fn p_hash(secret: &[u8], data: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut a = hmac_sha256(secret, data); // A(1)
    while out.len() < len {
        let mut input = Vec::with_capacity(a.len() + data.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(data);
        out.extend_from_slice(&hmac_sha256(secret, &input));
        a = hmac_sha256(secret, &a); // A(i+1)
    }
    out.truncate(len);
    out
}

/// The TLS 1.2 PRF with SHA-256: `PRF(secret, label, seed) = P_SHA256(secret, label || seed)`.
#[must_use]
pub fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(label.len() + seed.len());
    data.extend_from_slice(label);
    data.extend_from_slice(seed);
    p_hash(secret, &data, len)
}

/// Random bytes for hello nonces / cookies.
///
/// # Errors
/// Propagates RNG failure.
pub fn random(buf: &mut [u8]) -> Result<(), tpt_webrtc_core::DtlsError> {
    random_bytes(buf).map_err(|_| tpt_webrtc_core::DtlsError::Crypto)
}

/// Computes the TLS 1.2 master secret from the ECDHE pre-master secret.
#[must_use]
pub fn master_secret(
    pre_master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_sha256(pre_master, b"master secret", &seed, 48)
}

/// Key block for the AEAD suite: `client_write_key(16) | server_write_key(16)
/// | client_write_iv(4) | server_write_iv(4)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteKeys {
    /// 16-byte client write key.
    pub client_key: Vec<u8>,
    /// 16-byte server write key.
    pub server_key: Vec<u8>,
    /// 4-byte client write IV.
    pub client_iv: Vec<u8>,
    /// 4-byte server write IV.
    pub server_iv: Vec<u8>,
}

/// Expands the key block from the master secret (RFC 5246 §6.3, AEAD
/// lengths: 16+16 key bytes, 4+4 explicit-nonce IV bytes).
#[must_use]
pub fn key_block(master: &[u8], client_random: &[u8; 32], server_random: &[u8; 32]) -> WriteKeys {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    // 16 + 16 + 4 + 4 = 40
    let block = prf_sha256(master, b"key expansion", &seed, 40);
    WriteKeys {
        client_key: block[0..16].to_vec(),
        server_key: block[16..32].to_vec(),
        client_iv: block[32..36].to_vec(),
        server_iv: block[36..40].to_vec(),
    }
}

/// The RFC 5705 exporter master secret.
#[must_use]
pub fn exporter_master_secret(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_sha256(master, b"exporter", &seed, 48)
}

/// RFC 5705 §4 exporter value (empty context form used by DTLS-SRTP).
#[must_use]
pub fn export_keying_material(
    exporter_master: &[u8],
    label: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    len: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(2 + 64);
    seed.extend_from_slice(&(len as u16).to_be_bytes());
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_sha256(exporter_master, label, &seed, len)
}

/// Derives the DTLS-SRTP key material (RFC 5764 §4.2): 60 bytes via the
/// `EXTRACTOR-dtls_srtp` label, split client/server key + salt.
///
/// # Errors
/// Returns [`tpt_webrtc_core::DtlsError::InvalidState`] when the key
/// material has the wrong length (never for the 60-byte export).
pub fn srtp_keys_from_export(export: &[u8]) -> Result<crate::SrtpKeys, tpt_webrtc_core::DtlsError> {
    if export.len() != 60 {
        return Err(tpt_webrtc_core::DtlsError::InvalidState);
    }
    Ok(crate::SrtpKeys {
        client_key: export[0..16].to_vec(),
        server_key: export[16..32].to_vec(),
        client_salt: export[32..46].to_vec(),
        server_salt: export[46..60].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_hash_length_and_determinism() {
        let a = p_hash(b"secret", b"data", 100);
        let b = p_hash(b"secret", b"data", 100);
        assert_eq!(a.len(), 100);
        assert_eq!(a, b);
        let c = p_hash(b"secret", b"other", 100);
        assert_ne!(a, c);
    }

    #[test]
    fn prf_rfc5246_style_vector() {
        // Structured self-vector: PRF is deterministic, length-preserving
        // and label-sensitive.
        let x = prf_sha256(b"key", b"label", b"seed", 32);
        let y = prf_sha256(b"key", b"Label", b"seed", 32);
        assert_ne!(x, y);
        let long = prf_sha256(b"key", b"label", b"seed", 80);
        assert_eq!(&long[..32], &x[..], "prefix property of P_hash");
    }

    #[test]
    fn key_block_lengths() {
        let (cr, sr) = ([7u8; 32], [9u8; 32]);
        let master = master_secret(&[0xAA; 32], &cr, &sr);
        assert_eq!(master.len(), 48);
        let keys = key_block(&master, &cr, &sr);
        assert_eq!(keys.client_key.len(), 16);
        assert_eq!(keys.server_key.len(), 16);
        assert_eq!(keys.client_iv.len(), 4);
        assert_eq!(keys.server_iv.len(), 4);
        assert_ne!(keys.client_key, keys.server_key);
    }

    #[test]
    fn srtp_export_is_60_bytes_and_symmetric() {
        let (cr, sr) = ([1u8; 32], [2u8; 32]);
        let master = master_secret(&[0xBB; 32], &cr, &sr);
        let exporter = exporter_master_secret(&master, &cr, &sr);
        let export = export_keying_material(&exporter, b"EXTRACTOR-dtls_srtp", &cr, &sr, 60);
        assert_eq!(export.len(), 60);
        let keys = srtp_keys_from_export(&export).unwrap();
        assert_eq!(keys.client_key.len(), 16);
        assert_eq!(keys.client_salt.len(), 14);
        assert_ne!(keys.client_key, keys.server_key);
        assert_ne!(keys.client_salt, keys.server_salt);
    }
}
