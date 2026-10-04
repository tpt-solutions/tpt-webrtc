//! DTLS record layer (RFC 6347 §4.1) with the AEAD (RFC 5246 §6.2.3.3)
//! AEAD_AES_128_GCM cipher.

use ring::aead;

use crate::prf::WriteKeys;
use tpt_webrtc_core::DtlsError;

/// Content types (RFC 5246 §6.2.1).
pub mod content_type {
    /// ChangeCipherSpec.
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    /// Alert.
    pub const ALERT: u8 = 21;
    /// Handshake.
    pub const HANDSHAKE: u8 = 22;
    /// ApplicationData.
    pub const APPLICATION_DATA: u8 = 23;
}

/// DTLS 1.2 version on the wire: `{254, 253}`.
pub const DTLS_1_2_VERSION: [u8; 2] = [0xFE, 0xFD];

/// Fixed AEAD tag length (AES-128-GCM).
const TAG_LEN: usize = 16;

/// One direction's crypto state.
#[derive(Debug, Clone)]
struct CipherState {
    key: aead::LessSafeKey,
    /// Static 4-byte IV part of the per-record nonce.
    static_iv: Vec<u8>,
    next_seq: u64,
}

/// The DTLS record layer. Plaintext records are used before the
/// ChangeCipherSpec; AEAD records after.
#[derive(Debug, Default)]
pub struct RecordLayer {
    write: Option<CipherState>,
    read: Option<CipherState>,
}

impl RecordLayer {
    /// Fresh layer with both directions still in plaintext (epoch 0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the cipher for both directions from the negotiated keys;
    /// the role decides which write key is ours (client writes with the
    /// client key).
    pub fn activate(&mut self, is_client: bool, keys: &WriteKeys) {
        let make = |key: &[u8], iv: &[u8], seq: u64| CipherState {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_128_GCM, key).expect("16-byte AES-128 key"),
            ),
            static_iv: iv.to_vec(),
            next_seq: seq,
        };
        self.write = Some(if is_client {
            make(&keys.client_key, &keys.client_iv, 0)
        } else {
            make(&keys.server_key, &keys.server_iv, 0)
        });
        self.read = Some(if is_client {
            make(&keys.server_key, &keys.server_iv, 0)
        } else {
            make(&keys.client_key, &keys.client_iv, 0)
        });
    }

    /// Whether the write direction is encrypted (CCS sent).
    #[must_use]
    pub fn is_write_encrypted(&self) -> bool {
        self.write.is_some()
    }

    /// Builds a plaintext DTLS record (pre-CCS).
    pub fn plaintext_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + payload.len());
        out.push(content_type);
        out.extend_from_slice(&DTLS_1_2_VERSION);
        out.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        out.extend_from_slice(&[0u8; 6]); // sequence (unused for plaintext codec)
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Encrypts `plaintext` into a full DTLS record with the next write
    /// sequence number (epoch 1).
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] before CCS; [`DtlsError::Crypto`] on
    /// sealing failure.
    pub fn protect(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let (key, static_iv, seq) = {
            let w = self.write.as_ref().ok_or(DtlsError::InvalidState)?;
            let seq = w.next_seq;
            (w.key.clone(), w.static_iv.clone(), seq)
        };
        self.write.as_mut().expect("checked above").next_seq += 1;

        let mut nonce = static_iv.clone(); // 4 bytes static
        nonce.extend_from_slice(&seq.to_be_bytes()); // 8 bytes explicit
        let aad_data = aad(content_type, seq, plaintext.len());
        let mut in_out = plaintext.to_vec();
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_arr),
            aead::Aad::from(aad_data),
            &mut in_out,
        )
        .map_err(|_| DtlsError::Crypto)?;

        let mut out = Vec::with_capacity(21 + in_out.len());
        out.push(content_type);
        out.extend_from_slice(&DTLS_1_2_VERSION);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..8]); // 48-bit seq
        out.extend_from_slice(&((8 + in_out.len()) as u16).to_be_bytes()); // explicit nonce + ct + tag
        out.extend_from_slice(&nonce[4..12]); // explicit nonce part
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    /// Parses and decrypts one record from `data` (which must contain
    /// exactly one record).
    ///
    /// Returns `(content_type, epoch, plaintext)`.
    ///
    /// # Errors
    /// [`DtlsError::MalformedPacket`]-style failures map to
    /// [`DtlsError::InvalidState`] for structurally broken records and
    /// [`DtlsError::DecryptionFailed`] for authentication failures.
    pub fn unprotect(&mut self, data: &[u8]) -> Result<(u8, u16, Vec<u8>), DtlsError> {
        if data.len() < 13 {
            return Err(DtlsError::InvalidState);
        }
        let content_type = data[0];
        // Layout: type(1) version(2) epoch(2) seq(6) length(2).
        let epoch = u16::from_be_bytes([data[3], data[4]]);
        let seq = u64::from_be_bytes([0, 0, data[5], data[6], data[7], data[8], data[9], data[10]]);
        let len = u16::from_be_bytes([data[11], data[12]]) as usize;
        if data.len() < 13 + len {
            return Err(DtlsError::InvalidState);
        }
        let body = &data[13..13 + len];

        if epoch == 0 {
            return Ok((content_type, epoch, body.to_vec()));
        }
        if body.len() < 8 + TAG_LEN {
            return Err(DtlsError::DecryptionFailed);
        }
        let (key, static_iv) = {
            let r = self.read.as_ref().ok_or(DtlsError::DecryptionFailed)?;
            (r.key.clone(), r.static_iv.clone())
        };
        let mut nonce = static_iv;
        nonce.extend_from_slice(&body[..8]);
        let ct = &body[8..];
        let plaintext_len = ct.len() - TAG_LEN;
        let aad_data = aad(content_type, seq, plaintext_len);
        let mut in_out = ct.to_vec();
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce.try_into().expect("12-byte nonce")),
                aead::Aad::from(aad_data),
                &mut in_out,
            )
            .map_err(|_| DtlsError::DecryptionFailed)?;
        Ok((content_type, epoch, plain.to_vec()))
    }
}

/// AEAD additional data per RFC 5246 §6.2.3.3 as adapted by RFC 6347:
/// `epoch || seq(6) || type || version || plaintext_length`.
fn aad(content_type: u8, seq: u64, plaintext_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..8]);
    out.push(content_type);
    out.extend_from_slice(&DTLS_1_2_VERSION);
    out.extend_from_slice(&(plaintext_len as u16).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prf::{key_block, master_secret};

    fn keys() -> WriteKeys {
        let (cr, sr) = ([1u8; 32], [2u8; 32]);
        let master = master_secret(&[0xCC; 32], &cr, &sr);
        key_block(&master, &cr, &sr)
    }

    #[test]
    fn plaintext_record_shape() {
        let rec = RecordLayer::plaintext_record(content_type::HANDSHAKE, b"abc");
        assert_eq!(rec[0], content_type::HANDSHAKE);
        assert_eq!(&rec[1..3], &DTLS_1_2_VERSION);
        assert_eq!(rec.len(), 13 + 3);
        assert_eq!(&rec[13..], b"abc");
    }

    #[test]
    fn aead_roundtrip_and_sequence() {
        let mut client = RecordLayer::new();
        let mut server = RecordLayer::new();
        client.activate(true, &keys());
        server.activate(false, &keys());

        let r1 = client
            .protect(content_type::APPLICATION_DATA, b"hello")
            .unwrap();
        let r2 = client
            .protect(content_type::APPLICATION_DATA, b"world")
            .unwrap();
        assert_ne!(r1, r2, "sequence numbers must differ");

        let (ty, epoch, plain) = server.unprotect(&r1).unwrap();
        assert_eq!((ty, epoch), (content_type::APPLICATION_DATA, 1));
        assert_eq!(plain, b"hello");
        let (_, _, plain2) = server.unprotect(&r2).unwrap();
        assert_eq!(plain2, b"world");
    }

    #[test]
    fn tampering_fails_authentication() {
        let mut client = RecordLayer::new();
        let mut server = RecordLayer::new();
        client.activate(true, &keys());
        server.activate(false, &keys());
        let mut rec = client
            .protect(content_type::APPLICATION_DATA, b"secret")
            .unwrap();
        let last = rec.len() - 1;
        rec[last] ^= 0xFF;
        assert_eq!(server.unprotect(&rec), Err(DtlsError::DecryptionFailed));
    }

    #[test]
    fn protect_requires_activation() {
        let mut rl = RecordLayer::new();
        assert_eq!(
            rl.protect(content_type::APPLICATION_DATA, b"x"),
            Err(DtlsError::InvalidState)
        );
    }
}
