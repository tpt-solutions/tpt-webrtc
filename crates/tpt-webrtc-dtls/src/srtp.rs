//! SRTP / SRTCP sessions (RFC 3711) with the two profiles negotiated via
//! `use_srtp`: `AES128_CM_HMAC_SHA1_80` (RFC 3711) and
//! `AEAD_AES_128_GCM` (RFC 7714). The 256-bit variants work the same way
//! when 32-byte keys are supplied.
//!
//! Sessions operate on raw packet bytes; `tpt-webrtc-rtp` layers typed
//! helpers on top. Each session is one direction of one SSRC stream and
//! tracks the roll-over counter (ROC) plus a replay window for the
//! unprotect direction.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use crate::{SrtpCipher, SrtpKeys};

use tpt_webrtc_core::{constant_time_eq, hmac_sha1, DtlsError};

/// Auth tag length for the CM/HMAC-SHA1-80 profile.
const TAG_80: usize = 10;
/// GCM tag length.
const TAG_GCM: usize = 16;
/// Replay window size (packets).
const REPLAY_WINDOW: u64 = 64;

/// Direction of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Encrypt outgoing packets.
    Protect,
    /// Decrypt incoming packets.
    Unprotect,
}

/// One SRTP/SRTCP session for a single direction of one SSRC stream.
pub struct SrtpSession {
    cipher: SrtpCipher,
    /// 16- or 32-byte session encipherment key.
    enc_key: Vec<u8>,
    /// 14-byte session salt.
    salt: Vec<u8>,
    /// 20-byte session HMAC-SHA1 key (CM profile only).
    auth_key: Vec<u8>,
    /// Roll-over counter (protect: current; unprotect: highest seen).
    roc: u32,
    /// Replay tracking (bitfield over recent indices below `highest_index`).
    replay: u64,
    /// Highest 48-bit index seen (unprotect).
    highest_index: u64,
    /// SRTCP index counter (both directions; per session).
    rtcp_index: u32,
}

impl SrtpSession {
    /// Creates a session from the DTLS-SRTP keys, selecting the key pair
    /// for this direction (a client protecting uses the client key).
    ///
    /// # Errors
    /// [`DtlsError::SrtpKeyMaterial`] on wrong key/salt lengths for the cipher.
    pub fn new(
        keys: SrtpKeys,
        is_client: bool,
        direction: Direction,
        cipher: SrtpCipher,
    ) -> Result<Self, DtlsError> {
        let (key, salt) = match (is_client, direction) {
            (true, Direction::Protect) | (false, Direction::Unprotect) => {
                (keys.client_key.clone(), keys.client_salt.clone())
            }
            (false, Direction::Protect) | (true, Direction::Unprotect) => {
                (keys.server_key.clone(), keys.server_salt.clone())
            }
        };
        let key_ok = match cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::AeadAes128Gcm => key.len() == 16,
            SrtpCipher::Aes256CmHmacSha1_80 | SrtpCipher::AeadAes256Gcm => key.len() == 32,
        };
        if !key_ok || salt.len() != 14 {
            return Err(DtlsError::SrtpKeyMaterial);
        }
        // Session auth key: 20 bytes from label 1 (RFC 3711 §4.3.3).
        let auth_key = aes_cm_keystream(&key, &salt, 1, 20);
        Ok(Self {
            cipher,
            enc_key: key,
            salt,
            auth_key,
            roc: 0,
            replay: 0,
            highest_index: 0,
            rtcp_index: 0,
        })
    }

    /// Protects (encrypts + authenticates) one RTP packet given as raw
    /// bytes; returns the protected packet.
    ///
    /// # Errors
    /// [`DtlsError::InvalidState`] for malformed RTP headers,
    /// [`DtlsError::Crypto`] for cipher failures.
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let hdr_len = rtp_header_len(packet).ok_or(DtlsError::InvalidState)?;
        if packet.len() < hdr_len + 1 {
            return Err(DtlsError::InvalidState);
        }
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let seq = u16::from_be_bytes([packet[2], packet[3]]);

        match self.cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::Aes256CmHmacSha1_80 => {
                let iv = rtp_iv(&self.salt, ssrc, self.roc, seq);
                let mut out = packet[..hdr_len].to_vec();
                out.extend_from_slice(&aes_cm_crypt(&self.enc_key, &iv, &packet[hdr_len..]));
                // HMAC-SHA1 over header || encrypted payload || ROC.
                let mut mac_input = out.clone();
                mac_input.extend_from_slice(&self.roc.to_be_bytes());
                let tag = &hmac_sha1(&self.auth_key, &mac_input)[..TAG_80];
                out.extend_from_slice(tag);
                Ok(out)
            }
            SrtpCipher::AeadAes128Gcm | SrtpCipher::AeadAes256Gcm => {
                let iv = aead_iv(&self.salt, ssrc, self.roc, seq);
                let ct = gcm_crypt(&self.enc_key, &iv, &packet[..hdr_len], &packet[hdr_len..], true)?;
                let mut out = packet[..hdr_len].to_vec();
                out.extend_from_slice(&ct); // ciphertext || tag
                Ok(out)
            }
        }
    }

    /// Unprotects one RTP packet; returns the plaintext packet.
    ///
    /// # Errors
    /// [`DtlsError::SrtpAuthFailed`] on tag mismatch,
    /// [`DtlsError::SrtpReplay`] for replayed indices,
    /// [`DtlsError::InvalidState`] for malformed input.
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let hdr_len = rtp_header_len(packet).ok_or(DtlsError::InvalidState)?;
        let tag_len = self.tag_len();
        if packet.len() < hdr_len + 1 + tag_len {
            return Err(DtlsError::InvalidState);
        }
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let index = self.estimate_index(seq);

        match self.cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::Aes256CmHmacSha1_80 => {
                let (body, tag) = packet.split_at(packet.len() - tag_len);
                let mut mac_input = body.to_vec();
                mac_input.extend_from_slice(&index.roc.to_be_bytes());
                let want = &hmac_sha1(&self.auth_key, &mac_input)[..TAG_80];
                if !constant_time_eq(want, tag) {
                    return Err(DtlsError::SrtpAuthFailed);
                }
                let iv = rtp_iv(&self.salt, ssrc, index.roc, seq);
                let mut out = body[..hdr_len].to_vec();
                out.extend_from_slice(&aes_cm_crypt(&self.enc_key, &iv, &body[hdr_len..]));
                self.accept(index)?;
                Ok(out)
            }
            SrtpCipher::AeadAes128Gcm | SrtpCipher::AeadAes256Gcm => {
                let iv = aead_iv(&self.salt, ssrc, index.roc, seq);
                let (aad, ct) = packet.split_at(hdr_len);
                let plain = gcm_crypt(&self.enc_key, &iv, aad, ct, false)?;
                self.accept(index)?;
                let mut out = aad.to_vec();
                out.extend_from_slice(&plain);
                Ok(out)
            }
        }
    }

    /// Protects one RTCP compound packet: `| header(8) | ciphertext |
    /// E+index(4) | tag |`.
    ///
    /// # Errors
    /// Same as [`protect_rtp`](Self::protect_rtp).
    pub fn protect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, DtlsError> {
        if packet.len() < 8 {
            return Err(DtlsError::InvalidState);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        self.rtcp_index = (self.rtcp_index + 1) & 0x7FFF_FFFF;
        let index = self.rtcp_index;
        let e_index = 0x8000_0000u32 | index;

        match self.cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::Aes256CmHmacSha1_80 => {
                let iv = rtcp_iv(&self.salt, ssrc, index);
                let mut out = packet[..8].to_vec();
                out.extend_from_slice(&aes_cm_crypt(&self.enc_key, &iv, &packet[8..]));
                out.extend_from_slice(&e_index.to_be_bytes());
                let tag = &hmac_sha1(&self.auth_key, &out)[..TAG_80];
                out.extend_from_slice(tag);
                Ok(out)
            }
            SrtpCipher::AeadAes128Gcm | SrtpCipher::AeadAes256Gcm => {
                let iv = rtcp_aead_iv(&self.salt, ssrc, index);
                let ct = gcm_crypt(&self.enc_key, &iv, &packet[..8], &packet[8..], true)?;
                let mut out = packet[..8].to_vec();
                out.extend_from_slice(&ct);
                out.extend_from_slice(&e_index.to_be_bytes());
                Ok(out)
            }
        }
    }

    /// Unprotects one RTCP compound packet.
    ///
    /// # Errors
    /// Same as [`unprotect_rtp`](Self::unprotect_rtp).
    pub fn unprotect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, DtlsError> {
        let tag_len = self.tag_len();
        match self.cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::Aes256CmHmacSha1_80 => {
                if packet.len() < 8 + 4 + tag_len {
                    return Err(DtlsError::InvalidState);
                }
                let (body, tag) = packet.split_at(packet.len() - tag_len);
                let want = &hmac_sha1(&self.auth_key, body)[..TAG_80];
                if !constant_time_eq(want, tag) {
                    return Err(DtlsError::SrtpAuthFailed);
                }
                let e_index = index_field(body)?;
                let index = e_index & 0x7FFF_FFFF;
                let ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let iv = rtcp_iv(&self.salt, ssrc, index);
                let mut out = body[..8].to_vec();
                out.extend_from_slice(&aes_cm_crypt(
                    &self.enc_key,
                    &iv,
                    &body[8..body.len() - 4],
                ));
                Ok(out)
            }
            SrtpCipher::AeadAes128Gcm | SrtpCipher::AeadAes256Gcm => {
                if packet.len() < 8 + 4 + TAG_GCM {
                    return Err(DtlsError::InvalidState);
                }
                let split = packet.len() - 4 - TAG_GCM;
                let (head, rest) = packet.split_at(split);
                let e_index = index_field(rest)?;
                let index = e_index & 0x7FFF_FFFF;
                let ssrc = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
                let iv = rtcp_aead_iv(&self.salt, ssrc, index);
                let mut aad = head.to_vec();
                aad.extend_from_slice(&e_index.to_be_bytes());
                let plain = gcm_crypt(&self.enc_key, &iv, &aad, &rest[..rest.len() - 4], false)?;
                let mut out = head.to_vec();
                out.extend_from_slice(&plain);
                Ok(out)
            }
        }
    }

    fn tag_len(&self) -> usize {
        match self.cipher {
            SrtpCipher::Aes128CmHmacSha1_80 | SrtpCipher::Aes256CmHmacSha1_80 => TAG_80,
            SrtpCipher::AeadAes128Gcm | SrtpCipher::AeadAes256Gcm => TAG_GCM,
        }
    }

    /// RFC 3711 Appendix A index estimation: prefer the in-window candidate
    /// under the current ROC, otherwise assume the ROC just rolled over.
    fn estimate_index(&self, seq: u16) -> Index {
        let candidate = (u64::from(self.roc) << 16) | u64::from(seq);
        if self.highest_index == 0 || candidate + REPLAY_WINDOW > self.highest_index {
            Index { roc: self.roc, index: candidate }
        } else {
            Index {
                roc: self.roc.wrapping_add(1),
                index: (u64::from(self.roc.wrapping_add(1)) << 16) | u64::from(seq),
            }
        }
    }

    fn accept(&mut self, index: Index) -> Result<(), DtlsError> {
        if index.index + REPLAY_WINDOW <= self.highest_index {
            return Err(DtlsError::SrtpReplay);
        }
        if index.index > self.highest_index {
            let shift = index.index - self.highest_index;
            self.replay = if shift >= 64 { 0 } else { self.replay << shift };
            self.highest_index = index.index;
            self.roc = index.roc;
            return Ok(());
        }
        let offset = self.highest_index - index.index;
        let bit = 1u64 << offset;
        if self.replay & bit != 0 {
            return Err(DtlsError::SrtpReplay);
        }
        self.replay |= bit;
        Ok(())
    }
}

struct Index {
    roc: u32,
    index: u64,
}

/// Reads the big-endian u32 in the last 4 bytes of `body`.
fn index_field(body: &[u8]) -> Result<u32, DtlsError> {
    if body.len() < 4 {
        return Err(DtlsError::InvalidState);
    }
    Ok(u32::from_be_bytes([
        body[body.len() - 4],
        body[body.len() - 3],
        body[body.len() - 2],
        body[body.len() - 1],
    ]))
}

/// Length of the fixed part + CSRC list + extension of an RTP packet.
fn rtp_header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 || packet[0] >> 6 != 2 {
        return None;
    }
    let csrc = usize::from(packet[0] & 0x0F);
    let mut len = 12 + 4 * csrc;
    if packet[0] & 0x10 != 0 {
        if packet.len() < len + 4 {
            return None;
        }
        let ext_len = 4 * u16::from_be_bytes([packet[len + 2], packet[len + 3]]) as usize;
        len += 4 + ext_len;
    }
    Some(len)
}

/// AES-CM IV for RTP (RFC 3711 §4.1.1):
/// `(salt || 0^2) XOR (0^2 || SSRC || ROC || SEQ || 0^2 || block#)`.
fn rtp_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..14].copy_from_slice(salt);
    let mut pos = [0u8; 16];
    pos[2..6].copy_from_slice(&ssrc.to_be_bytes());
    pos[6..10].copy_from_slice(&roc.to_be_bytes());
    pos[10..12].copy_from_slice(&seq.to_be_bytes());
    for (a, b) in iv.iter_mut().zip(pos.iter()) {
        *a ^= *b;
    }
    iv
}

/// AES-CM IV for SRTCP: index (31-bit) in place of ROC/SEQ.
fn rtcp_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..14].copy_from_slice(salt);
    let mut pos = [0u8; 16];
    pos[2..6].copy_from_slice(&ssrc.to_be_bytes());
    pos[6] = ((index >> 24) & 0x7F) as u8;
    pos[7..10].copy_from_slice(&index.to_be_bytes()[1..4]);
    for (a, b) in iv.iter_mut().zip(pos.iter()) {
        *a ^= *b;
    }
    iv
}

/// GCM nonce for SRTP (RFC 7714 §8.1): `salt(12) XOR (0^2||SSRC||ROC||SEQ)`.
fn aead_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&salt[..12]);
    let mut pos = [0u8; 12];
    pos[2..6].copy_from_slice(&ssrc.to_be_bytes());
    pos[6..10].copy_from_slice(&roc.to_be_bytes());
    pos[10..12].copy_from_slice(&seq.to_be_bytes());
    for (a, b) in iv.iter_mut().zip(pos.iter()) {
        *a ^= *b;
    }
    iv
}

/// GCM nonce for SRTCP (RFC 7714 §9): `salt(12) XOR (0^2||SSRC||0||index31)`.
fn rtcp_aead_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&salt[..12]);
    let mut pos = [0u8; 12];
    pos[2..6].copy_from_slice(&ssrc.to_be_bytes());
    pos[6] = ((index >> 24) & 0x7F) as u8;
    pos[7..10].copy_from_slice(&index.to_be_bytes()[1..4]);
    for (a, b) in iv.iter_mut().zip(pos.iter()) {
        *a ^= *b;
    }
    iv
}

/// AES-CTR (AES-CM) keystream over `data`; increments the full 128-bit
/// counter per block.
fn aes_cm_crypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut counter = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let keystream = match key.len() {
            32 => {
                let cipher = Aes256::new_from_slice(key).expect("32-byte AES key");
                let mut block = aes::Block::clone_from_slice(&counter);
                cipher.encrypt_block(&mut block);
                block
            }
            _ => {
                let cipher = Aes128::new_from_slice(key).expect("16-byte AES key");
                let mut block = aes::Block::clone_from_slice(&counter);
                cipher.encrypt_block(&mut block);
                block
            }
        };
        for (p, k) in chunk.iter().zip(keystream.iter()) {
            out.push(p ^ k);
        }
        // Increment the full 128-bit counter (big-endian).
        for b in counter.iter_mut().rev() {
            let (sum, carry) = b.overflowing_add(1);
            *b = sum;
            if !carry {
                break;
            }
        }
    }
    out
}

/// AES-CM key-derivation keystream (RFC 3711 §4.3.3, libsrtp-compatible
/// IV construction: `label` XOR-ed into byte 0 of the masked salt).
fn aes_cm_keystream(key: &[u8], salt: &[u8], label: u8, len: usize) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv[0..14].copy_from_slice(salt);
    iv[0] ^= label;
    aes_cm_crypt(key, &iv, &vec![0u8; len])
}

/// AES-GCM encrypt/decrypt over SRTP data (key length selects AES-128/256).
fn gcm_crypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, DtlsError> {
    use ring::aead;
    let algorithm = match key.len() {
        32 => &aead::AES_256_GCM,
        _ => &aead::AES_128_GCM,
    };
    let unbound = aead::UnboundKey::new(algorithm, &key[..algorithm.key_len()])
        .map_err(|_| DtlsError::SrtpKeyMaterial)?;
    let key = aead::LessSafeKey::new(unbound);
    let mut in_out = data.to_vec();
    if encrypt {
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| DtlsError::Crypto)?;
    } else {
        key.open_in_place(
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| DtlsError::SrtpAuthFailed)?;
    }
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prf::srtp_keys_from_export;

    fn keys() -> SrtpKeys {
        let mut export = vec![0u8; 60];
        for (i, b) in export.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        srtp_keys_from_export(&export).unwrap()
    }

    fn rtp_packet(seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 0x60]; // v=2, PT=96
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 1, 0]); // timestamp
        p.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // ssrc
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn cm_rtp_roundtrip() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let mut dec = SrtpSession::new(keys(), true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let packet = rtp_packet(1000, b"opus frame data");
        let protected = enc.protect_rtp(&packet).unwrap();
        assert_eq!(protected.len(), packet.len() + TAG_80);
        assert_ne!(&protected[12..20], b"opus fra", "payload must be encrypted");
        let plain = dec.unprotect_rtp(&protected).unwrap();
        assert_eq!(plain, packet);
    }

    #[test]
    fn cm_rtp_rejects_tampering_and_replay() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let mut dec = SrtpSession::new(keys(), true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let packet = rtp_packet(1001, b"x");
        let mut protected = enc.protect_rtp(&packet).unwrap();
        let last = protected.len() - 1;
        protected[last] ^= 0xFF;
        assert_eq!(dec.unprotect_rtp(&protected), Err(DtlsError::SrtpAuthFailed));

        let good = enc.protect_rtp(&packet).unwrap();
        assert!(dec.unprotect_rtp(&good).is_ok());
        assert_eq!(dec.unprotect_rtp(&good), Err(DtlsError::SrtpReplay));
    }

    #[test]
    fn cm_rtp_sequence_rollover_estimates_roc() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let mut dec = SrtpSession::new(keys(), true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let last = enc.protect_rtp(&rtp_packet(0xFFFF, b"a")).unwrap();
        assert!(dec.unprotect_rtp(&last).is_ok());
        let first = enc.protect_rtp(&rtp_packet(0x0001, b"b")).unwrap();
        assert!(dec.unprotect_rtp(&first).is_ok(), "ROC must roll over");
    }

    #[test]
    fn cm_rtcp_roundtrip() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let mut dec = SrtpSession::new(keys(), true, Direction::Unprotect, SrtpCipher::Aes128CmHmacSha1_80).unwrap();
        let mut packet = vec![0x81, 200, 0, 7]; // SR, 7 words
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        packet.extend_from_slice(&[0u8; 24]);
        let protected = enc.protect_rtcp(&packet).unwrap();
        assert_eq!(protected.len(), packet.len() + 4 + TAG_80);
        let plain = dec.unprotect_rtcp(&protected).unwrap();
        assert_eq!(plain, packet);
    }

    #[test]
    fn gcm_rtp_roundtrip() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::AeadAes128Gcm).unwrap();
        let mut dec = SrtpSession::new(keys(), true, Direction::Unprotect, SrtpCipher::AeadAes128Gcm).unwrap();
        let packet = rtp_packet(2000, b"vp8 payload");
        let protected = enc.protect_rtp(&packet).unwrap();
        assert_eq!(protected.len(), packet.len() + TAG_GCM);
        let plain = dec.unprotect_rtp(&protected).unwrap();
        assert_eq!(plain, packet);
    }

    #[test]
    fn gcm_rtp_header_is_aad_not_encrypted() {
        let mut enc = SrtpSession::new(keys(), true, Direction::Protect, SrtpCipher::AeadAes128Gcm).unwrap();
        let packet = rtp_packet(2001, b"payload");
        let protected = enc.protect_rtp(&packet).unwrap();
        assert_eq!(&protected[..12], &packet[..12], "header is authenticated but clear");
        assert_ne!(&protected[12..], &packet[12..]);
    }

    #[test]
    fn key_derivation_is_deterministic_and_label_dependent() {
        let k = keys();
        let a = aes_cm_keystream(&k.client_key, &k.client_salt, 1, 20);
        let b = aes_cm_keystream(&k.client_key, &k.client_salt, 1, 20);
        let c = aes_cm_keystream(&k.client_key, &k.client_salt, 2, 20);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
