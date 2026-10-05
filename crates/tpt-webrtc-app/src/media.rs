//! Media plumbing: tracks plus the SRTP sender/receiver pair.

use std::time::Duration;

use tpt_webrtc_core::{PacketizerError, RtpError};
use tpt_webrtc_dtls::{Direction, SrtpSession};
use tpt_webrtc_rtp::jitter::JitterBuffer;
use tpt_webrtc_rtp::{
    MediaFrame, OpusPacketizer, Packetizer, RtpPacket, SrtpPacketExt, VideoPacketizerContext,
};

/// Track kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrackKind {
    /// Audio.
    Audio,
    /// Video.
    Video,
}

/// A media stream track (per spec: id + kind; the send/receive queues live
/// in [`RtpSender`]/[`RtpReceiver`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaStreamTrack {
    /// Track id.
    pub id: String,
    /// Audio or video.
    pub kind: TrackKind,
}

/// Send/receive failures on the media path.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    /// Packetizer failure.
    #[error("packetize: {0}")]
    Packetize(#[from] PacketizerError),
    /// RTP codec failure.
    #[error("rtp: {0}")]
    Rtp(#[from] RtpError),
    /// SRTP failure (protect/unprotect).
    #[error("srtp: {0}")]
    Srtp(String),
}

/// Sends one track's frames as SRTP-protected RTP on the ICE 5-tuple.
pub struct RtpSender {
    /// Track being sent.
    pub track: MediaStreamTrack,
    /// Outbound SSRC.
    pub ssrc: u32,
    /// Payload type.
    pub payload_type: u8,
    ctx: VideoPacketizerContext,
    packetizer: OpusPacketizer,
}

impl RtpSender {
    /// Creates a sender for an audio track (Opus payload, PT 111).
    #[must_use]
    pub fn new_audio(track: MediaStreamTrack, ssrc: u32) -> Self {
        let ssrc = if ssrc == 0 {
            tpt_webrtc_core::random_u32().unwrap_or(1)
        } else {
            ssrc
        };
        Self {
            track,
            ssrc,
            payload_type: 111,
            ctx: VideoPacketizerContext {
                sequence_number: tpt_webrtc_core::random_u32().unwrap_or(0) as u16,
                ssrc,
                payload_type: 111,
            },
            packetizer: OpusPacketizer,
        }
    }

    /// Packetizes one frame and protects every packet; returns wire bytes
    /// to hand to the transport.
    ///
    /// # Errors
    /// [`MediaError`] plumbing.
    pub fn send(
        &mut self,
        session: &mut SrtpSession,
        frame: &MediaFrame,
        mtu: usize,
    ) -> Result<Vec<Vec<u8>>, MediaError> {
        let packets = self.packetizer.packetize(&mut self.ctx, frame, mtu)?;
        let mut out = Vec::with_capacity(packets.len());
        for pkt in packets {
            out.push(
                pkt.protect(session)
                    .map_err(|e| MediaError::Srtp(e.to_string()))?,
            );
        }
        Ok(out)
    }
}

/// Receives one track: SRTP-unprotects into a jitter buffer and
/// depacketizes complete frames.
pub struct RtpReceiver {
    /// Track being received.
    pub track: MediaStreamTrack,
    /// Expected remote SSRC (set from SDP; 0 = accept any).
    pub ssrc: u32,
    jitter: JitterBuffer,
    packetizer: OpusPacketizer,
    frames: std::collections::VecDeque<MediaFrame>,
}

impl RtpReceiver {
    /// Creates a receiver for an audio track.
    #[must_use]
    pub fn new_audio(track: MediaStreamTrack) -> Self {
        Self {
            track,
            ssrc: 0,
            jitter: JitterBuffer::new(Duration::from_millis(60), Duration::from_millis(200)),
            packetizer: OpusPacketizer,
            frames: std::collections::VecDeque::new(),
        }
    }

    /// Feeds one protected RTP datagram; complete frames (marker-delimited)
    /// are depacketized into the frame queue.
    ///
    /// # Errors
    /// [`MediaError`] plumbing.
    pub fn receive(&mut self, session: &mut SrtpSession, wire: &[u8]) -> Result<(), MediaError> {
        let pkt: RtpPacket =
            RtpPacket::unprotect(session, wire).map_err(|e| MediaError::Srtp(e.to_string()))?;
        let ssrc = pkt.ssrc;
        if self.ssrc != 0 && ssrc != self.ssrc {
            return Ok(()); // foreign SSRC: ignore
        }
        let marker = pkt.marker;
        self.jitter.insert(pkt);
        while let Some(frame_packets) = self.jitter.get_frame(ssrc) {
            let frame = self.packetizer.depacketize(&frame_packets)?;
            self.frames.push_back(frame);
            if !marker && frame_packets.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Pops one complete received frame.
    #[must_use]
    pub fn recv_frame(&mut self) -> Option<MediaFrame> {
        self.frames.pop_front()
    }

    /// Buffered packets in the jitter buffer.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.jitter.len()
    }

    /// Queued complete frames.
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.frames.len()
    }
}

/// Builds the SRTP session pair for one connection from the exported keys
/// (protect = our key, unprotect = the peer's key).
#[must_use]
pub fn srtp_pair(keys: tpt_webrtc_dtls::SrtpKeys, is_client: bool) -> (SrtpSession, SrtpSession) {
    let protect = SrtpSession::new(
        keys.clone(),
        is_client,
        Direction::Protect,
        tpt_webrtc_dtls::SrtpCipher::Aes128CmHmacSha1_80,
    )
    .expect("exported keys are well-formed");
    let unprotect = SrtpSession::new(
        keys,
        is_client,
        Direction::Unprotect,
        tpt_webrtc_dtls::SrtpCipher::Aes128CmHmacSha1_80,
    )
    .expect("exported keys are well-formed");
    (protect, unprotect)
}
