# Changelog

All notable changes to `tpt-webrtc-rtp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- RTP Packet Codec (RFC 3550):
  - `RtpPacket` — serialization/parsing with header extensions
  - Header: version, padding, extension, CSRC count, marker, PT, sequence, timestamp, SSRC
  - Header extensions (RFC 8285): one-byte and two-byte headers
- Payload Packetizers:
  - `OpusPacketizer` (RFC 7587) — stereo, DTX, FEC
  - `Av1Packetizer` (AV1 RTP spec) — OBU framing, temporal scalability
  - `Vp8Packetizer` (RFC 7741) — payload descriptor, partitioning
  - `Vp9Packetizer` (VP9 RTP draft) — scalability, flex mode
  - `Packetizer` trait for extensibility
- RTCP (RFC 3550, RFC 4585, RFC 5104, draft-alvestrand-rmcat-remb):
  - `SenderReport`, `ReceiverReport`, `ReportBlock`
  - `SdesChunk`, `SourceDescription` (CNAME, NAME, etc.)
  - Feedback: `Nack` (RFC 4585), `TransportWideCongestionControl` (TWCC)
  - Payload-specific: `FullIntraRequest` (FIR), `PictureLossIndication` (PLI)
  - `Remb` — Receiver Estimated Max Bitrate
- Jitter Buffer:
  - Adaptive delay target
  - Missing packet detection → NACK generation
  - Frame reassembly from multiple packets
  - `JitterBuffer` with configurable capacity
- SRTP Integration:
  - `SrtpPacketExt` trait with `protect`/`unprotect` on `RtpPacket`
  - Delegates to `tpt_webrtc_dtls::SrtpSession`
- Media Frames:
  - `AudioFrame`, `VideoFrame`, `MediaFrame` for packetizer I/O
- Benchmark: `throughput` — packetization/serialization performance

### Supported RFCs
- RFC 3550 — RTP/RTCP
- RFC 4585 — RTP/AVPF (NACK)
- RFC 5104 — FIR/PLI
- RFC 7587 — Opus RTP
- RFC 7741 — VP8 RTP
- RFC 8285 — RTP Header Extensions
- draft-ietf-avtext-rtp-twcc — TWCC
- draft-alvestrand-rmcat-remb — REMB
- AV1 RTP spec — AV1 packetization

### Performance
- Zero-copy parsing where possible
- Pre-allocated buffers for hot paths
- Benchmark suite for regression detection

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-rtp-v0.1.0