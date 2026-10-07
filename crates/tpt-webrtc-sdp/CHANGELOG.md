# Changelog

All notable changes to `tpt-webrtc-sdp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-06

### Added
- RFC 8866 compliant SDP parser (`parse_sdp`) and generator (`generate_sdp`)
- Round-trip parsing: `generate_sdp(parse_sdp(sdp)) == sdp`
- Session description model: `SdpSession`, `Origin`, `Timing`, `Connection`
- Media description model: `MediaDescription`, `MediaType`, `Direction`, `Attribute`
- WebRTC extensions:
  - BUNDLE grouping (`a=group:BUNDLE`)
  - RTCP-MUX (`a=rtcp-mux`)
  - ICE credentials (`a=ice-ufrag`, `a=ice-pwd`, `a=candidate`)
  - DTLS fingerprint/setup (`a=fingerprint`, `a=setup`)
  - Simulcast (RFC 8851) — `a=simulcast`, `a=rid`
  - SSRC attributes (`a=ssrc`, `a=ssrc-group`)
  - RTP header extensions (`a=extmap`)
  - RTCP feedback (`a=rtcp-fb`)
- Offer/Answer model (`OfferAnswerModel`):
  - `create_offer()` — generates offer with local ICE/DTLS params
  - `set_remote_description()` — processes remote offer/answer
  - `create_answer()` — generates answer with negotiated params
  - `negotiate_codecs()` — returns `CodecNegotiation` per media section
- Codec negotiation: `CodecNegotiation`, `NegotiatedCodec`

### Supported Attributes
- Session: `v`, `o`, `s`, `t`, `a=group`, `a=msid-semantic`
- Media: `m`, `c`, `b`, `a=mid`, `a=rtcp-mux`, `a=ice-*`, `a=fingerprint`, `a=setup`, `a=rtpmap`, `a=fmtp`, `a=rtcp-fb`, `a=extmap`, `a=ssrc`, `a=ssrc-group`, `a=simulcast`, `a=rid`

[0.1.0]: https://github.com/tpt-solutions/tpt-webrtc/releases/tag/tpt-webrtc-sdp-v0.1.0