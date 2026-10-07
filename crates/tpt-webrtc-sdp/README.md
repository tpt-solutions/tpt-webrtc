# tpt-webrtc-sdp

[![Crates.io](https://img.shields.io/crates/v/tpt-webrtc-sdp.svg)](https://crates.io/crates/tpt-webrtc-sdp)
[![Documentation](https://docs.rs/tpt-webrtc-sdp/badge.svg)](https://docs.rs/tpt-webrtc-sdp)
[![License](https://img.shields.io/crates/l/tpt-webrtc-sdp.svg)](https://github.com/tpt-solutions/tpt-webrtc/blob/main/LICENSE-MIT)

SDP (RFC 8866) parser and generator with WebRTC-specific extensions — BUNDLE grouping, RTCP-MUX, ICE candidates/credentials, DTLS fingerprints/setup, simulcast (RFC 8851), RTP header extensions, SSRC descriptions — plus the offer/answer model (`OfferAnswerModel`) built on top of `tpt_webrtc_core::WebRtcConfig`.

## Features

- **Full SDP Parser/Generator** — RFC 8866 compliant round-trip parsing
- **WebRTC Extensions** — BUNDLE, RTCP-MUX, ICE, DTLS, simulcast
- **Offer/Answer Model** — `OfferAnswerModel` for WebRTC negotiation
- **Media Descriptions** — Audio/video with codecs, fmtp, rtcp-fb, extmaps
- **Zero-copy where possible** — Efficient parsing with minimal allocations

## Installation

```toml
[dependencies]
tpt-webrtc-sdp = "0.1"
```

MSRV: Rust 1.75+

## Quick Start

```rust
use tpt_webrtc_sdp::{parse_sdp, generate_sdp, OfferAnswerModel, WebRtcConfig};

let raw = "v=0\r\no=- 8 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
let session = parse_sdp(raw).unwrap();
assert_eq!(session.session_name, "-");
assert_eq!(generate_sdp(&session).unwrap(), raw);

// Create an offer
let config = WebRtcConfig::default();
let model = OfferAnswerModel::new(config);
let offer = model.create_offer().unwrap();
let sdp = generate_sdp(&offer).unwrap();
```

## Module Overview

| Module | Purpose |
|--------|---------|
| `parse` | `parse_sdp` — RFC 8866 parser |
| `generate` | `generate_sdp` — Session → SDP string |
| `model` | `SdpSession`, `MediaDescription`, `Attribute`, `SsrcAttribute`, `SimulcastConfig` |
| `offer_answer` | `OfferAnswerModel`, `CodecNegotiation`, `NegotiatedCodec` |

## Supported SDP Attributes

- **Session-level**: `v`, `o`, `s`, `t`, `a=group:BUNDLE`, `a=msid-semantic`
- **Media-level**: `m`, `c`, `b`, `a=mid`, `a=rtcp-mux`, `a=ice-ufrag`, `a=ice-pwd`, `a=fingerprint`, `a=setup`, `a=rtpmap`, `a=fmtp`, `a=rtcp-fb`, `a=extmap`, `a=ssrc`, `a=ssrc-group`, `a=simulcast`, `a=rid`

## Offer/Answer Model

The `OfferAnswerModel` implements the WebRTC offer/answer state machine:

1. `create_offer()` → generates initial offer with local ICE credentials, DTLS fingerprint, candidates
2. `set_remote_description()` → processes remote offer/answer
3. `create_answer()` → generates answer based on negotiated parameters
4. `negotiate_codecs()` → returns `CodecNegotiation` with selected codecs per media section

## License

Dual-licensed under `MIT OR Apache-2.0`.

## Contributing

See the main [CONTRIBUTING.md](https://github.com/tpt-solutions/tpt-webrtc/blob/main/CONTRIBUTING.md).