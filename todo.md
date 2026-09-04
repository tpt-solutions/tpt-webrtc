# tpt-webrtc — Build Todo

> Tracks bootstrap + full 11-crate build-out for the tpt-webrtc pure-Rust
> WebRTC stack, per `spec.txt`. License for every crate: `MIT OR Apache-2.0`.
> Author: TPT Solutions.
>
> **Deviations from `spec.txt` as written** (agreed before starting):
> - **Dependency license policy is stricter than the crate's own license.**
>   `deny.toml`'s allow-list carries `"MIT"` (plus a short permissive list)
>   but deliberately omits bare `"Apache-2.0"`. A dependency licensed
>   `MIT OR Apache-2.0` still passes (satisfied via its MIT branch); a
>   dependency licensed **Apache-2.0 only** gets flagged by `cargo deny` and
>   needs a manual call before it's allowed in.
> - `spec.txt` lists `tpt-math-rng` and `tpt-math-hash` as dependencies for
>   `tpt-webrtc-ice` / `tpt-webrtc-dtls`. Neither crate exists in the real
>   `tpt-math` workspace, so this todo uses `ring` / `getrandom` directly for
>   STUN transaction IDs and DTLS fingerprinting instead.
> - Formal verification via `tpt-telos` is kept, but scoped to just the ICE
>   and DTLS state machines, using tpt-telos's real current workflow
>   (standalone `.telos` contract files verified with the `telos` CLI) —
>   not the inline `#[requires]/#[ensures]` Rust attribute syntax shown
>   literally in spec.txt. It's a **non-blocking** checklist item in each
>   phase: ordinary Rust unit/integration tests are the actual correctness
>   gate for the phase milestone.

## Phase 0 — Repo Bootstrap

(one-time)

- [ ] Create root `Cargo.toml` workspace (`resolver = "2"`,
      `[workspace.package]`: `edition = "2021"`, `license = "MIT OR Apache-2.0"`,
      `authors = ["TPT Solutions"]`)
- [ ] Add `rust-toolchain.toml`
- [ ] Add `rustfmt.toml`
- [ ] Add `deny.toml`:
      `allow = ["MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "MPL-2.0"]`
      (bare `"Apache-2.0"` intentionally **not** in the allow-list),
      `deny = ["GPL-3.0", "AGPL-3.0"]`
- [ ] Add `.github/workflows/ci.yml` (fmt, clippy, test, deny check)
- [ ] Add `LICENSE-MIT` and `LICENSE-APACHE`
- [ ] Create empty `crates/` directory
- [ ] Add a Rust `.gitignore` (`/target`, etc.)
- [ ] Write root `README.md` stub — mission statement (AV1-first, zero
      libwebrtc, memory-safe, formally-verified core state machines); link
      to `spec.txt`
- [ ] `git init` (local only, unless/until a remote is decided)
- [ ] Initial commit
- [ ] Sanity check: `cargo build` succeeds on the empty workspace

## Per-Crate Checklist Template

Every crate phase below repeats this shape:

1. Scaffold `crates/<name>/` (Cargo.toml inheriting workspace fields, `lib.rs` stub)
2. Wire dependencies (internal `tpt-webrtc-*` + externals per spec's dependency audit)
3. Implement scope (see bullets under each crate below)
4. Unit tests + doctests
5. Rustdoc (crate-level + public API)
6. `cargo fmt --check` / `cargo clippy --all-targets --all-features -- -D warnings` clean
7. `cargo deny check` clean

---

## Phase 1 — Foundation

*Deliverables: `tpt-webrtc-core`, `tpt-webrtc-sdp`, `tpt-webrtc-ice`.*
**Milestone: can establish ICE connectivity between two peers using STUN**
(verified via Rust integration tests).

### tpt-webrtc-core

- [ ] Scaffold `crates/tpt-webrtc-core/`
- [ ] Wire deps: `tokio`, `ring`
- [ ] Implement `WebRtcConfig`, `IceServer`, `BweAlgorithm`
- [ ] Implement `WebRtcSocket` trait (async UDP/TCP socket abstraction)
- [ ] Implement error types: `WebRtcError`, `IceError`, `DtlsError`
      (+ `RtpError`, `SctpError`, `CodecError`, `SdpError` stubs used by later crates)
- [ ] Cryptographic primitive helpers (via `ring`) for later crates
- [ ] Unit tests + doctests
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

### tpt-webrtc-sdp

- [ ] Scaffold `crates/tpt-webrtc-sdp/`
- [ ] Wire deps: `tpt-webrtc-core`
- [ ] Implement `SdpSession`, `Origin`, `Timing`, `MediaDescription`
- [ ] Implement `Attribute` enum (RtpMap, Fmtp, IceUfrag, IcePwd, IceCandidate,
      Fingerprint, Setup, Mid, Bundle, RtcpMux, Simulcast, ExtMap, Ssrc,
      SsrcGroup, Custom)
- [ ] Implement `parse_sdp` / `generate_sdp` (RFC 8866)
- [ ] Implement BUNDLE and RTCP-MUX SDP extensions
- [ ] Implement `OfferAnswerModel` (`create_offer`, `create_answer`,
      `negotiate_codecs`) and `CodecNegotiation`
- [ ] Unit tests + doctests (round-trip parse/generate, offer/answer fixtures)
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

### tpt-webrtc-ice

- [ ] Scaffold `crates/tpt-webrtc-ice/`
- [ ] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-sdp`, `ring`/`getrandom`
      (transaction IDs — see deviation note above)
- [ ] Implement `IceState` enum and `IceAgent` (state, local/remote candidates,
      candidate pairs, nominated pair, embedded `StunClient`/`TurnClient`)
- [ ] Implement `IceAgent::gather_candidates`, `add_remote_candidate`,
      `check_connectivity`, `nominate_pair`, `state`
- [ ] Implement `StunMessage`, `StunMessageType`, `StunAttribute` (RFC 8489)
- [ ] Implement `StunClient` (`create_binding_request`, `parse_message`,
      `serialize_message`, `verify_integrity`)
- [ ] Implement basic `TurnClient` (`allocate`, `create_permission`,
      `send_indication`, `refresh`) and `TurnAllocation` (RFC 8656)
- [ ] Candidate gathering (host, server-reflexive via STUN, relay via TURN),
      pairing, and nomination logic
- [ ] Unit tests + doctests (STUN encode/decode round-trip, state transitions)
- [ ] Integration test: two in-process `IceAgent`s connect over loopback via a
      local STUN server
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean
- [ ] *(non-blocking)* Write `ice.telos` contract for the `IceAgent` state
      machine (gather → waiting/failed, checking → connected/failed
      transitions) and verify with `telos verify`

---

## Phase 2 — Security & Transport

*Deliverables: `tpt-webrtc-dtls`, `tpt-webrtc-rtp`, `tpt-webrtc-sctp`.*
**Milestone: can establish a secure DTLS connection and send encrypted RTP
packets** (verified via Rust integration tests).

### tpt-webrtc-dtls

- [ ] Scaffold `crates/tpt-webrtc-dtls/`
- [ ] Wire deps: `tpt-webrtc-core`, `ring`
- [ ] Implement `DtlsState`, `DtlsRole`, `DtlsTransport`
- [ ] Implement `DtlsTransport::new`, `start_handshake`, `process_packet`,
      `send_application_data`, `state`, `srtp_keys`
- [ ] Implement DTLS 1.2 handshake (RFC 6347) — ClientHello/ServerHello,
      cookie exchange, certificate exchange, key exchange, Finished
- [ ] Implement certificate management + fingerprinting (`DtlsCertificate`,
      `Fingerprint`) using `ring` (see deviation note re: `tpt-math-hash`)
- [ ] Implement `SrtpKeys` derivation (RFC 3711 / RFC 5764 DTLS-SRTP key export)
- [ ] Implement `SrtpSession`, `SrtpCipher` (AES-128/256-CM-HMAC-SHA1-80,
      AEAD-AES-128/256-GCM), `protect_rtp`/`unprotect_rtp`/`protect_rtcp`/`unprotect_rtcp`
- [ ] Unit tests + doctests (handshake state transitions, key derivation vectors)
- [ ] Integration test: full client/server DTLS handshake over loopback,
      derive matching SRTP keys on both sides
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean
- [ ] *(non-blocking)* Write `dtls.telos` contract for the `DtlsTransport`
      state machine (handshake → connected/failed, srtp_keys availability
      post-handshake) and verify with `telos verify`

### tpt-webrtc-rtp

- [ ] Scaffold `crates/tpt-webrtc-rtp/`
- [ ] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-dtls`
- [ ] Implement `RtpPacket` (`parse`, `serialize`, `payload_size`)
- [ ] Implement `Packetizer` trait
- [ ] Implement `Av1Packetizer` (packetize/depacketize)
- [ ] Implement `Vp8Packetizer`
- [ ] Implement `Vp9Packetizer`
- [ ] Implement `OpusPacketizer`
- [ ] Implement `RtcpPacket` (SenderReport, ReceiverReport, SourceDescription,
      Goodbye, TransportLayerFeedback, PayloadSpecificFeedback) — `parse`/`serialize`
- [ ] Implement `TransportLayerFeedback` (Nack, Twcc)
- [ ] Implement `PayloadSpecificFeedback` (Pli, Fir, Remb)
- [ ] Implement `JitterBuffer` (`new`, `insert`, `get_frame`, `flush`)
- [ ] Unit tests + doctests (packet round-trip, packetizer fragmentation/reassembly)
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

### tpt-webrtc-sctp

- [ ] Scaffold `crates/tpt-webrtc-sctp/`
- [ ] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-dtls`
- [ ] Implement `SctpState`, `SctpAssociation` (association setup over a
      shared `Arc<Mutex<DtlsTransport>>`)
- [ ] Implement SCTP over DTLS per RFC 8831 (INIT/INIT-ACK, COOKIE-ECHO/ACK,
      association establishment/shutdown)
- [ ] Implement `open_stream`, `send`, `recv`, `close_stream`
- [ ] Implement `SctpMessage`, `Reliability` (Reliable, PartialReliableRexmit,
      PartialReliableTimed, Unreliable) — ordered and unordered delivery
- [ ] Unit tests + doctests (association state transitions, stream open/send/close)
- [ ] Integration test: two associations exchange messages over an established
      DTLS transport from the Phase 2 DTLS integration test
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

---

## Phase 3 — Codecs & Media

*Deliverables: `tpt-webrtc-codecs`, `tpt-webrtc-media`.*
**Milestone: can send and receive AV1 video and Opus audio with hardware
acceleration.**

### tpt-webrtc-codecs

- [ ] Scaffold `crates/tpt-webrtc-codecs/`
- [ ] Wire deps: `tpt-webrtc-core`, `rav1e`, `dav1d`, `vpx`, `opus`
- [ ] Implement `VideoEncoder`/`VideoDecoder` traits, `VideoFrame`,
      `PixelFormat`, `EncodedPacket`, `VideoCodec`
- [ ] Implement `Av1Encoder`/`Av1EncoderConfig` (via `rav1e`)
- [ ] Implement `Av1Decoder` (via `dav1d`)
- [ ] Implement VP8 encoder/decoder (via `vpx`)
- [ ] Implement VP9 encoder/decoder (via `vpx`)
- [ ] Explicitly document: **no H.264 encoder/decoder** — patent licensing
      avoidance per spec.txt's H.264 Avoidance Strategy
- [ ] Implement `AudioEncoder` trait, `AudioFrame`, `OpusEncoder`/`OpusEncoderConfig`,
      `OpusApplication`
- [ ] Implement `HardwareEncoder` abstraction + `HardwareBackend` enum
- [ ] Implement NVENC backend (`NvencEncoder`)
- [ ] Implement Intel Quick Sync backend (`QsvEncoder`)
- [ ] Implement Apple VideoToolbox backend (`VideoToolboxEncoder`)
- [ ] Implement VA-API backend (`VaapiEncoder`)
- [ ] Unit tests + doctests (encode/decode round-trip per codec, bitrate/keyframe controls)
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean (flag `vpx`/`dav1d`/hardware SDK licenses individually)

### tpt-webrtc-media

- [ ] Scaffold `crates/tpt-webrtc-media/`
- [ ] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-codecs`, `tpt-webrtc-rtp`
- [ ] Implement `AudioProcessingPipeline`: `AcousticEchoCanceller`,
      `NoiseSuppressor`, `AutomaticGainControl` traits + default implementations
- [ ] Implement `BandwidthEstimator` trait
- [ ] Implement `GccEstimator` (Google Congestion Control — delay-based + loss-based)
- [ ] Implement `RembEstimator`
- [ ] Implement `TwccEstimator`
- [ ] Implement `VideoProcessingPipeline`: `VideoScaler`, `ColorConverter`
- [ ] Implement `SimulcastEncoder`/`SimulcastLayer`
- [ ] Unit tests + doctests (estimator convergence on synthetic feedback,
      simulcast layer fan-out)
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

---

## Phase 4 — Application Layer

*Deliverable: `tpt-webrtc-app`.*
**Milestone: can establish a full WebRTC connection with audio, video, and
data channels.**

### tpt-webrtc-app

- [ ] Scaffold `crates/tpt-webrtc-app/`
- [ ] Wire deps: all other `tpt-webrtc-*` crates
- [ ] Implement `PeerConnectionConfig`, `SignalingState`, `IceConnectionState`,
      `PeerConnectionState`
- [ ] Implement `PeerConnection` (`new`, `create_offer`, `create_answer`,
      `set_local_description`, `set_remote_description`, `add_ice_candidate`,
      `add_track`, `create_data_channel`, `close`)
- [ ] Implement `DataChannelState`, `DataChannel` (`send`, `send_text`,
      `recv`, `close`, `state`), `DataChannelMessage`
- [ ] Implement `MediaStreamTrack`, `TrackKind`, `MediaFrame`
- [ ] Implement `RtpSender` / `RtpReceiver` wiring packetizers, jitter buffer,
      and SSRC management to tracks
- [ ] Wire full offer/answer negotiation end-to-end through `tpt-webrtc-sdp`
- [ ] Implement signaling integration: WebSocket transport, HTTP transport
- [ ] Data channels: reliable, unreliable, ordered, unordered variants exercised
- [ ] Unit tests + doctests
- [ ] Integration test: two `PeerConnection`s complete offer/answer, ICE,
      DTLS, and exchange a data channel message end-to-end (loopback)
- [ ] End-to-end interop test against a real browser (Chrome) data channel
- [ ] End-to-end interop test against a real browser (Firefox) data channel
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean
- [ ] `cargo deny check` clean

---

## Phase 5 — Advanced Features

*No new crates — hardening and feature completion across `tpt-webrtc-media`,
`tpt-webrtc-codecs`, `tpt-webrtc-rtp`.*
**Milestone: production-ready WebRTC implementation with advanced features.**

- [ ] Flesh out `AcousticEchoCanceller` with a real AEC algorithm (pure-Rust
      DSP or a permissively-licensed wrapper — respect the dependency license
      policy above)
- [ ] Flesh out `NoiseSuppressor` with a real NS algorithm
- [ ] Flesh out `AutomaticGainControl` with a real AGC algorithm
- [ ] Implement `BbrEstimator` (BBR-based bandwidth estimation)
- [ ] Implement Scalable Video Coding (SVC) layer selection on top of the
      AV1/VP9 encoders
- [ ] Implement network adaptation / congestion response wiring BWE output
      into encoder bitrate control (`set_bitrate`)
- [ ] Performance benchmarking suite (encode/decode throughput, RTP
      packetization overhead, ICE connection setup latency)
- [ ] Address any regressions/bottlenecks found by benchmarking
- [ ] Comprehensive rustdoc pass across all crates (crate-level guides, examples)
- [ ] Worked examples: audio-only call, video-only call, data-channel-only,
      full audio+video+data call

---

## Phase 6 — Bindings & Ecosystem

*Deliverables: `tpt-webrtc-capi`, `tpt-webrtc-py`, Go bindings.*
**Milestone: drop-in replacement for libwebrtc in C++, Python, and Go
ecosystems.**

### tpt-webrtc-capi

- [ ] Scaffold `crates/tpt-webrtc-capi/`
- [ ] Wire deps: `tpt-webrtc-app`, `cbindgen`
- [ ] Implement `TptWebRtcConfig`, `TptWebRtcResult` C-ABI types
- [ ] Implement `tpt_webrtc_peer_connection_new` / `_create_offer` / `_free`
      and the remaining `PeerConnection` C API surface
- [ ] Generate `tpt_webrtc.h` via `cbindgen`
- [ ] `cargo deny check`: confirm `cbindgen`'s MPL-2.0 license is acceptable
      as a build-time-only tool dependency (not linked into the artifact)
- [ ] C smoke-test program exercising the generated header
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean

### tpt-webrtc-py

- [ ] Scaffold `crates/tpt-webrtc-py/`
- [ ] Wire deps: `tpt-webrtc-app`, `pyo3`
- [ ] Implement `PyPeerConnection` (`new`, `create_offer`, `create_answer`,
      `set_remote_description`) and supporting `Py*` wrapper types
- [ ] Package as a Python wheel (maturin or equivalent)
- [ ] Python smoke-test script exercising offer/answer
- [ ] Rustdoc
- [ ] `cargo fmt` / `clippy` clean

### Go bindings

- [ ] Decide binding strategy: over the C API (`tpt-webrtc-capi`) vs. rust2go
- [ ] Implement Go package wrapping the chosen binding layer
- [ ] Go smoke-test exercising offer/answer + data channel

### Integration examples

- [ ] FreeCAD integration example
- [ ] Blender integration example
- [ ] Standalone Python scripting example
- [ ] Community outreach / adoption tracking (3 production integrations target)

---

## Phase 7 — Compliance & Interop

*Cross-cutting verification once Phases 1-6 are functionally complete.*

- [ ] Run the W3C WebRTC interoperability test suite against
      `tpt-webrtc-app`; track pass rate toward 100%
- [ ] Interop test: connect to Chrome
- [ ] Interop test: connect to Firefox
- [ ] Interop test: connect to Safari
- [ ] Interop test: connect to a libwebrtc-based client
- [ ] `cargo deny check licenses` clean across the **entire** dependency tree
      (workspace + all bindings crates)
- [ ] Performance comparison benchmark vs. libwebrtc on standard scenarios
- [ ] Security review: confirm zero H.264 code paths, confirm memory-safety
      posture (no `unsafe` outside audited FFI boundaries to `rav1e`/`dav1d`/
      `vpx`/`opus`/hardware SDKs)
- [ ] Publish comprehensive documentation site / crate-level docs.rs presence
- [ ] Sign off against spec.txt's Success Metrics: protocol compliance,
      performance parity, interoperability, security, licensing cleanliness,
      adoption
