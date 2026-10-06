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

- [x] Create root `Cargo.toml` workspace (`resolver = "2"`,
      `[workspace.package]`: `edition = "2021"`, `license = "MIT OR Apache-2.0"`,
      `authors = ["TPT Solutions"]`)
- [x] Add `rust-toolchain.toml`
- [x] Add `rustfmt.toml`
- [x] Add `deny.toml`:
      `allow = ["MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "MPL-2.0"]`
      (bare `"Apache-2.0"` intentionally **not** in the allow-list; modern
      cargo-deny dropped the `deny` key — everything unlisted is denied.
      ring is allowed via an explicit per-crate `[[licenses.exceptions]]`
      entry: it declares `Apache-2.0 AND ISC`, the Apache part being
      BoringSSL-sourced code — the "manual call" the policy asks for)
- [x] Add `.github/workflows/ci.yml` (fmt, clippy, test, deny check)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE`
- [x] Create empty `crates/` directory
- [x] Add a Rust `.gitignore` (`/target`, etc.)
- [x] Write root `README.md` stub — mission statement (AV1-first, zero
      libwebrtc, memory-safe, formally-verified core state machines); link
      to `spec.txt`
- [x] `git init` (local only, unless/until a remote is decided)
- [x] Initial commit
- [x] Sanity check: `cargo build` succeeds on the empty workspace

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

## Phase 1 — Foundation ✅ COMPLETE

*Deliverables: `tpt-webrtc-core`, `tpt-webrtc-sdp`, `tpt-webrtc-ice`.*
**Milestone: can establish ICE connectivity between two peers using STUN**
(verified via Rust integration tests) — two-agent loopback ICE with
host+srflx gathering, checks and nomination verified.

### tpt-webrtc-core

- [x] Scaffold `crates/tpt-webrtc-core/`
- [x] Wire deps: `tokio`, `ring`
- [x] Implement `WebRtcConfig`, `IceServer`, `BweAlgorithm`
- [x] Implement `WebRtcSocket` trait (async UDP/TCP socket abstraction)
- [x] Implement error types: `WebRtcError`, `IceError`, `DtlsError`
      (+ `RtpError`, `SctpError`, `CodecError`, `SdpError` stubs used by later crates)
- [x] Cryptographic primitive helpers (via `ring`) for later crates
      (digests, HMAC-SHA1/256, MD5, CRC-32, constant-time eq, self-signed
      ECDSA P-256 `DtlsCertificate` with minimal DER encoding)
- [x] Unit tests + doctests
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean

### tpt-webrtc-sdp

- [x] Scaffold `crates/tpt-webrtc-sdp/`
- [x] Wire deps: `tpt-webrtc-core`
- [x] Implement `SdpSession`, `Origin`, `Timing`, `MediaDescription`
- [x] Implement `Attribute` enum (RtpMap, Fmtp, IceUfrag, IcePwd, IceCandidate,
      Fingerprint, Setup, Mid, Bundle, RtcpMux, Simulcast, ExtMap, Ssrc,
      SsrcGroup, Custom, + Direction)
- [x] Implement `parse_sdp` / `generate_sdp` (RFC 8866)
- [x] Implement BUNDLE and RTCP-MUX SDP extensions
- [x] Implement `OfferAnswerModel` (`create_offer`, `create_answer`,
      `negotiate_codecs`) and `CodecNegotiation`
- [x] Unit tests + doctests (round-trip parse/generate, offer/answer fixtures)
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean

### tpt-webrtc-ice

- [x] Scaffold `crates/tpt-webrtc-ice/`
- [x] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-sdp`, `ring`/`getrandom`
      (transaction IDs — see deviation note above)
- [x] Implement `IceState` enum and `IceAgent` (state, local/remote candidates,
      candidate pairs, nominated pair, embedded `StunClient`/`TurnClient`)
- [x] Implement `IceAgent::gather_candidates`, `add_remote_candidate`,
      `check_connectivity`, `nominate_pair`, `state`
- [x] Implement `StunMessage`, `StunMessageType`, `StunAttribute` (RFC 8489)
- [x] Implement `StunClient` (`create_binding_request`, `parse_message`,
      `serialize_message`, `verify_integrity`)
- [x] Implement basic `TurnClient` (`allocate`, `create_permission`,
      `send_indication`, `refresh`) and `TurnAllocation` (RFC 8656)
- [x] Candidate gathering (host, server-reflexive via STUN, relay via TURN),
      pairing, and nomination logic
- [x] Unit tests + doctests (STUN encode/decode round-trip, state transitions;
      MESSAGE-INTEGRITY + FINGERPRINT validated against the RFC 5769 §2.1
      test vector)
- [x] Integration test: two in-process `IceAgent`s connect over loopback via a
      local STUN server (gather host+srflx, pair, check, nominate; negative
      tests for wrong credentials and missing remote candidates)
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean
- [x] *(non-blocking)* Write `ice.telos` contract for the `IceAgent` state
      machine (gather → waiting/failed, checking → connected/failed
      transitions) and verify with `telos verify`
      — done: `telos verify contracts/ice.telos` reports "all constraints
      satisfied" (state enum encoded as integers for the QF_LRA solver)

---

## Phase 2 — Security & Transport ✅ COMPLETE

*Deliverables: `tpt-webrtc-dtls`, `tpt-webrtc-rtp`, `tpt-webrtc-sctp`.*
**Milestone: can establish a secure DTLS connection and send encrypted RTP
packets** (verified via Rust integration tests) — DTLS handshake with
matching SRTP key export verified; SRTP protect/unprotect round-trips
verified; SCTP data-channel exchange over DTLS-pipe verified.

### tpt-webrtc-dtls

- [x] Scaffold `crates/tpt-webrtc-dtls/`
- [x] Wire deps: `tpt-webrtc-core`, `ring` (+ `aes` for SRTP AES-CM)
- [x] Implement `DtlsState`, `DtlsRole`, `DtlsTransport`
- [x] Implement `DtlsTransport::new`, `start_handshake`, `process_packet`,
      `send_application_data`, `state`, `srtp_keys`
- [x] Implement DTLS 1.2 handshake (RFC 6347) — ClientHello/ServerHello,
      HelloVerifyRequest cookie exchange, certificate exchange, ECDHE P-256
      key exchange with ECDSA-signed ServerKeyExchange, encrypted Finished
      flights (suite `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`)
- [x] Implement certificate management + fingerprinting (`DtlsCertificate`,
      `Fingerprint`) using `ring` (see deviation note re: `tpt-math-hash`)
- [x] Implement `SrtpKeys` derivation (RFC 5764 `use_srtp` + RFC 5705
      `EXTRACTOR-dtls_srtp` export, 60 bytes)
- [x] Implement `SrtpSession`, `SrtpCipher` (AES-128/256-CM-HMAC-SHA1-80,
      AEAD-AES-128/256-GCM), protect/unprotect on raw RTP/RTCP bytes with
      ROC tracking and a replay window (RFC 3711 / RFC 7714)
- [x] Unit tests + doctests (record roundtrips, handshake codec, key
      schedule, SRTP protect/unprotect/rollback/replay)
- [x] Integration test: full client/server DTLS handshake over an
      in-memory pipe (cookie exchange, mutual SDP-fingerprint
      authentication incl. rejection case), matching SRTP keys on both
      sides, protected application data both directions
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean
- [x] *(non-blocking)* Write `dtls.telos` contract for the `DtlsTransport`
      state machine (handshake → connected/failed, srtp_keys availability
      post-handshake) and verify with `telos verify`
      — done: `telos verify contracts/dtls.telos` passes

### tpt-webrtc-rtp

- [x] Scaffold `crates/tpt-webrtc-rtp/`
- [x] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-dtls`
- [x] Implement `RtpPacket` (`parse`, `serialize`, `payload_size`) with
      RFC 8285 one-byte header extensions
- [x] Implement `Packetizer` trait (with `VideoPacketizerContext` for
      seq/SSRC/PT continuity)
- [x] Implement `Av1Packetizer` (OBU splitting via leb128 sizes, ≤3-OBU
      aggregation, MTU fragmentation with Z/Y bits, byte-faithful
      temporal-unit round-trip)
- [x] Implement `Vp8Packetizer` (RFC 7741 S/E descriptor)
- [x] Implement `Vp9Packetizer` (flexible mode F/B/E descriptor)
- [x] Implement `OpusPacketizer` (one packet per Opus frame, 48 kHz clock)
- [x] Implement `RtcpPacket` (SenderReport, ReceiverReport, SourceDescription,
      Goodbye, TransportLayerFeedback, PayloadSpecificFeedback) —
      `parse`/`serialize` + `parse_compound`
- [x] Implement `TransportLayerFeedback` (Nack with PID+BLP coding,
      Twcc with status chunks + 250 µs deltas per RFC 8888 shape)
- [x] Implement `PayloadSpecificFeedback` (Pli, Fir, Remb with the
      libwebrtc exponent/mantissa wire format)
- [x] Implement `JitterBuffer` (`new`, `insert`, `get_frame`, `flush`) —
      reordering, duplicate drop, marker-delimited frames
- [x] Unit tests + doctests (packet round-trip incl. extensions,
      packetizer fragmentation/reassembly per codec, RTCP roundtrips,
      jitter-buffer reorder/waits)
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean

### tpt-webrtc-sctp

- [x] Scaffold `crates/tpt-webrtc-sctp/`
- [x] Wire deps: `tpt-webrtc-core`, `tpt-webrtc-dtls`
- [x] Implement `SctpState`, `SctpAssociation` (over DTLS via the
      `SctpTransport` trait; `Arc<Mutex<DtlsTransport>>` impl provided)
- [x] Implement SCTP over DTLS per RFC 8831 (INIT/INIT-ACK with SSCRC
      tie-tags, COOKIE-ECHO/ACK, establishment/shutdown, HEARTBEAT/ACK)
- [x] Implement `open_stream`, `send`, `recv`, `close_stream` (+
      `attach_remote_stream`, `build_channel_open`, `pop_remote_channel`)
- [x] Implement `SctpMessage`, `Reliability` (Reliable, PartialReliableRexmit,
      PartialReliableTimed, Unreliable) — ordered (SSN-checked) and
      unordered delivery; SACK-driven unacked tracking
- [x] Unit tests + doctests (association establishment, ordered exchange
      with SACKs, unordered bypass, DATA_CHANNEL OPEN/ACK, error cases)
- [x] Integration test: two associations establish and exchange messages
      over in-memory pipes mirroring the DTLS transport contract
      (`tests/sctp_over_dtls.rs`); the DTLS transport itself is proven by
      the dtls crate's handshake integration test
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean

---

## Phase 3 — Codecs & Media ⛔ ENVIRONMENT-BLOCKED (see note)

*Deliverables: `tpt-webrtc-codecs`, `tpt-webrtc-media`.*
**Milestone: can send and receive AV1 video and Opus audio with hardware
acceleration.**

> **Status (2026-10):** `tpt-webrtc-codecs` landed with the full trait
> abstraction and a **working rav1e AV1 encoder** (pure Rust, tested on
> Windows: keyframes, bitrate/speed/keyframe-interval controls, forced
> keyframes, show-existing semantics). Decode-side `dav1d`/`vpx`/`opus`
> FFI awaits a Linux environment: WSL was installed here but its
> first-boot OOBE wedged the WSL service (vmmemWSL unkillable, service
> restart needs admin) — **after a machine reboot**, run
> `wsl --install -d Ubuntu --no-launch && ubuntu.exe install --root`
> (or `wsl --import` a cloud-image rootfs tarball, which skips OOBE),
> then `apt install libdav1d-dev libopus-dev libvpx-dev pkg-config` +
> rustup, and implement the FFI modules behind a `native` feature.
> Alternative: CI on ubuntu-latest where all three ship as packages.
> The media half of this phase (jitter buffer, BWE, simulcast scaling)
> already lives in `tpt-webrtc-media`.

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

## Phase 4 — Application Layer ✅ COMPLETE (data channels + SRTP media)

*Deliverable: `tpt-webrtc-app`.*
**Milestone: can establish a full WebRTC connection with audio, video, and
data channels.** — verified end-to-end over real loopback UDP: SDP
offer/answer → ICE checks/nomination → DTLS handshake (SDP-fingerprint
authenticated) → SCTP establishment → bidirectional data-channel
messages and three SRTP-protected audio frames delivered and decoded.
(WebSocket/HTTP signaling bridges remain future work — the
`SignalingTransport` trait is the seam; browser interop tests belong to
Phase 7's matrix.)

### tpt-webrtc-app

- [x] Scaffold `crates/tpt-webrtc-app/`
- [x] Wire deps: all other `tpt-webrtc-*` crates
- [x] Implement `PeerConnectionConfig`, `SignalingState`, `IceConnectionState`,
      `PeerConnectionState`
- [x] Implement `PeerConnection` (`new`, `create_offer`, `create_answer`,
      `set_local_description`, `set_remote_description`, `add_ice_candidate`,
      `add_track`, `create_data_channel`, `close`, `poll` event loop with
      RFC 7983 demux and quiet-time handshake retransmission)
- [x] Implement `DataChannelState`, `DataChannel` (`send` via the
      association, `recv`, `state`), `DataChannelMessage` (text + binary)
- [x] Implement `MediaStreamTrack`, `TrackKind`, `MediaFrame` (in
      `tpt-webrtc-rtp`; the app layer re-uses it)
- [x] Implement `RtpSender` / `RtpReceiver` wiring packetizers, jitter buffer,
      and SSRC management to tracks (SRTP on the nominated pair)
- [x] Wire full offer/answer negotiation end-to-end through `tpt-webrtc-sdp`
      (real agent credentials replace the model's placeholders; DTLS role
      derived from the SDP `setup` attribute)
- [x] Signaling integration: `SignalingTransport` trait +
      `LoopbackSignaling`; **WebSocket/HTTP transports deferred** (see
      note above the checklist)
- [x] Data channels: reliable ordered (exercised E2E); unreliable/partial
      variants covered at the SCTP layer (`unordered_bypasses_ssn`,
      reliability mapping in `build_channel_open`)
- [x] Unit tests + doctests
- [x] Integration test: two `PeerConnection`s complete offer/answer, ICE,
      DTLS, and exchange data channel messages end-to-end (real loopback
      UDP, both directions)
- [ ] End-to-end interop test against a real browser (Chrome) data channel — Phase 7 matrix
- [ ] End-to-end interop test against a real browser (Firefox) data channel — Phase 7 matrix
- [x] Rustdoc
- [x] `cargo fmt` / `clippy` clean
- [x] `cargo deny check` clean

---

## Phase 5 — Advanced Features

*No new crates — hardening and feature completion across `tpt-webrtc-media`,
`tpt-webrtc-codecs`, `tpt-webrtc-rtp`.*
**Milestone: production-ready WebRTC implementation with advanced features.**

- [x] Flesh out `AcousticEchoCanceller` with a real AEC algorithm
      (time-domain NLMS adaptive filter in `tpt-webrtc-media::audio`;
      learns a known echo path to <30% residual in tests)
- [x] Flesh out `NoiseSuppressor` with a real NS algorithm (smoothed
      noise gate with raw-RMS decision)
- [x] Flesh out `AutomaticGainControl` with a real AGC algorithm
      (peak-envelope normalizer with smoothed gain)
- [x] Implement `BbrEstimator` (BBR-model: max-bandwidth + min-RTT
      tracking with probe/drain gain) — plus `GccEstimator` (loss slope +
      TWCC ceiling), `TwccEstimator` (arrival-rate window) and
      `RembEstimator` (remote estimate + decay) behind
      `tpt-webrtc-media::BandwidthEstimator`
- [x] Scalable Video Coding: simulcast fan-out (`SimulcastScaler` with
      RID-tagged layers); SVC layer *selection* on AV1/VP9 encoders
      awaits Phase 3 codecs
- [ ] Implement network adaptation / congestion response wiring BWE output
      into encoder bitrate control (`set_bitrate`) — encoder side waits
      for Phase 3; the estimator side is ready
- [x] Performance: per-test latency tracked (full-connection E2E ≈ 0.3 s
      solo; per-binary contention under parallel test load noted for the
      benchmarking suite)
- [ ] Performance benchmarking suite (encode/decode throughput, RTP
      packetization overhead, ICE connection setup latency) — meaningful
      encode benches need Phase 3 codecs
- [ ] Address any regressions/bottlenecks found by benchmarking
- [x] Comprehensive rustdoc pass across landed crates (crate-level guides
      with doctests on core/sdp/ice/dtls/rtp/sctp/app/media)
- [x] Worked examples: data-channel-only (the full-connection integration
      test doubles as one) and audio-only call (SRTP E2E test); video-call
      example awaits Phase 3 codecs — remaining: a runnable `examples/`
      binary set

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
