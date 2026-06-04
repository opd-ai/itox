# UNIVERSAL BUG AUDIT (END-TO-END) — 2026-06-04

## Project Profile

**Purpose:** `github.com/opd-ai/itox` implements I2P-over-Tox transport sessions — a supplemental friend-to-friend transport for go-i2p routers. It provides authenticated, encrypted communication between mutually trusted Tox friends while integrating with the I2P router's TransportMuxer.

**Target Users:** I2P router operators who want to establish private, authenticated tunnels with known Tox friends outside the public I2P network.

**Deployment Model:** Library integrated into go-i2p router instances. Sessions exist only between mutual Tox friends. The Tox friend list serves as the sole ACL.

**Critical Paths:**
1. Session establishment (`GetSession` → `waitHandshake`)
2. Inbound packet handling (`handleInboundPacket` → `reassembler.addFrame`)
3. ACL authorization (`FriendACL.IsAuthorized`)
4. Peer registry management (`PeerRegistry.Register/Resolve/IsKnown`)

## Audit Scope

- **Packages audited:** 1 (github.com/opd-ai/itox)
- **Total source files:** 12 (excluding tests)
- **Total functions inspected:** 60 (25 functions + 35 methods)
- **Test coverage:** 79.3%
- **go vet warnings:** 1 (test file only — mutex pass by value)
- **go test -race:** PASS

## Coverage Log

| Package | 3b Logic | 3c Nil | 3d Errors | 3e Resources | 3f Concurrency | 3g Security | 3h Aliasing | 3i Init | 3j API |
|---------|----------|--------|-----------|--------------|----------------|-------------|-------------|---------|--------|
| itox    | ✅       | ✅     | ✅        | ✅           | ✅             | ✅          | ✅          | ✅      | ✅     |

## Goal-Achievement Summary

| Stated Goal | Status | Blocking Findings |
|-------------|--------|-------------------|
| Valid `lib/transport.Transport` implementation | ⚠️ | MEDIUM-1 (toxConn stub) |
| Compatible(ri) returns true only for registered Tox friends | ✅ | — |
| Sessions exist only between mutual Tox friends | ✅ | — |
| Tox friend list is the sole ACL | ⚠️ | MEDIUM-3 (timing side-channel) |
| Messages carried through toxcore Noise-IK channels | ✅ | — |
| Non-friends silently rejected with debug logging | ✅ | — |
| No RouterInfo netDB publication | ✅ | — |

## Findings

### CRITICAL

*No critical findings.*

### HIGH

- [ ] **HIGH-1: Memory Amplification via StreamID Exhaustion** — `framing.go:79-117` — Resource exhaustion — An authorized peer can create up to 65,535 concurrent stream IDs in the reassembler, each holding up to 65,535 fragments. Without a per-connection stream limit, this allows memory exhaustion. The cleanup loop only runs when a new frame arrives (`addFrame`), not on a background reaper. **Data flow:** Authorized peer sends frames with many unique streamID values → `reassembler.addFrame()` creates new `reassemblyState` entries → `r.streams` map grows unbounded → OOM. — **Remediation:** Add a `MaxConcurrentStreams` limit (e.g., 256) in `reassembler`. Reject new stream IDs when the limit is reached. Implement a background goroutine to periodically reap expired streams. Validation: `go test -race ./... && go test -run TestReassemblerMaxStreams`.

- [ ] **HIGH-2: Session Map Unbounded Growth** — `transport.go:92-99, 288-299` — Resource exhaustion — `MaxSessions` only gates the `acceptCh` channel buffer, not the `t.sessions` map. An authorized peer can trigger session creation via `newSession` without the session ever being consumed from `acceptCh`. The map grows unbounded until the next `friendSyncLoop` tick (30s default). **Data flow:** Authorized friend sends inbound packets → `handleInboundPacket` → `getOrCreateSession` → `newSession` adds to `t.sessions` unconditionally. — **Remediation:** Check `len(t.sessions) >= cfg.MaxSessions` before creating new sessions in `newSession`. Return `ErrTooManySessions` if exceeded. Validation: `go test -race ./... && go test -run TestSessionMapLimit`.

### MEDIUM

- [ ] **MEDIUM-1: toxConn Stub Violates net.Conn Contract** — `conn.go:14-21` — API contract violation — `toxConn` implements `net.Conn` but `Read()`/`Write()` always return errors, and `SetDeadline`/`SetReadDeadline`/`SetWriteDeadline` are no-ops returning `nil`. Any consumer that receives this connection from `Accept()` and attempts to use it as a real `net.Conn` will fail unexpectedly. This is a behavioral mismatch with the documented `transport.Transport` interface. **Data flow:** `Accept()` returns `*toxConn` → consumer calls `Read()`/`Write()` → immediate failure. — **Remediation:** Either implement functional `Read`/`Write` backed by the session's message queue, or document clearly that `Accept()` returns a notification-only connection and provide `QueueSendI2NP`/`ReadNextI2NP` as the actual data path. Validation: manual review of documentation.

- [ ] **MEDIUM-2: waitHandshake Ignores fragmentMessage Error** — `transport.go:197` — Error handling — The error from `fragmentMessage(0, nil)` is discarded with `_`. While this specific call cannot fail (empty payload always produces a valid frame), the pattern establishes a dangerous precedent and makes the code fragile to future changes. **Code:** `probeFrames, _ := fragmentMessage(0, nil)`. — **Remediation:** Either check and handle the error explicitly, or add a comment explaining why ignoring it is safe: `// fragmentMessage(0, nil) cannot fail: empty payload produces single frame`. Validation: `go vet ./...`.

- [ ] **MEDIUM-3: ACL Timing Side-Channel** — `acl.go:37-60` — Security — `IsAuthorized` has two code paths with different timing profiles: (1) `GetFriendByPublicKey` fails → immediate return (fast), (2) success → iterate friends with `subtle.ConstantTimeCompare` (slow). An attacker can distinguish "key not in friend list" from "key is in friend list" via timing analysis. Additionally, rejected keys are logged with their first 8 bytes (`acl.go:67`), which aids enumeration. **Data flow:** Attacker sends packets with candidate public keys → observes response timing → infers friend list membership. — **Remediation:** Always iterate the full friend list regardless of `GetFriendByPublicKey` result. Use constant-time comparison for the initial lookup or remove the early-exit path. Validation: timing analysis or audit by cryptographer.

- [ ] **MEDIUM-4: Reassembler State Reset on `total` Mismatch** — `framing.go:96` — Logic — If a new fragment arrives for an existing `streamID` with a different `total` value, the reassembly state is silently reset. An attacker can flush partial assemblies by replaying a single fragment with a different `total`, causing message loss or corruption of in-flight reassemblies. **Code:** `if state == nil || now.Sub(state.createdAt) > r.timeout || state.total != total { state = &reassemblyState{...} }`. — **Remediation:** Log when `total` mismatches occur. Consider rejecting mismatched `total` instead of resetting, or track the original `total` per stream and reject changes. Validation: `go test -run TestReassemblerTotalMismatch`.

- [ ] **MEDIUM-5: No Background Reaper for Expired Reassembly Streams** — `framing.go:88-93` — Resource leak — Expired partial assemblies are only cleaned up when a new frame arrives on *any* stream. If no frames arrive, stale entries persist indefinitely. This creates a slow memory leak under sporadic traffic patterns. **Code:** The cleanup loop `for sid, st := range r.streams { if now.Sub(st.createdAt) > r.timeout { delete(r.streams, sid) } }` only runs inside `addFrame`. — **Remediation:** Start a background goroutine in `newReassembler` that periodically (e.g., every `timeout/2`) scans and removes expired entries. Validation: `go test -race ./... && go test -run TestReassemblerBackgroundReap`.

### LOW

- [ ] **LOW-1: waitHandshake Busy-Poll Amplification** — `transport.go:192-216` — Performance — During handshake retry, the code sends probe packets every 20ms (initial backoff), doubling up to 500ms. With `RetryTimeout=10s`, this generates ~50-60 probe packets per pending peer. For 256 peers with incomplete handshakes, this creates ~12,800 probes/sec outbound — potential traffic amplification. — **Remediation:** Increase initial backoff to 100ms. Cap maximum retries or add jitter. Validation: load testing with many pending peers.

- [ ] **LOW-2: streamID Wraparound** — `session.go:108-116` — Logic — `nextStreamID` increments `s.streamID` (uint16) and wraps from 0 to 1. StreamID 0 is reserved for keepalive probes. After 65,534 messages, stream IDs are reused. If a slow peer hasn't completed reassembly of an old stream when the ID is reused, fragments from different messages may be conflated. — **Remediation:** Track active stream IDs in the reassembler and skip IDs still in use when wrapping. Validation: `go test -run TestStreamIDWrap`.

- [ ] **LOW-3: goroutine Leak on Context Cancel During Send** — `session.go:118-142` — Resource leak — The `sendLoop` goroutine reads from `s.sendQ` in a `for range` loop. If `s.Close()` is never called but the context is canceled, the goroutine continues waiting on `s.sendQ`. The context cancellation doesn't break the `for range s.sendQ` loop directly. — **Remediation:** Add a `select` case for `ctx.Done()` inside the send loop, or ensure `Close()` is always called when context is canceled. Validation: `go test -race ./... && go test -run TestSessionContextCancel`.

- [ ] **LOW-4: Potential Nil Pointer in deriveLocalAddr** — `transport.go:326-333` — Error handling — If `toxcrypto.FromSecretKey(secret)` fails, the code uses `secret` directly as the public key (fallback). This is documented as "best-effort fallback for malformed test keys" but could cause unexpected behavior in production with invalid keys. — **Remediation:** Log a warning when falling back. Consider returning an error instead of silently producing potentially invalid addresses. Validation: code review.

- [ ] **LOW-5: Missing Documentation on Exported Types** — Multiple files — Documentation — Several exported types and methods lack GoDoc comments: `ToxI2PAddr.Network()`, `ToxI2PAddr.String()`, `toxConn` methods, `DialRouter`, `AcceptConn`, `ReadNextI2NP`, `QueueSendI2NP`, `SendQueueSize`. Documentation coverage is 35.6%. — **Remediation:** Add GoDoc comments to all exported symbols. Validation: `go doc ./...`.

- [ ] **LOW-6: Duplication Between config.go and transport.go** — `config.go:56-76`, `transport.go:67-87` — Maintenance burden — The default-setting logic is duplicated in both `Config.Validate()` and `newToxTransportWithDeps()`. Changes to defaults require updates in two places. — **Remediation:** Extract shared default-setting logic into a helper function. Validation: code review.

- [ ] **LOW-7: Test File Contains go vet Warning** — `config_transport_test.go:41` — Code quality — `rekeyNoise` embeds `mockNoiseTransport` which contains `sync.Mutex`. The `Send` method has value receiver, passing mutex by value. While this is test-only code, it sets a bad example. — **Remediation:** Change `rekeyNoise.Send` receiver to pointer, or restructure to avoid embedding mutex-containing types. Validation: `go vet ./...`.

## Metrics Snapshot

| Metric | Value |
|--------|-------|
| Total functions | 60 |
| Functions above complexity 15 | 0 (itox package) |
| Avg cyclomatic complexity | 5.2 |
| Doc coverage | 35.6% |
| Duplication ratio | 1.65% |
| Test pass rate | 100% (all tests pass) |
| go vet warnings | 1 |
| Test coverage | 79.3% |

## False Positives Considered and Rejected

| Candidate | Reason Rejected |
|-----------|----------------|
| `Close()` called in defer and explicit cleanup | Intentional defensive cleanup; `closeOnce.Do` prevents double-close issues |
| Discarded errors in test files (e.g., `_ = registry.Register`) | Test-only code; explicitly commented as "doesn't matter for this test" |
| `errors.Is` not used for custom errors | Custom errors are sentinel values properly compared with `errors.Is` where appropriate |
| Context cancel func not called in some test cases | All test contexts have `defer cancel()` immediately after creation |
| Potential nil dereference in `peerKeyFromAddr` | Nil check exists at `transport.go:311`: `if addr == nil { return [32]byte{}, false }` |

## Dependencies Security Status

| Dependency | CVE Status | Notes |
|------------|------------|-------|
| `github.com/flynn/noise v1.1.0` | ✅ CVE-2021-4239 PATCHED | Nonce wraparound and desync bugs fixed in v1.0.0; pinned v1.1.0 is safe |
| `github.com/opd-ai/toxcore` | ⚠️ No CVE, but PR #194 fix | Capability negotiation bug fixed 2026-06-04; response path still incomplete |
| `github.com/go-i2p/go-i2p` | ⚠️ Closed DoS issues | Nil-pointer crashes on malformed RouterInfo (issues #25, #27) — verify current version |
| `github.com/go-i2p/noise` | ❓ Unverified fork | Pseudo-version; should verify CVE-2021-4239 patch applied |

## Remaining Scope

*Audit complete. All packages and checklist categories covered.*
