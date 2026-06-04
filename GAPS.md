# Implementation Gaps — 2026-06-04

## Gap 1: toxConn Does Not Function as a Real net.Conn

- **Stated Goal**: README claims `itox` provides "a valid `lib/transport.Transport` implementation" that "registers with the TransportMuxer" and works with standard I2P router patterns.
- **Current State**: The `toxConn` type returned by `Accept()` implements `net.Conn` but its `Read()` and `Write()` methods always return `ErrNotImplemented`. The deadline methods are no-ops. The actual data path uses `QueueSendI2NP` and `ReadNextI2NP` on `ToxSession`, bypassing `net.Conn` entirely.
- **Impact**: Any code that obtains a connection via `Accept()` and attempts to use standard `net.Conn` methods will fail immediately. This violates the principle of least surprise for `transport.Transport` consumers who expect `Accept()` to return functional connections.
- **Closing the Gap**:
  1. **Option A (Preferred)**: Implement `toxConn.Read()`/`Write()` by delegating to the underlying `ToxSession`'s message queues, bridging I2NP messages to byte streams.
  2. **Option B**: Document explicitly that `Accept()` returns a notification-only stub and that data must flow through `QueueSendI2NP`/`ReadNextI2NP`. Update all examples and integrate cleanly with TransportMuxer expectations.
  3. **Option C**: Remove `net.Conn` compliance claim and expose `ToxSession` directly as the primary API.

---

## Gap 2: Session Limit Not Fully Enforced

- **Stated Goal**: `Config.MaxSessions` is documented as limiting concurrent sessions ("Maximum number of concurrent sessions (default: 256)").
- **Current State**: `MaxSessions` sets the buffer size of `acceptCh` but does NOT bound the `sessions` map. Code in `newSession()` adds entries to `sessions` unconditionally. A peer that establishes sessions faster than they're consumed from `acceptCh` can grow `sessions` beyond `MaxSessions`.
- **Impact**: Memory growth under attack from authorized peers. Denial of service against resource-constrained routers.
- **Closing the Gap**: Add a check in `newSession()`: `if len(t.sessions) >= t.cfg.MaxSessions { return ErrTooManySessions }`.

---

## Gap 3: Reassembler Memory Bounds Not Enforced

- **Stated Goal**: Implicit in the fragmentation design is reliable, bounded message reassembly.
- **Current State**: The reassembler has no limit on concurrent `streamID` values or fragments per stream. An authorized peer can exhaust memory by sending frames with many unique stream IDs (up to 65,535) or many fragment indices per stream (up to 65,535 fragments × MTU bytes each).
- **Impact**: Memory exhaustion attack from any authorized Tox friend.
- **Closing the Gap**:
  1. Add `MaxConcurrentStreams` limit (reject new streams when limit reached).
  2. Add `MaxFragmentsPerStream` limit (reject fragments beyond limit).
  3. Implement background reaper goroutine to clean expired streams without requiring new frame arrival.

---

## Gap 4: Timing-Constant ACL Authorization

- **Stated Goal**: "The Tox friend list is the sole authorization layer" — implying security-critical access control.
- **Current State**: `IsAuthorized()` has timing-variable code paths. `GetFriendByPublicKey` failing causes immediate return (fast path), while success triggers iteration with `subtle.ConstantTimeCompare` (slow path). Timing analysis can leak friend list membership.
- **Impact**: Timing oracle allows enumeration of which public keys are in the Tox friend list.
- **Closing the Gap**: Ensure all code paths in `IsAuthorized()` have similar timing characteristics. Always iterate the friend list or use constant-time early-exit alternatives.

---

## Gap 5: Documentation Coverage for Exported API

- **Stated Goal**: As a library intended for integration into go-i2p routers, clear API documentation is essential.
- **Current State**: Documentation coverage is 35.6% per go-stats-generator. Many exported types, methods, and functions lack GoDoc comments, including: `ToxI2PAddr` methods, `toxConn` interface methods, `DialRouter`, `AcceptConn`, `ReadNextI2NP`, `QueueSendI2NP`, `SendQueueSize`.
- **Impact**: Integrators cannot understand API contracts without reading source code. Increases risk of misuse.
- **Closing the Gap**: Add comprehensive GoDoc comments to all exported symbols. Include usage examples for core workflows (session establishment, message sending/receiving).

---

## Gap 6: Graceful Degradation Under Handshake Failures

- **Stated Goal**: Sessions should exist "only between mutual Tox friends", implying clean handling when peers are unreachable or handshakes fail.
- **Current State**: `waitHandshake()` generates significant probe traffic (up to ~50-60 packets per peer over 10s timeout). With many pending peers (e.g., 256), this creates substantial outbound traffic (~12,800 probes/sec) even when peers are offline.
- **Impact**: Traffic amplification; potential for bandwidth exhaustion on metered connections; noise in network diagnostics.
- **Closing the Gap**: Implement exponential backoff with jitter starting from a higher base (e.g., 100ms). Add maximum retry count. Consider circuit-breaker pattern to stop probing peers that consistently fail.

---

## Summary Table

| Gap | Severity | Effort to Close |
|-----|----------|-----------------|
| 1. toxConn stub | MEDIUM | HIGH (requires design decision) |
| 2. Session limit not enforced | HIGH | LOW (simple check addition) |
| 3. Reassembler bounds | HIGH | MEDIUM (add limits + background reaper) |
| 4. Timing-constant ACL | MEDIUM | LOW (refactor comparison loop) |
| 5. Documentation coverage | LOW | MEDIUM (documentation effort) |
| 6. Handshake traffic amplification | LOW | LOW (tune backoff parameters) |
