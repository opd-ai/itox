# Implementation Gaps — 2026-06-04

## Gap 1: Race Condition in KnownPeers() Authorization Check

- **Stated Goal**: "The Tox friend list is the sole ACL." — "Re-validates friend status on every call — friend removal takes effect immediately." (peers.go:47)
- **Current State**: `KnownPeers()` acquires a single RWLock, iterates the registry entries, and calls `IsAuthorized()` on each entry while still holding the lock. If a friend is removed from the Tox client during iteration, the ACL is checked, but the lock is held for the entire duration, blocking concurrent register/resolve operations. Additionally, the ACL state can change after the lock is released, causing the returned list to be stale.
- **Impact**: (1) Concurrent calls to `PeerRegistry.Register()` or `Resolve()` can block indefinitely or return stale/inconsistent results. (2) High-frequency callers of `KnownPeers()` could cause denial-of-service by holding the lock while waiting for `IsAuthorized()` to complete. (3) The promise that "friend removal takes effect immediately" is violated — a deleted friend might still appear in the returned list for a brief moment.
- **Closing the Gap**: 
  ```go
  // Pseudocode:
  func (r *PeerRegistry) KnownPeers() [][32]byte {
    r.mu.RLock()
    entries := make([][32]byte, 0, len(r.entries))
    for _, toxPubKey := range r.entries {
      entries = append(entries, toxPubKey)
    }
    r.mu.RUnlock()
    
    // Now release lock before calling IsAuthorized
    var peers [][32]byte
    for _, toxPubKey := range entries {
      if r.acl.IsAuthorized(toxPubKey) {
        peers = append(peers, toxPubKey)
      }
    }
    return peers
  }
  ```
  Add a docstring: `// Note: Returns a snapshot; friend status may change between invocation and return.` This makes the TOCTOU window explicit.
  
  **Validation**: `go test -race ./...` with a test that removes friends while KnownPeers iterates.

---

## Gap 2: QueueSendI2NP TOCTOU Race on Session Close

- **Stated Goal**: "Messages are carried through toxcore Noise-IK channels only." (doc.go:26) — "Returns ErrSessionClosed if the session is closed" (session.go:68)
- **Current State**: `QueueSendI2NP()` performs a non-blocking check for closure at line 71-74, then tries to send on the channel at line 75-80. If the session is closed between these two checks, the send will panic (sending on a closed channel is a fatal error).
- **Impact**: A caller that invokes `QueueSendI2NP()` while `Close()` is running on another goroutine has a race window where a panic can occur instead of a clean `ErrSessionClosed`.
- **Closing the Gap**:
  ```go
  // Combine both checks into one select:
  func (s *ToxSession) QueueSendI2NP(msg i2np.Message) error {
    select {
    case <-s.closed:
      return fmt.Errorf("itox: queue send i2np: %w", ErrSessionClosed)
    case s.sendQ <- msg:
      return nil
    case <-time.After(0): // non-blocking default
      return fmt.Errorf("itox: queue send i2np: %w", ErrSendQueueFull)
    }
  }
  ```
  This way, if the channel is closed, the send operation itself will safely fail without a panic.
  
  **Validation**: `go test -race ./...` with a test that calls `QueueSendI2NP` concurrently with `Close()`.

---

## Gap 3: Inbound Connection Notifications Can Be Silently Dropped

- **Stated Goal**: "Sessions exist only between operators who are mutual Tox friends." (README.md:11) — "Non-friends are silently rejected with debug-level logging only" (doc.go:27)
- **Current State**: When an inbound packet arrives from an authorized friend, `handleInboundPacket()` attempts a non-blocking send to `acceptCh` (line 267-269). If `acceptCh` is full (buffered to `MaxSessions` capacity), the connection notification is silently dropped with no logging or error. A caller that never drains `Accept()` will cause the channel to fill, and subsequent legitimate connection attempts from friends will be discarded.
- **Impact**: An application that registers peers but does not call `Accept()` (or calls it too slowly) will mysteriously lose connections from registered friends. The router will appear offline to those friends even though packets are being received and processed.
- **Closing the Gap**:
  1. **Add logging**: Log dropped connections at WARN level in the default case:
     ```go
     select {
     case t.acceptCh <- &toxConn{local: t.Addr(), remote: addr}:
     default:
       t.logger.Warn("itox: inbound connection dropped (Accept buffer full)",
         slog.String("peer", hex.EncodeToString(peer[:8])),
         slog.Int("buffer_size", len(t.acceptCh)),
       )
     }
     ```
  
  2. **Add timeout or backpressure**: Consider adding a timeout or blocking behavior with context cancellation:
     ```go
     select {
     case t.acceptCh <- &toxConn{local: t.Addr(), remote: addr}:
     case <-t.closeCh:
     case <-t.cfg.Context.Done():
     }
     ```
  
  3. **Document the contract**: Add a docstring to `Accept()` clarifying that callers must drain connections regularly to avoid dropping inbound peers.
  
  **Validation**: Test with `MaxSessions=2`, register 3 peers, send inbound packets from all, verify at most 2 connections appear.

---

## Gap 4: Fragment Expiry Latency Not Bounded as Advertised

- **Stated Goal**: "Fragment timeout" configuration (config.go:14) sets when fragments should be discarded.
- **Current State**: The `backgroundReaper` goroutine runs a ticker every `timeout / 2`. A fragment that arrives just before a reap cycle may not be reaped until `timeout + timeout/2` (one full timeout, plus up to half a timeout for the next reap tick). This is not a correctness bug, but violates the semantic contract that fragments expire after `timeout`.
- **Impact**: Memory usage can be higher than expected. A sender that floods with single-fragment messages (1300 bytes each) could accumulate garbage up to `1300 bytes * floor(66KB / 1300) * 1.5x` = ~57KB extra, depending on timing.
- **Closing the Gap**:
  1. **Tighten the reaper**: Run the reaper every `timeout / 4` instead of `timeout / 2` to reduce the upper bound from `timeout * 1.5` to `timeout * 1.25`:
     ```go
     ticker := time.NewTicker(r.timeout / 4)
     ```
  
  2. **Or use a more efficient algorithm**: Replace the periodic reaper with a min-heap of expiration times. When a new fragment arrives, insert its expiration time. When reaping, pop all expired entries. This guarantees expiry within `timeout` + one iteration.
  
  3. **Document the behavior**: Add a comment in `newReassembler` clarifying the expiry window: `// Fragments may remain in memory for up to timeout * 1.5 due to reaper scheduling.`
  
  **Validation**: Write a benchmark with 1000s of fragments and verify memory usage stays within bounds.

---

## Gap 5: Config Default Application Lacks Explicit Validation

- **Stated Goal**: "Sensible defaults" (config.go comments and field names imply).
- **Current State**: `Validate()` calls `populateDefaults()`, but `populateDefaults()` is also exported and can be called manually. A caller who calls `populateDefaults()` without calling `Validate()` first will populate defaults even if required fields like `Tox` are nil. The function silently succeeds on a Config with `Tox == nil`.
- **Impact**: Low. Unlikely scenario. But violates the contract that `Validate()` is the entry point for validation. Could lead to nil dereferences later.
- **Closing the Gap**:
  1. Make `populateDefaults()` private (`populateDefaults` → `populatedefaults`).
  2. Call it only from `Validate()`.
  3. Add an explicit check in `populateDefaults()` (or outside it) to reject zero-valued limits if they are explicitly set (not just filled by defaults).
  
  **Validation**: Test that `Config{MaxSessions: 0, Tox: <valid>}.Validate()` replaces 0 with a default, not an error.

---

## Gap 6: Friend Removal Detection Latency Unbounded

- **Stated Goal**: "Friend removal takes effect immediately" (peers.go:47).
- **Current State**: The `friendSyncLoop` checks friend status every `FriendSyncInterval` (default 30 seconds). If a friend is removed from the Tox client, any existing sessions will continue to be used until the next sync check, which could take up to 30 seconds.
- **Impact**: After a friend is removed, the router may continue routing messages through that "friendship" for up to 30 seconds, violating the "immediate" promise. An attacker who tricks a user into removing them as a friend still has a 30-second window to intercept or inject traffic.
- **Closing the Gap**:
  1. **Reduce the default sync interval**: Change `defaultFriendSyncInterval = 30 * time.Second` to something like `5 * time.Second`.
  2. **Or make it configurable per-router**: Allow the application to set a lower sync interval for higher security requirements.
  3. **Add a listener callback**: If toxcore supports friend removal callbacks, use those instead of polling. This would make removal "immediate."
  4. **Document the latency**: "Friend removal takes effect within FriendSyncInterval, which defaults to 30 seconds."
  
  **Validation**: Remove a friend mid-test and measure how long until sessions for that friend are closed.

---

## Gap 7: Documentation Claims vs. Reality

- **Stated Goal**: "No RouterInfo netDB publication performed by this package." (doc.go:25).
- **Current State**: The code does not call any netDB APIs. However, the documentation does not explicitly state that the application must not call netDB APIs itself. A misunderstanding could lead to a user accidentally publishing itox RouterInfos to the netDB, breaking the design assumption.
- **Impact**: Low. An RTFM issue, not a code bug. But worth documenting.
- **Closing the Gap**:
  1. Add to the README: "Applications must NOT call I2P's StoreRouterInfo with itox RouterInfos. Doing so violates the design assumption that peer discovery is out-of-band only."
  2. Add a comment in the example/main.go showing the WRONG way to do things (as a negative example).

---

## Summary

**Total Gaps**: 7  
**Critical**: 1 (KnownPeers lock contention)  
**High**: 2 (QueueSendI2NP race, dropped inbound connections)  
**Medium**: 2 (fragment expiry latency, friend removal latency)  
**Low**: 2 (config validation, documentation)  

All gaps are discoverable and closeable without architectural changes. Most are behavioral (not crashing bugs) but affect correctness, concurrency safety, or contract satisfaction.
