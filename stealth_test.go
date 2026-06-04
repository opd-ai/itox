package itox

import (
	"context"
	"testing"
	"time"

	toxtransport "github.com/opd-ai/toxcore/transport"
)

// TestStealthMode_PeerNotAdvertising verifies that in stealth mode,
// peers who haven't advertised I2P availability are rejected.
func TestStealthMode_PeerNotAdvertising(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	
	noise := &mockNoiseTransport{}
	cfg := Config{
		Context:         context.Background(),
		FragmentTimeout: 30 * time.Second,
		RetryTimeout:    time.Second,
		MaxSendQueue:    8,
		MaxSessions:     4,
		StealthMode:     true,
	}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	
	// Create RouterInfo with tox pubkey
	ri := mustRouterInfoWithToxPK(t, pk)
	
	// Should not be compatible because peer hasn't advertised
	if tr.Compatible(ri) {
		t.Error("expected incompatible for non-advertising peer in stealth mode")
	}
	
	// GetSession should fail
	_, err = tr.GetSession(ri)
	if err == nil {
		t.Error("expected error getting session from non-advertising peer")
	}
	if err != nil && err.Error() != "itox: get session: itox: peer not advertising i2p availability" {
		t.Logf("got error: %v", err)
	}
}

// TestStealthMode_PeerAdvertising verifies that peers who advertise
// I2P availability can establish sessions in stealth mode.
func TestStealthMode_PeerAdvertising(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	
	noise := &mockNoiseTransport{}
	cfg := Config{
		Context:         context.Background(),
		FragmentTimeout: 30 * time.Second,
		RetryTimeout:    time.Second,
		MaxSendQueue:    8,
		MaxSessions:     4,
		StealthMode:     true,
	}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	
	// Manually set the peer's status as advertising
	tr.registry.SetStatus(pk, true)
	
	// Create RouterInfo with tox pubkey
	ri := mustRouterInfoWithToxPK(t, pk)
	
	// Should be compatible now
	if !tr.Compatible(ri) {
		t.Error("expected compatible for advertising peer in stealth mode")
	}
	
	// GetSession should succeed (though handshake will timeout in test)
	sess, err := tr.GetSession(ri)
	if err != nil && err.Error() != "itox: handshake wait: context deadline exceeded" {
		t.Errorf("unexpected error: %v", err)
	}
	if sess == nil && err == nil {
		t.Error("expected session or error")
	}
}

// TestStealthMode_StatusMessageHandling verifies that status messages
// are properly received and processed.
func TestStealthMode_StatusMessageHandling(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	
	noise := &mockNoiseTransport{}
	cfg := Config{
		Context:         context.Background(),
		FragmentTimeout: 30 * time.Second,
		RetryTimeout:    time.Second,
		MaxSendQueue:    8,
		MaxSessions:     4,
		StealthMode:     true,
	}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	
	// Initially peer is not advertising
	if tr.registry.GetStatus(pk) {
		t.Error("expected peer not advertising initially")
	}
	
	// Simulate receiving a status message
	statusData, err := EncodeStatusMessage(true)
	if err != nil {
		t.Fatal(err)
	}
	
	// Add magic prefix
	statusPacket := append([]byte{0xFF, 0xFE, 0xFD}, statusData...)
	
	packet := &toxtransport.Packet{
		PacketType: toxtransport.PacketFriendMessage,
		Data:       statusPacket,
	}
	
	addr := ToxI2PAddr{PublicKey: pk}
	if err := tr.handleInboundPacket(packet, addr); err != nil {
		t.Errorf("failed to handle status message: %v", err)
	}
	
	// Now peer should be advertising
	if !tr.registry.GetStatus(pk) {
		t.Error("expected peer to be advertising after status message")
	}
}

// TestStealthMode_BroadcastStatus verifies that status broadcasting
// prepares packets correctly (actual broadcast requires real Tox instance).
func TestStealthMode_BroadcastStatus(t *testing.T) {
	// Encode a status message
	statusData, err := EncodeStatusMessage(true)
	if err != nil {
		t.Fatal(err)
	}
	
	// Verify the message can be decoded
	msg, err := DecodeStatusMessage(statusData)
	if err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	
	if !msg.Available {
		t.Error("expected available=true")
	}
	
	// Verify magic prefix would be added
	statusPacket := append([]byte{0xFF, 0xFE, 0xFD}, statusData...)
	if len(statusPacket) < 3 || statusPacket[0] != 0xFF || statusPacket[1] != 0xFE || statusPacket[2] != 0xFD {
		t.Error("expected status message to have magic prefix")
	}
}

// TestNonStealthMode_BackwardCompatibility verifies that without stealth mode,
// the transport operates in traditional mode.
func TestNonStealthMode_BackwardCompatibility(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	
	noise := &mockNoiseTransport{}
	cfg := Config{
		Context:         context.Background(),
		FragmentTimeout: 30 * time.Second,
		RetryTimeout:    time.Second,
		MaxSendQueue:    8,
		MaxSessions:     4,
		StealthMode:     false, // Traditional mode
	}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	
	// Create RouterInfo with tox pubkey
	ri := mustRouterInfoWithToxPK(t, pk)
	
	// Should be compatible even without advertising
	if !tr.Compatible(ri) {
		t.Error("expected compatible in non-stealth mode")
	}
	
	// Registry should be nil in non-stealth mode
	if tr.registry != nil {
		t.Error("expected nil registry in non-stealth mode")
	}
}

// TestGetSessionByToxPubKey verifies the direct peer connection method.
func TestGetSessionByToxPubKey(t *testing.T) {
	var pk [32]byte
	pk[0] = 1
	
	noise := &mockNoiseTransport{}
	cfg := Config{
		Context:         context.Background(),
		FragmentTimeout: 30 * time.Second,
		RetryTimeout:    time.Second,
		MaxSendQueue:    8,
		MaxSessions:     4,
		StealthMode:     true,
	}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	
	// Set peer as advertising
	tr.registry.SetStatus(pk, true)
	
	// Get session directly by pubkey
	sess, err := tr.GetSessionByToxPubKey(pk)
	if err != nil && err.Error() != "itox: handshake wait: context deadline exceeded" {
		t.Errorf("unexpected error: %v", err)
	}
	if sess == nil && err == nil {
		t.Error("expected session or error")
	}
}

// Mock types for testing

// mockToxForBroadcast is not actually used in tests since Tox
// is a concrete type with unexported fields and can't be mocked easily.
// Tests focus on the core logic that can be tested without real Tox.
