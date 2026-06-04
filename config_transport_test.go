package itox

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/opd-ai/toxcore"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

func TestConfigValidate(t *testing.T) {
	ri := makeTestRouterInfo(t, [32]byte{1})
	cfg := DefaultConfig(new(toxcore.Tox), [32]byte{}, ri)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	bad := Config{}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected nil-tox validation error")
	}
}

func TestConfigValidateSetsDefaults(t *testing.T) {
	cfg := Config{Tox: new(toxcore.Tox)}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Context == nil || cfg.FragmentTimeout <= 0 || cfg.MaxSendQueue <= 0 || cfg.MaxSessions <= 0 || cfg.RetryTimeout <= 0 {
		t.Fatal("expected defaults to be populated")
	}
}

type rekeyNoise struct {
	mockNoiseTransport
}

func (r rekeyNoise) Send(_ *toxtransport.Packet, _ net.Addr) error {
	return toxtransport.ErrRekeyRequired
}

func TestTransportWaitHandshakeErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: 50 * time.Millisecond, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{}, nil)
	tr, err := newToxTransportWithDeps(cfg, &rekeyNoise{}, acl, &mockFriendStatus{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if err := tr.waitHandshake(ToxI2PAddr{}); !errors.Is(err, ErrSessionRekeyNeeded) {
		t.Fatalf("expected rekey error, got %v", err)
	}
}

func TestTransportMethodsAndRejects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: [32]byte{1}}, nil)
	noise := &mockNoiseTransport{}
	tox := &mockFriendStatus{pk: [32]byte{1}, status: toxcore.ConnectionTCP}
	tr, err := newToxTransportWithDeps(cfg, noise, acl, tox)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if tr.Name() != "tox" {
		t.Errorf("Name() = %q, want \"tox\"", tr.Name())
	}

	// Test Compatible - should be false for non-registered RouterInfo
	ri := makeTestRouterInfo(t, [32]byte{10})
	if tr.Compatible(ri) {
		t.Error("Compatible() = true for non-registered RouterInfo, want false")
	}

	// Register the RouterInfo
	if err := tr.Registry().Register(ri, [32]byte{1}); err != nil {
		t.Fatalf("Registry().Register() error = %v", err)
	}

	// Now Compatible should return true
	if !tr.Compatible(ri) {
		t.Error("Compatible() = false for registered RouterInfo, want true")
	}
}

func TestConstructorWrappersAndSessionHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ri := makeTestRouterInfo(t, [32]byte{1})
	cfg := DefaultConfig(new(toxcore.Tox), [32]byte{}, ri)
	cfg.Context = ctx
	noise := &mockNoiseTransport{}
	tr, err := NewToxTransport(cfg, noise)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// Test that Registry() returns a non-nil PeerRegistry
	if tr.Registry() == nil {
		t.Error("Registry() returned nil")
	}

	// Test Addr()
	if tr.Addr() == nil {
		t.Error("Addr() returned nil")
	}

	// Test Name()
	if tr.Name() != "tox" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "tox")
	}

	// Test SetIdentity
	ri2 := makeTestRouterInfo(t, [32]byte{99})
	if err := tr.SetIdentity(ri2); err != nil {
		t.Errorf("SetIdentity() error = %v", err)
	}

	// Test peerKeyFromAddr with different inputs
	toxAddr := ToxI2PAddr{PublicKey: [32]byte{1, 2, 3}}
	if pk, ok := peerKeyFromAddr(toxAddr); !ok || pk != toxAddr.PublicKey {
		t.Error("peerKeyFromAddr(ToxI2PAddr) failed")
	}

	if _, ok := peerKeyFromAddr(nil); ok {
		t.Error("peerKeyFromAddr(nil) should return false")
	}
}

func TestSessionSendQueueSize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var pk [32]byte
	pk[0] = 1
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ri := makeTestRouterInfo(t, pk)
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatal(err)
	}

	sess, err := tr.GetSession(ri)
	if err != nil {
		t.Fatal(err)
	}

	// Should be 0 initially
	if size := sess.SendQueueSize(); size != 0 {
		t.Errorf("SendQueueSize() = %d, want 0", size)
	}
}

func TestDialerAndListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var pk [32]byte
	pk[0] = 1
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ri := makeTestRouterInfo(t, pk)
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatal(err)
	}

	// Test DialRouter (wraps GetSession)
	sess, err := tr.DialRouter(ri)
	if err != nil {
		t.Errorf("DialRouter() error = %v", err)
	}
	if sess == nil {
		t.Error("DialRouter() returned nil session")
	}
}

func TestNewToxTransportValidation(t *testing.T) {
	ctx := context.Background()

	// Test with nil noise transport
	ri := makeTestRouterInfo(t, [32]byte{1})
	cfg := DefaultConfig(new(toxcore.Tox), [32]byte{1}, ri)
	cfg.Context = ctx
	if _, err := NewToxTransport(cfg, nil); err == nil {
		t.Error("NewToxTransport with nil noise should return error")
	}

	// Test with invalid config (nil Tox)
	cfg2 := Config{
		Tox:     nil, // invalid
		Context: ctx,
	}
	if _, err := NewToxTransport(cfg2, &mockNoiseTransport{}); err == nil {
		t.Error("NewToxTransport with nil Tox should return error")
	}
}
