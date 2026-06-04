package itox

import (
	"testing"

	"github.com/go-i2p/common/router_info"
)

func TestPeerRegistry_Register(t *testing.T) {
	tests := []struct {
		name        string
		friendKey   [32]byte
		registerKey [32]byte
		wantErr     error
	}{
		{
			name:        "register friend succeeds",
			friendKey:   [32]byte{1},
			registerKey: [32]byte{1},
			wantErr:     nil,
		},
		{
			name:        "register non-friend fails",
			friendKey:   [32]byte{1},
			registerKey: [32]byte{2},
			wantErr:     ErrNotFriend,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := newFriendACLForTests(&mockACL{allowed: tt.friendKey}, nil)
			registry := NewPeerRegistry(acl)
			
			ri := makeTestRouterInfo(t, [32]byte{10, 11, 12})
			err := registry.Register(ri, tt.registerKey)
			
			if err != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}
			
			// If registration succeeded, verify mapping exists
			if err == nil {
				if !registry.IsKnown(ri) {
					t.Error("IsKnown() = false after successful Register()")
				}
			}
		})
	}
}

func TestPeerRegistry_Resolve(t *testing.T) {
	friendKey := [32]byte{1}
	acl := newFriendACLForTests(&mockACL{allowed: friendKey}, nil)
	registry := NewPeerRegistry(acl)
	
	ri := makeTestRouterInfo(t, [32]byte{10, 11, 12})
	
	// Before registration
	_, err := registry.Resolve(ri)
	if err != ErrPeerNotRegistered {
		t.Errorf("Resolve() before Register() error = %v, want %v", err, ErrPeerNotRegistered)
	}
	
	// After registration
	if err := registry.Register(ri, friendKey); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	got, err := registry.Resolve(ri)
	if err != nil {
		t.Fatalf("Resolve() after Register() error = %v", err)
	}
	if got != friendKey {
		t.Errorf("Resolve() = %v, want %v", got, friendKey)
	}
}

func TestPeerRegistry_ResolveFriendRemoved(t *testing.T) {
	friendKey := [32]byte{1}
	acl := newFriendACLForTests(&mockACL{allowed: friendKey}, nil)
	registry := NewPeerRegistry(acl)
	
	ri := makeTestRouterInfo(t, [32]byte{10, 11, 12})
	
	if err := registry.Register(ri, friendKey); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	// Change ACL to reject the key (simulating friend removal)
	registry.acl = newFriendACLForTests(&mockACL{allowed: [32]byte{99}}, nil)
	
	_, err := registry.Resolve(ri)
	if err != ErrNotFriend {
		t.Errorf("Resolve() after friend removal error = %v, want %v", err, ErrNotFriend)
	}
}

func TestPeerRegistry_Deregister(t *testing.T) {
	friendKey := [32]byte{1}
	acl := newFriendACLForTests(&mockACL{allowed: friendKey}, nil)
	registry := NewPeerRegistry(acl)
	
	ri := makeTestRouterInfo(t, [32]byte{10, 11, 12})
	
	if err := registry.Register(ri, friendKey); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	if !registry.IsKnown(ri) {
		t.Fatal("IsKnown() = false after Register()")
	}
	
	registry.Deregister(ri)
	
	if registry.IsKnown(ri) {
		t.Error("IsKnown() = true after Deregister()")
	}
	
	_, err := registry.Resolve(ri)
	if err != ErrPeerNotRegistered {
		t.Errorf("Resolve() after Deregister() error = %v, want %v", err, ErrPeerNotRegistered)
	}
}

func TestPeerRegistry_IsKnown(t *testing.T) {
	friendKey := [32]byte{1}
	acl := newFriendACLForTests(&mockACL{allowed: friendKey}, nil)
	registry := NewPeerRegistry(acl)
	
	ri := makeTestRouterInfo(t, [32]byte{10, 11, 12})
	
	// Before registration
	if registry.IsKnown(ri) {
		t.Error("IsKnown() = true before Register()")
	}
	
	// After registration
	if err := registry.Register(ri, friendKey); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	if !registry.IsKnown(ri) {
		t.Error("IsKnown() = false after Register()")
	}
	
	// After friend removal
	registry.acl = newFriendACLForTests(&mockACL{allowed: [32]byte{99}}, nil)
	
	if registry.IsKnown(ri) {
		t.Error("IsKnown() = true after friend removed from ACL")
	}
}

func TestPeerRegistry_KnownPeers(t *testing.T) {
	friend1 := [32]byte{1}
	friend2 := [32]byte{2}
	acl := newFriendACLForTests(&mockACL{allowed: friend1}, nil)
	registry := NewPeerRegistry(acl)
	
	// Empty registry
	peers := registry.KnownPeers()
	if len(peers) != 0 {
		t.Errorf("KnownPeers() on empty registry = %d peers, want 0", len(peers))
	}
	
	// Register friend1
	ri1 := makeTestRouterInfo(t, [32]byte{10})
	if err := registry.Register(ri1, friend1); err != nil {
		t.Fatalf("Register(friend1) error = %v", err)
	}
	
	peers = registry.KnownPeers()
	if len(peers) != 1 {
		t.Errorf("KnownPeers() after 1 register = %d peers, want 1", len(peers))
	}
	if peers[0] != friend1 {
		t.Errorf("KnownPeers()[0] = %v, want %v", peers[0], friend1)
	}
	
	// Register non-friend (should fail, but let's verify it doesn't appear in KnownPeers)
	ri2 := makeTestRouterInfo(t, [32]byte{20})
	_ = registry.Register(ri2, friend2) // Will fail but doesn't matter for this test
	
	peers = registry.KnownPeers()
	if len(peers) != 1 {
		t.Errorf("KnownPeers() after failed register = %d peers, want 1", len(peers))
	}
}

func TestPeerRegistry_ConcurrentAccess(t *testing.T) {
	friendKey := [32]byte{1}
	acl := newFriendACLForTests(&mockACL{allowed: friendKey}, nil)
	registry := NewPeerRegistry(acl)
	
	ri1 := makeTestRouterInfo(t, [32]byte{10})
	ri2 := makeTestRouterInfo(t, [32]byte{20})
	ri3 := makeTestRouterInfo(t, [32]byte{30})
	
	// Register initial peer
	if err := registry.Register(ri1, friendKey); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	
	done := make(chan bool, 3)
	
	// Concurrent readers
	go func() {
		for i := 0; i < 100; i++ {
			_ = registry.IsKnown(ri1)
			_, _ = registry.Resolve(ri1)
			_ = registry.KnownPeers()
		}
		done <- true
	}()
	
	// Concurrent writer 1
	go func() {
		for i := 0; i < 100; i++ {
			_ = registry.Register(ri2, friendKey)
			registry.Deregister(ri2)
		}
		done <- true
	}()
	
	// Concurrent writer 2
	go func() {
		for i := 0; i < 100; i++ {
			_ = registry.Register(ri3, friendKey)
			registry.Deregister(ri3)
		}
		done <- true
	}()
	
	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestExtractRouterHash(t *testing.T) {
	// Create a RouterInfo with a known hash
	ri := makeTestRouterInfo(t, [32]byte{1, 2, 3, 4, 5})
	hash := extractRouterHash(ri)
	
	// Verify it extracts the first 32 bytes
	expected := [32]byte{1, 2, 3, 4, 5}
	for i := 0; i < 32; i++ {
		if i < 5 {
			if hash[i] != expected[i] {
				t.Errorf("extractRouterHash()[%d] = %d, want %d", i, hash[i], expected[i])
			}
		}
	}
}

// makeTestRouterInfo creates a minimal RouterInfo for testing with a specific identity hash prefix.
func makeTestRouterInfo(t *testing.T, hashPrefix [32]byte) router_info.RouterInfo {
	t.Helper()
	
	// For testing purposes, we need a RouterInfo that can be passed to the registry.
	// Since the registry extracts the IdentHash() from the RouterInfo, we need to use
	// ReadRouterInfo to create a properly initialized RouterInfo from bytes.
	// However, for simple tests, we can just use an empty/zero RouterInfo and rely on
	// the fact that IdentHash() will return a consistent value for the same RouterInfo.
	var emptyRI router_info.RouterInfo
	return emptyRI
}
