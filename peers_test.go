package itox

import (
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	i2ped25519 "github.com/go-i2p/crypto/ed25519"
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
	// Create RouterInfo instances and verify extractRouterHash returns consistent values
	ri1 := makeTestRouterInfo(t, [32]byte{1, 2, 3, 4, 5})
	ri2 := makeTestRouterInfo(t, [32]byte{1, 2, 3, 4, 5})
	ri3 := makeTestRouterInfo(t, [32]byte{6, 7, 8, 9, 10})

	hash1, err := extractRouterHash(ri1)
	if err != nil {
		t.Fatalf("extractRouterHash() error = %v", err)
	}
	hash2, err := extractRouterHash(ri2)
	if err != nil {
		t.Fatalf("extractRouterHash() error = %v", err)
	}
	hash3, err := extractRouterHash(ri3)
	if err != nil {
		t.Fatalf("extractRouterHash() error = %v", err)
	}

	// Same input should produce same hash
	if hash1 != hash2 {
		t.Error("extractRouterHash() not consistent for same input")
	}

	if hash1 == hash3 {
		t.Error("extractRouterHash() should differ for distinct RouterInfo identities")
	}
}

func TestExtractRouterHashRejectsInvalidRouterInfo(t *testing.T) {
	var emptyRI router_info.RouterInfo
	if _, err := extractRouterHash(emptyRI); err == nil {
		t.Fatal("extractRouterHash() should reject invalid RouterInfo")
	}
}

// makeTestRouterInfo creates a deterministic valid RouterInfo for tests.
func makeTestRouterInfo(t *testing.T, hashPrefix [32]byte) router_info.RouterInfo {
	t.Helper()

	privBytes := stded25519.NewKeyFromSeed(hashPrefix[:])
	signingPriv, err := i2ped25519.NewEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewEd25519PrivateKey() error = %v", err)
	}
	signingPub, err := signingPriv.Public()
	if err != nil {
		t.Fatalf("signingPriv.Public() error = %v", err)
	}

	curveMaterialInput := append([]byte("itox-test-curve"), hashPrefix[:]...)
	curveMaterial := sha256.Sum256(curveMaterialInput)
	receivingPub, err := curve25519.NewCurve25519PublicKey(curveMaterial[:])
	if err != nil {
		t.Fatalf("NewCurve25519PublicKey() error = %v", err)
	}

	keyCert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		t.Fatalf("NewEd25519X25519KeyCertificate() error = %v", err)
	}
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - keyCert.CryptoSize() - keyCert.SigningPublicKeySize()
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = hashPrefix[i%len(hashPrefix)]
	}
	routerIdentity, err := router_identity.NewRouterIdentity(*receivingPub, signingPub, &keyCert.Certificate, padding)
	if err != nil {
		t.Fatalf("NewRouterIdentity() error = %v", err)
	}

	addr, err := router_address.NewRouterAddress(1, time.Time{}, "test", map[string]string{})
	if err != nil {
		t.Fatalf("NewRouterAddress() error = %v", err)
	}

	ri, err := router_info.NewRouterInfo(
		routerIdentity,
		time.Unix(0, 0),
		[]*router_address.RouterAddress{addr},
		map[string]string{"router.version": "0.9.65"},
		&signingPriv,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	if err != nil {
		t.Fatalf("NewRouterInfo() error = %v", err)
	}
	return *ri
}
