package itox

import (
	"sync"

	"github.com/go-i2p/common/router_info"
)

// PeerRegistry maps RouterInfo identity hashes to Tox public keys.
// This is the only source of addressing for this transport.
type PeerRegistry struct {
	mu      sync.RWMutex
	entries map[[32]byte][32]byte // RouterInfo hash -> Tox pubkey
	acl     *FriendACL
}

// NewPeerRegistry creates a new PeerRegistry with the given FriendACL.
func NewPeerRegistry(acl *FriendACL) *PeerRegistry {
	return &PeerRegistry{
		entries: make(map[[32]byte][32]byte),
		acl:     acl,
	}
}

// Register maps the RouterInfo's identity hash to a Tox public key.
// Called by the application after receiving a friend's RouterInfo out-of-band.
// Returns ErrNotFriend if toxPubKey is not currently in the Tox friend list.
func (r *PeerRegistry) Register(ri router_info.RouterInfo, toxPubKey [32]byte) error {
	if !r.acl.IsAuthorized(toxPubKey) {
		return ErrNotFriend
	}

	hash, err := extractRouterHash(ri)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.entries[hash] = toxPubKey
	r.mu.Unlock()

	return nil
}

// Resolve returns the Tox public key for a RouterInfo's identity hash.
// Returns ErrPeerNotRegistered if no mapping exists.
// Returns ErrNotFriend if the mapped key is no longer a current Tox friend.
// Re-validates friend status on every call — friend removal takes effect immediately.
func (r *PeerRegistry) Resolve(ri router_info.RouterInfo) ([32]byte, error) {
	hash, err := extractRouterHash(ri)
	if err != nil {
		return [32]byte{}, err
	}

	r.mu.RLock()
	toxPubKey, ok := r.entries[hash]
	r.mu.RUnlock()

	if !ok {
		return [32]byte{}, ErrPeerNotRegistered
	}

	// Re-validate friend status
	if !r.acl.IsAuthorized(toxPubKey) {
		return [32]byte{}, ErrNotFriend
	}

	return toxPubKey, nil
}

// Deregister removes the mapping for a RouterInfo identity hash.
func (r *PeerRegistry) Deregister(ri router_info.RouterInfo) {
	hash, err := extractRouterHash(ri)
	if err != nil {
		return
	}
	r.mu.Lock()
	delete(r.entries, hash)
	r.mu.Unlock()
}

// IsKnown returns true if the RouterInfo has a mapping AND the mapped key is
// a current friend. This is the fast path called by Compatible().
func (r *PeerRegistry) IsKnown(ri router_info.RouterInfo) bool {
	hash, err := extractRouterHash(ri)
	if err != nil {
		return false
	}

	r.mu.RLock()
	toxPubKey, ok := r.entries[hash]
	r.mu.RUnlock()

	if !ok {
		return false
	}

	return r.acl.IsAuthorized(toxPubKey)
}

// KnownPeers returns all registered Tox public keys that are current friends.
func (r *PeerRegistry) KnownPeers() [][32]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var peers [][32]byte
	for _, toxPubKey := range r.entries {
		if r.acl.IsAuthorized(toxPubKey) {
			peers = append(peers, toxPubKey)
		}
	}

	return peers
}

// extractRouterHash extracts the RouterInfo identity hash as a [32]byte.
func extractRouterHash(ri router_info.RouterInfo) ([32]byte, error) {
	hash, err := ri.IdentHash()
	if err != nil {
		return [32]byte{}, ErrInvalidRouterInfo
	}
	var out [32]byte
	copy(out[:], hash[:])
	if out == ([32]byte{}) {
		return [32]byte{}, ErrInvalidRouterInfo
	}
	return out, nil
}
