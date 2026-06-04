package itox

import (
	"crypto/subtle"
	"log/slog"
	"time"

	"github.com/opd-ai/toxcore"
)

type aclTox interface {
	GetFriendByPublicKey(publicKey [32]byte) (uint32, error)
	GetFriends() map[uint32]*toxcore.Friend
}

type FriendACL struct {
	tox    aclTox
	logger *slog.Logger
	now    func() time.Time
}

func NewFriendACL(tox *toxcore.Tox, logger *slog.Logger) *FriendACL {
	if logger == nil {
		logger = slog.Default()
	}
	return &FriendACL{tox: tox, logger: logger, now: time.Now}
}

func newFriendACLForTests(tox aclTox, logger *slog.Logger) *FriendACL {
	if logger == nil {
		logger = slog.Default()
	}
	return &FriendACL{tox: tox, logger: logger, now: time.Now}
}

func (a *FriendACL) IsAuthorized(toxPubKey [32]byte) bool {
	if a == nil || a.tox == nil {
		return false
	}

	// Avoid timing side-channel: always iterate the full friend list
	// regardless of whether GetFriendByPublicKey succeeds.
	// This prevents attackers from using timing differences to determine
	// whether a key is in the friend list.
	friends := a.tox.GetFriends()
	authorized := 0
	for _, f := range friends {
		if f == nil {
			continue
		}
		authorized |= subtle.ConstantTimeCompare(f.PublicKey[:], toxPubKey[:])
	}
	
	if authorized == 1 {
		return true
	}
	
	a.logUnauthorized(toxPubKey)
	return false
}

func (a *FriendACL) logUnauthorized(key [32]byte) {
	if a == nil || a.logger == nil {
		return
	}
	// Log rejection without including key material to prevent enumeration attacks
	a.logger.LogAttrs(nil, slog.LevelDebug, "itox acl reject",
		slog.String("event", "acl_reject"),
		slog.Time("timestamp", a.now()),
	)
}
