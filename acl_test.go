package itox

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/opd-ai/toxcore"
)

type mockACLTox struct {
	lookupErr error
	friends   map[uint32]*toxcore.Friend
}

func (m *mockACLTox) GetFriendByPublicKey(_ [32]byte) (uint32, error) {
	if m.lookupErr != nil {
		return 0, m.lookupErr
	}
	return 1, nil
}
func (m *mockACLTox) GetFriends() map[uint32]*toxcore.Friend { return m.friends }

func TestFriendACLIsAuthorized(t *testing.T) {
	var key [32]byte
	key[0] = 0x42

	t.Run("authorized", func(t *testing.T) {
		acl := newFriendACLForTests(&mockACLTox{friends: map[uint32]*toxcore.Friend{1: {PublicKey: key}}}, slog.Default())
		if !acl.IsAuthorized(key) {
			t.Fatal("expected authorized friend")
		}
	})

	t.Run("unauthorized logs rejection event", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		acl := newFriendACLForTests(&mockACLTox{lookupErr: errors.New("no friend")}, logger)
		if acl.IsAuthorized(key) {
			t.Fatal("expected unauthorized")
		}
		out := buf.String()
		// Verify that rejection is logged without key material
		if !strings.Contains(out, "acl_reject") {
			t.Fatalf("expected acl_reject event in logs, got %q", out)
		}
		// Ensure no key material is included in logs (for security)
		if strings.Contains(out, "4200000000000000") {
			t.Fatalf("expected no key material in logs for security, got %q", out)
		}
	})
	
	t.Run("unauthorized with nil logger uses default", func(t *testing.T) {
		acl := newFriendACLForTests(&mockACLTox{lookupErr: errors.New("no friend")}, nil)
		if acl.IsAuthorized(key) {
			t.Fatal("expected unauthorized")
		}
		// Should not panic
	})
	
	t.Run("unauthorized with fully nil acl and logger", func(t *testing.T) {
		acl := &FriendACL{tox: &mockACLTox{lookupErr: errors.New("no friend")}, logger: nil}
		if acl.IsAuthorized(key) {
			t.Fatal("expected unauthorized")
		}
		// Should not panic calling logUnauthorized with nil logger
	})
	
	t.Run("nil acl returns false", func(t *testing.T) {
		var acl *FriendACL
		if acl.IsAuthorized(key) {
			t.Fatal("expected nil acl to reject")
		}
	})
	
	t.Run("nil tox returns false", func(t *testing.T) {
		acl := &FriendACL{tox: nil, logger: slog.Default()}
		if acl.IsAuthorized(key) {
			t.Fatal("expected nil tox to reject")
		}
	})
	
	t.Run("NewFriendACL with nil logger uses default", func(t *testing.T) {
		acl := newFriendACLForTests(&mockACLTox{friends: map[uint32]*toxcore.Friend{1: {PublicKey: key}}}, nil)
		if acl.logger == nil {
			t.Fatal("expected default logger when nil provided")
		}
	})
	
	t.Run("NewFriendACL constructor", func(t *testing.T) {
		// Test with non-nil logger
		logger := slog.Default()
		acl := NewFriendACL(new(toxcore.Tox), logger)
		if acl == nil {
			t.Fatal("NewFriendACL returned nil")
		}
		if acl.logger != logger {
			t.Error("NewFriendACL didn't preserve logger")
		}
		
		// Test with nil logger (should use default)
		acl2 := NewFriendACL(new(toxcore.Tox), nil)
		if acl2 == nil {
			t.Fatal("NewFriendACL with nil logger returned nil")
		}
		if acl2.logger == nil {
			t.Error("NewFriendACL with nil logger didn't set default")
		}
	})
}
