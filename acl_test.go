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

	t.Run("unauthorized logs short key", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		acl := newFriendACLForTests(&mockACLTox{lookupErr: errors.New("no friend")}, logger)
		if acl.IsAuthorized(key) {
			t.Fatal("expected unauthorized")
		}
		out := buf.String()
		if !strings.Contains(out, "tox_pubkey=4200000000000000") {
			t.Fatalf("expected 8-byte key prefix in logs, got %q", out)
		}
	})
}
