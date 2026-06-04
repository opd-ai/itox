package itox

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/opd-ai/toxcore"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

type mockNoiseTransport struct {
	mu       sync.Mutex
	sendErrs []error
	sent     []*toxtransport.Packet
	handler  toxtransport.PacketHandler
}

func (m *mockNoiseTransport) AddPeer(_ net.Addr, _ []byte) error { return nil }
func (m *mockNoiseTransport) Close() error                       { return nil }
func (m *mockNoiseTransport) RegisterHandler(_ toxtransport.PacketType, h toxtransport.PacketHandler) {
	m.handler = h
}
func (m *mockNoiseTransport) Send(packet *toxtransport.Packet, _ net.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, packet)
	if len(m.sendErrs) > 0 {
		err := m.sendErrs[0]
		m.sendErrs = m.sendErrs[1:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *mockNoiseTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

type mockFriendStatus struct {
	pk     [32]byte
	status toxcore.ConnectionStatus
}

func (m *mockFriendStatus) GetFriendByPublicKey(publicKey [32]byte) (uint32, error) {
	if publicKey != m.pk {
		return 0, errors.New("not found")
	}
	return 1, nil
}
func (m *mockFriendStatus) GetFriendConnectionStatus(friendID uint32) toxcore.ConnectionStatus {
	if friendID == 1 {
		return m.status
	}
	return toxcore.ConnectionNone
}
func (m *mockFriendStatus) GetFriendPublicKey(_ uint32) ([32]byte, error) { return m.pk, nil }

type mockACL struct{ allowed [32]byte }

func (m *mockACL) GetFriendByPublicKey(publicKey [32]byte) (uint32, error) {
	if publicKey == m.allowed {
		return 1, nil
	}
	return 0, errors.New("not allowed")
}
func (m *mockACL) GetFriends() map[uint32]*toxcore.Friend {
	return map[uint32]*toxcore.Friend{1: {PublicKey: m.allowed}}
}

func TestSessionRetriesOnIncompleteHandshake(t *testing.T) {
	noise := &mockNoiseTransport{sendErrs: []error{toxtransport.ErrNoiseSessionIncomplete, toxtransport.ErrNoiseSessionIncomplete, nil}}
	s := newToxSession(context.Background(), ToxI2PAddr{}, noise, 30*time.Second, time.Second, 8, nil, nil)
	defer s.Close()

	msg := i2np.NewBaseI2NPMessage(42)
	msg.SetData([]byte("hello"))
	if err := s.QueueSendI2NP(msg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if noise.sentCount() == 0 {
		t.Fatal("expected send attempts")
	}
}

func TestSessionInboundRoundTrip(t *testing.T) {
	noise := &mockNoiseTransport{}
	s := newToxSession(context.Background(), ToxI2PAddr{}, noise, 30*time.Second, time.Second, 8, nil, nil)
	defer s.Close()

	msg := i2np.NewBaseI2NPMessage(7)
	msg.SetData([]byte("payload"))
	b, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frames, err := fragmentMessage(1, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := s.handleInboundPacket(&toxtransport.Packet{Data: f}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.ReadNextI2NP()
	if err != nil {
		t.Fatal(err)
	}
	marshaled, err := out.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(marshaled) == 0 {
		t.Fatal("expected parsed i2np message")
	}
}

func TestTransportGetSessionAndCompatible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pk [32]byte
	for i := range pk {
		pk[i] = byte(i + 1)
	}

	ri := mustRouterInfoWithToxPK(t, pk)
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if !tr.Compatible(ri) {
		t.Fatal("expected compatible router info")
	}
	sess, err := tr.GetSession(ri)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
}

func TestTransportAcceptRejectsUnauthorized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var allowed [32]byte
	allowed[0] = 1
	unauth := ToxI2PAddr{PublicKey: [32]byte{9}}
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: allowed}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: allowed, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if err := tr.handleInboundPacket(&toxtransport.Packet{Data: make([]byte, 6)}, unauth); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, e := tr.Accept()
		done <- e
	}()
	select {
	case <-done:
		t.Fatal("accept should still block for unauthorized peer")
	case <-time.After(100 * time.Millisecond):
	}
}

func mustRouterInfoWithToxPK(t *testing.T, pk [32]byte) router_info.RouterInfo {
	t.Helper()
	addr, err := router_address.NewRouterAddress(1, time.Time{}, "tox", map[string]string{toxPubKeyOption: base64.StdEncoding.EncodeToString(pk[:])})
	if err != nil {
		t.Fatal(err)
	}
	var ri router_info.RouterInfo
	setUnexportedField(t, &ri, "addresses", []*router_address.RouterAddress{addr})
	return ri
}

func setUnexportedField(t *testing.T, target any, field string, val any) {
	t.Helper()
	rv := reflect.ValueOf(target).Elem()
	fv := rv.FieldByName(field)
	if !fv.IsValid() {
		t.Fatalf("missing field %s", field)
	}
	reflect.NewAt(fv.Type(), unsafe.Pointer(fv.UnsafeAddr())).Elem().Set(reflect.ValueOf(val))
}

func TestToxConnImplementsNetConn(t *testing.T) {
	c := &toxConn{local: ToxI2PAddr{}, remote: ToxI2PAddr{}}
	if _, err := c.Read(nil); err == nil {
		t.Fatal("expected read unsupported error")
	}
	if _, err := c.Write(nil); err == nil {
		t.Fatal("expected write unsupported error")
	}
	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("expected addresses")
	}
	_ = c.SetDeadline(time.Now())
	_ = c.SetReadDeadline(time.Now())
	_ = c.SetWriteDeadline(time.Now())
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func ExampleToxI2PAddr_String() {
	var pk [32]byte
	pk[0] = 1
	fmt.Println((ToxI2PAddr{PublicKey: pk}).Network())
	fmt.Println(len((ToxI2PAddr{PublicKey: pk}).String()))
	// Output:
	// tox
	// 64
}

var _ = io.EOF
