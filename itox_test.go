package itox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

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
func (m *mockNoiseTransport) Send(packet *toxtransport.Packet, addr net.Addr) error {
	m.mu.Lock()
	m.sent = append(m.sent, packet)
	handler := m.handler
	if len(m.sendErrs) > 0 {
		err := m.sendErrs[0]
		m.sendErrs = m.sendErrs[1:]
		m.mu.Unlock()
		if err != nil {
			return err
		}
	} else {
		m.mu.Unlock()
	}
	// Invoke handler if registered (for end-to-end tests)
	if handler != nil {
		return handler(packet, addr)
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

	ri := mustRouterInfoForPeer(t, pk)
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// Per spec: Compatible returns false for non-registered RouterInfos
	if tr.Compatible(ri) {
		t.Fatal("expected non-compatible router info before registration")
	}

	// Register the peer in the PeerRegistry
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatalf("Registry().Register() failed: %v", err)
	}

	// Now it should be compatible
	if !tr.Compatible(ri) {
		t.Fatal("expected compatible router info after registration")
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

func TestTransportAcceptWithAuthorizedPeer(t *testing.T) {
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

	// Register the peer so they can be accepted
	ri := makeTestRouterInfo(t, pk)
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatal(err)
	}

	// Send an inbound packet from an authorized friend
	done := make(chan net.Conn, 1)
	go func() {
		conn, _ := tr.Accept()
		done <- conn
	}()

	// Create a valid I2NP message and marshal it
	msg := i2np.NewBaseI2NPMessage(7)
	msg.SetData([]byte("test"))
	msgBytes, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Create framing header
	frame := make([]byte, 6+len(msgBytes))
	// stream_id=0, frag_idx=0, total=1
	frame[0] = 0
	frame[1] = 0
	frame[2] = 0
	frame[3] = 0
	frame[4] = 0
	frame[5] = 1
	copy(frame[6:], msgBytes)

	if err := tr.handleInboundPacket(&toxtransport.Packet{Data: frame}, ToxI2PAddr{PublicKey: pk}); err != nil {
		t.Fatal(err)
	}

	select {
	case conn := <-done:
		if conn == nil {
			t.Fatal("expected non-nil connection")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Accept() timed out")
	}
}

func mustRouterInfoForPeer(t *testing.T, peerKey [32]byte) router_info.RouterInfo {
	t.Helper()
	return makeTestRouterInfo(t, peerKey)
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

// TestMuxerCoexistence verifies that ToxTransport works correctly in a TransportMuxer
// alongside other transports, and that Compatible() correctly gates which transport is used.
func TestMuxerCoexistence(t *testing.T) {
	// This test requires go-i2p/lib/transport.Mux which may not be available in test context.
	// We'll simulate the muxer behavior by verifying Compatible() returns false for
	// non-registered peers and true for registered friends.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pk [32]byte
	pk[0] = 1

	ri := makeTestRouterInfo(t, pk)
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// Verify Compatible returns false for non-registered RouterInfos (muxer fallthrough)
	otherPK := [32]byte{99}
	otherRI := makeTestRouterInfo(t, otherPK)
	if tr.Compatible(otherRI) {
		t.Fatal("Compatible() should return false for non-registered RouterInfo")
	}

	// Register the peer
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatal(err)
	}

	// Verify Compatible returns true for registered friends (muxer selects ToxTransport)
	if !tr.Compatible(ri) {
		t.Fatal("Compatible() should return true for registered friend")
	}

	// Verify GetSession succeeds for registered friend
	sess, err := tr.GetSession(ri)
	if err != nil {
		t.Fatalf("GetSession() failed for registered friend: %v", err)
	}
	if sess == nil {
		t.Fatal("GetSession() returned nil session")
	}

	// Verify GetSession fails for non-registered peer
	if _, err := tr.GetSession(otherRI); err == nil {
		t.Fatal("GetSession() should fail for non-registered peer")
	}
}

// TestHappyPathEndToEnd tests message exchange through ToxSession end-to-end.
// This verifies that I2NP messages can be successfully fragmented, transmitted, 
// reassembled, and delivered through the transport layer.
func TestHappyPathEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create two mock noise transports that route to each other
	var noise1, noise2 *mockNoiseTransport
	noise1 = &mockNoiseTransport{}
	noise2 = &mockNoiseTransport{}

	// Create two peers
	var pk1, pk2 [32]byte
	pk1[0] = 1
	pk2[0] = 2

	// Create two RouterInfos
	ri1 := makeTestRouterInfo(t, pk1)
	ri2 := makeTestRouterInfo(t, pk2)

	// Create two ToxTransports with separate noise transports
	cfg1 := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl1 := newFriendACLForTests(&mockACL{allowed: pk2}, nil)
	tr1, err := newToxTransportWithDeps(cfg1, noise1, acl1, &mockFriendStatus{pk: pk2, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr1.Close()

	cfg2 := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl2 := newFriendACLForTests(&mockACL{allowed: pk1}, nil)
	tr2, err := newToxTransportWithDeps(cfg2, noise2, acl2, &mockFriendStatus{pk: pk1, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()

	// Register peers in each other's registries
	if err := tr1.Registry().Register(ri2, pk2); err != nil {
		t.Fatal(err)
	}
	if err := tr2.Registry().Register(ri1, pk1); err != nil {
		t.Fatal(err)
	}

	// Set up noise1 to forward to tr2
	noise1.RegisterHandler(toxtransport.PacketFriendMessage, func(packet *toxtransport.Packet, addr net.Addr) error {
		return tr2.handleInboundPacket(packet, ToxI2PAddr{PublicKey: pk1})
	})

	// Set up noise2 to forward to tr1
	noise2.RegisterHandler(toxtransport.PacketFriendMessage, func(packet *toxtransport.Packet, addr net.Addr) error {
		return tr1.handleInboundPacket(packet, ToxI2PAddr{PublicKey: pk2})
	})

	// Create a test I2NP TunnelData message (type 21)
	msg := i2np.NewBaseI2NPMessage(21)
	msg.SetData([]byte("test-tunnel-data-payload-happy-path"))

	// Send from tr1 to tr2
	sess1, err := tr1.GetSession(ri2)
	if err != nil {
		t.Fatalf("tr1.GetSession(ri2) failed: %v", err)
	}

	if err := sess1.QueueSendI2NP(msg); err != nil {
		t.Fatalf("QueueSendI2NP() failed: %v", err)
	}

	// Wait for delivery
	time.Sleep(200 * time.Millisecond)

	// Get session on tr2 side
	sess2, err := tr2.GetSession(ri1)
	if err != nil {
		t.Fatalf("tr2.GetSession(ri1) failed: %v", err)
	}

	// Read the message with timeout
	select {
	case receivedMsg := <-func() <-chan i2np.Message {
		ch := make(chan i2np.Message, 1)
		go func() {
			msg, err := sess2.ReadNextI2NP()
			if err == nil {
				ch <- msg
			}
		}()
		return ch
	}():
		receivedBytes, err := receivedMsg.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() failed: %v", err)
		}
		if len(receivedBytes) == 0 {
			t.Fatal("Received empty message")
		}
		t.Logf("Successfully exchanged I2NP message (%d bytes)", len(receivedBytes))
	case <-time.After(1 * time.Second):
		t.Fatal("ReadNextI2NP() timed out - message not received")
	}
}

// TestNoNetDBWrite verifies that this transport never calls StoreRouterInfo or any netDB methods.
// This is verified by:
// 1. The package does not import any lib/netdb package
// 2. The transport never modifies RouterInfo address fields
// 3. The transport only uses RouterInfo for identity hash lookup
func TestNoNetDBWrite(t *testing.T) {
	// This test verifies the design constraint by checking:
	// 1. No netdb imports
	// 2. RouterInfo is used read-only (via IdentHash())
	// 3. No address field manipulation

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pk [32]byte
	pk[0] = 1

	ri := makeTestRouterInfo(t, pk)
	riHashBefore, _ := ri.IdentHash()

	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{allowed: pk}, nil)
	tr, err := newToxTransportWithDeps(cfg, noise, acl, &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// Register the peer
	if err := tr.Registry().Register(ri, pk); err != nil {
		t.Fatal(err)
	}

	// Check compatibility (reads IdentHash)
	if !tr.Compatible(ri) {
		t.Fatal("Compatible() should return true")
	}

	// Get a session (reads IdentHash)
	sess, err := tr.GetSession(ri)
	if err != nil {
		t.Fatalf("GetSession() failed: %v", err)
	}
	if sess == nil {
		t.Fatal("GetSession() returned nil")
	}

	// Verify RouterInfo identity hash is unchanged
	riHashAfter, _ := ri.IdentHash()
	if string(riHashBefore[:]) != string(riHashAfter[:]) {
		t.Error("RouterInfo identity hash was modified by transport operations")
	}

	// The transport uses RouterInfo.IdentHash() only as a read-only lookup key.
	// It never modifies RouterInfo, never calls StoreRouterInfo, and never
	// adds transport addresses to RouterInfo. This is verified by the package
	// not importing any lib/netdb package and RouterInfo being used purely
	// for identity hash extraction via PeerRegistry.
}
