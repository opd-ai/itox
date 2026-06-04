package itox

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/i2np"
	"github.com/opd-ai/toxcore"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

type rekeyNoise struct{}

func (rekeyNoise) AddPeer(_ net.Addr, _ []byte) error                                      { return nil }
func (rekeyNoise) RegisterHandler(_ toxtransport.PacketType, _ toxtransport.PacketHandler) {}
func (rekeyNoise) Close() error                                                            { return nil }
func (rekeyNoise) Send(_ *toxtransport.Packet, _ net.Addr) error {
	return toxtransport.ErrRekeyRequired
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig(new(toxcore.Tox), [32]byte{})
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

func TestExtractAndPeerHelpers(t *testing.T) {
	var pk [32]byte
	pk[0] = 7
	addr, err := router_address.NewRouterAddress(1, time.Time{}, "tox", map[string]string{toxPubKeyOption: base64.StdEncoding.EncodeToString(pk[:])})
	if err != nil {
		t.Fatal(err)
	}
	var ri router_info.RouterInfo
	setUnexportedField(t, &ri, "addresses", []*router_address.RouterAddress{addr})

	got, ok := extractToxPubKey(ri)
	if !ok || got != pk {
		t.Fatalf("extractToxPubKey mismatch: ok=%v got=%x", ok, got)
	}

	if _, ok := peerKeyFromAddr(ToxI2PAddr{PublicKey: pk}); !ok {
		t.Fatal("expected peer key from ToxI2PAddr")
	}
	if _, ok := peerKeyFromAddr(nil); ok {
		t.Fatal("expected nil addr parse failure")
	}
}

func TestMappingValueMissing(t *testing.T) {
	m, err := data.GoMapToMapping(map[string]string{"x": "y"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mappingValue(*m, "missing"); ok {
		t.Fatal("expected missing key")
	}
}

func TestTransportWaitHandshakeErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: 50 * time.Millisecond, MaxSendQueue: 8, MaxSessions: 4}
	acl := newFriendACLForTests(&mockACL{}, nil)
	tr, err := newToxTransportWithDeps(cfg, rekeyNoise{}, acl, &mockFriendStatus{})
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
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: 100 * time.Millisecond, MaxSendQueue: 2, MaxSessions: 2}
	var allowed [32]byte
	allowed[0] = 1
	tr, err := newToxTransportWithDeps(cfg, noise, newFriendACLForTests(&mockACL{allowed: allowed}, nil), &mockFriendStatus{pk: allowed, status: toxcore.ConnectionNone})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if tr.Name() != "tox" {
		t.Fatal("unexpected transport name")
	}
	if tr.Addr() == nil {
		t.Fatal("expected non-nil addr")
	}
	if tr.Compatible(router_info.RouterInfo{}) {
		t.Fatal("empty routerinfo should be incompatible")
	}
	if err := tr.SetIdentity(router_info.RouterInfo{}); err == nil {
		t.Fatal("expected SetIdentity failure with missing key")
	}

	ri := mustRouterInfoWithToxPK(t, allowed)
	if err := tr.SetIdentity(ri); err != nil {
		t.Fatalf("unexpected SetIdentity error: %v", err)
	}
	if _, err := tr.GetSession(ri); !errors.Is(err, ErrPeerOffline) {
		t.Fatalf("expected offline error, got %v", err)
	}
}

func TestConstructorWrappersAndSessionHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := DefaultConfig(new(toxcore.Tox), [32]byte{})
	cfg.Context = ctx
	cfg.MaxSendQueue = 4
	cfg.MaxSessions = 4

	if _, err := NewToxTransport(cfg, nil); err == nil {
		t.Fatal("expected error for nil noise transport")
	}

	noise := &mockNoiseTransport{}
	tr, err := NewToxTransport(cfg, noise)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// AcceptConn wrapper should proxy Accept.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := tr.AcceptConn()
		if err != nil || conn == nil {
			t.Errorf("AcceptConn failed: %v", err)
		}
	}()
	select {
	case tr.acceptCh <- &toxConn{local: ToxI2PAddr{}, remote: ToxI2PAddr{}}:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("failed to inject accepted conn")
	}
	<-done

	// DialRouter wrapper should call GetSession; use incompatible RI for error path.
	if _, err := tr.DialRouter(router_info.RouterInfo{}); err == nil {
		t.Fatal("expected DialRouter to fail on incompatible RI")
	}
}

func TestSessionQueueAndCloseErrors(t *testing.T) {
	s := newToxSession(ToxI2PAddr{}, &mockNoiseTransport{}, 30*time.Second, 50*time.Millisecond, 1, nil, nil)
	m1 := i2np.NewBaseI2NPMessage(1)
	m1.SetData([]byte("x"))
	m2 := i2np.NewBaseI2NPMessage(1)
	m2.SetData([]byte("y"))
	if err := s.QueueSendI2NP(m1); err != nil {
		t.Fatal(err)
	}
	_ = s.SendQueueSize()
	if err := s.QueueSendI2NP(m2); err == nil {
		t.Fatal("expected queue full")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueSendI2NP(m1); err == nil {
		t.Fatal("expected closed queue failure")
	}
	if _, err := s.ReadNextI2NP(); err == nil {
		t.Fatal("expected closed read failure")
	}
}

func TestSessionHandleInboundInvalid(t *testing.T) {
	s := newToxSession(ToxI2PAddr{}, &mockNoiseTransport{}, 30*time.Second, 50*time.Millisecond, 2, nil, nil)
	defer s.Close()
	if err := s.handleInboundPacket(&toxtransport.Packet{Data: []byte{1}}); err == nil {
		t.Fatal("expected invalid frame error")
	}
}

func TestHandleInboundAuthorizedPathAndHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pk [32]byte
	pk[0] = 9
	noise := &mockNoiseTransport{}
	cfg := Config{Context: ctx, FragmentTimeout: 30 * time.Second, RetryTimeout: time.Second, MaxSendQueue: 4, MaxSessions: 4}
	tr, err := newToxTransportWithDeps(cfg, noise, newFriendACLForTests(&mockACL{allowed: pk}, nil), &mockFriendStatus{pk: pk, status: toxcore.ConnectionUDP})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	msg := i2np.NewBaseI2NPMessage(2)
	msg.SetData([]byte("ok"))
	encoded, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frames, err := fragmentMessage(1, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.handleInboundPacket(&toxtransport.Packet{Data: frames[0]}, ToxI2PAddr{PublicKey: pk}); err != nil {
		t.Fatal(err)
	}

	// getOrCreateSession returns the existing session after first packet.
	if tr.getOrCreateSession(ToxI2PAddr{PublicKey: pk}, pk) == nil {
		t.Fatal("expected session")
	}
	tr.removeSession(pk)
}

func TestExtractToxPubKeyNegativeCases(t *testing.T) {
	addr, err := router_address.NewRouterAddress(1, time.Time{}, "tox", map[string]string{toxPubKeyOption: "bad-base64"})
	if err != nil {
		t.Fatal(err)
	}
	var ri router_info.RouterInfo
	setUnexportedField(t, &ri, "addresses", []*router_address.RouterAddress{addr})
	if _, ok := extractToxPubKey(ri); ok {
		t.Fatal("expected invalid base64 to fail extraction")
	}
	if _, ok := peerKeyFromAddr(dummyAddr("not-hex")); ok {
		t.Fatal("expected non-hex addr parse failure")
	}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "dummy" }
func (d dummyAddr) String() string  { return string(d) }
