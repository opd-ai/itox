package itox

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/common/router_info"
	i2ptransport "github.com/go-i2p/go-i2p/lib/transport"
	"github.com/opd-ai/toxcore"
	toxcrypto "github.com/opd-ai/toxcore/crypto"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

type transportNoise interface {
	noiseSender
	AddPeer(addr net.Addr, publicKey []byte) error
	RegisterHandler(packetType toxtransport.PacketType, handler toxtransport.PacketHandler)
	Close() error
}

type friendStatus interface {
	GetFriendByPublicKey(publicKey [32]byte) (uint32, error)
	GetFriendConnectionStatus(friendID uint32) toxcore.ConnectionStatus
	GetFriendPublicKey(friendID uint32) ([32]byte, error)
}

type ToxTransport struct {
	cfg    Config
	logger *slog.Logger

	acl          *FriendACL
	noise        transportNoise
	tox          friendStatus
	peerRegistry *PeerRegistry

	mu       sync.RWMutex
	sessions map[[32]byte]*ToxSession

	acceptCh  chan net.Conn
	closeCh   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
	local     ToxI2PAddr
}

var _ i2ptransport.Transport = (*ToxTransport)(nil)

func NewToxTransport(cfg Config, noise transportNoise) (*ToxTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("itox: new transport: %w", err)
	}
	if noise == nil {
		return nil, fmt.Errorf("itox: new transport: noise transport is nil: %w", ErrInvalidConfig)
	}
	return newToxTransportWithDeps(cfg, noise, NewFriendACL(cfg.Tox, cfg.Logger), cfg.Tox)
}

func newToxTransportWithDeps(cfg Config, noise transportNoise, acl *FriendACL, tox friendStatus) (*ToxTransport, error) {
	// Defensively populate defaults (mirrors Config.Validate without requiring Tox).
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	if cfg.FragmentTimeout <= 0 {
		cfg.FragmentTimeout = defaultFragmentTimeout
	}
	if cfg.RetryTimeout <= 0 {
		cfg.RetryTimeout = defaultRetryTimeout
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if cfg.MaxSendQueue <= 0 {
		cfg.MaxSendQueue = defaultMaxSendQueue
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if acl == nil {
		acl = NewFriendACL(cfg.Tox, cfg.Logger)
	}
	
	t := &ToxTransport{
		cfg:          cfg,
		logger:       cfg.Logger,
		acl:          acl,
		noise:        noise,
		tox:          tox,
		peerRegistry: NewPeerRegistry(acl),
		sessions:     make(map[[32]byte]*ToxSession),
		acceptCh:     make(chan net.Conn, cfg.MaxSessions),
		closeCh:      make(chan struct{}),
		closed:       make(chan struct{}),
	}
	t.local = deriveLocalAddr(cfg.LocalSecretKey)
	noise.RegisterHandler(toxtransport.PacketFriendMessage, t.handleInboundPacket)
	go func() {
		<-cfg.Context.Done()
		_ = t.Close()
	}()
	return t, nil
}

// Name returns "tox". Appears in TransportMuxer.Name() output as
// "Muxed Transport: NTCP2, SSU2, tox".
func (t *ToxTransport) Name() string { return "tox" }

// Registry returns the PeerRegistry for registering friend RouterInfos.
func (t *ToxTransport) Registry() *PeerRegistry {
	return t.peerRegistry
}

// Compatible returns true if and only if PeerRegistry.IsKnown(ri) is true.
// For all standard I2P RouterInfos this returns false, so the muxer
// falls through to NTCP2/SSU2 without any involvement from this transport.
// Must be fast (read lock on PeerRegistry only) and side-effect free.
func (t *ToxTransport) Compatible(ri router_info.RouterInfo) bool {
	return t.peerRegistry.IsKnown(ri)
}

// SetIdentity stores the local RouterInfo identity. Does not modify RouterInfo.
func (t *ToxTransport) SetIdentity(ri router_info.RouterInfo) error {
	// Per spec: itox has no opinion about RouterInfo address fields.
	// We just store it for potential future use but don't extract anything from it.
	t.mu.Lock()
	defer t.mu.Unlock()
	// Update local address if we can derive it from the secret key
	t.local = deriveLocalAddr(t.cfg.LocalSecretKey)
	return nil
}

// GetSession returns an existing or new ToxSession for the given RouterInfo.
// Called by the muxer only after Compatible returned true.
// Calls PeerRegistry.Resolve to get the Tox public key.
// Blocks until Noise-IK handshake completes or Config.Context is cancelled.
func (t *ToxTransport) GetSession(ri router_info.RouterInfo) (i2ptransport.TransportSession, error) {
	toxPubKey, err := t.peerRegistry.Resolve(ri)
	if err != nil {
		return nil, fmt.Errorf("itox: get session: %w", err)
	}
	
	return t.getSessionByKey(toxPubKey)
}

func (t *ToxTransport) getSessionByKey(pub [32]byte) (i2ptransport.TransportSession, error) {
	if !t.acl.IsAuthorized(pub) {
		return nil, fmt.Errorf("itox: get session acl: %w", ErrUnauthorizedPeer)
	}
	
	friendID, err := t.tox.GetFriendByPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("itox: get session lookup: %w", err)
	}
	if t.tox.GetFriendConnectionStatus(friendID) == toxcore.ConnectionNone {
		return nil, fmt.Errorf("itox: get session status: %w", ErrPeerOffline)
	}

	t.mu.RLock()
	existing := t.sessions[pub]
	t.mu.RUnlock()
	if existing != nil {
		if err := t.waitHandshake(existing.remoteAddr); err != nil {
			return nil, err
		}
		return existing, nil
	}

	addr := ToxI2PAddr{PublicKey: pub}
	if err := t.noise.AddPeer(addr, pub[:]); err != nil {
		return nil, fmt.Errorf("itox: get session add peer: %w", err)
	}
	sess := t.newSession(addr, pub)
	if err := t.waitHandshake(addr); err != nil {
		t.removeSession(pub)
		_ = sess.Close()
		return nil, err
	}
	return sess, nil
}

func (t *ToxTransport) waitHandshake(addr net.Addr) error {
	ctx, cancel := context.WithTimeout(t.cfg.Context, t.cfg.RetryTimeout)
	defer cancel()
	// Build a minimal valid framing probe (streamID=0 marks keepalive/probe;
	// real stream IDs start at 1 so this is never confused with payload data).
	probeFrames, _ := fragmentMessage(0, nil)
	probe := &toxtransport.Packet{PacketType: toxtransport.PacketFriendMessage, Data: probeFrames[0]}
	for {
		err := t.noise.Send(probe, addr)
		if err == nil {
			return nil
		}
		if errors.Is(err, toxtransport.ErrRekeyRequired) {
			return fmt.Errorf("itox: handshake wait: %w", ErrSessionRekeyNeeded)
		}
		if !errors.Is(err, toxtransport.ErrNoiseSessionIncomplete) {
			return fmt.Errorf("itox: handshake wait: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("itox: handshake wait: %w", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Accept blocks waiting for an inbound Tox message.
// Extracts sender Tox public key from Noise-IK identity.
// Non-friends: close silently, log at slog.LevelDebug only, loop to next message.
// Returns only for authorized friends.
// The muxer's ensureAcceptLoop runs this in a persistent goroutine.
func (t *ToxTransport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.acceptCh:
		return conn, nil
	case <-t.closeCh:
		return nil, fmt.Errorf("itox: accept: transport closed")
	case <-t.cfg.Context.Done():
		return nil, fmt.Errorf("itox: accept: %w", t.cfg.Context.Err())
	}
}

// Addr returns the local ToxI2PAddr.
func (t *ToxTransport) Addr() net.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.local
}

// Close shuts down all active ToxSessions and the background friend-sync goroutine.
func (t *ToxTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closeCh)
		t.mu.Lock()
		for k, s := range t.sessions {
			_ = s.Close()
			delete(t.sessions, k)
		}
		t.mu.Unlock()
		if err := t.noise.Close(); err != nil {
			t.closeErr = fmt.Errorf("itox: close noise: %w", err)
		}
		close(t.closed)
	})
	return t.closeErr
}

func (t *ToxTransport) handleInboundPacket(packet *toxtransport.Packet, addr net.Addr) error {
	peer, ok := peerKeyFromAddr(addr)
	if !ok || !t.acl.IsAuthorized(peer) {
		// Per spec: Non-friends are dropped silently with debug-level logging only
		if ok {
			t.logger.Debug("itox: inbound packet from non-friend",
				slog.String("peer", hex.EncodeToString(peer[:8])),
			)
		}
		return nil
	}
	
	s := t.getOrCreateSession(addr, peer)
	if err := s.handleInboundPacket(packet); err != nil {
		return err
	}
	select {
	case t.acceptCh <- &toxConn{local: t.Addr(), remote: addr}:
	default:
	}
	return nil
}

func (t *ToxTransport) getOrCreateSession(addr net.Addr, peer [32]byte) *ToxSession {
	t.mu.RLock()
	s := t.sessions[peer]
	t.mu.RUnlock()
	if s != nil {
		return s
	}
	return t.newSession(addr, peer)
}

func (t *ToxTransport) newSession(addr net.Addr, peer [32]byte) *ToxSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing := t.sessions[peer]; existing != nil {
		return existing
	}
	s := newToxSession(t.cfg.Context, addr, t.noise, t.cfg.FragmentTimeout, t.cfg.RetryTimeout, t.cfg.MaxSendQueue, t.logger,
		func() { t.removeSession(peer) },
	)
	t.sessions[peer] = s
	return s
}

func (t *ToxTransport) removeSession(peer [32]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.sessions[peer]; s != nil {
		_ = s.Close()
		delete(t.sessions, peer)
	}
}

func peerKeyFromAddr(addr net.Addr) ([32]byte, bool) {
	if addr == nil {
		return [32]byte{}, false
	}
	if taddr, ok := addr.(ToxI2PAddr); ok {
		return taddr.PublicKey, true
	}
	raw, err := hex.DecodeString(addr.String())
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], raw)
	return out, true
}

func deriveLocalAddr(secret [32]byte) ToxI2PAddr {
	kp, err := toxcrypto.FromSecretKey(secret)
	if err == nil {
		return ToxI2PAddr{PublicKey: kp.Public}
	}
	// Best-effort fallback for malformed test keys.
	return ToxI2PAddr{PublicKey: secret}
}
