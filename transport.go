package itox

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	i2ptransport "github.com/go-i2p/go-i2p/lib/transport"
	"github.com/opd-ai/toxcore"
	toxcrypto "github.com/opd-ai/toxcore/crypto"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

const toxPubKeyOption = "tox-pubkey"

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

	acl      *FriendACL
	noise    transportNoise
	tox      friendStatus
	registry *StatusRegistry

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
	// Create StatusRegistry if StealthMode is enabled and not provided
	registry := cfg.StatusRegistry
	if cfg.StealthMode && registry == nil {
		registry = NewStatusRegistry(cfg.Logger)
	}
	t := &ToxTransport{
		cfg:      cfg,
		logger:   cfg.Logger,
		acl:      acl,
		noise:    noise,
		tox:      tox,
		registry: registry,
		sessions: make(map[[32]byte]*ToxSession),
		acceptCh: make(chan net.Conn, cfg.MaxSessions),
		closeCh:  make(chan struct{}),
		closed:   make(chan struct{}),
	}
	t.local = deriveLocalAddr(cfg.LocalSecretKey)
	noise.RegisterHandler(toxtransport.PacketFriendMessage, t.handleInboundPacket)
	go func() {
		<-cfg.Context.Done()
		_ = t.Close()
	}()
	return t, nil
}

func (t *ToxTransport) Name() string { return "tox" }

func (t *ToxTransport) Compatible(ri router_info.RouterInfo) bool {
	pub, ok := extractToxPubKey(ri)
	if !ok {
		return false
	}
	// In stealth mode, also check if peer has advertised I2P availability
	if t.cfg.StealthMode && t.registry != nil {
		return t.registry.GetStatus(pub)
	}
	return true
}

func (t *ToxTransport) SetIdentity(ri router_info.RouterInfo) error {
	pub, ok := extractToxPubKey(ri)
	if !ok {
		return fmt.Errorf("itox: set identity: missing tox pubkey")
	}
	t.mu.Lock()
	t.local = ToxI2PAddr{PublicKey: pub}
	t.mu.Unlock()
	return nil
}

func (t *ToxTransport) GetSession(ri router_info.RouterInfo) (i2ptransport.TransportSession, error) {
	pub, ok := extractToxPubKey(ri)
	if !ok {
		return nil, fmt.Errorf("itox: get session: router not compatible")
	}
	return t.getSessionByKey(pub)
}

// GetSessionByToxPubKey creates or retrieves a session for a Tox friend by public key.
// This method bypasses RouterInfo and is the primary path in stealth mode.
func (t *ToxTransport) GetSessionByToxPubKey(pubKey [32]byte) (i2ptransport.TransportSession, error) {
	return t.getSessionByKey(pubKey)
}

func (t *ToxTransport) getSessionByKey(pub [32]byte) (i2ptransport.TransportSession, error) {
	if !t.acl.IsAuthorized(pub) {
		return nil, fmt.Errorf("itox: get session acl: %w", ErrUnauthorizedPeer)
	}
	// In stealth mode, check if peer has advertised I2P availability
	if t.cfg.StealthMode && t.registry != nil {
		if !t.registry.GetStatus(pub) {
			return nil, fmt.Errorf("itox: get session: %w", ErrPeerNotAdvertising)
		}
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

func (t *ToxTransport) Addr() net.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.local
}

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
		return nil
	}
	
	// Check if this is a status message (magic prefix: statusMagicPrefix)
	if len(packet.Data) > 3 && 
	   packet.Data[0] == statusMagicByte1 && 
	   packet.Data[1] == statusMagicByte2 && 
	   packet.Data[2] == statusMagicByte3 {
		return t.handleStatusMessage(peer, packet.Data[3:])
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

// BroadcastI2PStatus sends an I2P availability announcement to all Tox friends.
// This should be called when the transport starts and when I2P status changes.
func (t *ToxTransport) BroadcastI2PStatus(available bool) error {
	if t.tox == nil || t.cfg.Tox == nil {
		return fmt.Errorf("itox: broadcast status: tox not available")
	}
	statusData, err := EncodeStatusMessage(available)
	if err != nil {
		return fmt.Errorf("itox: encode status message: %w", err)
	}
	
	// Prefix status messages with magic marker to distinguish from I2NP data
	statusPacket := append(statusMagicPrefix, statusData...)
	
	friends := t.cfg.Tox.GetFriends()
	sent := 0
	for friendID := range friends {
		friendPubKey, err := t.tox.GetFriendPublicKey(friendID)
		if err != nil {
			continue
		}
		addr := ToxI2PAddr{PublicKey: friendPubKey}
		packet := &toxtransport.Packet{
			PacketType: toxtransport.PacketFriendMessage,
			Data:       statusPacket,
		}
		if err := t.noise.Send(packet, addr); err != nil {
			t.logger.Debug("failed to send i2p status to friend",
				slog.Uint64("friend_id", uint64(friendID)),
				slog.Any("error", err),
			)
			continue
		}
		sent++
	}
	
	t.logger.Info("broadcast i2p status",
		slog.Bool("available", available),
		slog.Int("sent", sent),
		slog.Int("total_friends", len(friends)),
	)
	return nil
}

// handleStatusMessage processes an incoming I2P status announcement from a friend.
// This is called from handleInboundPacket when a status message is detected.
func (t *ToxTransport) handleStatusMessage(peer [32]byte, data []byte) error {
	if t.registry == nil {
		return nil // Status messages not used in non-stealth mode
	}
	
	msg, err := DecodeStatusMessage(data)
	if err != nil {
		t.logger.Debug("failed to decode status message",
			slog.String("peer", formatPeerID(peer)),
			slog.Any("error", err),
		)
		return err
	}
	
	t.registry.SetStatus(peer, msg.Available)
	t.logger.Info("received i2p status",
		slog.String("peer", formatPeerID(peer)),
		slog.Bool("available", msg.Available),
	)
	return nil
}

func extractToxPubKey(ri router_info.RouterInfo) ([32]byte, bool) {
	for _, addr := range ri.RouterAddresses() {
		style, err := addr.TransportStyle().Data()
		if err != nil || !strings.EqualFold(style, "tox") {
			continue
		}
		key, ok := mappingValue(addr.Options(), toxPubKeyOption)
		if !ok {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			continue
		}
		var pub [32]byte
		copy(pub[:], decoded)
		return pub, true
	}
	return [32]byte{}, false
}

func mappingValue(m data.Mapping, key string) (string, bool) {
	ik, err := data.ToI2PString(key)
	if err != nil {
		return "", false
	}
	v := m.Values().Get(ik)
	if v == nil {
		return "", false
	}
	s, err := v.Data()
	if err != nil {
		return "", false
	}
	return s, true
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
