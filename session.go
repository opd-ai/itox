package itox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-i2p/lib/i2np"
	toxtransport "github.com/opd-ai/toxcore/transport"
)

type noiseSender interface {
	Send(packet *toxtransport.Packet, addr net.Addr) error
}

type ToxSession struct {
	ctx context.Context

	remoteAddr net.Addr
	noise      noiseSender
	logger     *slog.Logger

	retryTimeout time.Duration
	reassembler  *reassembler

	inbound  chan i2np.Message
	sendQ    chan i2np.Message
	closing  chan struct{}
	closed   chan struct{}
	closeMu  sync.Mutex
	streamMu sync.Mutex
	streamID uint16

	onRekey func()
}

func newToxSession(ctx context.Context, remoteAddr net.Addr, noise noiseSender, fragmentTimeout time.Duration, retryTimeout time.Duration, maxSendQueue int, maxConcurrentStreams int, logger *slog.Logger, onRekey func()) *ToxSession {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s := &ToxSession{
		ctx:          ctx,
		remoteAddr:   remoteAddr,
		noise:        noise,
		logger:       logger,
		retryTimeout: retryTimeout,
		reassembler:  newReassembler(fragmentTimeout, maxConcurrentStreams),
		inbound:      make(chan i2np.Message, maxSendQueue),
		sendQ:        make(chan i2np.Message, maxSendQueue),
		closing:      make(chan struct{}),
		closed:       make(chan struct{}),
		streamID:     1,
		onRekey:      onRekey,
	}
	go s.sendLoop()
	return s
}

// QueueSendI2NP enqueues an I2NP message to be sent through this session.
// Returns ErrSessionClosed if the session is closed, or ErrSendQueueFull if the send queue is full.
func (s *ToxSession) QueueSendI2NP(msg i2np.Message) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	select {
	case <-s.closing:
		return fmt.Errorf("itox: queue send i2np: %w", ErrSessionClosed)
	default:
	}
	select {
	case s.sendQ <- msg:
		return nil
	default:
		return fmt.Errorf("itox: queue send i2np: %w", ErrSendQueueFull)
	}
}

// SendQueueSize returns the current number of I2NP messages waiting in the send queue.
func (s *ToxSession) SendQueueSize() int { return len(s.sendQ) }

// ReadNextI2NP blocks until an I2NP message arrives on this session.
// Returns ErrSessionClosed if the session is closed before a message arrives.
func (s *ToxSession) ReadNextI2NP() (i2np.Message, error) {
	select {
	case msg, ok := <-s.inbound:
		if !ok {
			return nil, fmt.Errorf("itox: read next i2np: %w", ErrSessionClosed)
		}
		return msg, nil
	case <-s.closed:
		return nil, fmt.Errorf("itox: read next i2np: %w", ErrSessionClosed)
	}
}

// Close terminates this session and cleans up resources.
func (s *ToxSession) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	select {
	case <-s.closing:
	default:
		close(s.closing)
		close(s.sendQ)
	}
	<-s.closed
	s.reassembler.close()
	return nil
}

func (s *ToxSession) nextStreamID() uint16 {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	// Skip stream ID 0 (reserved for keepalive) and any stream IDs still being reassembled
	attempts := 0
	for attempts < 1000 {
		s.streamID++
		if s.streamID == 0 {
			s.streamID = 1
		}
		// Avoid reusing stream IDs that are still being reassembled
		if !s.reassembler.isStreamActive(s.streamID) {
			return s.streamID
		}
		attempts++
	}
	// If we can't find an unused ID after 1000 attempts, log a warning and return the next one.
	// This shouldn't happen in practice with 65536 possible IDs unless there's
	// a massive number of concurrent slow reassemblies.
	s.logger.Warn("nextStreamID fallback after 1000 attempts; using potentially active stream ID",
		"streamID", s.streamID,
		"attempts", attempts)
	return s.streamID
}

func (s *ToxSession) sendLoop() {
	defer s.reassembler.close()
	defer close(s.inbound) // closed second: safe after s.closed signals shutdown
	defer close(s.closed)  // closed first: stops handleInboundPacket before inbound is closed
	for {
		select {
		case <-s.ctx.Done():
			// Context canceled; stop processing
			return
		case msg, ok := <-s.sendQ:
			if !ok {
				// Channel closed; normal shutdown
				return
			}
			if msg == nil {
				continue
			}
			encoded, err := msg.MarshalBinary()
			if err != nil {
				s.logger.Error("marshal i2np failed", slog.Any("error", err))
				continue
			}
			frames, err := fragmentMessage(s.nextStreamID(), encoded)
			if err != nil {
				s.logger.Error("fragment i2np failed", slog.Any("error", err))
				continue
			}
			for _, frame := range frames {
				if err := s.sendWithRetry(frame); err != nil {
					s.logger.Error("send frame failed", slog.Any("error", err))
					break
				}
			}
		}
	}
}

func (s *ToxSession) sendWithRetry(frame []byte) error {
	packet := &toxtransport.Packet{PacketType: toxtransport.PacketFriendMessage, Data: frame}
	ctx, cancel := context.WithTimeout(s.ctx, s.retryTimeout)
	defer cancel()
	backoff := 20 * time.Millisecond

	for {
		err := s.noise.Send(packet, s.remoteAddr)
		if err == nil {
			return nil
		}
		if errors.Is(err, toxtransport.ErrRekeyRequired) {
			if s.onRekey != nil {
				s.onRekey()
			}
			return fmt.Errorf("itox: send retry: %w", ErrSessionRekeyNeeded)
		}
		if !errors.Is(err, toxtransport.ErrNoiseSessionIncomplete) {
			return fmt.Errorf("itox: send retry: %w", err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("itox: send retry timeout: %w", ctx.Err())
		case <-time.After(backoff):
			backoff = time.Duration(math.Min(float64(backoff*2), float64(500*time.Millisecond)))
		}
	}
}

func (s *ToxSession) handleInboundPacket(packet *toxtransport.Packet) error {
	if packet == nil {
		return fmt.Errorf("itox: handle inbound: nil packet")
	}
	payload, complete, err := s.reassembler.addFrame(packet.Data)
	if err != nil {
		return fmt.Errorf("itox: handle inbound frame: %w", err)
	}
	if !complete {
		return nil
	}
	if len(payload) == 0 {
		return nil // discard keepalive/probe frames that carry no I2NP payload
	}
	msg := i2np.NewI2NPMessage(0)
	if err := msg.UnmarshalBinary(payload); err != nil {
		return fmt.Errorf("itox: parse i2np: %w", err)
	}
	select {
	case s.inbound <- msg:
		return nil
	case <-s.closed:
		return fmt.Errorf("itox: inbound session closed: %w", ErrSessionClosed)
	}
}
