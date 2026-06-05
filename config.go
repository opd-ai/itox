package itox

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/opd-ai/toxcore"
)

const (
	// defaultFragmentTimeout is the duration a reassembler waits for missing fragments
	// before discarding an incomplete message. 30 seconds allows ~66KB messages at 2KB/s rate.
	defaultFragmentTimeout = 30 * time.Second
	
	// defaultRetryTimeout bounds the total time spent retrying Noise session sends/handshake probes
	// before giving up. Individual retries use exponential backoff capped at 500ms.
	defaultRetryTimeout = 10 * time.Second
	
	defaultMaxSessions           = 256
	defaultMaxSendQueue          = 128
	defaultMaxConcurrentStreams  = 256
	
	// defaultFriendSyncInterval is how often the transport checks the Tox friend list
	// to update which peers are reachable. 30 seconds provides timely friend removal detection.
	defaultFriendSyncInterval = 30 * time.Second
)

type Config struct {
	Tox                     *toxcore.Tox
	LocalSecretKey          [32]byte
	LocalRouterInfo         router_info.RouterInfo
	FragmentTimeout         time.Duration
	RetryTimeout            time.Duration
	MaxSessions             int
	MaxSendQueue            int
	MaxConcurrentStreams    int
	FriendSyncInterval      time.Duration
	Context                 context.Context
	Logger                  *slog.Logger
}

// DefaultConfig returns a Config struct with all required fields populated and
// reasonable default values. The Context is set to context.Background() and Logger to slog.Default().
// Callers may override these defaults after creation if needed.
func DefaultConfig(tox *toxcore.Tox, secretKey [32]byte, ri router_info.RouterInfo) Config {
	return Config{
		Tox:                    tox,
		LocalSecretKey:         secretKey,
		LocalRouterInfo:        ri,
		FragmentTimeout:        defaultFragmentTimeout,
		RetryTimeout:           defaultRetryTimeout,
		MaxSessions:            defaultMaxSessions,
		MaxSendQueue:           defaultMaxSendQueue,
		MaxConcurrentStreams:   defaultMaxConcurrentStreams,
		FriendSyncInterval:     defaultFriendSyncInterval,
		Context:                context.Background(),
		Logger:                 slog.Default(),
	}
}

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("itox: validate config: %w", ErrInvalidConfig)
	}
	if c.Tox == nil {
		return fmt.Errorf("itox: validate config: tox is nil: %w", ErrInvalidConfig)
	}
	c.populateDefaults()
	return nil
}

// populateDefaults fills in missing or zero-valued fields with sensible defaults.
func (c *Config) populateDefaults() {
	if c.Context == nil {
		c.Context = context.Background()
	}
	if c.FragmentTimeout <= 0 {
		c.FragmentTimeout = defaultFragmentTimeout
	}
	if c.RetryTimeout <= 0 {
		c.RetryTimeout = defaultRetryTimeout
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = defaultMaxSessions
	}
	if c.MaxSendQueue <= 0 {
		c.MaxSendQueue = defaultMaxSendQueue
	}
	if c.MaxConcurrentStreams <= 0 {
		c.MaxConcurrentStreams = defaultMaxConcurrentStreams
	}
	if c.FriendSyncInterval <= 0 {
		c.FriendSyncInterval = defaultFriendSyncInterval
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}
