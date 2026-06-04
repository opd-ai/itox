package itox

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// I2PStatus represents the I2P availability status of a Tox friend.
type I2PStatus struct {
	Available bool      `json:"available"`
	Timestamp time.Time `json:"timestamp"`
}

// StatusMessage is the wire format for I2P status announcements over Tox.
type StatusMessage struct {
	Type      string `json:"type"`      // Always "i2p_status"
	Available bool   `json:"available"` // Whether I2P transport is available
	Version   int    `json:"version"`   // Protocol version (currently 1)
}

const (
	statusMessageType    = "i2p_status"
	statusMessageVersion = 1
	statusTTL            = 5 * time.Minute // How long status remains valid without updates
)

// StatusRegistry tracks I2P availability status for Tox friends.
// It provides thread-safe access to peer availability information.
type StatusRegistry struct {
	mu       sync.RWMutex
	statuses map[[32]byte]I2PStatus
	logger   *slog.Logger
	now      func() time.Time
}

// NewStatusRegistry creates a new status registry.
func NewStatusRegistry(logger *slog.Logger) *StatusRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &StatusRegistry{
		statuses: make(map[[32]byte]I2PStatus),
		logger:   logger,
		now:      time.Now,
	}
}

// SetStatus updates the I2P availability status for a peer.
func (r *StatusRegistry) SetStatus(pubKey [32]byte, available bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses[pubKey] = I2PStatus{
		Available: available,
		Timestamp: r.now(),
	}
	r.logger.Debug("i2p status updated",
		slog.String("peer", string(pubKey[:8])),
		slog.Bool("available", available),
	)
}

// GetStatus returns the I2P availability status for a peer.
// Returns false if the peer has no status or the status has expired.
func (r *StatusRegistry) GetStatus(pubKey [32]byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status, ok := r.statuses[pubKey]
	if !ok {
		return false
	}
	// Check if status has expired
	if r.now().Sub(status.Timestamp) > statusTTL {
		return false
	}
	return status.Available
}

// ClearStatus removes the status for a peer (e.g., when they go offline or are removed).
func (r *StatusRegistry) ClearStatus(pubKey [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.statuses, pubKey)
	r.logger.Debug("i2p status cleared",
		slog.String("peer", string(pubKey[:8])),
	)
}

// PruneExpired removes expired status entries.
func (r *StatusRegistry) PruneExpired() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for pubKey, status := range r.statuses {
		if r.now().Sub(status.Timestamp) > statusTTL {
			delete(r.statuses, pubKey)
			count++
		}
	}
	if count > 0 {
		r.logger.Debug("pruned expired statuses", slog.Int("count", count))
	}
	return count
}

// Count returns the number of peers with active status.
func (r *StatusRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.statuses)
}

// EncodeStatusMessage encodes an I2P status announcement for transmission over Tox.
func EncodeStatusMessage(available bool) ([]byte, error) {
	msg := StatusMessage{
		Type:      statusMessageType,
		Available: available,
		Version:   statusMessageVersion,
	}
	return json.Marshal(msg)
}

// DecodeStatusMessage decodes an I2P status announcement from Tox.
func DecodeStatusMessage(data []byte) (*StatusMessage, error) {
	var msg StatusMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	if msg.Type != statusMessageType {
		return nil, ErrInvalidStatusMessage
	}
	if msg.Version != statusMessageVersion {
		return nil, ErrUnsupportedStatusVersion
	}
	return &msg, nil
}
