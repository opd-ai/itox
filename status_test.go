package itox

import (
	"testing"
	"time"
)

func TestStatusRegistry_SetAndGet(t *testing.T) {
	reg := NewStatusRegistry(nil)
	var key [32]byte
	key[0] = 1

	// Initially no status
	if reg.GetStatus(key) {
		t.Error("expected false for peer with no status")
	}

	// Set available
	reg.SetStatus(key, true)
	if !reg.GetStatus(key) {
		t.Error("expected true after setting available")
	}

	// Set unavailable
	reg.SetStatus(key, false)
	if reg.GetStatus(key) {
		t.Error("expected false after setting unavailable")
	}
}

func TestStatusRegistry_Clear(t *testing.T) {
	reg := NewStatusRegistry(nil)
	var key [32]byte
	key[0] = 1

	reg.SetStatus(key, true)
	if !reg.GetStatus(key) {
		t.Error("expected status to be set")
	}

	reg.ClearStatus(key)
	if reg.GetStatus(key) {
		t.Error("expected false after clearing status")
	}
}

func TestStatusRegistry_Expiration(t *testing.T) {
	reg := NewStatusRegistry(nil)
	var key [32]byte
	key[0] = 1

	// Mock time
	now := time.Now()
	reg.now = func() time.Time { return now }

	reg.SetStatus(key, true)
	if !reg.GetStatus(key) {
		t.Error("expected status to be available")
	}

	// Advance time past TTL
	reg.now = func() time.Time { return now.Add(statusTTL + time.Second) }

	if reg.GetStatus(key) {
		t.Error("expected false for expired status")
	}
}

func TestStatusRegistry_PruneExpired(t *testing.T) {
	reg := NewStatusRegistry(nil)
	
	var key1, key2, key3 [32]byte
	key1[0] = 1
	key2[0] = 2
	key3[0] = 3

	now := time.Now()
	reg.now = func() time.Time { return now }

	// Set multiple statuses
	reg.SetStatus(key1, true)
	reg.SetStatus(key2, true)
	reg.SetStatus(key3, true)

	if reg.Count() != 3 {
		t.Errorf("expected count 3, got %d", reg.Count())
	}

	// Advance time to expire some entries
	reg.now = func() time.Time { return now.Add(statusTTL + time.Second) }

	pruned := reg.PruneExpired()
	if pruned != 3 {
		t.Errorf("expected 3 pruned entries, got %d", pruned)
	}
	if reg.Count() != 0 {
		t.Errorf("expected count 0 after pruning, got %d", reg.Count())
	}
}

func TestStatusRegistry_Count(t *testing.T) {
	reg := NewStatusRegistry(nil)
	
	if reg.Count() != 0 {
		t.Error("expected initial count 0")
	}

	var key1, key2 [32]byte
	key1[0] = 1
	key2[0] = 2

	reg.SetStatus(key1, true)
	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}

	reg.SetStatus(key2, false)
	if reg.Count() != 2 {
		t.Errorf("expected count 2, got %d", reg.Count())
	}

	reg.ClearStatus(key1)
	if reg.Count() != 1 {
		t.Errorf("expected count 1 after clear, got %d", reg.Count())
	}
}

func TestEncodeDecodeStatusMessage(t *testing.T) {
	tests := []struct {
		name      string
		available bool
	}{
		{"available", true},
		{"unavailable", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeStatusMessage(tt.available)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			msg, err := DecodeStatusMessage(data)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}

			if msg.Type != statusMessageType {
				t.Errorf("wrong type: got %s, want %s", msg.Type, statusMessageType)
			}
			if msg.Version != statusMessageVersion {
				t.Errorf("wrong version: got %d, want %d", msg.Version, statusMessageVersion)
			}
			if msg.Available != tt.available {
				t.Errorf("wrong available: got %v, want %v", msg.Available, tt.available)
			}
		})
	}
}

func TestDecodeStatusMessage_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"invalid json", []byte("not json")},
		{"wrong type", []byte(`{"type":"other","available":true,"version":1}`)},
		{"wrong version", []byte(`{"type":"i2p_status","available":true,"version":999}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeStatusMessage(tt.data)
			if err == nil {
				t.Error("expected error for invalid data")
			}
		})
	}
}

func TestStatusRegistry_Concurrent(t *testing.T) {
	reg := NewStatusRegistry(nil)
	var key [32]byte
	key[0] = 1

	done := make(chan bool)
	
	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			reg.SetStatus(key, i%2 == 0)
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = reg.GetStatus(key)
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Wait for both
	<-done
	<-done
}
