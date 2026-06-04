package itox

import (
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	MaxToxPayload   = 1300 // Tox message payload target after protocol overhead.
	frameHeaderSize = 6
)

type reassemblyState struct {
	createdAt time.Time
	total     uint16
	parts     map[uint16][]byte
}

type reassembler struct {
	timeout        time.Duration
	maxConcurrent  int
	now            func() time.Time
	mu             sync.Mutex
	streams        map[uint16]*reassemblyState
	reapCloseCh    chan struct{}
	reapDone       chan struct{}
}

func newReassembler(timeout time.Duration, maxConcurrent int) *reassembler {
	r := &reassembler{
		timeout:        timeout,
		maxConcurrent:  maxConcurrent,
		now:            time.Now,
		streams:        make(map[uint16]*reassemblyState),
		reapCloseCh:    make(chan struct{}),
		reapDone:       make(chan struct{}),
	}
	go r.backgroundReaper()
	return r
}

func fragmentMessage(streamID uint16, payload []byte) ([][]byte, error) {
	maxData := MaxToxPayload - frameHeaderSize
	if maxData <= 0 {
		return nil, fmt.Errorf("itox: fragment message: %w", ErrInvalidFrame)
	}
	if len(payload) == 0 {
		buf := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint16(buf[0:2], streamID)
		binary.BigEndian.PutUint16(buf[2:4], 0)
		binary.BigEndian.PutUint16(buf[4:6], 1)
		return [][]byte{buf}, nil
	}
	total := (len(payload) + maxData - 1) / maxData
	if total > int(^uint16(0)) {
		return nil, fmt.Errorf("itox: fragment message: too many fragments")
	}
	frames := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * maxData
		end := start + maxData
		if end > len(payload) {
			end = len(payload)
		}
		frame := make([]byte, frameHeaderSize+(end-start))
		binary.BigEndian.PutUint16(frame[0:2], streamID)
		binary.BigEndian.PutUint16(frame[2:4], uint16(i))
		binary.BigEndian.PutUint16(frame[4:6], uint16(total))
		copy(frame[6:], payload[start:end])
		frames = append(frames, frame)
	}
	return frames, nil
}

func parseFrame(frame []byte) (streamID, index, total uint16, payload []byte, err error) {
	if len(frame) < frameHeaderSize {
		return 0, 0, 0, nil, fmt.Errorf("itox: parse frame: %w", ErrInvalidFrame)
	}
	streamID = binary.BigEndian.Uint16(frame[0:2])
	index = binary.BigEndian.Uint16(frame[2:4])
	total = binary.BigEndian.Uint16(frame[4:6])
	if total == 0 || index >= total {
		return 0, 0, 0, nil, fmt.Errorf("itox: parse frame: %w", ErrInvalidFrame)
	}
	return streamID, index, total, frame[6:], nil
}

func (r *reassembler) addFrame(frame []byte) ([]byte, bool, error) {
	streamID, index, total, payload, err := parseFrame(frame)
	if err != nil {
		return nil, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	for sid, st := range r.streams {
		if now.Sub(st.createdAt) > r.timeout {
			delete(r.streams, sid)
		}
	}

	state := r.streams[streamID]
	if state == nil {
		// Check if adding a new stream would exceed the limit
		if len(r.streams) >= r.maxConcurrent {
			return nil, false, fmt.Errorf("itox: add frame: %w", ErrTooManyStreams)
		}
		state = &reassemblyState{createdAt: now, total: total, parts: map[uint16][]byte{}}
		r.streams[streamID] = state
	} else if now.Sub(state.createdAt) > r.timeout {
		// Expired reassembly; start fresh
		state = &reassemblyState{createdAt: now, total: total, parts: map[uint16][]byte{}}
		r.streams[streamID] = state
	} else if state.total != total {
		// Reject frame with mismatched total to prevent stream corruption
		return nil, false, fmt.Errorf("itox: add frame: total mismatch for stream %d (expected %d, got %d): %w", streamID, state.total, total, ErrInvalidFrame)
	}
	state.parts[index] = append([]byte(nil), payload...)

	if len(state.parts) != int(total) {
		return nil, false, nil
	}

	keys := make([]int, 0, len(state.parts))
	for idx := range state.parts {
		keys = append(keys, int(idx))
	}
	sort.Ints(keys)
	out := make([]byte, 0)
	for _, k := range keys {
		out = append(out, state.parts[uint16(k)]...)
	}
	delete(r.streams, streamID)
	return out, true, nil
}

func (r *reassembler) backgroundReaper() {
	defer close(r.reapDone)
	ticker := time.NewTicker(r.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-r.reapCloseCh:
			return
		case <-ticker.C:
			r.mu.Lock()
			now := r.now()
			for sid, st := range r.streams {
				if now.Sub(st.createdAt) > r.timeout {
					delete(r.streams, sid)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *reassembler) close() {
	close(r.reapCloseCh)
	<-r.reapDone
}

func (r *reassembler) isStreamActive(streamID uint16) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.streams[streamID]
	return exists
}
