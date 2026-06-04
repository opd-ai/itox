package itox

import (
	"bytes"
	"testing"
	"time"
)

func TestFragmentRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, MaxToxPayload*2+137)
	frames, err := fragmentMessage(7, payload)
	if err != nil {
		t.Fatalf("fragment failed: %v", err)
	}
	if len(frames) < 2 {
		t.Fatalf("expected fragmented payload, got %d frame(s)", len(frames))
	}

	r := newReassembler(30*time.Second, 256)
	defer r.close()
	var out []byte
	for _, f := range frames {
		joined, complete, err := r.addFrame(f)
		if err != nil {
			t.Fatalf("reassemble failed: %v", err)
		}
		if complete {
			out = joined
		}
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(out), len(payload))
	}
}

func TestParseFrameValidation(t *testing.T) {
	if _, _, _, _, err := parseFrame([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected short-frame error")
	}
	bad := make([]byte, 6)
	bad[3] = 5 // index=5, total=0
	if _, _, _, _, err := parseFrame(bad); err == nil {
		t.Fatal("expected invalid frame error")
	}
}

func TestReassemblerExpiresStaleFragments(t *testing.T) {
	r := newReassembler(10*time.Millisecond, 256)
	defer r.close()

	frames, err := fragmentMessage(9, bytes.Repeat([]byte{1}, MaxToxPayload))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.addFrame(frames[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, complete, err := r.addFrame(frames[1]); err != nil {
		t.Fatal(err)
	} else if complete {
		t.Fatal("expected incomplete after expiration reset")
	}
}
