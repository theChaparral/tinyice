package server

import (
	"context"
	"sync"
	"testing"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/relay"
)

// TestRegisterHLSConcurrent verifies that two parallel first-listener
// requests for the same mount don't each spawn a segmentLoop goroutine.
// Without the lock-then-check pattern in RegisterHLS, each goroutine
// built+started its own HLSOutput before atomically overwriting the
// other in s.hlsOutputs — the loser's goroutine ran forever, leaked.
func TestRegisterHLSConcurrent(t *testing.T) {
	r := relay.NewRelay(false, nil)
	stream := r.GetOrCreateStream("/test-hls-race")
	stream.ContentType = "audio/mpeg"

	hlsCtx, hlsCancel := context.WithCancel(context.Background())
	defer hlsCancel()

	s := &Server{
		Config:     &config.Config{},
		Relay:      r,
		hlsOutputs: make(map[string]*relay.HLSOutput),
		hlsCtx:     hlsCtx,
	}

	// 32 racers attempting to register the same mount.
	const racers = 32
	var wg sync.WaitGroup
	results := make([]*relay.HLSOutput, racers)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = s.RegisterHLS("/test-hls-race")
		}(i)
	}
	wg.Wait()

	// Every racer should have received the same singleton.
	first := results[0]
	if first == nil {
		t.Fatal("RegisterHLS returned nil")
	}
	for i, h := range results {
		if h != first {
			t.Fatalf("racer %d got a different HLSOutput than racer 0 — duplicate Start was called, leaking a goroutine", i)
		}
	}

	// And the map must have exactly one entry.
	s.hlsMu.RLock()
	count := len(s.hlsOutputs)
	s.hlsMu.RUnlock()
	if count != 1 {
		t.Fatalf("expected 1 hlsOutputs entry, got %d", count)
	}

	s.UnregisterHLS("/test-hls-race")
}
