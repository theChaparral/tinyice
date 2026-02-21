package relay

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Relay manages all active streams
type Relay struct {
	Streams    map[string]*Stream
	mu         sync.RWMutex
	LowLatency bool
	BytesIn    int64
	BytesOut   int64
	History    *HistoryManager
}

func NewRelay(lowLatency bool, history *HistoryManager) *Relay {
	return &Relay{
		Streams:    make(map[string]*Stream),
		LowLatency: lowLatency,
		History:    history,
	}
}

// GetOrCreateStream returns an existing stream or creates a new one
func (r *Relay) GetOrCreateStream(mount string) *Stream {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.Streams[mount]; ok {
		return s
	}

	s := &Stream{
		MountName:   mount,
		listeners:   make(map[string]chan struct{}),
		Buffer:      NewCircularBuffer(512 * 1024), // 2MB shared buffer per stream
		Started:     time.Now(),
		Name:        "Unnamed Stream",
		Description: "No description",
		Genre:       "N/A",
		Bitrate:     "N/A",
		ContentType: "audio/mpeg",
		IsOggStream: false,
		Enabled:     true,
		CurrentSong: "N/A",
		PageOffsets: make([]int64, 128), // Track last 128 Ogg pages
	}
	r.Streams[mount] = s
	return s
}

// RemoveStream deletes a stream (e.g., when source disconnects)
func (r *Relay) RemoveStream(mount string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.Streams[mount]; ok {
		s.Close()
		delete(r.Streams, mount)
	}
}

func (r *Relay) GetStreamVisibility(mount string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.Streams[mount]; ok {
		return s.Visible
	}
	return false
}

// GetStream safely retrieves a stream
func (r *Relay) GetStream(mount string) (*Stream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.Streams[mount]
	return s, ok
}

func (r *Relay) UpdateMetadata(mount, song string) {
	st := r.GetOrCreateStream(mount)
	st.SetCurrentSong(song, r)
}

// DisconnectAllListeners kicks all listeners from all active streams
func (r *Relay) DisconnectAllListeners() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.Streams {
		s.DisconnectListeners()
	}
}

// GetMetrics returns the current bandwidth usage since start
func (r *Relay) GetMetrics() (int64, int64) {
	return atomic.LoadInt64(&r.BytesIn), atomic.LoadInt64(&r.BytesOut)
}

// Snapshot returns a safe copy of all current streams
func (r *Relay) Snapshot() []StreamStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	streams := make([]StreamStats, 0, len(r.Streams))
	for _, s := range r.Streams {
		streams = append(streams, s.Snapshot())
	}

	// Sort by start time, newest first
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].Started.After(streams[j].Started)
	})

	return streams
}
