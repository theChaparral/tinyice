package relay

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Stream represents a single mount point (e.g., /stream)
type Stream struct {
	MountName   string
	ContentType string
	Description string
	Genre       string
	URL         string
	Name        string
	Bitrate     string
	Started     time.Time
	SourceIP    string
	Enabled     bool
	BytesIn     int64
	BytesOut    int64
	CurrentSong string
	Public      bool
	Hidden      bool

	listeners map[string]chan []byte // Map of listener ID to their data channel
	mu        sync.RWMutex
	
	// Burst buffer (simple ring buffer or just a slice of recent chunks)
	// We'll store the last N chunks for simplicity to start with.
	burstBuffer [][]byte
	burstSize   int
}

// Relay manages all active streams
type Relay struct {
	Streams    map[string]*Stream
	mu         sync.RWMutex
	LowLatency bool
	BytesIn    int64
	BytesOut   int64
}

func NewRelay(lowLatency bool) *Relay {
	return &Relay{
		Streams:    make(map[string]*Stream),
		LowLatency: lowLatency,
	}
}

// GetOrCreateStream returns an existing stream or creates a new one
func (r *Relay) GetOrCreateStream(mount string) *Stream {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.Streams[mount]; ok {
		return s
	}

	burstSize := 20
	if r.LowLatency {
		burstSize = 0 // Disable burst for lowest latency
	}

	s := &Stream{
		MountName:   mount,
		listeners:   make(map[string]chan []byte),
		burstBuffer: make([][]byte, 0, 10),
		burstSize:   burstSize,
		Started:     time.Now(),
		Name:        "Unnamed Stream",
		Description: "No description",
		Genre:       "N/A",
		Bitrate:     "N/A",
		ContentType: "audio/mpeg",
		Enabled:     true,
		CurrentSong: "N/A",
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

// GetStream safely retrieves a stream
func (r *Relay) GetStream(mount string) (*Stream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.Streams[mount]
	return s, ok
}

// Close closes all listeners on the stream
func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.listeners {
		close(ch)
		delete(s.listeners, id)
	}
}

// DisconnectListeners specifically kicks all listeners without closing the stream
func (s *Stream) DisconnectListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.listeners {
		close(ch)
		delete(s.listeners, id)
	}
}

// DisconnectAllListeners kicks all listeners from all active streams
func (r *Relay) DisconnectAllListeners() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.Streams {
		s.DisconnectListeners()
	}
}

// Broadcast sends data to all listeners and updates the burst buffer
func (s *Stream) Broadcast(data []byte, relay *Relay) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update Metrics (Incoming)
	atomic.AddInt64(&relay.BytesIn, int64(len(data)))
	atomic.AddInt64(&s.BytesIn, int64(len(data)))

	// 1. Update Burst Buffer (if enabled)
	// Make a copy of data to avoid race conditions if the source reuses the buffer
	chunk := make([]byte, len(data))
	copy(chunk, data)
	
	if s.burstSize > 0 {
		if len(s.burstBuffer) >= s.burstSize {
			// Remove oldest
			s.burstBuffer = s.burstBuffer[1:]
		}
		s.burstBuffer = append(s.burstBuffer, chunk)
	}

	// 2. Send to listeners
	for _, ch := range s.listeners {
		select {
		case ch <- chunk:
			// Success
			atomic.AddInt64(&relay.BytesOut, int64(len(chunk)))
			atomic.AddInt64(&s.BytesOut, int64(len(chunk)))
		default:
			// Listener is too slow
		}
	}
}

// GetMetrics returns the current bandwidth usage since start
func (r *Relay) GetMetrics() (int64, int64) {
	return atomic.LoadInt64(&r.BytesIn), atomic.LoadInt64(&r.BytesOut)
}

// Subscribe adds a listener and returns a channel that receives data
// It also returns the burst data to send immediately.
func (s *Stream) Subscribe(id string) (<-chan []byte, [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Buffer channel to avoid immediate blocking
	ch := make(chan []byte, 100) 
	s.listeners[id] = ch

	// Return current burst buffer to send immediately
	// We return a copy of the slice header, but the underlying arrays are immutable (we copied them in Broadcast)
	currentBurst := make([][]byte, len(s.burstBuffer))
	copy(currentBurst, s.burstBuffer)

	return ch, currentBurst
}


// Unsubscribe removes a listener
func (s *Stream) Unsubscribe(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.listeners[id]; ok {
		close(ch)
		delete(s.listeners, id)
	}
}

// UpdateMetadata updates stream info
func (s *Stream) UpdateMetadata(name, desc, genre, url, bitrate, contentType string, public, hidden bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name != "" {
		s.Name = name
	}
	if desc != "" {
		s.Description = desc
	}
	if genre != "" {
		s.Genre = genre
	}
	if url != "" {
		s.URL = url
	}
	if bitrate != "" {
		s.Bitrate = bitrate
	}
	if contentType != "" {
		s.ContentType = contentType
	}
	s.Public = public
	s.Hidden = hidden
}

// SetCurrentSong updates the current song info thread-safely
func (s *Stream) SetCurrentSong(song string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentSong = song
}

// SetHidden updates the visibility of the stream thread-safely
func (s *Stream) SetHidden(hidden bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Hidden = hidden
}

// SetBurstSize updates the burst buffer size thread-safely
func (s *Stream) SetBurstSize(size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.burstSize = size
}

// ListenersCount returns the number of active listeners
func (s *Stream) ListenersCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.listeners)
}

// StreamStats is a point-in-time snapshot of a stream for the UI
type StreamStats struct {
	MountName      string
	ContentType    string
	Description    string
	Genre          string
	URL            string
	Name           string
	Bitrate        string
	Started        time.Time
	SourceIP       string
	Enabled        bool
	BytesIn        int64
	BytesOut       int64
	CurrentSong    string
	Public         bool
	Hidden         bool
	ListenersCount int
	Uptime         string
}

// Snapshot returns a point-in-time copy of the stream's state
func (s *Stream) Snapshot() StreamStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return StreamStats{
		MountName:      s.MountName,
		ContentType:    s.ContentType,
		Description:    s.Description,
		Genre:          s.Genre,
		URL:            s.URL,
		Name:           s.Name,
		Bitrate:        s.Bitrate,
		Started:        s.Started,
		SourceIP:       s.SourceIP,
		Enabled:        s.Enabled,
		BytesIn:        atomic.LoadInt64(&s.BytesIn),
		BytesOut:       atomic.LoadInt64(&s.BytesOut),
		CurrentSong:    s.CurrentSong,
		Public:         s.Public,
		Hidden:         s.Hidden,
		ListenersCount: len(s.listeners),
		Uptime:         s.uptimeLocked(), // We need a non-locked version of uptime
	}
}

// uptimeLocked returns the formatted uptime string assuming the lock is already held
func (s *Stream) uptimeLocked() string {
	d := time.Since(s.Started).Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s_ := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s_)
}

// Uptime returns the duration since the stream started
func (s *Stream) Uptime() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.uptimeLocked()
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

