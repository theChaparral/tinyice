package relay

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CircularBuffer is a thread-safe fixed-size ring buffer for stream data
type CircularBuffer struct {
	Data []byte
	Size int64
	Head int64 // Current write position (absolute)
	mu   sync.RWMutex
}

func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		Data: make([]byte, size),
		Size: int64(size),
	}
}

func (cb *CircularBuffer) Write(p []byte) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	for len(p) > 0 {
		pos := cb.Head % cb.Size
		n := copy(cb.Data[pos:], p)
		cb.Head += int64(n)
		p = p[n:]
	}
}

// ReadAt reads data from the buffer starting at the absolute offset 'start'
func (cb *CircularBuffer) ReadAt(start int64, p []byte) (int, int64, bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	skipped := false
	if start >= cb.Head {
		return 0, start, false
	}

	// Don't read more than we have or what's available in the buffer
	if cb.Head-start > cb.Size {
		start = cb.Head - cb.Size // Listener is too slow, skip to oldest available
		skipped = true
	}

	pos := start % cb.Size
	available := cb.Head - start
	n := int64(len(p))
	if n > available {
		n = available
	}

	// Handle wrap-around
	if pos+n > cb.Size {
		n = cb.Size - pos
	}

	actual := copy(p, cb.Data[pos:pos+n])
	return actual, start + int64(actual), skipped
}

// FindNextPageBoundary searches for the next "OggS" magic in the buffer starting from 'start'
func (cb *CircularBuffer) FindNextPageBoundary(start int64) int64 {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if start < cb.Head-cb.Size {
		start = cb.Head - cb.Size
	}
	if start >= cb.Head-4 {
		return cb.Head
	}

	for i := start; i < cb.Head-4; {
		pos := i % cb.Size
		n := int64(4096) // Search window
		if i+n > cb.Head {
			n = cb.Head - i
		}
		if pos+n > cb.Size {
			n = cb.Size - pos
		}

		// Look for OggS in this segment
		data := cb.Data[pos : pos+n]
		for j := 0; j <= len(data)-4; j++ {
			if data[j] == 'O' && data[j+1] == 'g' && data[j+2] == 'g' && data[j+3] == 'S' {
				return i + int64(j)
			}
		}
		i += n - 3 // Overlap by 3 bytes to catch split magic
	}
	return start
}

// Stream represents a single mount point (e.g., /stream)
type Stream struct {
	MountName    string
	ContentType  string
	Description  string
	Genre        string
	URL          string
	Name         string
	Bitrate      string
	Started      time.Time
	SourceIP     string
	Enabled      bool
	BytesIn      int64
	BytesOut     int64
	BytesDropped int64 // Track total bytes dropped due to slow listeners
	CurrentSong  string
	Public       bool
	Visible      bool
	IsTranscoded bool // True if this stream is an output of a transcoder

	LastDataReceived time.Time

	OggHead         []byte // Store Ogg headers for Opus/Ogg streams
	OggHeaderOffset int64  // Absolute buffer offset where headers end
	LastPageOffset  int64  // Absolute offset of the last valid Ogg page start

	Buffer    *CircularBuffer
	listeners map[string]chan struct{} // Signal channel for new data
	mu        sync.RWMutex
}

// StreamReader wraps a signal-based stream subscription into an io.Reader
type StreamReader struct {
	Stream *Stream
	Offset int64
	Signal chan struct{}
	Ctx    context.Context
	ID     string
}

func (r *StreamReader) Read(p []byte) (int, error) {
	for {
		n, next, _ := r.Stream.Buffer.ReadAt(r.Offset, p)
		if n > 0 {
			r.Offset = next
			return n, nil
		}

		select {
		case <-r.Ctx.Done():
			return 0, io.EOF
		case _, ok := <-r.Signal:
			if !ok {
				return 0, io.EOF
			}
		}
	}
}

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
		Buffer:      NewCircularBuffer(512 * 1024), // 512KB shared buffer per stream
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

// Broadcast sends data to all listeners via the shared circular buffer
func (s *Stream) Broadcast(data []byte, relay *Relay) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastDataReceived = time.Now()

	// Update Metrics (Incoming)
	atomic.AddInt64(&relay.BytesIn, int64(len(data)))
	atomic.AddInt64(&s.BytesIn, int64(len(data)))

	// Track Ogg Page boundaries for alignment
	isOgg := strings.Contains(strings.ToLower(s.ContentType), "ogg") || strings.Contains(strings.ToLower(s.ContentType), "opus")
	if isOgg {
		for i := 0; i <= len(data)-4; i++ {
			if data[i] == 'O' && data[i+1] == 'g' && data[i+2] == 'g' && data[i+3] == 'S' {
				s.LastPageOffset = s.Buffer.Head + int64(i)
			}
		}
	}

	// 1. Write to shared buffer
	s.Buffer.Write(data)

	// 2. Signal all listeners that new data is available
	for _, ch := range s.listeners {
		select {
		case ch <- struct{}{}:
		default:
			// Listener is already signaled or slow, skip
		}
	}
}

// GetMetrics returns the current bandwidth usage since start
func (r *Relay) GetMetrics() (int64, int64) {
	return atomic.LoadInt64(&r.BytesIn), atomic.LoadInt64(&r.BytesOut)
}

// Subscribe adds a listener and returns its starting offset and a signal channel
func (s *Stream) Subscribe(id string, burstSize int) (int64, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan struct{}, 1)
	s.listeners[id] = ch

	// Start at current head minus burst size for instant playback
	start := s.Buffer.Head - int64(burstSize)
	if start < 0 {
		start = 0
	}

	// For Ogg/Opus, align to the last known page boundary if we are within the burst
	if strings.Contains(strings.ToLower(s.ContentType), "ogg") || strings.Contains(strings.ToLower(s.ContentType), "opus") {
		if s.LastPageOffset > start {
			start = s.LastPageOffset
		}
	}
	
	// Ensure we don't go back further than the buffer allows
	if s.Buffer.Head-start > s.Buffer.Size {
		start = s.Buffer.Head - s.Buffer.Size
	}

	return start, ch
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
func (s *Stream) UpdateMetadata(name, desc, genre, url, bitrate, contentType string, public, visible bool) {
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
	s.Visible = visible
}

// SetCurrentSong updates the current song info thread-safely
func (s *Stream) SetCurrentSong(song string, relay *Relay) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CurrentSong != song {
		s.CurrentSong = song
		if relay.History != nil {
			relay.History.Add(s.MountName, song)
		}
	}
}

// GetCurrentSong returns the current song info thread-safely
func (s *Stream) GetCurrentSong() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentSong
}

// SetVisible updates the visibility of the stream thread-safely
func (s *Stream) SetVisible(visible bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Visible = visible
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
	BytesDropped   int64
	CurrentSong    string
	Public         bool
	Visible        bool
	IsTranscoded   bool
	ListenersCount int
	Uptime         string
	Health         float64
}

// Snapshot returns a point-in-time copy of the stream's state
func (s *Stream) Snapshot() StreamStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bi := atomic.LoadInt64(&s.BytesIn)
	bd := atomic.LoadInt64(&s.BytesDropped)
	
	// Health calculation
	// 1. Loss-based health
	health := 100.0
	total := bi + bd
	if total > 0 {
		health = (float64(bi) / float64(total)) * 100.0
	}

	// 2. Source Stall Penalty (User Request)
	// If we haven't received data for more than 5 seconds, health starts dropping
	if !s.LastDataReceived.IsZero() {
		silence := time.Since(s.LastDataReceived)
		if silence > 5*time.Second {
			penalty := float64(silence/time.Second) * 2.0 // 2% per second of silence
			health -= penalty
		}
	} else if time.Since(s.Started) > 10*time.Second {
		// Never received data and stream started > 10s ago
		health = 0
	}

	if health < 0 {
		health = 0
	}

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
		BytesIn:        bi,
		BytesOut:       atomic.LoadInt64(&s.BytesOut),
		BytesDropped:   bd,
		CurrentSong:    s.CurrentSong,
		Public:         s.Public,
		Visible:        s.Visible,
		IsTranscoded:   s.IsTranscoded,
		ListenersCount: len(s.listeners),
		Uptime:         s.uptimeLocked(),
		Health:         health,
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
