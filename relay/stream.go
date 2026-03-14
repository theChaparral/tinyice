package relay

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stream represents a single mount point (e.g., /stream, /live, /radio).
//
// A Stream is the fundamental unit of audio distribution in TinyIce. Each stream:
//   - Has its own circular buffer for audio data
//   - Manages multiple concurrent listeners
//   - Tracks statistics and metadata
//   - Supports different audio formats (MP3, Ogg/Opus, etc.)
//
// Lifecycle:
//   - Created when a source connects or via admin interface
//   - Buffer accumulates audio data from the source
//   - Listeners subscribe and receive data from the buffer
//   - Destroyed when source disconnects (or manually removed)
//
// Thread Safety:
//   - All fields are protected by the mu RWMutex
//   - Atomic operations are used for performance-critical counters
//   - Safe for concurrent access from multiple goroutines
//
// Performance Considerations:
//   - Each stream has a 2MB circular buffer by default
//   - Listener signal channels are buffered (size 1) to prevent blocking
//   - Ogg page tracking enables proper synchronization for Opus streams
//
// Example Usage:
//
//	stream := relay.GetOrCreateStream("/live")
//	stream.Broadcast(audioData, relayInstance)
//	offset, signal := stream.Subscribe("listener-id", 32*1024)
type Stream struct {
	// Basic stream information
	MountName   string // Mount point path (e.g., "/stream", "/live")
	ContentType string // MIME type (e.g., "audio/mpeg", "audio/ogg")
	Description string // Stream description for directory listings
	Genre       string // Music genre
	URL         string // Associated website URL
	Name        string // Display name
	Bitrate     string // Bitrate in kbps (e.g., "128", "192")

	// Timing and source information
	Started          time.Time // When the stream was created
	SourceIP         string    // IP address of the source client
	LastDataReceived time.Time // Last time data was received from source

	// Stream state and visibility
	Enabled      bool // Whether the stream is accepting connections
	Public       bool // Whether to advertise in public directories
	Visible      bool // Whether to show in admin UI
	IsTranscoded bool // True if this stream is an output of a transcoder

	// Format-specific optimizations
	IsOggStream bool // Pre-calculated for speed (true for Ogg/Opus streams)

	// Audio data and listener management
	CurrentSong string // Currently playing song title

	// Statistics (atomic for performance)
	BytesIn      int64 // Total bytes received from source
	BytesOut     int64 // Total bytes sent to listeners
	BytesDropped int64 // Track total bytes dropped due to slow listeners

	// Ogg/Opus specific state for proper synchronization
	// These fields enable new listeners to start at proper page boundaries
	OggHead         []byte  // Store Ogg headers for Opus/Ogg streams
	OggHeaderOffset int64   // Absolute buffer offset where headers end
	LastPageOffset  int64   // Absolute offset of the last valid Ogg page start
	PageOffsets     []int64 // Circular list of last ~100 page starts
	PageIndex       int     // Index for managing PageOffsets circular list

	// Core streaming infrastructure
	Buffer    *CircularBuffer          // Audio data buffer (typically 2MB)
	listeners map[string]chan struct{} // Signal channels for connected listeners
	mu     sync.RWMutex             // Mutex protecting all fields
	closed int32                    // Atomic flag: 1 = stream closed
}

// IsOgg returns true if the stream is Ogg-based (Ogg/Vorbis, Ogg/Opus, etc).
//
// This method performs a case-insensitive check of the ContentType field to determine
// if the stream uses Ogg container format. This is important for proper handling of
// Opus streams which require special synchronization.
//
// Returns:
//
//	true if the stream content type contains "ogg" or "opus"
//	false otherwise
//
// Performance:
//   - O(1) operation (simple string contains check)
//   - Thread-safe (reads immutable field)
//
// Example:
//
//	if stream.IsOgg() {
//	    // Handle Ogg/Opus specific logic
//	}
func (s *Stream) IsOgg() bool {
	ct := strings.ToLower(s.ContentType)
	return strings.Contains(ct, "ogg") || strings.Contains(ct, "opus")
}

// Close closes all listeners on the stream and cleans up resources.
//
// This method should be called when a stream is being removed or when the source
// disconnects. It ensures all listener goroutines can exit gracefully by closing
// their signal channels.
//
// Behavior:
//   - Locks the stream mutex for the entire operation
//   - Closes all listener signal channels
//   - Removes all listeners from the listeners map
//   - Does NOT remove the stream from the Relay
//
// Thread Safety:
//   - Safe to call from any goroutine
//   - Uses exclusive lock (Lock) to prevent concurrent modifications
//
// Example:
//
//	stream.Close()
//	relay.RemoveStream("/live")
func (s *Stream) Close() {
	atomic.StoreInt32(&s.closed, 1)
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

// Broadcast sends data to all listeners via the shared circular buffer.
//
// This is the core method that distributes audio data from sources to all connected
// listeners. It handles writing to the circular buffer, updating statistics, tracking
// Ogg page boundaries (for Opus streams), and notifying listeners of new data.
//
// Parameters:
//
//	data  - The audio data to broadcast to all listeners
//	relay - The relay instance for updating global statistics
//
// Behavior:
//   - Updates LastDataReceived timestamp
//   - Updates bytes-in statistics (both stream and global)
//   - For Ogg streams: tracks "OggS" page boundaries for synchronization
//   - Writes data to the circular buffer
//   - Signals all listeners via their channels (non-blocking)
//
// Performance:
//   - Locks the stream mutex for the entire operation
//   - Uses atomic operations for statistics to avoid lock contention
//   - Non-blocking listener notification (select with default case)
//   - O(n) where n is number of listeners (for signaling)
//
// Thread Safety:
//   - Safe to call from any goroutine
//   - Uses exclusive lock (Lock) to protect stream state
//
// Example:
//
//	stream.Broadcast(audioChunk, relayInstance)
func (s *Stream) Broadcast(data []byte, relay *Relay) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update timestamp to track source activity
	s.LastDataReceived = time.Now()

	// Update Metrics (Incoming) - uses atomic for performance
	atomic.AddInt64(&relay.BytesIn, int64(len(data)))
	atomic.AddInt64(&s.BytesIn, int64(len(data)))

	// Track Ogg Page boundaries for alignment
	// This enables new Opus listeners to start at proper page boundaries
	if s.IsOggStream {
		for i := 0; i <= len(data)-4; i++ {
			if data[i] == 'O' && data[i+1] == 'g' && data[i+2] == 'g' && data[i+3] == 'S' {
				offset := s.Buffer.Head + int64(i)
				s.LastPageOffset = offset
				s.PageOffsets[s.PageIndex%len(s.PageOffsets)] = offset
				s.PageIndex++
			}
		}
	}

	// 1. Write to shared buffer - this makes data available to listeners
	s.Buffer.Write(data)

	// 2. Signal all listeners that new data is available
	// Use non-blocking send to avoid blocking on slow listeners
	for _, ch := range s.listeners {
		select {
		case ch <- struct{}{}:
			// Successfully signaled listener
		default:
			// Listener is already signaled or slow, skip
		}
	}
}

// Subscribe adds a listener and returns its starting offset and a signal channel.
//
// This method registers a new listener for the stream and determines the optimal
// starting position in the buffer. For Ogg/Opus streams, it ensures the listener
// starts at a proper Ogg page boundary to avoid corruption.
//
// Parameters:
//
//	id        - Unique identifier for this listener
//	burstSize - Number of bytes to rewind from current position for instant playback
//
// Returns:
//
//	int64          - Absolute offset in buffer to start reading from
//	chan struct{}  - Signal channel that will be closed when stream ends or listener is removed
//
// Behavior:
//   - Creates a buffered signal channel (size 1) for the listener
//   - Calculates starting position as (current head - burstSize)
//   - For Ogg streams: aligns to nearest valid Ogg page boundary
//   - Ensures position is within valid buffer range
//   - Adds listener to the listeners map
//
// Ogg Synchronization:
//
//	The method implements sophisticated Ogg page boundary detection to ensure
//	Opus listeners start at valid page boundaries. This prevents audio corruption
//	and ensures proper decoding from the first packet.
//
// Thread Safety:
//   - Safe to call from any goroutine
//   - Uses exclusive lock (Lock) to protect stream state
//
// Performance:
//   - O(n) where n is number of tracked page offsets (typically ~100)
//   - Lock held for entire operation
//
// Example:
//
//	offset, signal := stream.Subscribe("listener-123", 32*1024)
//	reader := NewStreamReader(stream.Buffer, offset, signal, ctx, "listener-123")
func (s *Stream) Subscribe(id string, burstSize int) (int64, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create buffered signal channel for this listener
	ch := make(chan struct{}, 1)
	s.listeners[id] = ch

	// Start at current head minus burst size for instant playback
	// This gives the listener immediate audio data instead of waiting for new data
	start := s.Buffer.Head - int64(burstSize)
	if start < 0 {
		start = 0
	}

	// For Ogg/Opus, align to the oldest known page boundary within the valid buffer range
	// This is crucial for proper Opus decoding - listeners MUST start at page boundaries
	if s.IsOggStream {
		validStart := s.Buffer.Head - s.Buffer.Size
		if validStart < 0 {
			validStart = 0
		}

		// If we have an OggHead persistent storage, we want to start reading
		// from the Buffer AFTER the initial headers to avoid duplicates.
		if s.OggHeaderOffset > start {
			start = s.OggHeaderOffset
		}

		if start < validStart {
			start = validStart
		}

		// Find the best page boundary that is >= start and still valid
		bestAlign := s.LastPageOffset
		found := false
		for _, po := range s.PageOffsets {
			// Find the smallest PO that is >= start AND is still valid
			if po >= start && po >= validStart && po < bestAlign {
				bestAlign = po
				found = true
			}
		}
		if found {
			start = bestAlign
		} else if bestAlign >= validStart && bestAlign > 0 {
			start = bestAlign
		} else {
			start = s.Buffer.Head // Fallback to now if nothing valid found
		}
	}

	// Ensure we don't go back further than the buffer allows
	if s.Buffer.Head-start > s.Buffer.Size {
		start = s.Buffer.Head - s.Buffer.Size
	}

	return start, ch
}

// SubscribeSafe is like Subscribe but returns false if the stream is already closed.
// This prevents adding listeners to a closed stream.
func (s *Stream) SubscribeSafe(id string, burstSize int) (int64, chan struct{}, bool) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return 0, nil, false
	}
	offset, ch := s.Subscribe(id, burstSize)
	return offset, ch, true
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
func (s *Stream) UpdateMetadata(name, desc, genre, url, bitrate, contentType string, public, visible bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	if name != "" && s.Name != name {
		s.Name = name
		changed = true
	}
	if desc != "" && s.Description != desc {
		s.Description = desc
		changed = true
	}
	if genre != "" && s.Genre != genre {
		s.Genre = genre
		changed = true
	}
	if url != "" && s.URL != url {
		s.URL = url
		changed = true
	}
	if bitrate != "" && s.Bitrate != bitrate {
		s.Bitrate = bitrate
		changed = true
	}
	if contentType != "" && s.ContentType != contentType {
		s.ContentType = contentType
		ct := strings.ToLower(contentType)
		s.IsOggStream = strings.Contains(ct, "ogg") || strings.Contains(ct, "opus")
		changed = true
	}
	if s.Public != public {
		s.Public = public
		changed = true
	}
	if s.Visible != visible {
		s.Visible = visible
		changed = true
	}
	return changed
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

// GetStartedTime returns the stream start time (implements TimeProvider interface)
func (s *Stream) GetStartedTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Started
}
