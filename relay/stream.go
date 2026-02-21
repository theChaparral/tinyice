package relay

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
	IsOggStream  bool // Pre-calculated for speed

	LastDataReceived time.Time

	OggHead         []byte  // Store Ogg headers for Opus/Ogg streams
	OggHeaderOffset int64   // Absolute buffer offset where headers end
	LastPageOffset  int64   // Absolute offset of the last valid Ogg page start
	PageOffsets     []int64 // Circular list of last ~100 page starts
	PageIndex       int

	Buffer    *CircularBuffer
	listeners map[string]chan struct{} // Signal channel for new data
	mu        sync.RWMutex
}



// IsOgg returns true if the stream is Ogg-based (Ogg/Vorbis, Ogg/Opus, etc)
func (s *Stream) IsOgg() bool {
	ct := strings.ToLower(s.ContentType)
	return strings.Contains(ct, "ogg") || strings.Contains(ct, "opus")
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

// Broadcast sends data to all listeners via the shared circular buffer
func (s *Stream) Broadcast(data []byte, relay *Relay) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastDataReceived = time.Now()

	// Update Metrics (Incoming)
	atomic.AddInt64(&relay.BytesIn, int64(len(data)))
	atomic.AddInt64(&s.BytesIn, int64(len(data)))

	// Track Ogg Page boundaries for alignment
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

	// For Ogg/Opus, align to the oldest known page boundary within the valid buffer range
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