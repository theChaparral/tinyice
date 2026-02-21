package relay

import (
	"time"
)

// StreamInterface defines the basic operations for a stream
type StreamInterface interface {
	Broadcast(data []byte, relay *Relay)
	Subscribe(id string, burstSize int) (int64, chan struct{})
	Unsubscribe(id string)
	Close()
	ListenersCount() int
	GetCurrentSong() string
	SetCurrentSong(song string, relay *Relay)
	UpdateMetadata(name, desc, genre, url, bitrate, contentType string, public, visible bool) bool
	Snapshot() StreamStats
	Uptime() string
	IsOgg() bool
}

// RelayInterface defines the operations for the relay manager
type RelayInterface interface {
	GetOrCreateStream(mount string) *Stream
	GetStream(mount string) (*Stream, bool)
	RemoveStream(mount string)
	DisconnectAllListeners()
	GetMetrics() (int64, int64)
	Snapshot() []StreamStats
	UpdateMetadata(mount, song string)
	GetStreamVisibility(mount string) bool
}

// BufferInterface defines operations for the circular buffer
type BufferInterface interface {
	Write(p []byte)
	ReadAt(start int64, p []byte) (int, int64, bool)
}

// StreamStatsProvider defines objects that can provide stream statistics
type StreamStatsProvider interface {
	Snapshot() StreamStats
}

// MetadataProvider defines objects that can provide metadata
type MetadataProvider interface {
	GetCurrentSong() string
	SetCurrentSong(song string, relay *Relay)
	UpdateMetadata(name, desc, genre, url, bitrate, contentType string, public, visible bool) bool
}

// TimeProvider defines objects that can provide time-related information
type TimeProvider interface {
	Uptime() string
	GetStartedTime() time.Time
}