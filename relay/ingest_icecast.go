package relay

import (
	"context"
	"sync/atomic"
	"time"
)

// IcecastIngestSource wraps an Icecast PUT/SOURCE connection as an IngestSource.
// The actual source handling remains in server/handlers_stream.go.
// This adapter provides pipeline-compatible metadata and health.
type IcecastIngestSource struct {
	mount   string
	stream  *Stream
	relay   *Relay
	started time.Time
}

func NewIcecastIngestSource(mount string, stream *Stream, relay *Relay) *IcecastIngestSource {
	return &IcecastIngestSource{
		mount:   mount,
		stream:  stream,
		relay:   relay,
		started: time.Now(),
	}
}

func (s *IcecastIngestSource) Protocol() string { return "icecast" }
func (s *IcecastIngestSource) Mount() string    { return s.mount }

func (s *IcecastIngestSource) Tracks() []*Track {
	codec := "mp3"
	if s.stream.IsOgg() {
		codec = "opus"
	}
	return []*Track{NewAudioTrack(s.stream, codec)}
}

// Start is a no-op — the actual source connection is managed by the HTTP handler.
func (s *IcecastIngestSource) Start(ctx context.Context) error { return nil }

// Stop is a no-op — the source disconnects by closing the HTTP connection.
func (s *IcecastIngestSource) Stop() {}

func (s *IcecastIngestSource) Health() SourceHealth {
	return SourceHealth{
		Status:  calculateHealthStatus(s.stream.LastDataReceived),
		Uptime:  time.Since(s.started),
		BytesIn: atomic.LoadInt64(&s.stream.BytesIn),
	}
}
