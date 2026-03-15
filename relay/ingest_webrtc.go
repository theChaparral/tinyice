package relay

import (
	"context"
	"sync/atomic"
	"time"
)

// WebRTCIngestSource wraps a WebRTC source connection as an IngestSource.
type WebRTCIngestSource struct {
	mount   string
	stream  *Stream
	manager *WebRTCManager
	started time.Time
}

func NewWebRTCIngestSource(mount string, stream *Stream, manager *WebRTCManager) *WebRTCIngestSource {
	return &WebRTCIngestSource{
		mount:   mount,
		stream:  stream,
		manager: manager,
		started: time.Now(),
	}
}

func (s *WebRTCIngestSource) Protocol() string { return "webrtc" }
func (s *WebRTCIngestSource) Mount() string    { return s.mount }

func (s *WebRTCIngestSource) Tracks() []*Track {
	return []*Track{NewAudioTrack(s.stream, "opus")}
}

func (s *WebRTCIngestSource) Start(ctx context.Context) error { return nil }

func (s *WebRTCIngestSource) Stop() {
	s.manager.DisconnectSource(s.mount)
}

func (s *WebRTCIngestSource) Health() SourceHealth {
	return SourceHealth{
		Status:  calculateHealthStatus(s.stream.LastDataReceived),
		Uptime:  time.Since(s.started),
		BytesIn: atomic.LoadInt64(&s.stream.BytesIn),
	}
}
