package relay

import (
	"context"
	"time"
)

// AutoDJIngestSource wraps the AutoDJ Streamer as an IngestSource.
type AutoDJIngestSource struct {
	mount    string
	streamer *Streamer
	relay    *Relay
}

func NewAutoDJIngestSource(mount string, streamer *Streamer, relay *Relay) *AutoDJIngestSource {
	return &AutoDJIngestSource{
		mount:    mount,
		streamer: streamer,
		relay:    relay,
	}
}

func (s *AutoDJIngestSource) Protocol() string { return "autodj" }
func (s *AutoDJIngestSource) Mount() string    { return s.mount }

func (s *AutoDJIngestSource) Tracks() []*Track {
	stream, ok := s.relay.GetStream(s.mount)
	if !ok {
		return nil
	}
	codec := "mp3"
	s.streamer.mu.RLock()
	if s.streamer.Format == "opus" {
		codec = "opus"
	}
	s.streamer.mu.RUnlock()
	return []*Track{NewAudioTrack(stream, codec)}
}

func (s *AutoDJIngestSource) Start(ctx context.Context) error {
	s.streamer.Play()
	return nil
}

func (s *AutoDJIngestSource) Stop() {
	s.streamer.Stop()
}

func (s *AutoDJIngestSource) Health() SourceHealth {
	stats := s.streamer.GetStats()
	status := StatusHealthy
	if stats.State != StatePlaying {
		status = StatusDegraded
	}
	return SourceHealth{
		Status: status,
		Uptime: time.Since(stats.StartTime),
	}
}
