package relay

import (
	"context"
	"sync/atomic"
	"time"
)

// RelayIngestSource wraps a relay pull connection as an IngestSource.
type RelayIngestSource struct {
	mount    string
	instance *RelayInstance
	manager  *RelayManager
	relay    *Relay
}

func NewRelayIngestSource(mount string, instance *RelayInstance, manager *RelayManager, relay *Relay) *RelayIngestSource {
	return &RelayIngestSource{
		mount:    mount,
		instance: instance,
		manager:  manager,
		relay:    relay,
	}
}

func (s *RelayIngestSource) Protocol() string { return "relay" }
func (s *RelayIngestSource) Mount() string    { return s.mount }

func (s *RelayIngestSource) Tracks() []*Track {
	stream, ok := s.relay.GetStream(s.mount)
	if !ok {
		return nil
	}
	codec := "mp3"
	if stream.IsOgg() {
		codec = "opus"
	}
	return []*Track{NewAudioTrack(stream, codec)}
}

func (s *RelayIngestSource) Start(ctx context.Context) error { return nil }

func (s *RelayIngestSource) Stop() {
	s.manager.StopRelay(s.mount)
}

func (s *RelayIngestSource) Health() SourceHealth {
	s.instance.mu.Lock()
	defer s.instance.mu.Unlock()

	status := StatusHealthy
	switch s.instance.State {
	case RelayConnecting, RelayReconnecting:
		status = StatusDegraded
	case RelayFailed:
		status = StatusDead
	}

	var bytesIn int64
	if stream, ok := s.relay.GetStream(s.mount); ok {
		bytesIn = atomic.LoadInt64(&stream.BytesIn)
	}

	return SourceHealth{
		Status:    status,
		Uptime:    time.Since(s.instance.LastConnected),
		BytesIn:   bytesIn,
		LastError: s.instance.LastError,
	}
}
