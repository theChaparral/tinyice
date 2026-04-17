package relay

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// MediaType represents the kind of media in a track
type MediaType int

const (
	MediaAudio MediaType = iota
	MediaVideo
)

func (m MediaType) String() string {
	if m == MediaVideo {
		return "video"
	}
	return "audio"
}

// TrackMetadata holds codec-specific information
type TrackMetadata struct {
	SampleRate int
	Channels   int
	Bitrate    int
	Width      int     // video only
	Height     int     // video only
	FPS        float64 // video only
	CodecExtra []byte  // codec-specific init data (SPS/PPS, OpusHead, etc.)
}

// Track represents a single media track (audio or video).
// Wraps the existing Stream type for buffer/listener management.
type Track struct {
	Type     MediaType
	Codec    string // cached hint; may be updated by ResolveCodec below
	Stream   *Stream
	Metadata TrackMetadata
}

// ResolveCodec (re)detects the track's codec from the wrapped Stream's
// current ContentType / Ogg-sniff state. Call this after ingest has started
// producing data — the codec hint captured at track creation may be wrong,
// because Stream metadata isn't populated until the first bytes arrive.
func (t *Track) ResolveCodec() string {
	if t == nil || t.Stream == nil {
		return t.Codec
	}
	if t.Stream.IsOgg() {
		t.Codec = "opus"
	} else if t.Codec == "" {
		t.Codec = "mp3"
	}
	return t.Codec
}

// NewAudioTrack creates a Track wrapping an existing Stream for audio.
func NewAudioTrack(stream *Stream, codec string) *Track {
	return &Track{
		Type:   MediaAudio,
		Codec:  codec,
		Stream: stream,
	}
}

// NewTrackFromStream wraps an existing Stream as a Track of the requested
// media type / codec. Used by outputs that want to attach an already-live
// Stream (e.g. the /video sub-mount RTMP/SRT ingest created) without
// allocating yet another Stream + buffer.
func NewTrackFromStream(media MediaType, codec string, stream *Stream) *Track {
	return &Track{
		Type:   media,
		Codec:  codec,
		Stream: stream,
	}
}

// NewVideoTrack creates a Track for video with a dedicated buffer.
func NewVideoTrack(codec string, bufferSize int) *Track {
	return &Track{
		Type:  MediaVideo,
		Codec: codec,
		Stream: &Stream{
			MountName:   "video",
			listeners:   make(map[string]chan struct{}),
			Buffer:      NewCircularBuffer(bufferSize),
			Started:     time.Now(),
			Enabled:     true,
			PageOffsets: make([]int64, 2048),
		},
	}
}

// SourceHealth represents the health status of an ingest source
type SourceHealth struct {
	Status    HealthStatus
	Uptime    time.Duration
	BytesIn   int64
	LastError string
}

// PipelineHealth aggregates health across source and tracks
type PipelineHealth struct {
	Status     HealthStatus
	Source     SourceHealth
	TrackCount int
	Listeners  int
}

// IngestSource represents any source of media data
type IngestSource interface {
	Protocol() string // "icecast", "webrtc", "rtmp", "srt", "autodj", "relay"
	Mount() string
	Tracks() []*Track
	Start(ctx context.Context) error
	Stop()
	Health() SourceHealth
}

// OutputAdapter represents any output format
type OutputAdapter interface {
	Protocol() string // "icecast", "hls", "dash", "webrtc"
	SupportsMediaType(MediaType) bool
	Start(ctx context.Context, tracks []*Track) error
	Stop()
}

// HTTPOutputAdapter extends OutputAdapter for HTTP-based outputs
type HTTPOutputAdapter interface {
	OutputAdapter
	ContentType() string
	ServeListener(w http.ResponseWriter, r *http.Request) error
}

// Pipeline connects sources to outputs through a stream
type Pipeline struct {
	Mount    string
	TenantID string // empty = default tenant
	Source   IngestSource
	Outputs  []OutputAdapter
	Tracks   []*Track
	Health   PipelineHealth
	Created  time.Time
	mu       sync.RWMutex
}

// NewPipeline creates a new pipeline for the given mount.
func NewPipeline(mount string) *Pipeline {
	return &Pipeline{
		Mount:   mount,
		Outputs: make([]OutputAdapter, 0),
		Tracks:  make([]*Track, 0),
		Created: time.Now(),
	}
}

// AddTrack adds a media track to the pipeline.
func (p *Pipeline) AddTrack(t *Track) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Tracks = append(p.Tracks, t)
}

// GetAudioTrack returns the first audio track, or nil.
func (p *Pipeline) GetAudioTrack() *Track {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, t := range p.Tracks {
		if t.Type == MediaAudio {
			return t
		}
	}
	return nil
}

// GetVideoTrack returns the first video track, or nil.
func (p *Pipeline) GetVideoTrack() *Track {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, t := range p.Tracks {
		if t.Type == MediaVideo {
			return t
		}
	}
	return nil
}

// ListenerCount returns total listeners across all tracks.
func (p *Pipeline) ListenerCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := 0
	for _, t := range p.Tracks {
		total += t.Stream.ListenersCount()
	}
	return total
}

// AddOutput registers an output adapter.
func (p *Pipeline) AddOutput(o OutputAdapter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Outputs = append(p.Outputs, o)
}
