package relay

import (
	"context"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

// HLSConfig holds configuration for HLS output.
type HLSConfig struct {
	SegmentDuration time.Duration // target segment duration (default 4s)
	WindowSize      int           // number of segments in playlist (default 6)
	RingCapacity    int           // max segments in ring buffer (default 30)
}

// DefaultHLSConfig returns sensible defaults.
func DefaultHLSConfig() HLSConfig {
	return HLSConfig{
		SegmentDuration: 4 * time.Second,
		WindowSize:      6,
		RingCapacity:    30,
	}
}

// HLSOutput implements OutputAdapter for HLS streaming.
// It reads audio from the stream, segments it into TS chunks, and stores them.
type HLSOutput struct {
	mount  string
	config HLSConfig
	ring   *SegmentRing
	muxer  *TSMuxer
	tracks []*Track
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// NewHLSOutput creates a new HLS output for the given mount.
func NewHLSOutput(mount string, config HLSConfig) *HLSOutput {
	return &HLSOutput{
		mount:  mount,
		config: config,
		ring:   NewSegmentRing(config.RingCapacity),
		muxer:  NewTSMuxer(),
	}
}

func (h *HLSOutput) Protocol() string                    { return "hls" }
func (h *HLSOutput) SupportsMediaType(mt MediaType) bool { return mt == MediaAudio }

// Start begins the segmentation loop, reading from the audio track's stream.
func (h *HLSOutput) Start(ctx context.Context, tracks []*Track) error {
	h.mu.Lock()
	h.tracks = tracks
	h.mu.Unlock()

	// Find the audio track
	var audioTrack *Track
	for _, t := range tracks {
		if t.Type == MediaAudio {
			audioTrack = t
			break
		}
	}
	if audioTrack == nil {
		return nil // No audio track, nothing to do
	}

	segCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel

	go h.segmentLoop(segCtx, audioTrack)
	return nil
}

// Stop stops the segmentation loop.
func (h *HLSOutput) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
}

// Ring returns the segment ring for serving.
func (h *HLSOutput) Ring() *SegmentRing {
	return h.ring
}

// Playlist returns the current M3U8 playlist.
func (h *HLSOutput) Playlist() string {
	return h.ring.GenerateM3U8(h.mount, h.config.WindowSize)
}

// segmentLoop reads from the audio stream and creates TS segments.
func (h *HLSOutput) segmentLoop(ctx context.Context, track *Track) {
	stream := track.Stream
	id := "hls-" + h.mount

	// Subscribe to the stream with a small burst
	offset, signal := stream.Subscribe(id, 8192)
	defer stream.Unsubscribe(id)

	reader := NewStreamReader(stream.Buffer, offset, signal, ctx, id)

	segBuf := make([]byte, 0, 256*1024) // accumulate audio data for one segment
	readBuf := make([]byte, 4096)

	// Use a time-based approach — accumulate for segmentDuration
	segStart := time.Now()
	var ptsCounter int64

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := reader.Read(readBuf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}

		segBuf = append(segBuf, readBuf[:n]...)

		// Check if we've accumulated enough for a segment
		elapsed := time.Since(segStart)
		if elapsed >= h.config.SegmentDuration && len(segBuf) > 0 {
			// Mux the accumulated audio into a TS segment
			tsData := h.muxer.MuxMP3Segment(segBuf, ptsCounter)
			h.ring.Push(tsData, elapsed, ptsCounter, false)

			// Advance PTS
			ptsCounter += int64(elapsed.Seconds() * tsClockRate)

			logger.L.Debugw("HLS: Created segment",
				"mount", h.mount,
				"duration", elapsed,
				"bytes", len(tsData),
				"sequence", h.ring.Sequence()-1,
			)

			// Reset for next segment
			segBuf = segBuf[:0]
			segStart = time.Now()
		}
	}
}
