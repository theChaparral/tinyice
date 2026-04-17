package relay

import (
	"context"
	"strings"
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

// HLSOutput implements OutputAdapter for HLS streaming. It accumulates audio
// (and optionally video) bytes from the attached tracks and emits MPEG-TS
// segments every SegmentDuration. With an audio track only it produces
// MP3-in-MPEG-TS audio segments; with a video track too it produces
// interleaved A/V segments via MuxAVSegment.
type HLSOutput struct {
	mount  string
	config HLSConfig
	ring   *SegmentRing
	muxer  *TSMuxer
	tracks []*Track
	cancel context.CancelFunc
	mu     sync.RWMutex

	// hasVideo is a cached flag so the HTTP layer / status API can tell
	// clients whether this HLS mount is A/V without reaching into the
	// pipeline state.
	hasVideo bool
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

func (h *HLSOutput) Protocol() string { return "hls" }

// SupportsMediaType now advertises video support too, since Start accepts a
// video track and segmentLoop muxes it in if present.
func (h *HLSOutput) SupportsMediaType(mt MediaType) bool {
	return mt == MediaAudio || mt == MediaVideo
}

// HasVideo reports whether this HLS output was started with a video track
// alongside audio. The frontend uses this to decide between <audio> and
// <video> playback.
func (h *HLSOutput) HasVideo() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hasVideo
}

// Start begins the segmentation loop. Pass an audio track (required) and
// optionally a video track. When both are present, segments are muxed A/V.
func (h *HLSOutput) Start(ctx context.Context, tracks []*Track) error {
	h.mu.Lock()
	h.tracks = tracks
	h.mu.Unlock()

	var audioTrack, videoTrack *Track
	for _, t := range tracks {
		switch t.Type {
		case MediaAudio:
			if audioTrack == nil {
				audioTrack = t
			}
		case MediaVideo:
			if videoTrack == nil {
				videoTrack = t
			}
		}
	}
	if audioTrack == nil {
		return nil // No audio track, nothing to do
	}

	h.mu.Lock()
	h.hasVideo = videoTrack != nil
	h.mu.Unlock()

	segCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel

	go h.segmentLoop(segCtx, audioTrack, videoTrack)
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

// segmentLoop reads from the audio stream (and optional video stream),
// accumulates a segment's worth of each, and every SegmentDuration flushes
// what we have into a TS segment.
func (h *HLSOutput) segmentLoop(ctx context.Context, audio *Track, video *Track) {
	id := "hls-" + h.mount

	audioOffset, audioSignal := audio.Stream.Subscribe(id, 8192)
	defer audio.Stream.Unsubscribe(id)
	audioReader := NewStreamReader(audio.Stream.Buffer, audioOffset, audioSignal, ctx, id)

	var videoStream *Stream
	var videoReader *StreamReader
	if video != nil && video.Stream != nil {
		videoStream = video.Stream
		videoOffset, videoSignal := videoStream.Subscribe(id, 64*1024)
		defer videoStream.Unsubscribe(id)
		videoReader = NewStreamReader(videoStream.Buffer, videoOffset, videoSignal, ctx, id)
	}

	audioBuf := make([]byte, 0, 256*1024)
	videoBuf := make([]byte, 0, 512*1024)
	readBuf := make([]byte, 4096)

	segStart := time.Now()
	var audioPTS, videoPTS int64

	// Pick the PMT stream_type for the audio track. Anything the client
	// has said is AAC (RTMP ingest, or a Content-Type advertised as
	// such) goes out as ADTS — the RTMP path prepends the ADTS header
	// to the payload before broadcast so the bytes are already in the
	// right shape.
	audioStreamType := audioStreamTypeMP3
	if audio != nil && audio.Stream != nil {
		ct := strings.ToLower(audio.Stream.ContentType)
		if strings.Contains(ct, "aac") {
			audioStreamType = audioStreamTypeAAC
		}
	}

	flushIfReady := func(force bool) {
		elapsed := time.Since(segStart)
		if (!force && elapsed < h.config.SegmentDuration) || len(audioBuf) == 0 {
			return
		}
		segDur := h.config.SegmentDuration
		var tsData []byte
		if videoStream != nil && len(videoBuf) > 0 {
			tsData = h.muxer.MuxAVSegment(audioBuf, videoBuf, audioPTS, videoPTS, audioStreamType)
		} else {
			tsData = h.muxer.MuxMP3Segment(audioBuf, audioPTS)
		}
		h.ring.Push(tsData, segDur, audioPTS, false)
		inc := int64(segDur.Seconds() * tsClockRate)
		audioPTS += inc
		videoPTS += inc

		logger.L.Debugw("HLS: Created segment",
			"mount", h.mount,
			"declared_duration", segDur,
			"wallclock_elapsed", elapsed,
			"bytes", len(tsData),
			"audio_bytes", len(audioBuf),
			"video_bytes", len(videoBuf),
			"has_video", videoStream != nil,
			"sequence", h.ring.Sequence()-1,
		)
		audioBuf = audioBuf[:0]
		videoBuf = videoBuf[:0]
		segStart = time.Now()
	}

	// Drive both readers off select-like polling: read whichever has data
	// available without blocking too long, and check the segment timer on
	// every iteration.
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Non-blocking-ish audio read: audioReader.Read blocks waiting for
		// the signal, which is fine here — audio arrives at roughly
		// real-time. We drain a single chunk per iteration then pick up
		// any buffered video before flushing.
		n, err := audioReader.Read(readBuf)
		if err != nil {
			return
		}
		if n > 0 {
			audioBuf = append(audioBuf, readBuf[:n]...)
		}

		// Drain whatever video is available at this moment without
		// blocking. If nothing is there we just move on — the next
		// audio read will give video time to catch up via its own
		// signal channel.
		if videoReader != nil {
			for {
				vn, verr := videoReader.Read(readBuf)
				if vn > 0 {
					videoBuf = append(videoBuf, readBuf[:vn]...)
				}
				if verr != nil || vn == 0 {
					break
				}
				if vn < len(readBuf) {
					break
				}
			}
		}

		flushIfReady(false)
	}
}
