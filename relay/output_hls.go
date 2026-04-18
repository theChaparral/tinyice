package relay

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

// pesUnit is a single access unit queued for inclusion in the next HLS
// segment, with both its presentation (PTS) and decode (DTS) timestamps
// on the 90 kHz MPEG clock. For audio and for video without B-frames
// dts == pts; for video with B-frames dts comes from the FLV
// CompositionTime adjustment.
type pesUnit struct {
	pts  int64
	dts  int64
	data []byte
}

// HLSConfig holds configuration for HLS output.
type HLSConfig struct {
	SegmentDuration time.Duration // target segment duration (default 1s for low latency)
	WindowSize      int           // number of segments exposed in the live playlist (DVR window)
	RingCapacity    int           // max segments retained in the ring buffer
}

// DefaultHLSConfig returns sensible defaults tuned for low latency + a
// 60 s DVR window. Shorter segments reduce glass-to-glass latency (the
// player needs ~3 segments of buffer to start, so 1 s segments ≈ 3 s
// startup vs. 12 s with the previous 4 s default); exposing 60 segments
// in the playlist lets the player scrub back a minute without extra
// wiring on our side.
func DefaultHLSConfig() HLSConfig {
	return HLSConfig{
		SegmentDuration: 1 * time.Second,
		WindowSize:      60,
		RingCapacity:    90,
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

// segmentLoop picks the right implementation: if there's a video track,
// use the frame-hub driven path so each frame gets its own PES with the
// real FLV timestamp. Audio-only mounts that only produce bytes
// (Icecast SOURCE of MP3 / Opus) stay on the byte-buffer path.
func (h *HLSOutput) segmentLoop(ctx context.Context, audio *Track, video *Track) {
	if video != nil && video.Stream != nil && video.Stream.Frames != nil &&
		audio != nil && audio.Stream != nil && audio.Stream.Frames != nil {
		h.segmentLoopFramed(ctx, audio, video)
		return
	}
	h.segmentLoopByteBuffer(ctx, audio, video)
}

// segmentLoopFramed consumes per-frame records from the audio + video
// FrameHubs and emits one PES per frame with the correct PTS. Flushes a
// segment roughly every SegmentDuration, preferring keyframe boundaries
// for the segment start so HLS clients that join mid-stream get a fresh
// IDR at segment-0 of their window.
func (h *HLSOutput) segmentLoopFramed(ctx context.Context, audio, video *Track) {
	audioFrames := audio.Stream.Frames.Subscribe(ctx)
	videoFrames := video.Stream.Frames.Subscribe(ctx)

	audioStreamType := audioStreamTypeMP3
	if ct := strings.ToLower(audio.Stream.ContentType); strings.Contains(ct, "aac") {
		audioStreamType = audioStreamTypeAAC
	}

	var (
		audioBatch []pesUnit
		videoBatch []pesUnit
		segStart   = time.Now()
		segHasIDR  bool
		emittedOne bool
	)

	flush := func() {
		if len(audioBatch) == 0 && len(videoBatch) == 0 {
			return
		}
		tsData := h.buildAVSegment(audioBatch, videoBatch, audioStreamType)
		// Use the first PTS as the segment's nominal start, and derive
		// the segment duration from the actual span of PTS values we
		// included. Previously we always declared SegmentDuration
		// regardless of what the content contained, which made the
		// player buffer whenever keyframe interval didn't match — e.g.
		// an OBS keyframe every 5 s into a 4 s advertised window left
		// 1 s of "phantom" duration the player waited to arrive.
		firstPTS, lastEndPTS := pesBatchRange(videoBatch, audioBatch)
		startPTS := firstPTS
		segDur := h.config.SegmentDuration
		if lastEndPTS > firstPTS {
			segDur = time.Duration(lastEndPTS-firstPTS) * time.Second / 90000
		}
		h.ring.Push(tsData, segDur, startPTS, false)
		logger.L.Debugw("HLS: framed segment",
			"mount", h.mount,
			"bytes", len(tsData),
			"duration", segDur,
			"audio_frames", len(audioBatch),
			"video_frames", len(videoBatch),
			"sequence", h.ring.Sequence()-1,
		)
		audioBatch = audioBatch[:0]
		videoBatch = videoBatch[:0]
		segHasIDR = false
		emittedOne = true
		segStart = time.Now()
	}

	// For A/V the keyframe arrival drives segment flushes (the timer only
	// acts as a fallback when keyframes stop coming). For audio-only we
	// fall back to purely time-driven flushes. The fallback window is
	// generous — three SegmentDurations — so a 1 s advertised segment
	// won't prematurely cut a GOP when the source sends keyframes every
	// 2 s. Users who want segments closer to SegmentDuration should set
	// their encoder's keyframe interval to match.
	fallback := 3 * h.config.SegmentDuration
	if fallback < 2*time.Second {
		fallback = 2 * time.Second
	}
	timer := time.NewTicker(h.config.SegmentDuration)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-audioFrames:
			if !ok {
				return
			}
			audioBatch = append(audioBatch, pesUnit{pts: f.PTS, dts: f.DTS, data: f.Data})
		case f, ok := <-videoFrames:
			if !ok {
				return
			}
			// Prefer to start segments on keyframes: if we've already
			// emitted one segment, any subsequent keyframe closes the
			// current one and starts the new segment at the IDR.
			if f.Keyframe {
				if emittedOne || time.Since(segStart) >= h.config.SegmentDuration {
					if segHasIDR || len(videoBatch) > 0 || len(audioBatch) > 0 {
						flush()
					}
				}
				segHasIDR = true
			}
			videoBatch = append(videoBatch, pesUnit{pts: f.PTS, dts: f.DTS, data: f.Data})
		case <-timer.C:
			// Audio-only flush path: no video frames, so keyframes
			// can never trigger. Flush on the advertised segment
			// cadence.
			if len(videoBatch) == 0 && time.Since(segStart) >= h.config.SegmentDuration {
				flush()
				continue
			}
			// Stuck-stream fallback: if a video stream has a gap
			// larger than `fallback` without a keyframe, emit what
			// we have so the player isn't frozen waiting.
			if len(videoBatch) > 0 && time.Since(segStart) >= fallback {
				flush()
			}
		}
	}
}

// pesBatchRange returns the earliest first-PTS across audio + video and the
// latest end-PTS (last frame's PTS rounded up to include its own duration
// by using the following frame's start, or falling back to the last PTS
// itself when there's only one frame).
func pesBatchRange(videoBatch, audioBatch []pesUnit) (first, end int64) {
	first = -1
	end = -1
	consider := func(batch []pesUnit) {
		for _, u := range batch {
			if first < 0 || u.pts < first {
				first = u.pts
			}
			if u.pts > end {
				end = u.pts
			}
		}
	}
	consider(videoBatch)
	consider(audioBatch)
	if first < 0 {
		first = 0
	}
	if end < first {
		end = first
	}
	return first, end
}

// buildAVSegment muxes a list of audio + video access units into a single
// MPEG-TS segment. Each frame becomes its own PES packet with its own
// PTS.
func (h *HLSOutput) buildAVSegment(audioBatch, videoBatch []pesUnit, audioStreamType byte) []byte {
	var buf bytes.Buffer
	h.muxer.writePAT(&buf)
	h.muxer.writePMTAV(&buf, audioStreamType)
	for _, v := range videoBatch {
		h.muxer.writeVideoPES(&buf, v.data, v.pts, v.dts)
	}
	for _, a := range audioBatch {
		h.muxer.writeAudioPES(&buf, a.data, a.pts)
	}
	return buf.Bytes()
}

// segmentLoopByteBuffer is the old byte-level Icecast SOURCE path — one
// PES per segment, approximate PTS derived from wall-clock segment
// duration. Still correct for MP3 / Opus audio-only mounts where the
// source doesn't hand us frame timestamps.
func (h *HLSOutput) segmentLoopByteBuffer(ctx context.Context, audio *Track, video *Track) {
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
