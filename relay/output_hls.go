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

// DefaultHLSConfig returns sensible defaults tuned for compatibility
// with mobile browsers. Apple's HLS Authoring Specification (the de-
// facto baseline iOS Safari validates against) recommends a 6 s
// segment target with a hard minimum of 4 s; segments shorter than
// that without LL-HLS partial-segment tags cause iOS to over-buffer
// or refuse playback outright. We use 4 s as a compromise that keeps
// glass-to-glass latency around 10-12 s while staying within the
// "regular HLS" envelope. WindowSize=15 exposes ~60 s of DVR; the
// 90-segment ring keeps the maths spacious for the case where
// upstream keyframe interval briefly drifts above the target.
func DefaultHLSConfig() HLSConfig {
	return HLSConfig{
		SegmentDuration: 4 * time.Second,
		WindowSize:      15,
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

	// relay is needed for self-healing across source flaps. When the
	// upstream RTMP source drops, the audio/video Stream objects are
	// removed from the relay and their FrameHub channels close. The
	// segment loop catches the channel close, looks up fresh Stream
	// pointers via relay.GetStream(mount), and resubscribes. Without
	// this the segment loop would exit on the first source drop and
	// the player would see stale ring contents followed by nothing.
	// nil is tolerated for backward compatibility with call sites
	// that build a one-shot HLSOutput against tracks they own.
	relay *Relay

	// hasVideo is a cached flag so the HTTP layer / status API can tell
	// clients whether this HLS mount is A/V without reaching into the
	// pipeline state.
	hasVideo bool

	// videoSubMount is the relay mount where the video track lives —
	// e.g. "/zonetv/video" for an RTMP mount at "/zonetv". Used by the
	// self-healing path to look up the fresh video Stream after a
	// source-side flap.
	videoSubMount string

	// nextSessionStartPTS is the output-side PTS/DTS value at which
	// the NEXT session's first frame should land. By forwarding this
	// across the resubscribe boundary we keep the output timeline
	// monotonically increasing through source flaps — the player
	// sees one continuous PCR/PTS axis with a brief "no new frames"
	// gap, which it can ride out without rebuilding its demuxer.
	// Compare to the previous design where each new session reset
	// PTS to 0 and forced an #EXT-X-DISCONTINUITY tag, which was
	// visible to the user as a hard stall every time the RTMP
	// source dropped (every 20-50 s on a flappy publisher).
	// Read + written only from segmentLoopFramed (single goroutine);
	// no synchronisation needed.
	nextSessionStartPTS int64
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

// WithRelay sets the relay reference so the segment loop can
// self-heal after a source flap. Idempotent. Returns h for chaining.
func (h *HLSOutput) WithRelay(r *Relay) *HLSOutput {
	h.relay = r
	return h
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
	if videoTrack != nil && videoTrack.Stream != nil {
		h.videoSubMount = videoTrack.Stream.MountName
	}
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

// segmentLoopFramed wraps the per-session framed loop in a
// resubscribe-on-source-flap retry. Each "session" is one continuous
// run of frames from the upstream Stream's FrameHub. When the source
// disconnects, both FrameHub channels close and the inner loop
// returns. We then clear the segment ring (so viewers don't replay
// pre-flap segments), wait for a fresh Stream to appear under the
// same mount, and restart with the new Track pointers. The next
// segment pushed after a resubscribe is flagged as a discontinuity.
func (h *HLSOutput) segmentLoopFramed(ctx context.Context, audio, video *Track) {
	for ctx.Err() == nil {
		h.runFramedSession(ctx, audio, video)
		if ctx.Err() != nil || h.relay == nil {
			return
		}
		// Inner loop returned because both upstream FrameHubs closed
		// (RemoveStream on source disconnect). Drop the ring so the
		// player doesn't keep replaying segments from the previous
		// connection while we wait for the new source — and then poll
		// for fresh Stream pointers under the same mount.
		h.ring.Clear()
		newAudio, newVideo := h.waitForFreshStreams(ctx)
		if newAudio == nil {
			return
		}
		audio, video = newAudio, newVideo
		logger.L.Infow("HLS: resubscribed after source flap",
			"mount", h.mount, "has_video", video != nil)
	}
}

// waitForFreshStreams polls the relay at 500 ms cadence until the
// audio mount (and, if this output is A/V, the video sub-mount) both
// exist and have a non-nil FrameHub. Returns nil on context cancel.
func (h *HLSOutput) waitForFreshStreams(ctx context.Context) (*Track, *Track) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		as, aok := h.relay.GetStream(h.mount)
		var vs *Stream
		vok := h.videoSubMount == ""
		if !vok {
			vs, vok = h.relay.GetStream(h.videoSubMount)
		}
		if aok && vok && as != nil && as.Frames != nil &&
			(vs == nil || vs.Frames != nil) {
			audioCodec := "mp3"
			if as.IsOgg() {
				audioCodec = "opus"
			}
			at := NewAudioTrack(as, audioCodec)
			var vt *Track
			if vs != nil {
				vt = NewTrackFromStream(MediaVideo, "h264", vs)
			}
			return at, vt
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-tick.C:
		}
	}
}

// runFramedSession consumes per-frame records from the audio + video
// FrameHubs and emits one PES per frame with the correct PTS. Flushes
// a segment roughly every SegmentDuration, preferring keyframe
// boundaries for the segment start so HLS clients that join mid-
// stream get a fresh IDR at segment-0 of their window. Returns when
// both FrameHub channels close (caller decides whether to restart
// the session against a fresh Stream pair).
func (h *HLSOutput) runFramedSession(ctx context.Context, audio, video *Track) {
	audioFrames := audio.Stream.Frames.Subscribe(ctx)
	videoFrames := video.Stream.Frames.Subscribe(ctx)
	// Discontinuity marker is now suppressed across normal source
	// flaps because we forward the output PTS axis monotonically
	// (see h.nextSessionStartPTS). We only emit a discontinuity when
	// the AUDIO codec changes mid-stream (the AAC vs MP3 PMT swap
	// path below), since that's a real demuxer-rebuild boundary that
	// the player can't bridge without one.
	_ = false // (kept for code-shape continuity)

	// audioStreamType is sampled at flush time, not registration time.
	// RTMP ingest defaults the input stream's ContentType to
	// "audio/mpeg" and only flips it to "audio/aac" after the first
	// AAC SequenceHeader (AudioSpecificConfig) arrives. If a viewer
	// requests the HLS playlist in that ~700 ms window, RegisterHLS
	// starts this loop with ContentType still defaulted; sampling
	// once at the top would lock the PMT to MP3 forever and every
	// segment would advertise MP3 audio while carrying AAC bytes
	// (mpv / ffmpeg report it as "mp3float: Header missing" on every
	// frame). Re-sampling each flush + emitting a discontinuity when
	// the codec changes makes the player resync cleanly.
	currentAudioStreamType := func() byte {
		t := audioStreamTypeMP3
		if ct := strings.ToLower(audio.Stream.ContentType); strings.Contains(ct, "aac") {
			t = audioStreamTypeAAC
		}
		return t
	}
	prevAudioStreamType := currentAudioStreamType()

	var (
		audioBatch []pesUnit
		videoBatch []pesUnit
		segStart   = time.Now()
		segHasIDR  bool
		// ptsBase is subtracted from every audio + video frame's
		// PTS and DTS before muxing. Within a session it normalises
		// the source's FLV timestamps to start at h.nextSessionStartPTS
		// (which is 0 on the very first session, and the
		// end-of-previous-session output PTS for subsequent
		// sessions). That keeps the output timeline monotonically
		// increasing across source flaps, so the player can ride
		// out a brief gap without rebuilding its demuxer (no
		// #EXT-X-DISCONTINUITY needed).
		ptsBase int64 = -1
		// lastEmittedDTS tracks the last output DTS we put on the
		// wire so we can advance h.nextSessionStartPTS at session
		// end. Initialised to nextSessionStartPTS so a session that
		// never gets a frame still leaves a sane value behind.
		lastEmittedDTS int64 = h.nextSessionStartPTS
	)

	flush := func() {
		if len(audioBatch) == 0 && len(videoBatch) == 0 {
			return
		}
		audioStreamType := currentAudioStreamType()
		// PMT changes are a hard discontinuity for HLS players —
		// without the #EXT-X-DISCONTINUITY marker hls.js / Safari
		// keep trying to decode AAC bytes as MP3 across the boundary
		// and stutter for a few segments before giving up. The first
		// segment after a source-flap resubscribe is also a
		// discontinuity (fresh PTS timeline + possibly different
		// codec / resolution).
		// Only the audio-codec-change case is a real demuxer-rebuild
		// boundary (the player has to swap from MP3 to AAC parsing
		// or vice versa). Source flaps no longer trigger a
		// discontinuity because PTS continuity is preserved by
		// h.nextSessionStartPTS forwarding the output timeline
		// across sessions.
		discontinuity := audioStreamType != prevAudioStreamType
		prevAudioStreamType = audioStreamType

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
		h.ring.Push(tsData, segDur, startPTS, discontinuity)
		logger.L.Debugw("HLS: framed segment",
			"mount", h.mount,
			"bytes", len(tsData),
			"duration", segDur,
			"audio_frames", len(audioBatch),
			"video_frames", len(videoBatch),
			"sequence", h.ring.Sequence()-1,
			"audio_st", audioStreamType,
			"discontinuity", discontinuity,
		)
		audioBatch = audioBatch[:0]
		videoBatch = videoBatch[:0]
		segHasIDR = false
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
				// Persist where the output timeline is now so the
				// next session continues from here rather than
				// snapping back to zero.
				h.nextSessionStartPTS = lastEmittedDTS
				return
			}
			if ptsBase < 0 {
				// Map this session's first input PTS onto
				// h.nextSessionStartPTS so the output timeline is
				// continuous with the previous session.
				ptsBase = f.DTS - h.nextSessionStartPTS
				if f.PTS-ptsBase < h.nextSessionStartPTS {
					ptsBase = f.PTS - h.nextSessionStartPTS
				}
			}
			outDTS := f.DTS - ptsBase
			outPTS := f.PTS - ptsBase
			if outDTS > lastEmittedDTS {
				lastEmittedDTS = outDTS
			}
			audioBatch = append(audioBatch, pesUnit{pts: outPTS, dts: outDTS, data: f.Data})
		case f, ok := <-videoFrames:
			if !ok {
				h.nextSessionStartPTS = lastEmittedDTS
				return
			}
			if ptsBase < 0 {
				ptsBase = f.DTS - h.nextSessionStartPTS
				if f.PTS-ptsBase < h.nextSessionStartPTS {
					ptsBase = f.PTS - h.nextSessionStartPTS
				}
			}
			outDTS := f.DTS - ptsBase
			outPTS := f.PTS - ptsBase
			if outDTS > lastEmittedDTS {
				lastEmittedDTS = outDTS
			}
			// Prefer to start segments on keyframes, but respect the
			// configured SegmentDuration as a TARGET (not a minimum):
			// flush at the first keyframe at-or-after SegmentDuration
			// elapsed. Previously the condition was "emittedOne ||
			// time.Since >= SegmentDuration" which collapsed to
			// flushing on every GOP after the first segment — so a
			// source with a 2 s GOP locked us to 2 s segments
			// regardless of the configured 4 s target, and mobile
			// HLS players that need ≥4 s segments couldn't play.
			if f.Keyframe {
				if time.Since(segStart) >= h.config.SegmentDuration {
					if segHasIDR || len(videoBatch) > 0 || len(audioBatch) > 0 {
						flush()
					}
				}
				segHasIDR = true
			}
			videoBatch = append(videoBatch, pesUnit{pts: outPTS, dts: outDTS, data: f.Data})
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
// PTS, and the two batches are interleaved by DTS so audio and video
// packets travel close together on the wire.
//
// Apple's HLS Authoring Specification §4.4.5 says audio packets MUST
// NOT be separated from the corresponding video packets by more than
// 100 ms. Dumping the entire video batch before the entire audio
// batch (the previous behaviour) made a 6 s segment carry ~6000 ms of
// video before any audio — iOS Safari refused to play such streams
// and the browser sat in a "stalled" state forever with no
// MediaError. Interleaving by DTS keeps audio≤100 ms behind video at
// the natural frame cadence of the source.
func (h *HLSOutput) buildAVSegment(audioBatch, videoBatch []pesUnit, audioStreamType byte) []byte {
	var buf bytes.Buffer
	h.muxer.writePAT(&buf)
	h.muxer.writePMTAV(&buf, audioStreamType)
	// Merge-sort by DTS. Audio frames have dts == pts. Video frames
	// with B-frames have dts < pts; sorting by dts produces the right
	// on-wire ordering for the decoder buffer.
	vi, ai := 0, 0
	for vi < len(videoBatch) && ai < len(audioBatch) {
		if videoBatch[vi].dts <= audioBatch[ai].dts {
			h.muxer.writeVideoPES(&buf, videoBatch[vi].data, videoBatch[vi].pts, videoBatch[vi].dts)
			vi++
		} else {
			h.muxer.writeAudioPES(&buf, audioBatch[ai].data, audioBatch[ai].pts)
			ai++
		}
	}
	for ; vi < len(videoBatch); vi++ {
		h.muxer.writeVideoPES(&buf, videoBatch[vi].data, videoBatch[vi].pts, videoBatch[vi].dts)
	}
	for ; ai < len(audioBatch); ai++ {
		h.muxer.writeAudioPES(&buf, audioBatch[ai].data, audioBatch[ai].pts)
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

	// Pick the PMT stream_type for the audio track. Sampled per-flush
	// rather than once at loop start: RTMP ingest defaults its
	// ContentType to "audio/mpeg" until the first AAC SequenceHeader
	// arrives, and the framed loop above had the same one-shot bug
	// that locked HLS to MP3 even on AAC sources whenever a viewer
	// hit the playlist in the first ~700 ms. Re-sampling + flagging
	// the segment as a discontinuity on change makes hls.js / Safari
	// resync cleanly.
	currentAudioStreamType := func() byte {
		t := audioStreamTypeMP3
		if audio != nil && audio.Stream != nil {
			ct := strings.ToLower(audio.Stream.ContentType)
			if strings.Contains(ct, "aac") {
				t = audioStreamTypeAAC
			}
		}
		return t
	}
	prevAudioStreamType := currentAudioStreamType()

	flushIfReady := func(force bool) {
		elapsed := time.Since(segStart)
		if (!force && elapsed < h.config.SegmentDuration) || len(audioBuf) == 0 {
			return
		}
		audioStreamType := currentAudioStreamType()
		discontinuity := audioStreamType != prevAudioStreamType
		prevAudioStreamType = audioStreamType
		segDur := h.config.SegmentDuration
		var tsData []byte
		if videoStream != nil && len(videoBuf) > 0 {
			tsData = h.muxer.MuxAVSegment(audioBuf, videoBuf, audioPTS, videoPTS, audioStreamType)
		} else {
			tsData = h.muxer.MuxMP3Segment(audioBuf, audioPTS)
		}
		h.ring.Push(tsData, segDur, audioPTS, discontinuity)
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
