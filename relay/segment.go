package relay

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// Segment represents a single media segment (e.g., a .ts or .m4s chunk).
type Segment struct {
	Index         int           // Monotonically increasing segment index
	Data          []byte        // The actual segment data
	Duration      time.Duration // Duration of audio/video in this segment
	StartPTS      int64         // Presentation timestamp of first frame (90kHz for MPEG-TS)
	Discontinuity bool          // True if there's a discontinuity before this segment
	CreatedAt     time.Time
}

// SegmentRing is a fixed-capacity ring buffer of segments for HLS/DASH serving.
// It holds the last N segments, discarding oldest when full.
type SegmentRing struct {
	segments []*Segment
	capacity int
	head     int // next write position
	count    int // number of valid segments
	sequence int // global sequence number (monotonically increasing)
	mu       sync.RWMutex
}

// NewSegmentRing creates a segment ring with the given capacity.
func NewSegmentRing(capacity int) *SegmentRing {
	return &SegmentRing{
		segments: make([]*Segment, capacity),
		capacity: capacity,
	}
}

// Push adds a segment to the ring, returning the assigned sequence number.
func (r *SegmentRing) Push(data []byte, duration time.Duration, startPTS int64, discontinuity bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Copy data to prevent caller from mutating
	copied := make([]byte, len(data))
	copy(copied, data)

	seq := r.sequence
	r.segments[r.head] = &Segment{
		Index:         seq,
		Data:          copied,
		Duration:      duration,
		StartPTS:      startPTS,
		Discontinuity: discontinuity,
		CreatedAt:     time.Now(),
	}

	r.head = (r.head + 1) % r.capacity
	r.sequence++
	if r.count < r.capacity {
		r.count++
	}

	return seq
}

// Get returns a segment by its sequence number, or nil if expired/not found.
func (r *SegmentRing) Get(sequence int) *Segment {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := 0; i < r.count; i++ {
		idx := (r.head - r.count + i + r.capacity) % r.capacity
		if r.segments[idx] != nil && r.segments[idx].Index == sequence {
			return r.segments[idx]
		}
	}
	return nil
}

// Latest returns the N most recent segments (newest last).
func (r *SegmentRing) Latest(n int) []*Segment {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n > r.count {
		n = r.count
	}

	result := make([]*Segment, 0, n)
	for i := r.count - n; i < r.count; i++ {
		idx := (r.head - r.count + i + r.capacity) % r.capacity
		if r.segments[idx] != nil {
			result = append(result, r.segments[idx])
		}
	}
	return result
}

// Count returns the number of segments currently in the ring.
func (r *SegmentRing) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Clear drops every segment currently in the ring but keeps the
// monotonically-increasing sequence counter. Use when the upstream
// source has disconnected and reconnected with a fresh PTS timeline:
// the old segments are no longer valid (the player would replay
// pre-flap footage before reaching the new content), but rewinding
// the sequence number would confuse HLS clients that expect
// EXT-X-MEDIA-SEQUENCE to never decrease.
func (r *SegmentRing) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.segments {
		r.segments[i] = nil
	}
	r.head = 0
	r.count = 0
}

// Sequence returns the next sequence number that will be assigned.
func (r *SegmentRing) Sequence() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sequence
}

// GenerateM3U8 generates a live HLS playlist from the current segments.
// windowSize is the number of segments to include in the playlist.
//
// Protocol version is VERSION 6 to legitimately use
// EXT-X-INDEPENDENT-SEGMENTS, which RFC 8216 §7 introduced at
// version 6. Declaring this with VERSION:3 (which we used previously)
// is a spec violation and iOS Safari rejects such playlists with
// MEDIA_ERR_SRC_NOT_SUPPORTED.
func (r *SegmentRing) GenerateM3U8(mountPath string, windowSize int) string {
	segments := r.Latest(windowSize)
	if len(segments) == 0 {
		return "#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-TARGETDURATION:4\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-INDEPENDENT-SEGMENTS\n"
	}

	// TARGETDURATION must be an integer that is >= ceil of every EXTINF in
	// the playlist. The previous implementation used int(s)+1 which
	// rounded 4.000 s up to 5 (slightly inflating advertised latency) and
	// 4.5 s to 5 (fine) — use math.Ceil for a tight upper bound.
	maxDur := time.Duration(0)
	for _, s := range segments {
		if s.Duration > maxDur {
			maxDur = s.Duration
		}
	}
	targetDuration := int(math.Ceil(maxDur.Seconds()))
	if targetDuration < 1 {
		targetDuration = 1
	}

	mediaSequence := segments[0].Index

	playlist := "#EXTM3U\n"
	// VERSION 6 is the minimum that allows EXT-X-INDEPENDENT-SEGMENTS
	// per RFC 8216 §7. Declaring this with a lower version is a spec
	// violation and iOS Safari rejects the playlist outright with
	// MEDIA_ERR_SRC_NOT_SUPPORTED.
	playlist += "#EXT-X-VERSION:6\n"
	playlist += fmt.Sprintf("#EXT-X-TARGETDURATION:%d\n", targetDuration)
	playlist += fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", mediaSequence)
	// Every segment we emit starts on an IDR (the framed segment loop
	// flushes on keyframe boundaries). Declaring that explicitly lets
	// players start decoding at the first segment of their window
	// instead of buffering an extra two or three segments "in case
	// random-access happens to be later". Without this tag iOS Safari
	// in particular waits for ~3 segments before showing a frame; on
	// short-segment streams (~2 s) that's a 6 s blank-screen startup
	// that some users perceive as "video doesn't load".
	playlist += "#EXT-X-INDEPENDENT-SEGMENTS\n"
	// No blank separator line between headers and segment list. RFC
	// 8216 §4.1 explicitly forbids blank lines in HLS playlists, and
	// while hls.js / VLC / ffmpeg tolerate them, iOS Safari treats a
	// blank line as a parse error and stalls without surfacing a
	// MediaError (Buffer 0.0 s, Frames 0, ticking timer, eventual
	// "stalled" event). Concatenate the segment list directly.

	for _, s := range segments {
		if s.Discontinuity {
			playlist += "#EXT-X-DISCONTINUITY\n"
		}
		playlist += fmt.Sprintf("#EXTINF:%.3f,\n", s.Duration.Seconds())
		playlist += fmt.Sprintf("%s/segment-%d.ts\n", mountPath, s.Index)
	}

	return playlist
}
