package relay

import (
	"strings"
	"testing"
	"time"
)

func TestSegmentRingPushAndGet(t *testing.T) {
	ring := NewSegmentRing(3)

	seq0 := ring.Push([]byte("seg0"), 4*time.Second, 0, false)
	seq1 := ring.Push([]byte("seg1"), 4*time.Second, 360000, false)
	seq2 := ring.Push([]byte("seg2"), 4*time.Second, 720000, false)

	if seq0 != 0 || seq1 != 1 || seq2 != 2 {
		t.Fatalf("unexpected sequences: %d %d %d", seq0, seq1, seq2)
	}

	if ring.Count() != 3 {
		t.Fatalf("expected 3 segments, got %d", ring.Count())
	}

	s := ring.Get(1)
	if s == nil {
		t.Fatal("expected segment 1")
	}
	if string(s.Data) != "seg1" {
		t.Fatalf("expected seg1, got %s", string(s.Data))
	}
}

func TestSegmentRingOverflow(t *testing.T) {
	ring := NewSegmentRing(2) // capacity 2

	ring.Push([]byte("a"), 4*time.Second, 0, false)
	ring.Push([]byte("b"), 4*time.Second, 0, false)
	ring.Push([]byte("c"), 4*time.Second, 0, false) // overwrites "a"

	if ring.Count() != 2 {
		t.Fatalf("expected 2, got %d", ring.Count())
	}

	// Segment 0 should be gone
	if ring.Get(0) != nil {
		t.Fatal("expected segment 0 to be evicted")
	}

	// Segments 1 and 2 should exist
	if ring.Get(1) == nil || ring.Get(2) == nil {
		t.Fatal("expected segments 1 and 2 to exist")
	}
}

func TestSegmentRingLatest(t *testing.T) {
	ring := NewSegmentRing(5)
	for i := 0; i < 5; i++ {
		ring.Push([]byte{byte(i)}, 4*time.Second, 0, false)
	}

	latest := ring.Latest(3)
	if len(latest) != 3 {
		t.Fatalf("expected 3, got %d", len(latest))
	}
	if latest[0].Index != 2 || latest[2].Index != 4 {
		t.Fatalf("expected indices 2,3,4 got %d,%d,%d", latest[0].Index, latest[1].Index, latest[2].Index)
	}
}

func TestSegmentRingDataIsCopied(t *testing.T) {
	ring := NewSegmentRing(3)
	data := []byte("original")
	ring.Push(data, 4*time.Second, 0, false)

	// Mutate original — segment should be unaffected
	data[0] = 'X'
	s := ring.Get(0)
	if s.Data[0] != 'o' {
		t.Fatal("segment data should be a copy, not a reference")
	}
}

func TestGenerateM3U8(t *testing.T) {
	ring := NewSegmentRing(10)
	ring.Push([]byte("ts1"), 4*time.Second, 0, false)
	ring.Push([]byte("ts2"), 4*time.Second, 360000, false)
	ring.Push([]byte("ts3"), 4*time.Second, 720000, true) // discontinuity

	m3u8 := ring.GenerateM3U8("/stream", 3)

	if !strings.Contains(m3u8, "#EXTM3U") {
		t.Fatal("missing EXTM3U header")
	}
	if !strings.Contains(m3u8, "#EXT-X-TARGETDURATION:5") {
		t.Fatalf("wrong target duration in:\n%s", m3u8)
	}
	if !strings.Contains(m3u8, "#EXT-X-MEDIA-SEQUENCE:0") {
		t.Fatal("wrong media sequence")
	}
	if !strings.Contains(m3u8, "#EXTINF:4.000,") {
		t.Fatal("missing EXTINF")
	}
	if !strings.Contains(m3u8, "/stream/segment-0.ts") {
		t.Fatal("missing segment URL")
	}
	if !strings.Contains(m3u8, "#EXT-X-DISCONTINUITY") {
		t.Fatal("missing discontinuity tag")
	}
}

func TestGenerateM3U8Empty(t *testing.T) {
	ring := NewSegmentRing(5)
	m3u8 := ring.GenerateM3U8("/stream", 3)

	if !strings.Contains(m3u8, "#EXTM3U") {
		t.Fatal("empty playlist should still have EXTM3U")
	}
}
