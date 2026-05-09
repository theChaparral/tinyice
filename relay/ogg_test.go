package relay

import (
	"testing"
	"time"
)

func TestFindNextPageBoundaryRejectsFalseOggS(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)

	// Fake OggS at offset 10 with invalid version=5
	copy(data[10:], []byte("OggS"))
	data[14] = 5

	// Real OggS at offset 50 with valid version=0
	copy(data[50:], []byte("OggS"))
	data[54] = 0
	data[76] = 1  // number_page_segments = 1
	data[77] = 10 // segment of 10 bytes

	result := FindNextPageBoundary(data, bufSize, 256, 0)
	if result != 50 {
		t.Fatalf("expected offset 50, got %d", result)
	}
}

func TestFindNextPageBoundaryFindsValidOgg(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)

	copy(data[0:], []byte("OggS"))
	data[4] = 0  // valid version
	data[26] = 1 // number_page_segments = 1
	data[27] = 10

	result := FindNextPageBoundary(data, bufSize, 256, 0)
	if result != 0 {
		t.Fatalf("expected offset 0, got %d", result)
	}
}

// TestFindNextPageBoundaryNoInfiniteLoopAtWrap reproduces the production
// hang from r4dio (2026-05-09): if the search position landed near the
// circular-buffer wrap so that the truncated segment had n <= 3 bytes,
// the iterator advanced by `n - 3` (which is 0, -1, or -2) and the
// loop pinned cb.mu.RLock forever, blocking every Broadcast. The fix
// guarantees forward progress; this test bounds completion at 1s as a
// regression guard.
func TestFindNextPageBoundaryNoInfiniteLoopAtWrap(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)
	// Place the start position 3 bytes before the wrap so the
	// segment is clamped to n=3, which is < len("OggS"). The
	// pre-fix code stepped by `n-3 = 0` here.
	start := int64(253)
	head := int64(300) // ahead of bufSize so wrap is in play
	done := make(chan int64, 1)
	go func() {
		done <- FindNextPageBoundary(data, bufSize, head, start)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("FindNextPageBoundary spun for >1s — infinite-loop regression at buffer wrap")
	}
}
