# Phase 1: Streaming Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix buffer bugs, add close guards, improve error recovery, add health monitoring, and harden listener/source management — making the existing streaming engine production-grade.

**Architecture:** All changes are to existing `relay/` and `server/` packages. No new abstractions — just fixing bugs, adding guards, and improving resilience. Each task is independent and can be committed separately.

**Tech Stack:** Go 1.25, existing relay/server packages, `sync/atomic` for close guards, `math/rand` for jitter, `time` for backoff.

**Spec:** `docs/superpowers/specs/2026-03-14-streaming-hardening-design.md` (Phase 1)

---

## Chunk 1: Buffer & Stream Fixes

### Task 1: Fix CircularBuffer wrap-around reads

**Files:**
- Modify: `relay/buffer.go:95-130`
- Create: `relay/buffer_test.go`

The `ReadAt` method truncates reads at the buffer boundary instead of wrapping around. When `pos+n > Size`, it should read to the end, then continue from offset 0.

- [ ] **Step 1: Write failing test for wrap-around read**

```go
// relay/buffer_test.go
package relay

import (
	"bytes"
	"testing"
)

func TestReadAtWrapsAround(t *testing.T) {
	buf := NewCircularBuffer(16) // Small buffer to force wrapping

	// Write 20 bytes — this wraps around (writes 16, overwrites first 4)
	data := []byte("ABCDEFGHIJKLMNOPQRST") // 20 bytes
	buf.Write(data)
	// Buffer now contains: "QRST" at [0:4] + "EFGHIJKLMNOP" at [4:16]
	// Head is at 20. Valid range: [4, 20) = offsets 4..19
	// data[4:20] = "EFGHIJKLMNOPQRST"

	// Read 8 bytes starting at offset 12 (which is position 12 in the ring)
	// This spans the wrap point: positions 12..15 = "MNOP", then 0..3 = "QRST"
	out := make([]byte, 8)
	n, next, skipped := buf.ReadAt(12, out)

	if skipped {
		t.Fatal("unexpected skip")
	}
	// BUG: currently n=4 (truncated at boundary). Should be 8.
	if n != 8 {
		t.Fatalf("expected 8 bytes, got %d", n)
	}
	if next != 20 {
		t.Fatalf("expected next=20, got %d", next)
	}
	expected := []byte("MNOPQRST")
	if !bytes.Equal(out[:n], expected) {
		t.Fatalf("expected %q, got %q", expected, out[:n])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestReadAtWrapsAround -v`
Expected: FAIL — `expected 8 bytes, got 4`

- [ ] **Step 3: Fix ReadAt to handle wrap-around**

Replace the read logic in `relay/buffer.go` `ReadAt` method. The current code at lines 122-129:

```go
// Handle wrap-around: if read would cross buffer boundary, limit to segment
if pos+n > cb.Size {
    n = cb.Size - pos
}

// Perform the actual read
actual := copy(p, cb.Data[pos:pos+n])
return actual, start + int64(actual), skipped
```

Replace with:

```go
// Handle wrap-around: read in two parts if crossing buffer boundary
if pos+n > cb.Size {
    // Part 1: read from pos to end of buffer
    firstPart := cb.Size - pos
    copy(p, cb.Data[pos:pos+firstPart])
    // Part 2: read remainder from start of buffer
    secondPart := n - firstPart
    copy(p[firstPart:], cb.Data[0:secondPart])
    return int(n), start + n, skipped
}

// No wrap — single contiguous read
actual := copy(p, cb.Data[pos:pos+n])
return actual, start + int64(actual), skipped
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestReadAtWrapsAround -v`
Expected: PASS

- [ ] **Step 5: Add more buffer tests**

Add these tests to `relay/buffer_test.go`:

```go
func TestReadAtNoWrap(t *testing.T) {
	buf := NewCircularBuffer(64)
	buf.Write([]byte("Hello, World!"))

	out := make([]byte, 5)
	n, next, skipped := buf.ReadAt(0, out)
	if n != 5 || next != 5 || skipped {
		t.Fatalf("n=%d next=%d skipped=%v", n, next, skipped)
	}
	if string(out[:n]) != "Hello" {
		t.Fatalf("got %q", out[:n])
	}
}

func TestReadAtSkipsSlowListener(t *testing.T) {
	buf := NewCircularBuffer(16)
	// Write 32 bytes — buffer wraps twice, oldest valid data starts at offset 16
	buf.Write(bytes.Repeat([]byte("X"), 32))

	out := make([]byte, 4)
	n, next, skipped := buf.ReadAt(0, out) // offset 0 is behind the buffer
	if !skipped {
		t.Fatal("expected skip for slow listener")
	}
	if n == 0 {
		t.Fatal("expected some data after skip")
	}
	_ = next
}

func TestReadAtAheadOfHead(t *testing.T) {
	buf := NewCircularBuffer(16)
	buf.Write([]byte("test"))

	out := make([]byte, 4)
	n, _, _ := buf.ReadAt(100, out) // way ahead of head
	if n != 0 {
		t.Fatalf("expected 0 bytes for future offset, got %d", n)
	}
}

func TestWriteAndReadFullWrap(t *testing.T) {
	buf := NewCircularBuffer(8)
	// Write 3 chunks that progressively wrap
	buf.Write([]byte("AAAA"))     // head=4
	buf.Write([]byte("BBBB"))     // head=8
	buf.Write([]byte("CCCC"))     // head=12, buffer=[CCCC BBBB] -> [CCCC at 0:4, BBBB at 4:8] wait no
	// Actually: head=12. data[0:4]="CCCC", data[4:8]="BBBB"
	// Valid range: [4, 12) = "BBBBCCCC"

	out := make([]byte, 8)
	n, next, _ := buf.ReadAt(4, out)
	if n != 8 {
		t.Fatalf("expected 8, got %d", n)
	}
	if next != 12 {
		t.Fatalf("expected next=12, got %d", next)
	}
	if string(out) != "BBBBCCCC" {
		t.Fatalf("expected BBBBCCCC, got %q", string(out))
	}
}
```

- [ ] **Step 6: Run all buffer tests**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run 'TestReadAt|TestWrite' -v`
Expected: All PASS

- [ ] **Step 7: Add Available() and Reset() methods**

Add to `relay/buffer.go`:

```go
// Available returns the number of valid bytes in the buffer.
func (cb *CircularBuffer) Available() int64 {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	if cb.Head < cb.Size {
		return cb.Head
	}
	return cb.Size
}

// Reset clears the buffer without reallocating.
func (cb *CircularBuffer) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.Head = 0
	// Zero the data to prevent stale reads
	for i := range cb.Data {
		cb.Data[i] = 0
	}
}
```

- [ ] **Step 8: Test Available() and Reset()**

Add to `relay/buffer_test.go`:

```go
func TestAvailable(t *testing.T) {
	buf := NewCircularBuffer(16)
	if buf.Available() != 0 {
		t.Fatalf("expected 0, got %d", buf.Available())
	}
	buf.Write([]byte("ABCD"))
	if buf.Available() != 4 {
		t.Fatalf("expected 4, got %d", buf.Available())
	}
	buf.Write(bytes.Repeat([]byte("X"), 20))
	if buf.Available() != 16 { // capped at buffer size
		t.Fatalf("expected 16, got %d", buf.Available())
	}
}

func TestReset(t *testing.T) {
	buf := NewCircularBuffer(16)
	buf.Write([]byte("data"))
	buf.Reset()
	if buf.Head != 0 {
		t.Fatalf("expected Head=0 after reset, got %d", buf.Head)
	}
	if buf.Available() != 0 {
		t.Fatal("expected Available()=0 after reset")
	}
}
```

- [ ] **Step 9: Run all tests and commit**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run 'TestReadAt|TestWrite|TestAvailable|TestReset' -v -race`
Expected: All PASS

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/buffer.go relay/buffer_test.go
git commit -m "fix: circular buffer wrap-around reads, add Available/Reset"
```

---

### Task 2: Add stream close guard (Broadcast/Close race)

**Files:**
- Modify: `relay/stream.go`
- Create: `relay/stream_test.go`

`Broadcast()` can panic if called concurrently with `Close()` because it sends on listener channels that `Close()` has already closed.

- [ ] **Step 1: Write test for concurrent Broadcast and Close**

```go
// relay/stream_test.go
package relay

import (
	"sync"
	"testing"
)

func TestBroadcastAfterCloseNoPanic(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")

	// Subscribe a listener
	s.Subscribe("listener-1", 0)

	// Run Broadcast and Close concurrently — should not panic
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.Broadcast([]byte("data"), r)
		}
	}()

	go func() {
		defer wg.Done()
		s.Close()
	}()

	wg.Wait()
}

func TestSubscribeAfterCloseRejects(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")
	s.Close()

	_, _, ok := s.SubscribeSafe("listener-after-close", 1024)
	if ok {
		t.Fatal("expected SubscribeSafe to return false after Close")
	}
}
```

- [ ] **Step 2: Run test to verify it fails/panics**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run 'TestBroadcastAfterClose|TestSubscribeAfterClose' -v -race 2>&1 || true`
Expected: FAIL — panic on send to closed channel, and `SubscribeSafe` does not exist yet.

- [ ] **Step 3: Add closed guard to Stream**

Modify `relay/stream.go`. Add `closed` field and update methods:

Add import `"sync/atomic"` (already imported).

Add field to `Stream` struct after the `mu` field:

```go
closed int32 // atomic: 1 = closed
```

Modify `Close()`:

```go
func (s *Stream) Close() {
	atomic.StoreInt32(&s.closed, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.listeners {
		close(ch)
		delete(s.listeners, id)
	}
}
```

Modify `Broadcast()` — add guard at the very top, before acquiring the lock:

```go
func (s *Stream) Broadcast(data []byte, relay *Relay) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// ... rest of existing code unchanged
```

Add `SubscribeSafe()` — same as `Subscribe()` but returns a third `ok` bool:

```go
// SubscribeSafe is like Subscribe but returns ok=false if the stream is closed.
func (s *Stream) SubscribeSafe(id string, burstSize int) (int64, chan struct{}, bool) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return 0, nil, false
	}
	offset, ch := s.Subscribe(id, burstSize)
	return offset, ch, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run 'TestBroadcastAfterClose|TestSubscribeAfterClose' -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/stream.go relay/stream_test.go
git commit -m "fix: guard against Broadcast/Subscribe on closed stream"
```

---

### Task 3: Fix Ogg Subscribe fallback for empty PageOffsets

**Files:**
- Modify: `relay/stream.go:260-318` (Subscribe method)
- Modify: `relay/stream_test.go`

When an Ogg stream has no tracked page offsets yet, `Subscribe()` falls through to `start = s.Buffer.Head`, giving the listener zero burst.

- [ ] **Step 1: Write failing test**

```go
// Add to relay/stream_test.go

func TestSubscribeOggEmptyPageOffsetsFallsBackToBurst(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/ogg-test")
	s.ContentType = "audio/ogg"
	s.IsOggStream = true

	// Write some data but no OggS pages tracked
	s.Buffer.Write(make([]byte, 4096))
	// PageOffsets are all zero, LastPageOffset is 0

	offset, _ := s.Subscribe("listener-1", 2048)

	// Should get a burst of ~2048 bytes, not start at Head
	expectedMin := s.Buffer.Head - 2048
	if offset >= s.Buffer.Head {
		t.Fatalf("expected burst offset < Head(%d), got %d", s.Buffer.Head, offset)
	}
	if offset < expectedMin {
		t.Fatalf("expected offset >= %d, got %d", expectedMin, offset)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestSubscribeOggEmptyPageOffsetsFallsBackToBurst -v`
Expected: FAIL — `expected burst offset < Head`

- [ ] **Step 3: Fix Subscribe fallback**

In `relay/stream.go`, in the `Subscribe` method, replace the final else clause in the Ogg block (around line 304-309):

```go
		if found {
			start = bestAlign
		} else if bestAlign >= validStart && bestAlign > 0 {
			start = bestAlign
		} else {
			start = s.Buffer.Head // Fallback to now if nothing valid found
		}
```

Replace with:

```go
		if found {
			start = bestAlign
		} else if bestAlign >= validStart && bestAlign > 0 {
			start = bestAlign
		} else {
			// No valid Ogg page boundaries found — fall back to burst-based offset
			// (same as non-Ogg streams) rather than starting at Head with no burst
			start = s.Buffer.Head - int64(burstSize)
			if start < validStart {
				start = validStart
			}
			if start < 0 {
				start = 0
			}
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestSubscribeOggEmptyPageOffsetsFallsBackToBurst -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/stream.go relay/stream_test.go
git commit -m "fix: Ogg Subscribe falls back to burst offset when no page boundaries exist"
```

---

### Task 4: Validate OggS page headers in FindNextPageBoundary

**Files:**
- Modify: `relay/ogg.go`
- Create: `relay/ogg_test.go`

The current `FindNextPageBoundary` matches any occurrence of "OggS" in the buffer, including false positives in binary data.

- [ ] **Step 1: Write failing test**

```go
// relay/ogg_test.go
package relay

import (
	"testing"
)

func TestFindNextPageBoundaryRejectsFalseOggS(t *testing.T) {
	// Create a buffer with a fake "OggS" followed by an invalid version byte
	bufSize := int64(256)
	data := make([]byte, bufSize)

	// Place fake OggS at offset 10 with invalid version (version=5 instead of 0)
	copy(data[10:], []byte("OggS"))
	data[14] = 5 // version byte — must be 0 for valid Ogg

	// Place real OggS at offset 50 with valid version 0
	copy(data[50:], []byte("OggS"))
	data[54] = 0 // valid version
	data[55] = 0 // header type
	// Granule position (8 bytes) — can be anything
	// Serial number (4 bytes) — can be anything
	// Page sequence (4 bytes) — can be anything
	// Checksum (4 bytes) — skip validation for now
	data[76] = 1 // number_page_segments = 1
	data[77] = 10 // segment table: one segment of 10 bytes

	head := int64(256)
	start := int64(0)

	result := FindNextPageBoundary(data, bufSize, head, start)

	// Should skip the fake OggS at 10 and find the real one at 50
	if result != 50 {
		t.Fatalf("expected offset 50, got %d", result)
	}
}

func TestFindNextPageBoundaryFindsValidOgg(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)

	// Place valid OggS at offset 0
	copy(data[0:], []byte("OggS"))
	data[4] = 0 // valid version
	data[26] = 1 // number_page_segments = 1
	data[27] = 10 // segment table

	head := int64(256)
	start := int64(0)

	result := FindNextPageBoundary(data, bufSize, head, start)
	if result != 0 {
		t.Fatalf("expected offset 0, got %d", result)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestFindNextPageBoundary -v`
Expected: FAIL — current code returns 10 (the fake OggS) instead of 50.

- [ ] **Step 3: Add Ogg page header validation**

Replace the `FindNextPageBoundary` function in `relay/ogg.go`:

```go
package relay

import (
	"bytes"
)

// isValidOggPage checks if the bytes at the given position form a valid Ogg page header.
// An Ogg page header is at least 27 bytes:
//   [0:4]   "OggS" capture pattern
//   [4]     version (must be 0)
//   [5]     header type flags
//   [6:14]  granule position
//   [14:18] serial number
//   [18:22] page sequence number
//   [22:26] checksum
//   [26]    number_page_segments
//   [27:27+N] segment table (N = number_page_segments)
func isValidOggPage(data []byte, bufferSize int64, pos int64, head int64) bool {
	// Need at least 27 bytes after OggS to read the minimal header
	headerEnd := pos + 27
	if headerEnd > head {
		return false // Not enough data in buffer
	}

	// Read version byte (offset 4 from start of page)
	verPos := (pos + 4) % bufferSize
	if data[verPos] != 0 {
		return false // Version must be 0
	}

	// Read number_page_segments (offset 26 from start of page)
	segPos := (pos + 26) % bufferSize
	numSegments := data[segPos]

	// Sanity check: must have at least the segment table available
	fullHeaderEnd := pos + 27 + int64(numSegments)
	if fullHeaderEnd > head {
		return false // Not enough data for segment table
	}

	return true
}

// FindNextPageBoundary searches for the next valid Ogg page boundary in the buffer.
// It validates that "OggS" matches are actually valid Ogg page headers.
func FindNextPageBoundary(buffer []byte, bufferSize, head, start int64) int64 {
	if start < head-bufferSize {
		start = head - bufferSize
	}
	if start >= head-4 {
		return head
	}

	const magic = "OggS"
	for i := start; i < head-4; {
		pos := i % bufferSize
		n := int64(32 * 1024) // Search window
		if i+n > head {
			n = head - i
		}
		if pos+n > bufferSize {
			n = bufferSize - pos
		}

		segment := buffer[pos : pos+n]
		searchStart := int64(0)
		for {
			idx := bytes.Index(segment[searchStart:], []byte(magic))
			if idx == -1 {
				break
			}
			absOffset := i + searchStart + int64(idx)
			if isValidOggPage(buffer, bufferSize, absOffset, head) {
				return absOffset
			}
			// Skip past this false positive and keep searching
			searchStart += int64(idx) + 1
			if searchStart >= int64(len(segment)) {
				break
			}
		}
		i += n - 3 // Overlap to catch magic split across segments
	}
	return head
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestFindNextPageBoundary -v`
Expected: PASS

- [ ] **Step 5: Run all relay tests**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -v -race`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/ogg.go relay/ogg_test.go
git commit -m "fix: validate OggS page headers to prevent false sync"
```

---

## Chunk 2: Error Recovery & Reconnection

### Task 5: Add exponential backoff and proper HTTP client to RelayManager

**Files:**
- Modify: `relay/client.go`
- Create: `relay/client_test.go`

The relay pull currently uses `http.DefaultClient` (no timeouts) and retries with a fixed 5-second delay.

- [ ] **Step 1: Write test for backoff behavior**

```go
// relay/client_test.go
package relay

import (
	"testing"
	"time"
)

func TestBackoffWithJitter(t *testing.T) {
	b := &backoff{base: 1 * time.Second, max: 60 * time.Second}

	d1 := b.next()
	if d1 < 500*time.Millisecond || d1 > 2*time.Second {
		t.Fatalf("first backoff out of range: %v", d1)
	}

	d2 := b.next()
	if d2 < 1*time.Second || d2 > 4*time.Second {
		t.Fatalf("second backoff out of range: %v", d2)
	}

	// After many calls, should cap at max
	for i := 0; i < 20; i++ {
		b.next()
	}
	d := b.next()
	if d > 61*time.Second {
		t.Fatalf("backoff exceeded max: %v", d)
	}

	b.reset()
	d = b.next()
	if d > 2*time.Second {
		t.Fatalf("after reset, backoff should be small: %v", d)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestBackoffWithJitter -v`
Expected: FAIL — `backoff` type doesn't exist.

- [ ] **Step 3: Implement backoff and update RelayInstance**

Add to `relay/client.go` after the imports:

```go
import (
	"math"
	"math/rand"
)
```

Add the backoff type and update RelayInstance:

```go
type backoff struct {
	base    time.Duration
	max     time.Duration
	attempt int
}

func (b *backoff) next() time.Duration {
	exp := math.Pow(2, float64(b.attempt))
	delay := time.Duration(float64(b.base) * exp)
	if delay > b.max {
		delay = b.max
	}
	// Add jitter: 50%-100% of calculated delay
	jitter := time.Duration(float64(delay) * (0.5 + rand.Float64()*0.5))
	b.attempt++
	return jitter
}

func (b *backoff) reset() {
	b.attempt = 0
}

// RelayState represents the connection state of a relay
type RelayState int

const (
	RelayConnecting   RelayState = iota
	RelayConnected
	RelayReconnecting
	RelayFailed
)
```

Add health fields to `RelayInstance`:

```go
type RelayInstance struct {
	URL       string
	Mount     string
	Password  string
	BurstSize int
	Visible   bool
	cancel    context.CancelFunc
	mu        sync.Mutex
	Active    bool

	// Health tracking
	State          RelayState
	LastConnected  time.Time
	LastError      string
	ReconnectCount int
}
```

Replace `runRelay` to use backoff:

```go
func (rm *RelayManager) runRelay(ctx context.Context, inst *RelayInstance) {
	bo := &backoff{base: 1 * time.Second, max: 60 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			inst.mu.Lock()
			inst.State = RelayConnecting
			inst.mu.Unlock()

			rm.performPull(ctx, inst)

			inst.mu.Lock()
			wasConnected := inst.State == RelayConnected
			inst.State = RelayReconnecting
			inst.ReconnectCount++
			inst.mu.Unlock()

			// Reset backoff after a successful connection (was connected before disconnect)
			if wasConnected {
				bo.reset()
			}

			delay := bo.next()
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}
```

Add a dedicated HTTP client to `RelayManager`:

```go
type RelayManager struct {
	instances map[string]*RelayInstance
	mu        sync.RWMutex
	relay     *Relay
	client    *http.Client
}

func NewRelayManager(r *Relay) *RelayManager {
	return &RelayManager{
		instances: make(map[string]*RelayInstance),
		relay:     r,
		client: &http.Client{
			Timeout: 0, // No overall timeout (streaming is indefinite)
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}
}
```

Update imports at the top of `relay/client.go` — add these to the existing import block:

```go
"math"
"math/rand"
"net"
```

Update `performPull` to use `rm.client` instead of `http.DefaultClient`:

In the `performPull` method, change:
```go
resp, err := http.DefaultClient.Do(req)
```
to:
```go
resp, err := rm.client.Do(req)
```

Also add state tracking to `performPull`. There are 3 specific locations to update:

1. After the `http.NewRequestWithContext` error check (line ~127):
```go
if err != nil {
    inst.mu.Lock()
    inst.LastError = fmt.Sprintf("request creation failed: %v", err)
    inst.mu.Unlock()
    return
}
```

2. After the `rm.client.Do(req)` error check (line ~140):
```go
if err != nil {
    inst.mu.Lock()
    inst.LastError = fmt.Sprintf("connection failed: %v", err)
    inst.mu.Unlock()
    logger.L.Errorf("Relay connection failed: %v", err)
    return
}
```

3. After the `resp.StatusCode != http.StatusOK` check (line ~147), before `GetOrCreateStream`:
```go
inst.mu.Lock()
inst.State = RelayConnected
inst.LastConnected = time.Now()
inst.LastError = ""
inst.mu.Unlock()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestBackoffWithJitter -v`
Expected: PASS

- [ ] **Step 5: Build to verify compilation**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/client.go relay/client_test.go
git commit -m "feat: exponential backoff with jitter and proper HTTP client for relay pulls"
```

---

### Task 6: Replace AutoDJ busy-poll with channel-based wake

**Files:**
- Modify: `relay/streamer.go`

The `runStreamerLoop` uses `time.Sleep(100ms)` when stopped, wasting CPU.

- [ ] **Step 1: Add stateCh channel to Streamer**

Add a channel field to the `Streamer` struct:

```go
stateCh chan struct{} // Signaled when state changes (play/stop)
```

Initialize it in `StartStreamer` alongside `idleCh`:

```go
stateCh: make(chan struct{}, 1),
```

- [ ] **Step 2: Update Play/Stop/TogglePlay to signal stateCh**

Add a helper method:

```go
func (s *Streamer) signalStateChange() {
	select {
	case s.stateCh <- struct{}{}:
	default:
	}
}
```

Add `s.signalStateChange()` at the end of `Play()`, `Stop()`, and `TogglePlay()` (after the `s.mu.Unlock()` via defer).

Actually, since they use `defer s.mu.Unlock()`, add the signal before the return. Example for `Play()`:

```go
func (s *Streamer) Play() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StatePlaying
	s.signalStateChange()
}
```

Similarly for `Stop()` and `TogglePlay()`.

- [ ] **Step 3: Replace busy-poll in runStreamerLoop**

In `relay/streamer.go`, in `runStreamerLoop`, replace:

```go
		default:
			if s.State != StatePlaying {
				time.Sleep(100 * time.Millisecond)
				continue
			}
```

With:

```go
		default:
			if s.State != StatePlaying {
				// Wait for state change instead of busy-polling
				select {
				case <-ctx.Done():
					return
				case <-s.stateCh:
					continue
				}
			}
```

- [ ] **Step 4: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/streamer.go
git commit -m "perf: replace AutoDJ busy-poll with channel-based state wake"
```

---

### Task 7: Add file validation before streaming

**Files:**
- Modify: `relay/streamer.go` (streamFile method)

Currently corrupt or missing files cause a 1-second error sleep loop.

- [ ] **Step 1: Add validateAudioFile helper**

Add to `relay/streamer.go`:

```go
// validateAudioFile checks if a file exists, is readable, and has a valid MP3 header.
func validateAudioFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not accessible: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory")
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	// Check for valid MP3 header (sync word 0xFFE0 or 0xFFFB)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open: %w", err)
	}
	defer f.Close()

	header := make([]byte, 4)
	if _, err := f.Read(header); err != nil {
		return fmt.Errorf("cannot read header: %w", err)
	}

	// Check for ID3v2 tag (starts with "ID3") or MP3 sync word
	if header[0] == 'I' && header[1] == 'D' && header[2] == '3' {
		return nil // ID3 tagged MP3
	}
	if header[0] == 0xFF && (header[1]&0xE0) == 0xE0 {
		return nil // MP3 frame sync
	}

	return fmt.Errorf("unrecognized audio format (header: %x)", header[:4])
}
```

- [ ] **Step 2: Use validateAudioFile in runStreamerLoop**

In `runStreamerLoop`, after `filePath` is determined and before `streamFile` is called, add:

```go
			if err := validateAudioFile(filePath); err != nil {
				logger.L.Warnf("Streamer %s: Skipping invalid file %s: %v", s.Name, filePath, err)
				continue
			}
```

This replaces the current behavior where `streamFile` fails on `mp3.NewDecoder` and sleeps for 1 second.

- [ ] **Step 3: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/streamer.go
git commit -m "fix: validate audio files before streaming to skip corrupt files"
```

---

### Task 8: Track WebRTC source PeerConnections for disconnect

**Files:**
- Modify: `relay/webrtc.go`

`HandleSourceOffer` creates PeerConnections but doesn't track them, making it impossible to disconnect a WebRTC source.

- [ ] **Step 1: Add sources map to WebRTCManager**

In `relay/webrtc.go`, update the `WebRTCManager` struct:

```go
type WebRTCManager struct {
	api     *webrtc.API
	relay   *Relay
	mu      sync.RWMutex
	sources map[string]*webrtc.PeerConnection // mount -> active source PC
}
```

Update `NewWebRTCManager`:

```go
func NewWebRTCManager(r *Relay) *WebRTCManager {
	s := webrtc.SettingEngine{}
	s.SetICETimeouts(10*time.Second, 20*time.Second, 2*time.Second)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	return &WebRTCManager{
		api:     api,
		relay:   r,
		sources: make(map[string]*webrtc.PeerConnection),
	}
}
```

- [ ] **Step 2: Track PeerConnection in HandleSourceOffer**

In `HandleSourceOffer`, after creating `peerConnection`, add tracking:

```go
	// Close existing source for this mount if any
	wm.mu.Lock()
	if existing, ok := wm.sources[mount]; ok {
		existing.Close()
	}
	wm.sources[mount] = peerConnection
	wm.mu.Unlock()
```

Add cleanup on connection state change inside the `OnTrack` callback (or add a new `OnConnectionStateChange` handler after `peerConnection` creation):

```go
	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logger.L.Infow("WebRTC Source: Connection state changed", "mount", mount, "state", state.String())
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateDisconnected {
			wm.mu.Lock()
			if wm.sources[mount] == peerConnection {
				delete(wm.sources, mount)
			}
			wm.mu.Unlock()
		}
	})
```

- [ ] **Step 3: Add DisconnectSource method**

```go
// DisconnectSource closes the WebRTC source PeerConnection for a given mount.
func (wm *WebRTCManager) DisconnectSource(mount string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	pc, ok := wm.sources[mount]
	if !ok {
		return fmt.Errorf("no WebRTC source for mount %s", mount)
	}
	delete(wm.sources, mount)
	return pc.Close()
}
```

- [ ] **Step 4: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/webrtc.go
git commit -m "feat: track WebRTC source PeerConnections, add DisconnectSource"
```

---

## Chunk 3: Health Monitoring & Graceful Degradation

### Task 9: Add stream health monitor

**Files:**
- Create: `relay/health.go`
- Create: `relay/health_test.go`

- [ ] **Step 1: Write test for health status calculation**

```go
// relay/health_test.go
package relay

import (
	"testing"
	"time"
)

func TestHealthStatus(t *testing.T) {
	tests := []struct {
		name     string
		lastData time.Duration // ago
		want     HealthStatus
	}{
		{"healthy - recent data", 1 * time.Second, StatusHealthy},
		{"degraded - 10s ago", 10 * time.Second, StatusDegraded},
		{"dead - 60s ago", 60 * time.Second, StatusDead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateHealthStatus(time.Now().Add(-tt.lastData))
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestHealthStatus -v`
Expected: FAIL — functions don't exist.

- [ ] **Step 3: Implement health.go**

```go
// relay/health.go
package relay

import (
	"context"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

// HealthStatus represents the health of a stream
type HealthStatus int

const (
	StatusHealthy  HealthStatus = iota // Receiving data normally
	StatusDegraded                      // No data for >5s
	StatusDead                          // No data for >30s
)

func (h HealthStatus) String() string {
	switch h {
	case StatusHealthy:
		return "healthy"
	case StatusDegraded:
		return "degraded"
	case StatusDead:
		return "dead"
	default:
		return "unknown"
	}
}

// calculateHealthStatus determines stream health based on last data time.
func calculateHealthStatus(lastDataReceived time.Time) HealthStatus {
	if lastDataReceived.IsZero() {
		return StatusDead
	}
	silence := time.Since(lastDataReceived)
	if silence > 30*time.Second {
		return StatusDead
	}
	if silence > 5*time.Second {
		return StatusDegraded
	}
	return StatusHealthy
}

// StreamHealthEvent is emitted when a stream's health status changes.
type StreamHealthEvent struct {
	Mount     string
	OldStatus HealthStatus
	NewStatus HealthStatus
	Timestamp time.Time
}

// HealthMonitor watches all streams and reports health changes.
type HealthMonitor struct {
	relay         *Relay
	interval      time.Duration
	deadTimeout   time.Duration
	lastStatus    map[string]HealthStatus
	mu            sync.Mutex
	onEvent       func(StreamHealthEvent)
	autoRemoveDead bool
}

// NewHealthMonitor creates a health monitor for the given relay.
func NewHealthMonitor(r *Relay) *HealthMonitor {
	return &HealthMonitor{
		relay:          r,
		interval:       5 * time.Second,
		deadTimeout:    60 * time.Second,
		lastStatus:     make(map[string]HealthStatus),
		autoRemoveDead: false,
	}
}

// WithAutoRemove enables automatic removal of dead streams.
func (hm *HealthMonitor) WithAutoRemove(timeout time.Duration) *HealthMonitor {
	hm.autoRemoveDead = true
	hm.deadTimeout = timeout
	return hm
}

// OnEvent registers a callback for health status changes.
func (hm *HealthMonitor) OnEvent(fn func(StreamHealthEvent)) {
	hm.onEvent = fn
}

// Start begins the health monitoring loop. Blocks until ctx is cancelled.
func (hm *HealthMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hm.check()
		}
	}
}

func (hm *HealthMonitor) check() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	snapshots := hm.relay.Snapshot()
	activeStreams := make(map[string]bool)

	for _, ss := range snapshots {
		activeStreams[ss.MountName] = true

		// Get last data received from the stream
		stream, ok := hm.relay.GetStream(ss.MountName)
		if !ok {
			continue
		}

		stream.mu.RLock()
		lastData := stream.LastDataReceived
		started := stream.Started
		stream.mu.RUnlock()

		// If never received data, use stream start time for timeout calculation
		checkTime := lastData
		if checkTime.IsZero() {
			checkTime = started
		}

		newStatus := calculateHealthStatus(checkTime)
		oldStatus, known := hm.lastStatus[ss.MountName]
		if !known {
			oldStatus = StatusHealthy
		}

		if newStatus != oldStatus {
			hm.lastStatus[ss.MountName] = newStatus
			logger.L.Infow("Stream health changed",
				"mount", ss.MountName,
				"from", oldStatus.String(),
				"to", newStatus.String(),
			)
			if hm.onEvent != nil {
				hm.onEvent(StreamHealthEvent{
					Mount:     ss.MountName,
					OldStatus: oldStatus,
					NewStatus: newStatus,
					Timestamp: time.Now(),
				})
			}
		}

		// Auto-remove dead streams
		if hm.autoRemoveDead && newStatus == StatusDead {
			silence := time.Since(checkTime)
			if silence > hm.deadTimeout {
				logger.L.Warnw("Auto-removing dead stream", "mount", ss.MountName, "silence", silence)
				hm.relay.RemoveStream(ss.MountName)
				delete(hm.lastStatus, ss.MountName)
			}
		}
	}

	// Clean up status for streams that no longer exist
	for mount := range hm.lastStatus {
		if !activeStreams[mount] {
			delete(hm.lastStatus, mount)
		}
	}
}
```

- [ ] **Step 4: Run test**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestHealthStatus -v`
Expected: PASS

- [ ] **Step 5: Add integration test**

Add to `relay/health_test.go`:

```go
func TestHealthMonitorDetectsStateChange(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test-health")
	s.LastDataReceived = time.Now().Add(-10 * time.Second) // 10s ago = degraded

	hm := NewHealthMonitor(r)

	var gotEvent *StreamHealthEvent
	hm.OnEvent(func(e StreamHealthEvent) {
		gotEvent = &e
	})

	// Run one check cycle
	hm.check()

	if gotEvent == nil {
		t.Fatal("expected health event, got none")
	}
	if gotEvent.NewStatus != StatusDegraded {
		t.Fatalf("expected Degraded, got %v", gotEvent.NewStatus)
	}
}
```

- [ ] **Step 6: Run all health tests**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./relay/ -run TestHealth -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add relay/health.go relay/health_test.go
git commit -m "feat: add stream health monitor with status tracking and auto-remove"
```

---

### Task 10: Add slow-listener detection to serveStreamData

**Files:**
- Modify: `server/handlers_stream.go`

Slow listeners that can't keep up accumulate `BytesDropped` but never get disconnected.

- [ ] **Step 1: Add skip counter and disconnect logic**

In `server/handlers_stream.go`, in `serveStreamData`, add a counter before the inner for loop:

```go
	consecutiveSkips := 0
	maxConsecutiveSkips := 5 // disconnect after 5 consecutive buffer skips
```

Inside the inner `for` loop, there are TWO skip paths that need the counter:

**Path 1:** The Ogg skip path (around line 325-328). Before the `continue`, add the counter:
```go
			if skipped && stream.IsOggStream {
				consecutiveSkips++
				if consecutiveSkips >= maxConsecutiveSkips {
					logger.L.Warnw("Slow listener disconnected (ogg sync skip)",
						"id", id, "mount", currentMount,
						"consecutive_skips", consecutiveSkips,
					)
					return false
				}
				offset = relay.FindNextPageBoundary(stream.Buffer.Data, stream.Buffer.Size, stream.Buffer.Head, next)
				continue
			}
```

**Path 2:** After the existing non-Ogg skip handling block (around line 333):
```go
			if skipped {
				atomic.AddInt64(&stream.BytesDropped, next-offset)
				consecutiveSkips++
				if consecutiveSkips >= maxConsecutiveSkips {
					logger.L.Warnw("Slow listener disconnected",
						"id", id, "mount", currentMount,
						"consecutive_skips", consecutiveSkips,
					)
					return false
				}
			} else {
				consecutiveSkips = 0
			}
```

- [ ] **Step 2: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add server/handlers_stream.go
git commit -m "fix: disconnect slow listeners after consecutive buffer skips"
```

---

### Task 11: Add fallback hysteresis to handleListener

**Files:**
- Modify: `server/handlers_stream.go`

When a primary stream comes back briefly and drops again, listeners ping-pong between mounts.

- [ ] **Step 1: Add hysteresis tracking**

In `server/handlers_stream.go`, in `handleListener`, add before the main `for` loop:

```go
	var primaryFirstSeen time.Time // when primary stream was first seen alive after fallback
	const fallbackHysteresis = 30 * time.Second
```

Replace the primary recovery check (the block around lines 231-236):

```go
		if mount != originalMount {
			if _, ok := s.Relay.GetStream(originalMount); ok {
				logger.L.Infow("Primary stream returned, recovering from fallback", "mount", originalMount)
				mount = originalMount
			}
		}
```

With:

```go
		if mount != originalMount {
			if _, ok := s.Relay.GetStream(originalMount); ok {
				if primaryFirstSeen.IsZero() {
					primaryFirstSeen = time.Now()
				}
				if time.Since(primaryFirstSeen) >= fallbackHysteresis {
					logger.L.Infow("Primary stream stable, recovering from fallback",
						"mount", originalMount,
						"stable_for", time.Since(primaryFirstSeen),
					)
					mount = originalMount
					primaryFirstSeen = time.Time{} // reset
				}
			} else {
				primaryFirstSeen = time.Time{} // reset if primary went away again
			}
		}
```

- [ ] **Step 2: Add X-Stream-Status header**

In `handleListener`, after `w.Header().Set("Content-Type", stream.ContentType)`, add:

```go
		if mount != originalMount {
			w.Header().Set("X-Stream-Status", "fallback")
		} else {
			w.Header().Set("X-Stream-Status", "primary")
		}
```

- [ ] **Step 3: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add server/handlers_stream.go
git commit -m "fix: add 30s hysteresis for fallback recovery, add X-Stream-Status header"
```

---

### Task 12: Wire health monitor into Server startup

**Files:**
- Modify: `server/server.go`

- [ ] **Step 1: Add HealthMonitor field to Server**

Add to the `Server` struct:

```go
	HealthM *relay.HealthMonitor
```

- [ ] **Step 2: Initialize in NewServer**

In `NewServer`, after the other manager initializations, add:

```go
	hm := relay.NewHealthMonitor(r)
```

And set it on the server:
```go
	HealthM: hm,
```

- [ ] **Step 3: Start health monitor in Server.Start**

In `Server.Start()`, after the existing `go s.statsRecordingTask()` line, add:

```go
	go s.HealthM.Start(context.Background())
```

Note: The health monitor's context should ideally be tied to the server lifecycle. For now, it will be stopped when the process exits. A cleaner approach would be to create a cancellable context in `Start()` and cancel it in `Shutdown()`, but that can be done in a follow-up.

Wire up webhook events — after `HealthM` creation in `NewServer`, add:

```go
	hm.OnEvent(func(e relay.StreamHealthEvent) {
		// Dispatch webhook for health state changes
		// This will be wired to the webhook system
		logger.L.Infow("Stream health event",
			"mount", e.Mount,
			"old_status", e.OldStatus.String(),
			"new_status", e.NewStatus.String(),
		)
	})
```

- [ ] **Step 4: Build and verify**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build ./...`
Expected: No errors

- [ ] **Step 5: Run all tests**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./... -v -race`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
cd /Users/dev/dev/tinyice-streaming-hardening
git add server/server.go
git commit -m "feat: wire stream health monitor into server startup"
```

---

## Deferred Items (Phase 1b)

These spec items are deferred to a follow-up plan to keep this plan focused:

- **BytesIn/BytesOut rolling rate calculation** (spec 1.1) — needs a ring buffer of timestamped counters
- **Relay `MaxRetries` config** (spec 1.2) — add to `RelayConfig` and `runRelay` loop
- **AutoDJ granular error handling** (spec 1.2) — classify decoder errors in `runStreamerLoop`
- **WebRTC sync limit configurability and timeout** (spec 1.2) — make 512KB limit and search timeout configurable
- **WebRTC ICE restart support** (spec 1.2)
- **WebRTC DTLS fingerprint logging** (spec 1.2)
- **Per-listener stats** (spec 1.3) — bytes sent, drops, latency estimate per listener
- **Listener connection duration tracking** (spec 1.3)
- **Silence/comfort noise on buffer underrun** (spec 1.4)
- **Webhook dispatch for health events** (spec 1.3) — Task 12 logs events but does not call `dispatchWebhook`

---

## Final Verification

- [ ] **Step 1: Full build**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go build -o /dev/null ./...`
Expected: Clean build

- [ ] **Step 2: Full test suite with race detector**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go test ./... -race -v`
Expected: All PASS

- [ ] **Step 3: Vet**

Run: `cd /Users/dev/dev/tinyice-streaming-hardening && go vet ./...`
Expected: No issues
