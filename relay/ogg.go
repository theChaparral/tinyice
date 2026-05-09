package relay

import (
	"bytes"
)

// isValidOggPage checks if bytes at the given absolute position form a valid Ogg page header.
// Ogg page header: [0:4] "OggS", [4] version (must be 0), [26] number_page_segments, [27:27+N] segment table.
func isValidOggPage(data []byte, bufferSize int64, pos int64, head int64) bool {
	headerEnd := pos + 27
	if headerEnd > head {
		return false
	}
	verPos := (pos + 4) % bufferSize
	if data[verPos] != 0 {
		return false
	}
	segPos := (pos + 26) % bufferSize
	numSegments := data[segPos]
	fullHeaderEnd := pos + 27 + int64(numSegments)
	if fullHeaderEnd > head {
		return false
	}
	return true
}

// FindNextPageBoundary searches for the next valid Ogg page boundary in the buffer.
//
// The previous implementation had a production-fatal bug: at the
// circular-buffer wrap point `pos + n > bufferSize` clamps n to as
// little as 1, 2, or 3 bytes. With `i += n - 3` the iterator then
// stayed put (n=3 → +0) or moved backwards (n=2 → -1, n=1 → -2),
// spinning forever inside the loop. Because callers hold
// CircularBuffer.mu.RLock for the duration of the scan, every
// Broadcast (which needs cb.mu.Lock) eventually blocked, which in
// turn blocked Stream.Snapshot, which blocked Relay.Snapshot, which
// blocked Relay.GetStream, which froze every HTTPS handler that
// touched the relay map. Confirmed live in r4dio's pprof goroutine
// dump: one StreamReader stuck in this loop for 3+ minutes; 100+
// goroutines queued behind it.
//
// The fix: tracker step is `max(n - magicLen + 1, 1)` so we always
// move forward by at least 1 byte. We also skip the search entirely
// when n < magicLen — there's no room for the 4-byte magic in fewer
// bytes, and the caller is allowed to miss an "OggS" that straddles
// a circular-buffer wrap (those are rare; the next page boundary a
// few bytes later still resyncs listeners).
func FindNextPageBoundary(buffer []byte, bufferSize, head, start int64) int64 {
	if start < head-bufferSize {
		start = head - bufferSize
	}
	if start >= head-4 {
		return head
	}

	const magic = "OggS"
	const magicLen = int64(len(magic))
	for i := start; i < head-4; {
		pos := i % bufferSize
		n := int64(32 * 1024)
		if i+n > head {
			n = head - i
		}
		if pos+n > bufferSize {
			n = bufferSize - pos
		}
		if n <= 0 {
			// Defensive — shouldn't be reachable given the loop
			// condition above, but if it ever is, avoid an
			// infinite loop.
			break
		}

		if n >= magicLen {
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
				searchStart += int64(idx) + 1
				if searchStart >= int64(len(segment)) {
					break
				}
			}
		}
		// Advance by n - 3 so a magic that straddles the next
		// segment boundary is still detectable, but never less
		// than 1 byte — otherwise, at the wrap point the loop
		// pinned cb.mu.RLock and deadlocked the whole relay.
		step := n - magicLen + 1
		if step < 1 {
			step = 1
		}
		i += step
	}
	return head
}
