// Package relay provides the core audio streaming and relay functionality for TinyIce.
//
// The relay package implements the fundamental components needed for internet radio
// streaming including circular buffers for audio data, stream management for multiple
// mount points, listener connection handling, and various audio format support.
package relay

import (
	"sync"
)

// CircularBuffer is a thread-safe fixed-size ring buffer for stream data.
//
// This buffer implementation is optimized for audio streaming scenarios where
// multiple listeners may connect at different times and need instant access
// to recent audio data. Old data can be safely overwritten when the buffer
// is full.
//
// The buffer uses absolute positioning (Head) to track write positions,
// allowing listeners to subscribe at different offsets and catch up to
// the live stream.
//
// Performance Characteristics:
//   - O(1) write operations (amortized)
//   - O(1) read operations for non-wrapping reads
//   - Thread-safe with RWMutex for concurrent access
//   - Fixed memory footprint (no dynamic allocations during operation)
//
// Typical Usage:
//   buffer := NewCircularBuffer(512 * 1024) // 512KB buffer
//   buffer.Write(audioData)
//   bytesRead, newOffset, skipped := buffer.ReadAt(offset, readBuffer)
type CircularBuffer struct {
	Data []byte       // The actual buffer storage
	Size int64        // Maximum size of the buffer in bytes
	Head int64        // Current write position (absolute, monotonically increasing)
	mu   sync.RWMutex // Mutex for thread-safe operations
}

// NewCircularBuffer creates a new CircularBuffer with the specified size.
//
// The size parameter determines the maximum amount of audio data that can be
// buffered. Typical values range from 64KB to 2MB depending on the expected
// listener latency requirements. Larger buffers allow listeners to rewind further
// but consume more memory.
func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		Data: make([]byte, size),
		Size: int64(size),
	}
}

// Write appends data to the circular buffer.
//
// Write is thread-safe and can be called concurrently from multiple goroutines.
// The data is written in chunks, automatically handling buffer wrap-around.
// The method locks the buffer for the entire duration of the write operation.
//
// Performance characteristics:
//   - O(1) complexity for typical writes
//   - Locks the buffer during the entire operation
//   - Handles partial writes when data spans buffer boundaries
func (cb *CircularBuffer) Write(p []byte) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Write data in chunks, handling buffer wrap-around
	// This loop continues until all data is written
	for len(p) > 0 {
		pos := cb.Head % cb.Size    // Calculate position within buffer bounds
		n := copy(cb.Data[pos:], p) // Copy as much as fits in current segment
		cb.Head += int64(n)         // Advance write position
		p = p[n:]                   // Advance source pointer
	}
}

// ReadAt reads data from the buffer starting at the absolute offset 'start'.
//
// ReadAt is designed for audio streaming scenarios where listeners may connect
// at different times and need to catch up to the live stream. It handles
// buffer wrap-around automatically and limits reads to available data.
//
// If the requested position is ahead of the current write position, ReadAt
// returns (0, start, false) indicating no data is available. If the listener
// is too far behind (> buffer size), it skips to the oldest available data
// and returns the skipped flag as true.
//
// ReadAt uses RLock for read operations, allowing concurrent reads from
// multiple goroutines. This makes it safe to call from any goroutine.
//
// Example:
//   bytesRead, newOffset, wasSkipped := buffer.ReadAt(currentOffset, audioBuffer)
func (cb *CircularBuffer) ReadAt(start int64, p []byte) (int, int64, bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	skipped := false
	
	// If requested position is ahead of current write position, no data available
	if start >= cb.Head {
		return 0, start, false
	}

	// Don't read more than we have or what's available in the buffer
	// If listener is too far behind (> buffer size), skip to oldest available data
	if cb.Head-start > cb.Size {
		start = cb.Head - cb.Size // Listener is too slow, skip to oldest available
		skipped = true
	}

	pos := start % cb.Size   // Calculate read position within buffer bounds
	available := cb.Head - start // Calculate available bytes from start position
	n := int64(len(p))        // Requested read size
	
	// Limit read to available data
	if n > available {
		n = available
	}

	// Handle wrap-around: if read would cross buffer boundary, limit to segment
	if pos+n > cb.Size {
		n = cb.Size - pos
	}

	// Perform the actual read
	actual := copy(p, cb.Data[pos:pos+n])
	return actual, start + int64(actual), skipped
}

