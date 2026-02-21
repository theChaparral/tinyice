// Package relay provides the core audio streaming and relay functionality for TinyIce.
// It includes circular buffers, stream management, transcoding, and various protocol
// handlers for creating a complete internet radio streaming server.
package relay

import (
	"sync"
)

// CircularBuffer is a thread-safe fixed-size ring buffer for stream data.
//
// This buffer implementation is optimized for audio streaming scenarios where:
//   - Multiple listeners may connect at different times
//   - New listeners need instant access to recent audio data
//   - Old data can be safely overwritten when the buffer is full
//
// The buffer uses absolute positioning (Head) to track write positions, allowing
// listeners to subscribe at different offsets and catch up to the live stream.
//
// Performance Characteristics:
//   - O(1) write operations (amortized)
//   - O(1) read operations for non-wrapping reads
//   - Thread-safe with RWMutex for concurrent access
//   - Fixed memory footprint (no dynamic allocations during operation)
//
// Typical Usage:
//   - Create with NewCircularBuffer(size) where size is the maximum buffer size in bytes
//   - Write audio data with Write() method
//   - Read from specific positions with ReadAt() method
//   - Find Ogg page boundaries with FindNextPageBoundary() (in ogg.go)
type CircularBuffer struct {
	Data []byte      // The actual buffer storage
	Size int64       // Maximum size of the buffer in bytes
	Head int64       // Current write position (absolute, monotonically increasing)
	mu   sync.RWMutex // Mutex for thread-safe operations
}

// NewCircularBuffer creates a new CircularBuffer with the specified size.
//
// Parameters:
//   size - The size of the buffer in bytes. Typical values range from 64KB to 2MB
//     depending on the expected listener latency requirements.
//
// Returns:
//   A pointer to the initialized CircularBuffer ready for use.
//
// Example:
//   buffer := NewCircularBuffer(512 * 1024) // 512KB buffer
func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		Data: make([]byte, size),
		Size: int64(size),
	}
}

// Write appends data to the circular buffer.
//
// This method is thread-safe and can be called concurrently from multiple goroutines.
// The data is written in chunks, handling buffer wrap-around automatically.
//
// Parameters:
//   p - The byte slice containing data to write to the buffer
//
// Performance:
//   - Locks the buffer during the entire write operation
//   - Handles partial writes when data spans the buffer boundary
//   - O(1) complexity for typical writes
//
// Example:
//   buffer.Write(audioChunk)
func (cb *CircularBuffer) Write(p []byte) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Write data in chunks, handling buffer wrap-around
	// This loop continues until all data is written
	for len(p) > 0 {
		pos := cb.Head % cb.Size   // Calculate position within buffer bounds
		n := copy(cb.Data[pos:], p) // Copy as much as fits in current segment
		cb.Head += int64(n)         // Advance write position
		p = p[n:]                   // Advance source pointer
	}
}

// ReadAt reads data from the buffer starting at the absolute offset 'start'.
//
// This method is designed for audio streaming scenarios where listeners may connect
// at different times and need to catch up to the live stream.
//
// Parameters:
//   start - The absolute offset to start reading from
//   p     - The byte slice to read data into
//
// Returns:
//   int   - The number of bytes actually read
//   int64 - The new absolute offset after this read
//   bool  - True if the reader was skipped forward due to buffer wrap-around
//
// Behavior:
//   - Returns (0, start, false) if start >= current head (no data available)
//   - Automatically handles buffer wrap-around
//   - Limits reads to available data
//   - Skips to oldest available data if listener is too far behind
//
// Thread Safety:
//   - Uses RLock for read operations, allowing concurrent reads
//   - Safe to call from multiple goroutines simultaneously
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

