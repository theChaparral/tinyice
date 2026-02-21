package relay

import (
	"sync"
)

// CircularBuffer is a thread-safe fixed-size ring buffer for stream data
type CircularBuffer struct {
	Data []byte
	Size int64
	Head int64 // Current write position (absolute)
	mu   sync.RWMutex
}

func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		Data: make([]byte, size),
		Size: int64(size),
	}
}

func (cb *CircularBuffer) Write(p []byte) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	for len(p) > 0 {
		pos := cb.Head % cb.Size
		n := copy(cb.Data[pos:], p)
		cb.Head += int64(n)
		p = p[n:]
	}
}

// ReadAt reads data from the buffer starting at the absolute offset 'start'
func (cb *CircularBuffer) ReadAt(start int64, p []byte) (int, int64, bool) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	skipped := false
	if start >= cb.Head {
		return 0, start, false
	}

	// Don't read more than we have or what's available in the buffer
	if cb.Head-start > cb.Size {
		start = cb.Head - cb.Size // Listener is too slow, skip to oldest available
		skipped = true
	}

	pos := start % cb.Size
	available := cb.Head - start
	n := int64(len(p))
	if n > available {
		n = available
	}

	// Handle wrap-around
	if pos+n > cb.Size {
		n = cb.Size - pos
	}

	actual := copy(p, cb.Data[pos:pos+n])
	return actual, start + int64(actual), skipped
}

