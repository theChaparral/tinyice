package relay

import (
	"bytes"
)

// FindNextPageBoundary searches for the next "OggS" magic in the buffer starting from 'start'
// This is used for Ogg/Opus stream synchronization
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
		idx := bytes.Index(segment, []byte(magic))
		if idx != -1 {
			return i + int64(idx)
		}
		i += n - 3 // Overlap
	}
	return head
}
