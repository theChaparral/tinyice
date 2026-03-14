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
		n := int64(32 * 1024)
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
			searchStart += int64(idx) + 1
			if searchStart >= int64(len(segment)) {
				break
			}
		}
		i += n - 3
	}
	return head
}
