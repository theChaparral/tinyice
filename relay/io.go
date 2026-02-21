package relay

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// StreamWriter is a generic writer that broadcasts data to a stream and optionally tracks statistics
type StreamWriter struct {
	stream    *Stream
	relay     *Relay
	stats     *int64
	headerBuf *bytes.Buffer
	capture   bool
	debug     bool
	name      string
}

// NewStreamWriter creates a new StreamWriter
func NewStreamWriter(stream *Stream, relay *Relay) *StreamWriter {
	return &StreamWriter{
		stream: stream,
		relay:  relay,
	}
}

// WithStats enables statistics tracking
func (w *StreamWriter) WithStats(stats *int64) *StreamWriter {
	w.stats = stats
	return w
}

// WithHeaderCapture enables Ogg header capture
func (w *StreamWriter) WithHeaderCapture() *StreamWriter {
	w.headerBuf = &bytes.Buffer{}
	w.capture = true
	return w
}

// WithDebug enables debug logging
func (w *StreamWriter) WithDebug(name string) *StreamWriter {
	w.debug = true
	w.name = name
	return w
}

// Write implements io.Writer interface
func (w *StreamWriter) Write(p []byte) (n int, err error) {
	if w.capture && w.headerBuf != nil {
		w.headerBuf.Write(p)
	}
	
	if w.debug {
		logrus.Debugf("StreamWriter(%s): Broadcasting %d bytes to %s", w.name, len(p), w.stream.MountName)
	}
	
	w.stream.Broadcast(p, w.relay)
	
	if w.stats != nil {
		atomic.AddInt64(w.stats, int64(len(p)))
	}
	
	return len(p), nil
}

// GetCapturedHeaders returns captured Ogg headers (if capture was enabled)
func (w *StreamWriter) GetCapturedHeaders() []byte {
	if w.headerBuf != nil {
		return w.headerBuf.Bytes()
	}
	return nil
}

// StreamReader is a generic reader that reads from a circular buffer with signal-based notification
type StreamReader struct {
	buffer   *CircularBuffer
	offset   int64
	signal   chan struct{}
	ctx      context.Context
	id       string
	oggSync  bool
	stream   *Stream // Optional reference to stream for Ogg synchronization
}

// NewStreamReader creates a new StreamReader
func NewStreamReader(buffer *CircularBuffer, offset int64, signal chan struct{}, ctx context.Context, id string) *StreamReader {
	return &StreamReader{
		buffer: buffer,
		offset: offset,
		signal: signal,
		ctx:    ctx,
		id:     id,
	}
}

// WithOggSync enables Ogg page boundary synchronization
func (r *StreamReader) WithOggSync(stream *Stream) *StreamReader {
	r.oggSync = true
	r.stream = stream
	return r
}

// Read implements io.Reader interface
func (r *StreamReader) Read(p []byte) (int, error) {
	for {
		n, next, skipped := r.buffer.ReadAt(r.offset, p)
		
		// Handle Ogg synchronization if enabled
		if skipped && r.oggSync && r.stream != nil {
			r.stream.mu.RLock()
			r.offset = FindNextPageBoundary(r.stream.Buffer.Data, r.stream.Buffer.Size, r.stream.Buffer.Head, next)
			r.stream.mu.RUnlock()
			continue // Retry read at aligned offset
		}
		
		if n > 0 {
			r.offset = next
			return n, nil
		}

		// Wait for new data or context cancellation
		select {
		case <-r.ctx.Done():
			return 0, io.EOF
		case _, ok := <-r.signal:
			if !ok {
				return 0, io.EOF
			}
		}
	}
}