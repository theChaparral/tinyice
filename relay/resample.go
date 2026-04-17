package relay

import (
	"encoding/binary"
	"io"
)

// LinearResampler wraps an io.Reader of interleaved S16LE stereo PCM and
// emits interleaved S16LE stereo PCM at a different sample rate using linear
// interpolation between consecutive input frames.
//
// This is a correctness-first implementation, not a studio-grade one. It
// fixes the "Opus transcoder plays 8.8% too fast" bug by giving the Opus
// encoder the 48 kHz samples it expects even when the decoder produces
// 44.1 / 22.05 / 32 / 96 kHz. A proper band-limited sinc resampler would
// give nicer high-frequency behaviour but is substantially more work; the
// goal here is to eliminate audible speed drift.
//
// The resampler is not safe for concurrent use. Construct one per
// transcoder / AutoDJ pipeline.
type LinearResampler struct {
	src     io.Reader
	inRate  int
	outRate int

	// Previous input frame — interpolation anchor.
	prevL, prevR int16
	havePrev     bool

	// acc is a position counter in [0, outRate). When acc < outRate we emit
	// the output sample at position acc/outRate between prev and curr, then
	// advance acc += inRate. When acc >= outRate we've passed the current
	// input frame; subtract outRate and consume the next input.
	acc int64

	// Input read buffer.
	inBuf []byte

	// Pending output bytes waiting to be delivered to the caller.
	pending []byte
}

// NewLinearResampler returns a resampler converting inRate → outRate. If the
// rates match it returns src unchanged (as an io.Reader) to avoid pointless
// allocation and sample touching.
func NewLinearResampler(src io.Reader, inRate, outRate int) io.Reader {
	if inRate == outRate || inRate <= 0 || outRate <= 0 {
		return src
	}
	return &LinearResampler{
		src:     src,
		inRate:  inRate,
		outRate: outRate,
	}
}

func (r *LinearResampler) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		// Read more input. Size chosen to keep each Read cheap while
		// producing enough output to avoid thrashing.
		const inFrames = 1024
		need := inFrames * 4
		if cap(r.inBuf) < need {
			r.inBuf = make([]byte, need)
		}
		r.inBuf = r.inBuf[:need]
		n, err := io.ReadFull(r.src, r.inBuf)
		if n == 0 {
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		// Trim to whole stereo frames.
		n -= n % 4
		if n == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		r.pending = r.processInput(r.inBuf[:n], r.pending[:0])
		// If the source is at EOF but we've produced some output, serve
		// that now; on the next Read we'll hit the src error path.
		if len(r.pending) > 0 {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	k := copy(p, r.pending)
	r.pending = r.pending[k:]
	return k, nil
}

// processInput consumes `in` (whole stereo S16LE frames) and appends
// resampled output frames to dst.
func (r *LinearResampler) processInput(in []byte, dst []byte) []byte {
	frames := len(in) / 4
	for i := 0; i < frames; i++ {
		currL := int16(binary.LittleEndian.Uint16(in[i*4:]))
		currR := int16(binary.LittleEndian.Uint16(in[i*4+2:]))

		if !r.havePrev {
			// First input frame — anchor and emit nothing yet; we need a
			// pair of input frames before we can interpolate.
			r.prevL, r.prevR = currL, currR
			r.havePrev = true
			continue
		}

		// Emit output samples while acc still falls between prev and curr.
		for r.acc < int64(r.outRate) {
			frac := float64(r.acc) / float64(r.outRate)
			ol := int16(float64(r.prevL)*(1.0-frac) + float64(currL)*frac)
			or := int16(float64(r.prevR)*(1.0-frac) + float64(currR)*frac)
			dst = append(dst,
				byte(uint16(ol)),
				byte(uint16(ol)>>8),
				byte(uint16(or)),
				byte(uint16(or)>>8),
			)
			r.acc += int64(r.inRate)
		}
		r.acc -= int64(r.outRate)
		r.prevL, r.prevR = currL, currR
	}
	return dst
}
