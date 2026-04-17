package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand"
)

// OggPageRewriter wraps an io.Writer, parses an Ogg page stream as bytes
// arrive, and rewrites each page's bitstream serial, page sequence, granule
// position and CRC before forwarding it on.
//
// Late-joining listeners on a passthrough Ogg source would otherwise see:
//
//	BOS   (granule 0, serial S, seq 0)
//	Tags  (granule 0, serial S, seq 1)
//	Audio (granule G_large, serial S, seq N_large)   ← multi-minute gap
//
// Strict decoders (ffmpeg with "sync" behaviour) interpret the granule jump
// as that many seconds of missing audio and fill it with concealment /
// silence — the symptom is a robotic / chirpy start and garbled time-base.
//
// The rewriter turns that into a clean chained stream:
//
//	BOS   (granule 0,   serial S', seq 0)
//	Tags  (granule 0,   serial S', seq 1)
//	Audio (granule 960, serial S', seq 2)
//	Audio (granule 1920, serial S', seq 3)
//	...
//
// The rewriter is stateful and not safe for concurrent use. Allocate one
// per listener.
type OggPageRewriter struct {
	dst io.Writer

	// Partial-page buffer. Pages arrive in arbitrarily-sized chunks from the
	// circular buffer read path; we accumulate here until a full page is
	// available.
	buf []byte

	// Output framing state.
	localSerial uint32
	localSeq    uint32

	// Granule rebase: subtracted from every non-zero, non-continuation
	// granule so the listener sees a timeline that starts near zero.
	granuleOffset  int64
	haveFirstAudio bool

	// PreSkip parsed from the most recently seen OpusHead BOS packet
	// (0 for Vorbis / FLAC-in-Ogg or when no OpusHead is present). The
	// first audio page after a BOS is anchored at PreSkip + 960 so a
	// strict Opus decoder doesn't skip past the entire first frame.
	preSkip int64

	// Scratch buffer reused across pages to avoid an allocation per page.
	scratch []byte
}

// NewOggPageRewriter allocates a rewriter with a random bitstream serial.
func NewOggPageRewriter(dst io.Writer) *OggPageRewriter {
	return &OggPageRewriter{
		dst:         dst,
		localSerial: randomSerial(),
	}
}

func randomSerial() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return mathrand.Uint32()
	}
	return binary.LittleEndian.Uint32(b[:])
}

// Write accepts arbitrary byte chunks, extracts complete Ogg pages, rewrites
// them and forwards them to the underlying writer. It always reports len(p)
// bytes consumed (the caller's accounting is in raw input bytes, not output).
// Partial pages are held until the next Write completes them.
func (r *OggPageRewriter) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	for {
		// Find the next candidate page start.
		idx := bytes.Index(r.buf, []byte("OggS"))
		if idx < 0 {
			// Retain the last 3 bytes so a partial "OggS" spanning a
			// Write boundary still resyncs.
			if len(r.buf) > 3 {
				r.buf = r.buf[len(r.buf)-3:]
			}
			break
		}
		if idx > 0 {
			// Discard any leading bytes that aren't part of a page — this
			// is normal right after a slow-listener seek, and also skips
			// past the bytes of a fake-OggS page we rejected below.
			r.buf = r.buf[idx:]
		}
		if len(r.buf) < 27 {
			break
		}
		numSegs := int(r.buf[26])
		hdrLen := 27 + numSegs
		if len(r.buf) < hdrLen {
			break
		}
		bodyLen := 0
		for i := 0; i < numSegs; i++ {
			bodyLen += int(r.buf[27+i])
		}
		pageLen := hdrLen + bodyLen
		if len(r.buf) < pageLen {
			break
		}
		// Verify the CRC on the source page before trusting it. "OggS" is
		// only 4 bytes and can appear inside Opus / Vorbis audio data —
		// without this check the rewriter would emit a bogus rewritten
		// page, and the decoder would give up.
		pageBytes := r.buf[:pageLen]
		claimedCRC := binary.LittleEndian.Uint32(pageBytes[22:26])
		// Zero CRC field in a scratch slice, recompute, and compare.
		if cap(r.scratch) < pageLen {
			r.scratch = make([]byte, pageLen)
		}
		r.scratch = r.scratch[:pageLen]
		copy(r.scratch, pageBytes)
		r.scratch[22], r.scratch[23], r.scratch[24], r.scratch[25] = 0, 0, 0, 0
		if oggCRC(r.scratch) != claimedCRC {
			// Fake OggS — advance one byte and keep scanning.
			r.buf = r.buf[1:]
			continue
		}
		r.rewritePage(r.scratch)
		if _, err := r.dst.Write(r.scratch); err != nil {
			return 0, err
		}
		r.buf = r.buf[pageLen:]
	}
	return len(p), nil
}

// rewritePage edits the page header in-place so it carries our serial,
// sequence counter, rebased granule, and a freshly computed CRC.
func (r *OggPageRewriter) rewritePage(page []byte) {
	headerType := page[5]
	isBOS := headerType&0x02 != 0

	// A BOS page seen *after* we've already emitted pages indicates a
	// chained logical stream (the source started a new stream without
	// tearing the mount down, or the sources in front of tinyice rotated
	// serials). Spec-compliant behaviour is to emit that as a new logical
	// stream with a fresh bitstream serial and seq=0. Without this reset
	// the rewriter would keep incrementing seq, giving the decoder a
	// non-zero-seq BOS page which most implementations reject.
	if isBOS && r.localSeq > 0 {
		r.localSerial = randomSerial()
		r.localSeq = 0
		r.haveFirstAudio = false
		r.granuleOffset = 0
		r.preSkip = 0
	}
	if isBOS {
		// Parse OpusHead PreSkip if this BOS carries one — it lets us
		// anchor the first audio granule past the decoder's required
		// skip window so we don't cut off the first packet.
		body := pageBodyOffset(page)
		if body > 0 && body+12 <= len(page) &&
			bytes.Equal(page[body:body+8], []byte("OpusHead")) {
			r.preSkip = int64(binary.LittleEndian.Uint16(page[body+10 : body+12]))
		}
	}

	rawGranule := binary.LittleEndian.Uint64(page[6:14])
	var newGranule uint64
	switch {
	case rawGranule == 0:
		newGranule = 0
	case rawGranule == 0xFFFFFFFFFFFFFFFF:
		// Continuation marker — preserve.
		newGranule = rawGranule
	default:
		if !r.haveFirstAudio {
			// Anchor first audio at PreSkip + 960 samples (one typical
			// 20 ms Opus frame at 48 kHz). For Opus this guarantees the
			// page's granule is past the encoder's delay window; for
			// Vorbis / FLAC-in-Ogg (PreSkip = 0) it reduces to the
			// previous behaviour of anchoring near zero.
			r.granuleOffset = int64(rawGranule) - (r.preSkip + 960)
			r.haveFirstAudio = true
		}
		rebased := int64(rawGranule) - r.granuleOffset
		if rebased < 0 {
			rebased = 0
		}
		newGranule = uint64(rebased)
	}
	binary.LittleEndian.PutUint64(page[6:14], newGranule)
	binary.LittleEndian.PutUint32(page[14:18], r.localSerial)
	binary.LittleEndian.PutUint32(page[18:22], r.localSeq)
	r.localSeq++

	// Zero the CRC field, then recompute across the whole page.
	page[22], page[23], page[24], page[25] = 0, 0, 0, 0
	binary.LittleEndian.PutUint32(page[22:26], oggCRC(page))
}

// pageBodyOffset returns the byte offset of the first body byte within a
// fully-buffered Ogg page, or -1 if the page header is truncated.
func pageBodyOffset(page []byte) int {
	if len(page) < 27 {
		return -1
	}
	numSegs := int(page[26])
	hdrLen := 27 + numSegs
	if len(page) < hdrLen {
		return -1
	}
	return hdrLen
}

// --- Ogg CRC32 -------------------------------------------------------------
//
// The Ogg spec uses CRC-32/MPEG-2: polynomial 0x04C11DB7, non-reflected
// input, non-reflected output, initial 0, no final XOR. The table is
// generated on the fly in a package-level init().

var oggCRCTable [256]uint32

func init() {
	for i := 0; i < 256; i++ {
		c := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if c&0x80000000 != 0 {
				c = (c << 1) ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		oggCRCTable[i] = c
	}
}

func oggCRC(data []byte) uint32 {
	var c uint32
	for _, b := range data {
		c = (c << 8) ^ oggCRCTable[byte(c>>24)^b]
	}
	return c
}
