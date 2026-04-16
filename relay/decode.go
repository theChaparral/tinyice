package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jfreymuth/oggvorbis"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/kazzmir/opus-go/opus"
	"github.com/mewkiz/flac"
	"github.com/mewkiz/flac/frame"
	"github.com/hajimehoshi/go-mp3"
)

// PCMDecoder produces interleaved signed 16-bit little-endian stereo PCM
// via the embedded io.Reader, at the rate reported by SampleRate().
//
// Channels are always 2 (mono inputs are duplicated, >2 channel inputs are
// downmixed to the first two channels) so downstream encoders don't need to
// special-case the layout.
type PCMDecoder interface {
	io.Reader
	SampleRate() int
}

// OpenDecoder inspects the first few bytes of r and returns a PCMDecoder
// that streams S16LE stereo PCM. It supports MP3, Ogg Opus, Ogg Vorbis, and
// native FLAC.
func OpenDecoder(r io.Reader) (PCMDecoder, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	peek, err := br.Peek(128)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return nil, fmt.Errorf("decode: peek failed: %w", err)
	}
	if len(peek) < 4 {
		return nil, fmt.Errorf("decode: stream too short")
	}

	switch {
	case peek[0] == 'I' && peek[1] == 'D' && peek[2] == '3':
		return newMP3Decoder(br)
	case peek[0] == 0xFF && peek[1]&0xE0 == 0xE0:
		return newMP3Decoder(br)
	case bytes.Equal(peek[:4], []byte("fLaC")):
		return newFLACDecoder(br)
	case bytes.Equal(peek[:4], []byte("OggS")):
		if bytes.Contains(peek, []byte("OpusHead")) {
			return newOggOpusDecoder(br)
		}
		// Vorbis identification packet is "\x01vorbis". Accept either a strict
		// check or the textual "vorbis" token anywhere in the first page.
		if bytes.Contains(peek, []byte("vorbis")) {
			return newOggVorbisDecoder(br)
		}
		return nil, fmt.Errorf("decode: unknown Ogg codec (first 128 bytes do not mention Opus or Vorbis)")
	}
	return nil, fmt.Errorf("decode: unknown audio format (header: %x)", peek[:4])
}

// --- MP3 --------------------------------------------------------------------

type mp3Decoder struct {
	*mp3.Decoder
}

func newMP3Decoder(r io.Reader) (PCMDecoder, error) {
	d, err := mp3.NewDecoder(r)
	if err != nil {
		return nil, fmt.Errorf("decode mp3: %w", err)
	}
	return &mp3Decoder{d}, nil
}

func (m *mp3Decoder) SampleRate() int { return m.Decoder.SampleRate() }

// --- Ogg Vorbis -------------------------------------------------------------

type vorbisDecoder struct {
	r        *oggvorbis.Reader
	pcmF     []float32
	pending  []byte
	channels int
}

func newOggVorbisDecoder(r io.Reader) (PCMDecoder, error) {
	vr, err := oggvorbis.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("decode vorbis: %w", err)
	}
	if vr.Channels() < 1 {
		return nil, fmt.Errorf("decode vorbis: invalid channel count %d", vr.Channels())
	}
	return &vorbisDecoder{
		r:        vr,
		pcmF:     make([]float32, 4096*vr.Channels()),
		channels: vr.Channels(),
	}, nil
}

func (v *vorbisDecoder) SampleRate() int { return v.r.SampleRate() }

func (v *vorbisDecoder) Read(p []byte) (int, error) {
	for len(v.pending) == 0 {
		n, err := v.r.Read(v.pcmF)
		if n == 0 {
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		frames := n / v.channels
		v.pending = float32ToStereoS16LE(v.pcmF[:n], v.channels, frames, v.pending[:0])
	}
	n := copy(p, v.pending)
	v.pending = v.pending[n:]
	return n, nil
}

// --- Ogg Opus ---------------------------------------------------------------

type opusDecoder struct {
	reader   *ogg.OpusReader
	dec      *opus.Decoder
	pcm      []int16
	pending  []byte
	channels int
}

func newOggOpusDecoder(r io.Reader) (PCMDecoder, error) {
	or, err := ogg.NewOpusReader(r)
	if err != nil {
		return nil, fmt.Errorf("decode opus: read header: %w", err)
	}
	dec, err := opus.NewDecoderFromHead(or.Head)
	if err != nil {
		return nil, fmt.Errorf("decode opus: init decoder: %w", err)
	}
	ch := dec.Channels()
	if ch < 1 {
		ch = 1
	}
	// Opus frames are at most 120 ms. At 48 kHz that's 5760 samples per channel.
	return &opusDecoder{
		reader:   or,
		dec:      dec,
		pcm:      make([]int16, 5760*ch),
		channels: ch,
	}, nil
}

func (o *opusDecoder) SampleRate() int { return o.dec.SampleRate() }

func (o *opusDecoder) Read(p []byte) (int, error) {
	for len(o.pending) == 0 {
		pkt, err := o.reader.ReadAudioPacket()
		if err != nil {
			return 0, err
		}
		if pkt == nil {
			return 0, io.EOF
		}
		samples, _, derr := o.dec.DecodePacket(pkt, o.pcm)
		if derr != nil {
			return 0, fmt.Errorf("decode opus: %w", derr)
		}
		if len(samples) == 0 {
			continue
		}
		frames := len(samples) / o.channels
		o.pending = int16ToStereoS16LE(samples, o.channels, frames, o.pending[:0])
	}
	n := copy(p, o.pending)
	o.pending = o.pending[n:]
	return n, nil
}

// --- FLAC -------------------------------------------------------------------

type flacDecoder struct {
	stream   *flac.Stream
	pending  []byte
	channels int
	bitDepth int
}

func newFLACDecoder(r io.Reader) (PCMDecoder, error) {
	s, err := flac.New(r)
	if err != nil {
		return nil, fmt.Errorf("decode flac: %w", err)
	}
	if s.Info == nil {
		return nil, fmt.Errorf("decode flac: missing StreamInfo")
	}
	return &flacDecoder{
		stream:   s,
		channels: int(s.Info.NChannels),
		bitDepth: int(s.Info.BitsPerSample),
	}, nil
}

func (f *flacDecoder) SampleRate() int { return int(f.stream.Info.SampleRate) }

func (f *flacDecoder) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		fr, err := f.stream.ParseNext()
		if err != nil {
			return 0, err
		}
		if fr == nil || len(fr.Subframes) == 0 {
			continue
		}
		f.pending = flacFrameToStereoS16LE(fr, f.channels, f.bitDepth, f.pending[:0])
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

// --- conversion helpers -----------------------------------------------------

func clampInt32ToInt16(v int32) int16 {
	if v > 32767 {
		return 32767
	}
	if v < -32768 {
		return -32768
	}
	return int16(v)
}

func clampFloatToInt16(v float32) int16 {
	s := v * 32767.0
	if s > 32767 {
		return 32767
	}
	if s < -32768 {
		return -32768
	}
	return int16(s)
}

// float32ToStereoS16LE converts an interleaved float32 block with `channels`
// channels and `frames` sample-frames into interleaved S16LE stereo, appending
// to dst.
func float32ToStereoS16LE(src []float32, channels, frames int, dst []byte) []byte {
	tmp := make([]byte, 0, frames*4)
	for i := 0; i < frames; i++ {
		var l, r float32
		switch channels {
		case 1:
			l = src[i]
			r = l
		default:
			l = src[i*channels]
			r = src[i*channels+1]
		}
		li := clampFloatToInt16(l)
		ri := clampFloatToInt16(r)
		tmp = append(tmp, byte(li), byte(li>>8), byte(ri), byte(ri>>8))
	}
	return append(dst, tmp...)
}

// int16ToStereoS16LE converts an interleaved int16 block with `channels`
// channels and `frames` sample-frames into interleaved S16LE stereo, appending
// to dst.
func int16ToStereoS16LE(src []int16, channels, frames int, dst []byte) []byte {
	tmp := make([]byte, 0, frames*4)
	for i := 0; i < frames; i++ {
		var l, r int16
		switch channels {
		case 1:
			l = src[i]
			r = l
		default:
			l = src[i*channels]
			r = src[i*channels+1]
		}
		tmp = append(tmp, byte(l), byte(l>>8), byte(r), byte(r>>8))
	}
	return append(dst, tmp...)
}

// flacFrameToStereoS16LE converts a FLAC frame's subframes (int32 at bitDepth)
// into interleaved S16LE stereo, appending to dst.
func flacFrameToStereoS16LE(fr *frame.Frame, channels, bitDepth int, dst []byte) []byte {
	if channels <= 0 || len(fr.Subframes) == 0 {
		return dst
	}
	shift := bitDepth - 16
	nSamples := fr.Subframes[0].NSamples
	tmp := make([]byte, 0, nSamples*4)
	left := fr.Subframes[0].Samples
	var right []int32
	if channels >= 2 && len(fr.Subframes) >= 2 {
		right = fr.Subframes[1].Samples
	} else {
		right = left
	}
	for i := 0; i < nSamples; i++ {
		var ls, rs int32
		if i < len(left) {
			ls = left[i]
		}
		if i < len(right) {
			rs = right[i]
		}
		if shift > 0 {
			ls >>= shift
			rs >>= shift
		} else if shift < 0 {
			ls <<= uint(-shift)
			rs <<= uint(-shift)
		}
		li := clampInt32ToInt16(ls)
		ri := clampInt32ToInt16(rs)
		tmp = append(tmp, byte(li), byte(li>>8), byte(ri), byte(ri>>8))
	}
	return append(dst, tmp...)
}

// --- Ogg header parsing (used by Icecast SOURCE handler) --------------------

// FindOggHeaderEnd walks Ogg pages in data and returns the byte offset where
// the first audio data page begins, i.e. the first page whose granule
// position is not zero and not 0xFFFFFFFFFFFFFFFF (the continuation marker).
//
// If data does not yet contain a complete non-header page, needMore=true and
// endPos is undefined.
//
// If the buffer is malformed (no OggS magic at offset 0), abort=true signals
// that capture should stop so a non-Ogg stream doesn't hang the caller.
func FindOggHeaderEnd(data []byte) (endPos int, needMore bool, abort bool) {
	offset := 0
	for {
		if offset+27 > len(data) {
			return 0, true, false
		}
		if !bytes.Equal(data[offset:offset+4], []byte("OggS")) {
			return 0, false, true
		}
		numSegments := int(data[offset+26])
		headerLen := 27 + numSegments
		if offset+headerLen > len(data) {
			return 0, true, false
		}
		bodyLen := 0
		for i := 0; i < numSegments; i++ {
			bodyLen += int(data[offset+27+i])
		}
		pageLen := headerLen + bodyLen
		if offset+pageLen > len(data) {
			return 0, true, false
		}
		granule := binary.LittleEndian.Uint64(data[offset+6:])
		if granule != 0 && granule != 0xFFFFFFFFFFFFFFFF {
			return offset, false, false
		}
		offset += pageLen
	}
}
