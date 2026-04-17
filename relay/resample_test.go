package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"testing"
)

// s16LESineStereo produces `frames` stereo S16LE frames of a sine wave at
// `freq` Hz sampled at `rate` Hz.
func s16LESineStereo(rate, freq, frames int, amp float64) []byte {
	buf := make([]byte, frames*4)
	for i := 0; i < frames; i++ {
		v := int16(amp * 32767 * math.Sin(2*math.Pi*float64(freq)*float64(i)/float64(rate)))
		binary.LittleEndian.PutUint16(buf[i*4:], uint16(v))
		binary.LittleEndian.PutUint16(buf[i*4+2:], uint16(v))
	}
	return buf
}

func TestLinearResampler_Passthrough(t *testing.T) {
	// Matching rates: should return the src unchanged.
	src := bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	out := NewLinearResampler(src, 48000, 48000)
	if out != src {
		t.Errorf("expected passthrough when in/out rates match, got %T", out)
	}
}

func TestLinearResampler_Upsample44kTo48k_FrameCount(t *testing.T) {
	// 1 second of 44100 stereo = 44100 frames. After resample to 48k we
	// expect ~48000 frames (within a couple of frames of tolerance due to
	// the leading interpolator warm-up).
	in := s16LESineStereo(44100, 1000, 44100, 0.5)
	r := NewLinearResampler(bytes.NewReader(in), 44100, 48000)
	got, err := io.ReadAll(r)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("read: %v", err)
	}
	frames := len(got) / 4
	// Expect roughly 48000 ± small margin.
	if frames < 47900 || frames > 48100 {
		t.Errorf("frames=%d, want approximately 48000", frames)
	}
}

func TestLinearResampler_Downsample96kTo48k_FrameCount(t *testing.T) {
	in := s16LESineStereo(96000, 1000, 96000, 0.5)
	r := NewLinearResampler(bytes.NewReader(in), 96000, 48000)
	got, err := io.ReadAll(r)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("read: %v", err)
	}
	frames := len(got) / 4
	// 96k → 48k is 2:1 downsample, so 96000 → ~48000.
	if frames < 47900 || frames > 48100 {
		t.Errorf("frames=%d, want approximately 48000", frames)
	}
}

func TestLinearResampler_PreservesAmplitude(t *testing.T) {
	// 440 Hz sine, half-amplitude. After resampling we should still see
	// peak magnitudes close to 0.5 * 32767 = 16383.
	in := s16LESineStereo(44100, 440, 44100, 0.5)
	r := NewLinearResampler(bytes.NewReader(in), 44100, 48000)
	got, err := io.ReadAll(r)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("read: %v", err)
	}
	var maxAbs int16
	for i := 0; i+1 < len(got); i += 4 {
		v := int16(binary.LittleEndian.Uint16(got[i:]))
		if v < 0 {
			v = -v
		}
		if v > maxAbs {
			maxAbs = v
		}
	}
	if maxAbs < 15500 || maxAbs > 17000 {
		t.Errorf("peak=%d, want ~16383 (within ±1000)", maxAbs)
	}
}
