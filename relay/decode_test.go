package relay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeOggPage builds the bytes of a single Ogg page with the given granule
// position and body length. The body content is zero-filled.
func makeOggPage(granule uint64, serial uint32, seq uint32, bodyLen int) []byte {
	numSegments := (bodyLen + 254) / 255
	if numSegments == 0 {
		numSegments = 1
	}
	page := make([]byte, 0, 27+numSegments+bodyLen)
	page = append(page, 'O', 'g', 'g', 'S')
	page = append(page, 0) // version
	page = append(page, 0) // header type
	var gp [8]byte
	binary.LittleEndian.PutUint64(gp[:], granule)
	page = append(page, gp[:]...)
	var ser [4]byte
	binary.LittleEndian.PutUint32(ser[:], serial)
	page = append(page, ser[:]...)
	var sq [4]byte
	binary.LittleEndian.PutUint32(sq[:], seq)
	page = append(page, sq[:]...)
	page = append(page, 0, 0, 0, 0) // CRC — FindOggHeaderEnd doesn't verify
	page = append(page, byte(numSegments))
	remaining := bodyLen
	for i := 0; i < numSegments; i++ {
		if remaining >= 255 {
			page = append(page, 255)
			remaining -= 255
		} else {
			page = append(page, byte(remaining))
			remaining = 0
		}
	}
	page = append(page, make([]byte, bodyLen)...)
	return page
}

func TestFindOggHeaderEnd_HeadersThenAudio(t *testing.T) {
	hdr1 := makeOggPage(0, 42, 0, 19)       // OpusHead-sized BOS
	hdr2 := makeOggPage(0, 42, 1, 64)       // Tags
	audio := makeOggPage(960, 42, 2, 200)   // First audio page
	data := append(append(append([]byte{}, hdr1...), hdr2...), audio...)

	end, needMore, abort := FindOggHeaderEnd(data)
	if abort || needMore {
		t.Fatalf("unexpected flags: needMore=%v abort=%v", needMore, abort)
	}
	if end != len(hdr1)+len(hdr2) {
		t.Fatalf("end=%d, want %d", end, len(hdr1)+len(hdr2))
	}
}

func TestFindOggHeaderEnd_NeedMore(t *testing.T) {
	hdr := makeOggPage(0, 1, 0, 12)
	_, needMore, abort := FindOggHeaderEnd(hdr)
	if abort {
		t.Fatalf("abort unexpected")
	}
	if !needMore {
		t.Fatalf("expected needMore=true when no audio page yet")
	}
}

func TestFindOggHeaderEnd_Abort(t *testing.T) {
	// At least 27 bytes so the function gets past the "need more data" check
	// and actually evaluates the OggS magic.
	data := make([]byte, 64)
	copy(data, "ID3\x03\x00\x00")
	_, _, abort := FindOggHeaderEnd(data)
	if !abort {
		t.Fatalf("expected abort on non-Ogg bytes")
	}
}

func TestFindOggHeaderEnd_IgnoresContinuation(t *testing.T) {
	// A page whose granule is the magic continuation sentinel should be
	// treated as a header page, not audio.
	cont := makeOggPage(0xFFFFFFFFFFFFFFFF, 1, 0, 10)
	audio := makeOggPage(480, 1, 1, 20)
	data := append(cont, audio...)
	end, needMore, abort := FindOggHeaderEnd(data)
	if abort || needMore {
		t.Fatalf("unexpected flags: needMore=%v abort=%v", needMore, abort)
	}
	if end != len(cont) {
		t.Fatalf("end=%d, want %d", end, len(cont))
	}
}

func TestOpenDecoder_RejectsUnknown(t *testing.T) {
	_, err := OpenDecoder(bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03, 0x04}))
	if err == nil {
		t.Fatalf("expected error for unknown format")
	}
}

func TestOpenDecoder_DetectsMP3ID3(t *testing.T) {
	// We can't fully decode without a real MP3 frame, but the factory should
	// at least attempt the MP3 path and fail with an MP3-specific error.
	data := append([]byte("ID3\x03\x00\x00\x00\x00\x00\x00"), 0xFF, 0xFB)
	_, err := OpenDecoder(bytes.NewReader(data))
	if err == nil {
		return // some go-mp3 versions are lenient; either outcome is OK
	}
	// Error is fine — just make sure we didn't report "unknown format".
	if bytes.Contains([]byte(err.Error()), []byte("unknown audio format")) {
		t.Fatalf("MP3 sniff should not fall through to unknown: %v", err)
	}
}
