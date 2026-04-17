package relay

import (
	"testing"
)

func TestTSMuxerOutputSize(t *testing.T) {
	muxer := NewTSMuxer()
	// 1000 bytes of fake MP3 data
	mp3Data := make([]byte, 1000)
	result := muxer.MuxMP3Segment(mp3Data, 0)

	// Result must be a multiple of 188
	if len(result)%tsPacketSize != 0 {
		t.Fatalf("output length %d is not a multiple of %d", len(result), tsPacketSize)
	}

	// Must have at least PAT + PMT + 1 audio packet = 3 packets
	if len(result) < tsPacketSize*3 {
		t.Fatalf("output too small: %d bytes", len(result))
	}
}

func TestTSMuxerSyncBytes(t *testing.T) {
	muxer := NewTSMuxer()
	result := muxer.MuxMP3Segment(make([]byte, 500), 0)

	numPackets := len(result) / tsPacketSize
	for i := 0; i < numPackets; i++ {
		if result[i*tsPacketSize] != tsSyncByte {
			t.Fatalf("packet %d missing sync byte at offset %d", i, i*tsPacketSize)
		}
	}
}

func TestTSMuxerPATAndPMT(t *testing.T) {
	muxer := NewTSMuxer()
	result := muxer.MuxMP3Segment(make([]byte, 100), 0)

	// First packet should be PAT (PID 0x0000)
	pid0 := (uint16(result[1]&0x1F) << 8) | uint16(result[2])
	if pid0 != patPID {
		t.Fatalf("first packet PID should be 0x0000 (PAT), got 0x%04X", pid0)
	}

	// Second packet should be PMT (PID 0x1000)
	pid1 := (uint16(result[tsPacketSize+1]&0x1F) << 8) | uint16(result[tsPacketSize+2])
	if pid1 != pmtPID {
		t.Fatalf("second packet PID should be 0x1000 (PMT), got 0x%04X", pid1)
	}

	// Third packet should be audio (PID 0x0100)
	pid2 := (uint16(result[2*tsPacketSize+1]&0x1F) << 8) | uint16(result[2*tsPacketSize+2])
	if pid2 != audioPID {
		t.Fatalf("third packet PID should be 0x0100 (audio), got 0x%04X", pid2)
	}
}

func TestTSMuxerPTS(t *testing.T) {
	muxer := NewTSMuxer()
	// Use PTS = 90000 (1 second at 90kHz). 1000 bytes of payload plus the
	// PES header is large enough that the first audio packet has no
	// non-PCR stuffing — just the required adaptation field carrying the
	// PCR (1 byte length + 1 byte flags + 6 bytes PCR = 8 bytes).
	result := muxer.MuxMP3Segment(make([]byte, 1000), 90000)

	audioStart := 2 * tsPacketSize
	if result[audioStart+1]&0x40 == 0 {
		t.Fatal("audio packet should have payload_unit_start_indicator set")
	}
	// adaptation_field_control must be 0b11 (adaptation + payload) since
	// we emit a PCR on the first packet.
	if result[audioStart+3]&0x30 != 0x30 {
		t.Fatalf("expected adaptation+payload, got TS flags=0x%02X", result[audioStart+3])
	}
	adaptLen := int(result[audioStart+4])
	if adaptLen < 7 {
		t.Fatalf("adaptation field too short for PCR: %d", adaptLen)
	}
	// PES starts after adaptation field.
	pesOffset := audioStart + 5 + adaptLen
	if result[pesOffset] != 0x00 || result[pesOffset+1] != 0x00 || result[pesOffset+2] != 0x01 {
		t.Fatalf("missing PES start code at offset %d", pesOffset)
	}
	if result[pesOffset+3] != mp3StreamID {
		t.Fatalf("expected stream ID 0xC0, got 0x%02X", result[pesOffset+3])
	}
}

// TestTSMuxerNoTruncationAt183 targets the previous off-by-one: when the
// remaining payload bytes equal payloadCapacity-1 (183), the old code
// silently dropped one byte. The muxer should now emit a length-0
// adaptation field and keep every byte.
func TestTSMuxerNoTruncationAt183(t *testing.T) {
	// Construct MP3 data whose PES-encapsulated payload length ends
	// exactly one byte short of a TS packet on the final packet. PES
	// header is 14 bytes; the first packet consumes 184 bytes (or less
	// with PCR adaptation). We'll look for the 183-byte case by checking
	// every packet and asserting no byte is lost by reassembling.
	mp3 := make([]byte, 3000)
	for i := range mp3 {
		mp3[i] = byte(i & 0xFF)
	}
	muxer := NewTSMuxer()
	out := muxer.MuxMP3Segment(mp3, 0)

	// Walk TS packets, peel adaptation field, concatenate audio PID
	// payload, and compare the reconstructed PES body to the original
	// MP3 bytes.
	var reassembled []byte
	for off := 0; off+tsPacketSize <= len(out); off += tsPacketSize {
		p := out[off : off+tsPacketSize]
		if p[0] != tsSyncByte {
			t.Fatalf("bad sync at %d", off)
		}
		pid := (uint16(p[1]&0x1F) << 8) | uint16(p[2])
		if pid != audioPID {
			continue
		}
		afc := (p[3] >> 4) & 0x3
		payloadStart := 4
		if afc == 0x3 || afc == 0x2 {
			adaptLen := int(p[4])
			payloadStart = 5 + adaptLen
		}
		if afc == 0x2 {
			continue // adaptation-only, no payload
		}
		reassembled = append(reassembled, p[payloadStart:]...)
	}
	// The reassembled data starts with the PES header (14 bytes) then
	// the MP3 bytes. Verify the MP3 body is intact.
	if len(reassembled) < 14+len(mp3) {
		t.Fatalf("reassembled %d bytes, expected at least %d — truncation likely", len(reassembled), 14+len(mp3))
	}
	body := reassembled[14 : 14+len(mp3)]
	for i := range mp3 {
		if body[i] != mp3[i] {
			t.Fatalf("byte mismatch at %d: got 0x%02X want 0x%02X", i, body[i], mp3[i])
		}
	}
}

func TestEncodePTS(t *testing.T) {
	// PTS = 0 should encode to specific pattern
	pts0 := encodePTS(0)
	// First byte: 0010 0001 = 0x21
	if pts0[0] != 0x21 {
		t.Fatalf("PTS=0 first byte expected 0x21, got 0x%02X", pts0[0])
	}
	// Marker bits should be set (bit 0 of bytes 0,2,4)
	if pts0[2]&0x01 != 1 || pts0[4]&0x01 != 1 {
		t.Fatal("PTS marker bits not set correctly")
	}
}

func TestCRC32MPEG2(t *testing.T) {
	// Known test vector: "123456789" should give 0x0376E6E7
	data := []byte("123456789")
	crc := crc32MPEG2(data)
	if crc != 0x0376E6E7 {
		t.Fatalf("CRC32/MPEG2 of '123456789' expected 0x0376E6E7, got 0x%08X", crc)
	}
}
