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
	// Use PTS = 90000 (1 second at 90kHz)
	// Use enough data so the first audio packet has no adaptation field stuffing
	result := muxer.MuxMP3Segment(make([]byte, 1000), 90000)

	// Find the audio PES start (third packet, after TS header)
	audioStart := 2 * tsPacketSize
	// payload_unit_start_indicator should be set
	if result[audioStart+1]&0x40 == 0 {
		t.Fatal("audio packet should have payload_unit_start_indicator set")
	}
	// First audio packet should have payload only (no adaptation field) since data is large
	// PES start code should be 00 00 01 at byte 4
	pesOffset := audioStart + 4
	if result[pesOffset] != 0x00 || result[pesOffset+1] != 0x00 || result[pesOffset+2] != 0x01 {
		t.Fatalf("missing PES start code at offset %d", pesOffset)
	}
	// Stream ID should be 0xC0 (MP3 audio)
	if result[pesOffset+3] != mp3StreamID {
		t.Fatalf("expected stream ID 0xC0, got 0x%02X", result[pesOffset+3])
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
