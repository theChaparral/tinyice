package relay

import (
	"testing"
)

func TestTSDemuxerRoundTrip(t *testing.T) {
	// Use the TSMuxer to create a segment, then demux it
	muxer := NewTSMuxer()
	originalData := []byte("fake-mp3-audio-data-for-testing-purposes-1234567890")
	tsData := muxer.MuxMP3Segment(originalData, 90000)

	demuxer := NewTSDemuxer()
	var receivedAudio []byte
	var receivedPTS int64

	demuxer.OnAudio(func(data []byte, pts int64) {
		receivedAudio = append(receivedAudio, data...)
		if pts != 0 {
			receivedPTS = pts
		}
	})

	demuxer.Feed(tsData)

	if len(receivedAudio) == 0 {
		t.Fatal("demuxer received no audio data")
	}

	// The demuxed audio should contain our original data
	found := false
	for i := 0; i <= len(receivedAudio)-len(originalData); i++ {
		match := true
		for j := 0; j < len(originalData); j++ {
			if receivedAudio[i+j] != originalData[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("original audio data not found in demuxed output (got %d bytes)", len(receivedAudio))
	}

	if receivedPTS != 90000 {
		t.Fatalf("expected PTS 90000, got %d", receivedPTS)
	}
}

func TestDecodePTS(t *testing.T) {
	// Encode PTS=90000 and decode it back
	encoded := encodePTS(90000)
	decoded := decodePTS(encoded)
	if decoded != 90000 {
		t.Fatalf("PTS round-trip failed: expected 90000, got %d", decoded)
	}
}
