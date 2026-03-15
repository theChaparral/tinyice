package relay

import "testing"

func TestFindNextPageBoundaryRejectsFalseOggS(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)

	// Fake OggS at offset 10 with invalid version=5
	copy(data[10:], []byte("OggS"))
	data[14] = 5

	// Real OggS at offset 50 with valid version=0
	copy(data[50:], []byte("OggS"))
	data[54] = 0
	data[76] = 1  // number_page_segments = 1
	data[77] = 10 // segment of 10 bytes

	result := FindNextPageBoundary(data, bufSize, 256, 0)
	if result != 50 {
		t.Fatalf("expected offset 50, got %d", result)
	}
}

func TestFindNextPageBoundaryFindsValidOgg(t *testing.T) {
	bufSize := int64(256)
	data := make([]byte, bufSize)

	copy(data[0:], []byte("OggS"))
	data[4] = 0  // valid version
	data[26] = 1 // number_page_segments = 1
	data[27] = 10

	result := FindNextPageBoundary(data, bufSize, 256, 0)
	if result != 0 {
		t.Fatalf("expected offset 0, got %d", result)
	}
}
