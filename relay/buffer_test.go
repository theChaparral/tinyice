package relay

import (
	"testing"
)

func TestReadAtWrapsAround(t *testing.T) {
	cb := NewCircularBuffer(16)
	// Write 20 bytes: "ABCDEFGHIJKLMNOPQRST"
	// After write, buffer contains: "EFGHIJKLMNOPQRST" overwrites first 4 -> data = "QRST EFGHIJKLMNOP"
	// Actually: positions 0-15 get written with A-P, then Head=16, pos=0, writes Q-T at 0-3.
	// So data = [Q R S T E F G H I J K L M N O P], Head=20
	// Reading 8 bytes at offset 12: pos=12%16=12, bytes at 12..15 = M N O P, then wrap 0..3 = Q R S T
	data := []byte("ABCDEFGHIJKLMNOPQRST")
	cb.Write(data)

	buf := make([]byte, 8)
	n, newOffset, skipped := cb.ReadAt(12, buf)

	if skipped {
		t.Fatal("expected no skip")
	}
	if n != 8 {
		t.Fatalf("expected 8 bytes, got %d", n)
	}
	if newOffset != 20 {
		t.Fatalf("expected newOffset=20, got %d", newOffset)
	}
	expected := "MNOPQRST"
	if string(buf[:n]) != expected {
		t.Fatalf("expected %q, got %q", expected, string(buf[:n]))
	}
}

func TestReadAtNoWrap(t *testing.T) {
	cb := NewCircularBuffer(16)
	cb.Write([]byte("ABCDEFGH"))

	buf := make([]byte, 4)
	n, newOffset, skipped := cb.ReadAt(2, buf)

	if skipped {
		t.Fatal("expected no skip")
	}
	if n != 4 {
		t.Fatalf("expected 4 bytes, got %d", n)
	}
	if newOffset != 6 {
		t.Fatalf("expected newOffset=6, got %d", newOffset)
	}
	if string(buf[:n]) != "CDEF" {
		t.Fatalf("expected %q, got %q", "CDEF", string(buf[:n]))
	}
}

func TestReadAtSkipsSlowListener(t *testing.T) {
	cb := NewCircularBuffer(8)
	// Write 20 bytes so the buffer has wrapped well past offset 0
	cb.Write([]byte("ABCDEFGHIJKLMNOPQRST"))
	// Head=20, Size=8, oldest available = 20-8=12

	buf := make([]byte, 4)
	n, newOffset, skipped := cb.ReadAt(0, buf)

	if !skipped {
		t.Fatal("expected skip for slow listener")
	}
	if n != 4 {
		t.Fatalf("expected 4 bytes, got %d", n)
	}
	// After skip, start=12, pos=12%8=4, read 4 bytes from pos 4..7
	if newOffset != 16 {
		t.Fatalf("expected newOffset=16, got %d", newOffset)
	}
}

func TestReadAtAheadOfHead(t *testing.T) {
	cb := NewCircularBuffer(16)
	cb.Write([]byte("ABCD"))

	buf := make([]byte, 4)
	n, newOffset, _ := cb.ReadAt(10, buf)

	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
	if newOffset != 10 {
		t.Fatalf("expected newOffset=10, got %d", newOffset)
	}
}

func TestWriteAndReadFullWrap(t *testing.T) {
	cb := NewCircularBuffer(8)
	// Write 3 chunks of 4 bytes = 12 bytes total
	cb.Write([]byte("AAAA"))
	cb.Write([]byte("BBBB"))
	cb.Write([]byte("CCCC"))
	// Head=12, data = [C C C C B B B B] (positions: 0-3=CCCC from 3rd write at pos 8%8=0, 4-7=BBBB)
	// Wait: 1st write pos 0-3 = AAAA, Head=4
	//       2nd write pos 4-7 = BBBB, Head=8
	//       3rd write pos 0-3 = CCCC, Head=12
	// data = [C C C C B B B B]
	// oldest = 12-8=4, reading from 4: pos=4%8=4, 8 bytes available
	// Read 8 bytes spanning wrap: pos 4..7 = BBBB, then 0..3 = CCCC

	buf := make([]byte, 8)
	n, newOffset, skipped := cb.ReadAt(4, buf)

	if skipped {
		t.Fatal("expected no skip")
	}
	if n != 8 {
		t.Fatalf("expected 8 bytes, got %d", n)
	}
	if newOffset != 12 {
		t.Fatalf("expected newOffset=12, got %d", newOffset)
	}
	expected := "BBBBCCCC"
	if string(buf[:n]) != expected {
		t.Fatalf("expected %q, got %q", expected, string(buf[:n]))
	}
}

func TestAvailable(t *testing.T) {
	cb := NewCircularBuffer(8)

	if a := cb.Available(); a != 0 {
		t.Fatalf("expected Available()=0, got %d", a)
	}

	cb.Write([]byte("ABCD"))
	if a := cb.Available(); a != 4 {
		t.Fatalf("expected Available()=4, got %d", a)
	}

	// Write more than buffer size, should cap at Size
	cb.Write([]byte("EFGHIJKL"))
	if a := cb.Available(); a != 8 {
		t.Fatalf("expected Available()=8, got %d", a)
	}
}

func TestKeyframeIndex(t *testing.T) {
	buf := NewCircularBuffer(1024)
	buf.Write(make([]byte, 500))

	buf.RecordKeyframe(0)
	buf.RecordKeyframe(100)
	buf.RecordKeyframe(300)

	// Nearest keyframe at or before offset 250 should be 100
	kf := buf.NearestKeyframe(250)
	if kf != 100 {
		t.Fatalf("expected keyframe at 100, got %d", kf)
	}

	// Nearest keyframe at or before offset 300 should be 300
	kf = buf.NearestKeyframe(300)
	if kf != 300 {
		t.Fatalf("expected keyframe at 300, got %d", kf)
	}

	// Latest keyframe should be 300
	kf = buf.LatestKeyframe()
	if kf != 300 {
		t.Fatalf("expected latest keyframe at 300, got %d", kf)
	}
}

func TestKeyframeIndexEmpty(t *testing.T) {
	buf := NewCircularBuffer(1024)
	if buf.NearestKeyframe(100) != -1 {
		t.Fatal("expected -1 for empty keyframe index")
	}
	if buf.LatestKeyframe() != -1 {
		t.Fatal("expected -1 for empty keyframe index")
	}
}

func TestKeyframeIndexExpiry(t *testing.T) {
	buf := NewCircularBuffer(100) // small buffer
	buf.Write(make([]byte, 200))  // head=200, valid range [100, 200)

	buf.RecordKeyframe(50)  // expired (before valid range)
	buf.RecordKeyframe(150) // valid

	kf := buf.NearestKeyframe(200)
	if kf != 150 {
		t.Fatalf("expected 150 (expired keyframe at 50 should be ignored), got %d", kf)
	}
}

func TestReset(t *testing.T) {
	cb := NewCircularBuffer(8)
	cb.Write([]byte("ABCDEFGH"))

	cb.Reset()

	if cb.Head != 0 {
		t.Fatalf("expected Head=0 after Reset, got %d", cb.Head)
	}
	for i, b := range cb.Data {
		if b != 0 {
			t.Fatalf("expected Data[%d]=0 after Reset, got %d", i, b)
		}
	}
}
