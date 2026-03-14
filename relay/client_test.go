package relay

import (
	"testing"
	"time"
)

func TestBackoffWithJitter(t *testing.T) {
	b := &backoff{base: 1 * time.Second, max: 60 * time.Second}

	d1 := b.next()
	if d1 < 500*time.Millisecond || d1 > 2*time.Second {
		t.Fatalf("first backoff out of range: %v", d1)
	}

	d2 := b.next()
	if d2 < 1*time.Second || d2 > 4*time.Second {
		t.Fatalf("second backoff out of range: %v", d2)
	}

	for i := 0; i < 20; i++ {
		b.next()
	}
	d := b.next()
	if d > 61*time.Second {
		t.Fatalf("backoff exceeded max: %v", d)
	}

	b.reset()
	d = b.next()
	if d > 2*time.Second {
		t.Fatalf("after reset, backoff should be small: %v", d)
	}
}
