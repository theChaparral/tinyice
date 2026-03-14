package relay

import (
	"sync"
	"testing"
)

func TestSubscribeOggEmptyPageOffsetsFallsBackToBurst(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/ogg-test")
	s.ContentType = "audio/ogg"
	s.IsOggStream = true
	s.Buffer.Write(make([]byte, 4096))

	offset, _ := s.Subscribe("listener-1", 2048)

	if offset >= s.Buffer.Head {
		t.Fatalf("expected burst offset < Head(%d), got %d", s.Buffer.Head, offset)
	}
	expectedMin := s.Buffer.Head - 2048
	if offset < expectedMin {
		t.Fatalf("expected offset >= %d, got %d", expectedMin, offset)
	}
}

func TestBroadcastAfterCloseNoPanic(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")
	s.Subscribe("listener-1", 0)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.Broadcast([]byte("data"), r)
		}
	}()
	go func() {
		defer wg.Done()
		s.Close()
	}()
	wg.Wait()
}

func TestSubscribeAfterCloseRejects(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")
	s.Close()

	_, _, ok := s.SubscribeSafe("listener-after-close", 1024)
	if ok {
		t.Fatal("expected SubscribeSafe to return false after Close")
	}
}
