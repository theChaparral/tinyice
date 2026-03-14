package relay

import (
	"sync"
	"testing"
)

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
