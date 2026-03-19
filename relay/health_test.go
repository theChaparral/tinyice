package relay

import (
	"testing"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

func init() {
	logger.Init("error", false, "")
}

func TestHealthStatus(t *testing.T) {
	tests := []struct {
		name     string
		lastData time.Duration
		want     HealthStatus
	}{
		{"healthy - recent data", 1 * time.Second, StatusHealthy},
		{"degraded - 10s ago", 10 * time.Second, StatusDegraded},
		{"dead - 60s ago", 60 * time.Second, StatusDead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateHealthStatus(time.Now().Add(-tt.lastData))
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestHealthMonitorDetectsStateChange(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test-health")
	s.LastDataReceived = time.Now().Add(-10 * time.Second)

	hm := NewHealthMonitor(r)
	var gotEvent *StreamHealthEvent
	hm.OnEvent(func(e StreamHealthEvent) {
		gotEvent = &e
	})

	hm.check()

	if gotEvent == nil {
		t.Fatal("expected health event, got none")
	}
	if gotEvent.NewStatus != StatusDegraded {
		t.Fatalf("expected Degraded, got %v", gotEvent.NewStatus)
	}
}
