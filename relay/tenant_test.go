package relay

import (
	"testing"
)

func TestTenantLimits(t *testing.T) {
	tm := NewTenantManager()
	tenant := tm.CreateTenant("test", "Test Tenant", "free")

	if !tenant.CanCreateStream() {
		t.Fatal("free plan should allow 1 stream initially")
	}

	// Simulate adding a pipeline
	tenant.mu.Lock()
	tenant.pipelines["/stream"] = NewPipeline("/stream")
	tenant.mu.Unlock()

	if tenant.CanCreateStream() {
		t.Fatal("free plan should not allow more than 1 stream")
	}
}

func TestTenantBandwidthLimit(t *testing.T) {
	tm := NewTenantManager()
	tenant := tm.CreateTenant("bw", "BW Test", "free")
	// Free plan has 10GB limit = 10240 MB

	if tenant.CheckBandwidthLimit() {
		t.Fatal("should not be over limit initially")
	}

	// Simulate exceeding bandwidth
	tenant.RecordBytesOut(11 * 1024 * 1024 * 1024) // 11GB
	if !tenant.CheckBandwidthLimit() {
		t.Fatal("should be over bandwidth limit")
	}
}

func TestTenantListenerTracking(t *testing.T) {
	tm := NewTenantManager()
	tenant := tm.CreateTenant("listen", "Listen Test", "starter")

	tenant.UpdateListenerCount(10)
	tenant.UpdateListenerCount(20)
	tenant.UpdateListenerCount(-5)

	stats := tenant.GetStats()
	if stats.CurrentListeners != 25 {
		t.Fatalf("expected 25 current listeners, got %d", stats.CurrentListeners)
	}
	if stats.PeakListeners != 30 {
		t.Fatalf("expected peak 30, got %d", stats.PeakListeners)
	}
}

func TestTenantManagerDomainMapping(t *testing.T) {
	tm := NewTenantManager()
	tm.CreateTenant("acme", "ACME Radio", "pro")
	tm.SetCustomDomain("acme", "radio.acme.com")

	tenant := tm.GetTenantByDomain("radio.acme.com")
	if tenant == nil {
		t.Fatal("expected tenant from domain lookup")
	}
	if tenant.ID != "acme" {
		t.Fatalf("expected acme, got %s", tenant.ID)
	}

	// Unknown domain
	if tm.GetTenantByDomain("unknown.com") != nil {
		t.Fatal("expected nil for unknown domain")
	}
}

func TestDefaultTenant(t *testing.T) {
	tm := NewTenantManager()
	d := tm.GetOrCreateDefaultTenant()

	if d.ID != "default" {
		t.Fatalf("expected default, got %s", d.ID)
	}
	if d.Plan != "enterprise" {
		t.Fatalf("expected enterprise, got %s", d.Plan)
	}

	// Should return same instance
	d2 := tm.GetOrCreateDefaultTenant()
	if d != d2 {
		t.Fatal("expected same default tenant instance")
	}
}

func TestPlanLimits(t *testing.T) {
	free := PlanLimits("free")
	if free.MaxStreams != 1 {
		t.Fatalf("free plan should have 1 max stream, got %d", free.MaxStreams)
	}
	if free.AllowRTMP {
		t.Fatal("free plan should not allow RTMP")
	}

	pro := PlanLimits("pro")
	if !pro.AllowVideo {
		t.Fatal("pro plan should allow video")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) < 20 {
		t.Fatalf("key too short: %s", key)
	}
	if key[:8] != "tinyice_" {
		t.Fatalf("key should start with tinyice_, got %s", key[:8])
	}
}
