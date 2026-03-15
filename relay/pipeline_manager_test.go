package relay

import "testing"

func TestPipelineManagerGetOrCreate(t *testing.T) {
	r := NewRelay(false, nil)
	pm := NewPipelineManager(r)

	p := pm.GetOrCreatePipeline("/live")
	if p.Mount != "/live" {
		t.Fatalf("expected /live, got %s", p.Mount)
	}

	// Same mount returns same pipeline
	p2 := pm.GetOrCreatePipeline("/live")
	if p != p2 {
		t.Fatal("expected same pipeline instance")
	}

	if pm.PipelineCount() != 1 {
		t.Fatalf("expected 1 pipeline, got %d", pm.PipelineCount())
	}
}

func TestPipelineManagerBackwardCompat(t *testing.T) {
	r := NewRelay(false, nil)
	pm := NewPipelineManager(r)

	// GetOrCreateStream should work like Relay.GetOrCreateStream
	s := pm.GetOrCreateStream("/compat")
	if s == nil {
		t.Fatal("expected non-nil stream")
	}
	if s.MountName != "/compat" {
		t.Fatalf("expected /compat, got %s", s.MountName)
	}

	// Should also have created a pipeline
	p, ok := pm.GetPipeline("/compat")
	if !ok {
		t.Fatal("expected pipeline to exist")
	}
	if p.GetAudioTrack() == nil {
		t.Fatal("expected audio track in pipeline")
	}
	if p.GetAudioTrack().Stream != s {
		t.Fatal("pipeline audio track should reference the same stream")
	}
}

func TestPipelineManagerRemove(t *testing.T) {
	r := NewRelay(false, nil)
	pm := NewPipelineManager(r)

	pm.GetOrCreatePipeline("/remove-me")
	pm.RemovePipeline("/remove-me")

	_, ok := pm.GetPipeline("/remove-me")
	if ok {
		t.Fatal("expected pipeline to be removed")
	}
	if pm.PipelineCount() != 0 {
		t.Fatalf("expected 0 pipelines, got %d", pm.PipelineCount())
	}
}

func TestPipelineManagerSnapshot(t *testing.T) {
	r := NewRelay(false, nil)
	pm := NewPipelineManager(r)

	pm.GetOrCreatePipeline("/a")
	pm.GetOrCreatePipeline("/b")

	stats := pm.Snapshot()
	if len(stats) != 2 {
		t.Fatalf("expected 2 pipeline stats, got %d", len(stats))
	}
}
