package relay

import (
	"testing"
)

func TestNewAudioTrack(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")
	track := NewAudioTrack(s, "mp3")

	if track.Type != MediaAudio {
		t.Fatalf("expected MediaAudio, got %v", track.Type)
	}
	if track.Codec != "mp3" {
		t.Fatalf("expected mp3, got %s", track.Codec)
	}
	if track.Stream != s {
		t.Fatal("track.Stream should reference the original stream")
	}
}

func TestPipelineAddTrackAndCount(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")

	p := NewPipeline("/test")
	p.AddTrack(NewAudioTrack(s, "opus"))

	if p.GetAudioTrack() == nil {
		t.Fatal("expected audio track")
	}
	if p.GetVideoTrack() != nil {
		t.Fatal("expected no video track")
	}
	if p.ListenerCount() != 0 {
		t.Fatalf("expected 0 listeners, got %d", p.ListenerCount())
	}
}

func TestResolveCodecNilSafe(t *testing.T) {
	// ResolveCodec's "nil-receiver" branch tried to return t.Codec on a
	// nil t — i.e. dereferenced the nil pointer. Calling on a nil
	// receiver should return "" rather than panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ResolveCodec panicked on nil receiver: %v", r)
		}
	}()
	var t1 *Track
	if got := t1.ResolveCodec(); got != "" {
		t.Fatalf("expected empty codec for nil receiver, got %q", got)
	}
	// Stream-nil but track-non-nil should return the cached codec.
	t2 := &Track{Codec: "opus"}
	if got := t2.ResolveCodec(); got != "opus" {
		t.Fatalf("expected cached codec opus, got %q", got)
	}
}

func TestPipelineStats(t *testing.T) {
	r := NewRelay(false, nil)
	s := r.GetOrCreateStream("/test")

	p := NewPipeline("/test")
	p.AddTrack(NewAudioTrack(s, "mp3"))

	stats := p.Stats()
	if stats.Mount != "/test" {
		t.Fatalf("expected /test, got %s", stats.Mount)
	}
	if len(stats.Tracks) != 1 {
		t.Fatalf("expected 1 track, got %d", len(stats.Tracks))
	}
	if stats.Tracks[0].Type != "audio" {
		t.Fatalf("expected audio, got %s", stats.Tracks[0].Type)
	}
}
