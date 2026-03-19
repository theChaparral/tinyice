package relay

import (
	"context"
	"net/http"
)

// IcecastOutputAdapter provides progressive HTTP streaming (Icecast-compatible).
// The actual serving logic remains in server/handlers_stream.go.
// This adapter provides the OutputAdapter interface for pipeline registration.
type IcecastOutputAdapter struct {
	contentType string
	tracks      []*Track
}

func NewIcecastOutputAdapter() *IcecastOutputAdapter {
	return &IcecastOutputAdapter{
		contentType: "audio/mpeg",
	}
}

func (o *IcecastOutputAdapter) Protocol() string                    { return "icecast" }
func (o *IcecastOutputAdapter) SupportsMediaType(mt MediaType) bool { return mt == MediaAudio }
func (o *IcecastOutputAdapter) ContentType() string                 { return o.contentType }

func (o *IcecastOutputAdapter) Start(ctx context.Context, tracks []*Track) error {
	o.tracks = tracks
	// Determine content type from the audio track
	for _, t := range tracks {
		if t.Type == MediaAudio {
			if t.Codec == "opus" {
				o.contentType = "audio/ogg"
			} else {
				o.contentType = "audio/mpeg"
			}
			break
		}
	}
	return nil
}

func (o *IcecastOutputAdapter) Stop() {}

// ServeListener is a placeholder — actual serving is done by server/handlers_stream.go.
func (o *IcecastOutputAdapter) ServeListener(w http.ResponseWriter, r *http.Request) error {
	return nil
}
