package relay

import (
	"context"
)

// WebRTCOutputAdapter provides WebRTC listener output.
// The actual WebRTC logic remains in relay/webrtc.go.
type WebRTCOutputAdapter struct {
	manager *WebRTCManager
	tracks  []*Track
}

func NewWebRTCOutputAdapter(manager *WebRTCManager) *WebRTCOutputAdapter {
	return &WebRTCOutputAdapter{
		manager: manager,
	}
}

func (o *WebRTCOutputAdapter) Protocol() string                    { return "webrtc" }
func (o *WebRTCOutputAdapter) SupportsMediaType(mt MediaType) bool { return true } // WebRTC supports audio and video

func (o *WebRTCOutputAdapter) Start(ctx context.Context, tracks []*Track) error {
	o.tracks = tracks
	return nil
}

func (o *WebRTCOutputAdapter) Stop() {}
