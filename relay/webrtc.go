package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/sirupsen/logrus"
)

type WebRTCManager struct {
	api   *webrtc.API
	relay *Relay
	mu    sync.RWMutex
}

func NewWebRTCManager(r *Relay) *WebRTCManager {
	s := webrtc.SettingEngine{}
	// Optimize for many listeners
	s.SetICETimeouts(10*time.Second, 20*time.Second, 2*time.Second)
	
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	return &WebRTCManager{
		api:   api,
		relay: r,
	}
}

func (wm *WebRTCManager) HandleOffer(mount string, offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
	stream, ok := wm.relay.GetStream(mount)
	if !ok {
		return nil, fmt.Errorf("stream not found")
	}

	peerConnection, err := wm.api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	})
	if err != nil {
		return nil, err
	}

	// Create a track for Opus audio
	audioTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, "audio", "tinyice")
	if err != nil {
		return nil, err
	}

	if _, err = peerConnection.AddTrack(audioTrack); err != nil {
		return nil, err
	}

	// Set the remote SessionDescription
	if err = peerConnection.SetRemoteDescription(offer); err != nil {
		return nil, err
	}

	// Create answer
	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}

	// Sets the LocalDescription and starts gathering ICE candidates
	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	if err = peerConnection.SetLocalDescription(answer); err != nil {
		return nil, err
	}
	<-gatherComplete

	// Start feeding the track
	go wm.streamToTrack(peerConnection, audioTrack, stream)

	return peerConnection.LocalDescription(), nil
}

func (wm *WebRTCManager) streamToTrack(pc *webrtc.PeerConnection, track *webrtc.TrackLocalStaticSample, stream *Stream) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateClosed || s == webrtc.PeerConnectionStateFailed {
			cancel()
		}
	})

	logrus.Infof("WebRTC listener started for %s", stream.MountName)
	defer logrus.Infof("WebRTC listener stopped for %s", stream.MountName)

	id := fmt.Sprintf("webrtc-%d", time.Now().UnixNano())
	offset, signal := stream.Subscribe(id, 64*1024)
	defer stream.Unsubscribe(id)

	reader := &streamReader{
		stream: stream,
		offset: offset,
		signal: signal,
		ctx:    ctx,
		id:     id,
	}

	opusReader, err := ogg.NewOpusReader(reader)
	if err != nil {
		logrus.WithError(err).Error("Failed to initialize Ogg/Opus reader for WebRTC")
		return
	}

	for {
		packet, err := opusReader.ReadAudioPacket()
		if err != nil {
			if err != io.EOF && !errors.Is(err, context.Canceled) {
				logrus.WithError(err).Error("Error reading Opus packet")
			}
			return
		}

		// WebRTC expects 48kHz Opus samples. 
		// We use a fixed duration of 20ms per packet which is standard.
		if err := track.WriteSample(media.Sample{
			Data:     packet.Data,
			Duration: 20 * time.Millisecond,
		}); err != nil {
			return
		}
	}
}
