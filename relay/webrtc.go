package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/sirupsen/logrus"
)

type SimplePacer struct {
	startTime time.Time
	sentMS    int64
}

func (p *SimplePacer) Pace(duration time.Duration) {
	if p.startTime.IsZero() {
		p.startTime = time.Now()
	}
	p.sentMS += duration.Milliseconds()
	targetTime := p.startTime.Add(time.Duration(p.sentMS) * time.Millisecond)
	wait := time.Until(targetTime)
	if wait > 0 {
		time.Sleep(wait)
	}
}

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

	// WebRTC requires Opus (usually in Ogg container for us)
	ct := strings.ToLower(stream.ContentType)
	if !strings.Contains(ct, "ogg") && !strings.Contains(ct, "opus") {
		return nil, fmt.Errorf("WebRTC requires Opus stream (got %s)", stream.ContentType)
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

	id := fmt.Sprintf("webrtc-%d", time.Now().UnixNano())
	// For WebRTC we start at the current head (no burst)
	offset, signal := stream.Subscribe(id, 0)
	defer stream.Unsubscribe(id)

	// Seek to next "OggS" magic
	syncBuf := make([]byte, 16384)
	foundSync := false
	var searched int64 = 0
	for !foundSync && searched < 512*1024 {
		select {
		case <-ctx.Done():
			return
		case <-signal:
			n, next, _ := stream.Buffer.ReadAt(offset, syncBuf)
			if n == 0 {
				continue
			}
			// Use a robust sliding window to find "OggS"
			for i := 0; i <= n-4; i++ {
				if syncBuf[i] == 'O' && syncBuf[i+1] == 'g' && syncBuf[i+2] == 'g' && syncBuf[i+3] == 'S' {
					offset += int64(i)
					foundSync = true
					break
				}
			}
			if !foundSync {
				// Keep the last 3 bytes in case "OggS" is split between reads
				offset = next - 3 
				searched += int64(n)
			}
		}
	}

	if !foundSync {
		logrus.Errorf("WebRTC: Could not find Ogg sync in first 512KB for %s. Is it an Opus stream?", stream.MountName)
		return
	}

	reader := &StreamReader{
		Stream: stream,
		Offset: offset,
		Signal: signal,
		Ctx:    ctx,
		ID:     id,
	}

	// We wrap the reader to prepend the OggHead if available.
	// This ensures NewOpusReader always sees the ID/Tag headers.
	var finalReader io.Reader = reader
	if stream.OggHead != nil {
		finalReader = io.MultiReader(bytes.NewReader(stream.OggHead), reader)
	}

	opusReader, err := ogg.NewOpusReader(finalReader)
	if err != nil {
		logrus.WithError(err).Error("Failed to initialize Ogg/Opus reader for WebRTC")
		return
	}

	pacer := &SimplePacer{}
	logrus.Infof("WebRTC: Beginning packet transmission for %s", stream.MountName)
	sentCount := 0
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
		pacer.Pace(20 * time.Millisecond)
		if err := track.WriteSample(media.Sample{
			Data:     packet.Data,
			Duration: 20 * time.Millisecond,
		}); err != nil {
			return
		}
		sentCount++
		if sentCount%50 == 0 {
			logrus.Debugf("WebRTC: Sent 50 packets to %s (approx 1s audio)", stream.MountName)
		}
	}
}
