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

	"github.com/kazzmir/opus-go/ogg"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/oggwriter"
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

	// Catch-up logic: If we are more than 500ms behind, reset the pacer baseline
	if wait < -500*time.Millisecond {
		p.startTime = time.Now()
		p.sentMS = 0
		return
	}

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

type relayWriter struct {
	relay  *Relay
	stream *Stream
}

func (rw *relayWriter) Write(p []byte) (n int, err error) {
	logrus.Debugf("relayWriter: Broadcasting %d bytes to %s", len(p), rw.stream.MountName)
	rw.stream.Broadcast(p, rw.relay)
	return len(p), nil
}

func (wm *WebRTCManager) HandleSourceOffer(mount string, offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
	peerConnection, err := wm.api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	})
	if err != nil {
		return nil, err
	}

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		logrus.Infof("WebRTC Source: Received track %s from %s", track.ID(), mount)
		
		stream := wm.relay.GetOrCreateStream(mount)
		stream.mu.Lock()
		stream.ContentType = "audio/ogg" 
		stream.IsOggStream = true
		stream.SourceIP = "webrtc-source"
		// Reset page offsets so we don't sync to old pages from a previous session
		stream.PageOffsets = make([]int64, 128)
		stream.PageIndex = 0
		stream.OggHeaderOffset = stream.Buffer.Head
		stream.mu.Unlock()

		// Capture headers written by oggwriter.NewWith
		var headerBuf bytes.Buffer
		multi := io.MultiWriter(&headerBuf, &relayWriter{wm.relay, stream})

		writer, err := oggwriter.NewWith(multi, 48000, 2)
		if err != nil {
			logrus.WithError(err).Error("Failed to create Ogg writer for WebRTC source")
			return
		}
		defer writer.Close()

		// Save captured headers immediately
		stream.mu.Lock()
		h := make([]byte, headerBuf.Len())
		copy(h, headerBuf.Bytes())
		stream.OggHead = h
		logrus.Infof("WebRTC Source: Captured %d bytes of Ogg/Opus headers at offset %d", len(h), stream.OggHeaderOffset)
		stream.mu.Unlock()

		for {
			rtpPacket, _, err := track.ReadRTP()
			if err != nil {
				if err != io.EOF {
					logrus.WithError(err).Error("Error reading RTP packet from source")
				}
				return
			}
			if err := writer.WriteRTP(rtpPacket); err != nil {
				logrus.WithError(err).Error("Error writing RTP to Ogg muxer")
				return
			}
		}
	})

	if err = peerConnection.SetRemoteDescription(offer); err != nil {
		return nil, err
	}

	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}

	gatherComplete := webrtc.GatheringCompletePromise(peerConnection)
	if err = peerConnection.SetLocalDescription(answer); err != nil {
		return nil, err
	}
	<-gatherComplete

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
		logrus.WithField("mount", stream.MountName).Error("WebRTC: Could not find Ogg sync in first 512KB. Is it an Opus stream?")
		return
	}

	reader := NewStreamReader(stream.Buffer, offset, signal, ctx, id).WithOggSync(stream)

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

	// Default Opus duration is 20ms. If we detect drift, the pacer will self-correct.
	const defaultDuration = 20 * time.Millisecond

	for {
		packet, err := opusReader.ReadAudioPacket()
		if err != nil {
			if err != io.EOF && !errors.Is(err, context.Canceled) {
				logrus.WithError(err).Error("Error reading Opus packet")
			}
			return
		}

		// WebRTC expects 48kHz Opus samples.
		pacer.Pace(defaultDuration)
		if err := track.WriteSample(media.Sample{
			Data:     packet.Data,
			Duration: defaultDuration,
		}); err != nil {
			return
		}
		sentCount++
		if sentCount%100 == 0 {
			logrus.Debugf("WebRTC: Sent 100 packets to %s", stream.MountName)
		}
	}
}
