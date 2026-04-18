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

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/oggwriter"
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
	api     *webrtc.API
	relay   *Relay
	mu      sync.RWMutex
	sources map[string]*webrtc.PeerConnection
}

func NewWebRTCManager(r *Relay) *WebRTCManager {
	s := webrtc.SettingEngine{}
	// Optimize for many listeners
	s.SetICETimeouts(10*time.Second, 20*time.Second, 2*time.Second)

	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	return &WebRTCManager{
		api:     api,
		relay:   r,
		sources: make(map[string]*webrtc.PeerConnection),
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
	logger.L.Debugw("relayWriter: Broadcasting", "bytes", len(p), "mount", rw.stream.MountName)
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

	wm.mu.Lock()
	if existing, ok := wm.sources[mount]; ok {
		existing.Close()
	}
	wm.sources[mount] = peerConnection
	wm.mu.Unlock()

	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logger.L.Infow("WebRTC Source: Connection state changed", "mount", mount, "state", state.String())
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateDisconnected {
			wm.mu.Lock()
			if wm.sources[mount] == peerConnection {
				delete(wm.sources, mount)
			}
			wm.mu.Unlock()
		}
	})

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		logger.L.Infow("WebRTC Source: Received track", "track", track.ID(), "mount", mount)

		stream := wm.relay.GetOrCreateStream(mount)
		headOffset := stream.Buffer.HeadOffset()
		stream.mu.Lock()
		stream.ContentType = "audio/ogg"
		stream.IsOggStream = true
		stream.SourceIP = "webrtc-source"
		// Reset page offsets so we don't sync to old pages from a previous session
		stream.PageOffsets = make([]int64, 2048)
		stream.PageIndex = 0
		stream.OggHeaderOffset = headOffset
		stream.mu.Unlock()

		// Capture headers written by oggwriter.NewWith
		var headerBuf bytes.Buffer
		multi := io.MultiWriter(&headerBuf, &relayWriter{wm.relay, stream})

		writer, err := oggwriter.NewWith(multi, 48000, 2)
		if err != nil {
			logger.L.Errorf("Failed to create Ogg writer for WebRTC source: %v", err)
			return
		}
		defer writer.Close()

		// Save captured headers immediately
		stream.mu.Lock()
		h := make([]byte, headerBuf.Len())
		copy(h, headerBuf.Bytes())
		stream.OggHead = h
		logger.L.Infow("WebRTC Source: Captured Ogg/Opus headers", "bytes", len(h), "offset", stream.OggHeaderOffset)
		stream.mu.Unlock()

		for {
			rtpPacket, _, err := track.ReadRTP()
			if err != nil {
				if err != io.EOF {
					logger.L.Errorf("Error reading RTP packet from source: %v", err)
				}
				return
			}
			if err := writer.WriteRTP(rtpPacket); err != nil {
				logger.L.Errorf("Error writing RTP to Ogg muxer: %v", err)
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
		logger.L.Errorw("WebRTC: Could not find Ogg sync in first 512KB. Is it an Opus stream?", "mount", stream.MountName)
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
		logger.L.Errorf("Failed to initialize Ogg/Opus reader for WebRTC: %v", err)
		return
	}

	pacer := &SimplePacer{}
	logger.L.Infof("WebRTC: Beginning packet transmission for %s", stream.MountName)
	sentCount := 0

	// Default Opus duration is 20ms. If we detect drift, the pacer will self-correct.
	const defaultDuration = 20 * time.Millisecond

	for {
		packet, err := opusReader.ReadAudioPacket()
		if err != nil {
			if err != io.EOF && !errors.Is(err, context.Canceled) {
				logger.L.Errorf("Error reading Opus packet: %v", err)
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
			logger.L.Debugw("WebRTC: Sent 100 packets", "mount", stream.MountName)
		}
	}
}

// HandleWHEPOffer accepts a raw SDP offer from a browser (WHEP egress)
// and returns a raw SDP answer. Unlike HandleOffer (which only attaches
// an Opus track from the legacy /webrtc/offer path), this picks both
// audio and video tracks when the mount has them. The returned string
// is the SDP answer only — the HTTP layer wraps it with the WHEP
// headers (Location, 201 status).
func (wm *WebRTCManager) HandleWHEPOffer(mount, sdpOffer string) (string, error) {
	stream, ok := wm.relay.GetStream(mount)
	if !ok {
		return "", fmt.Errorf("stream not found")
	}

	pc, err := wm.api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	})
	if err != nil {
		return "", err
	}

	// Audio: only attach when the source is Opus. Browsers don't decode
	// MP3 over WebRTC, so mounts without Opus get video-only playback.
	var audioTrack *webrtc.TrackLocalStaticSample
	ct := strings.ToLower(stream.ContentType)
	if strings.Contains(ct, "ogg") || strings.Contains(ct, "opus") {
		audioTrack, err = webrtc.NewTrackLocalStaticSample(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
			"audio", "tinyice-audio")
		if err != nil {
			pc.Close()
			return "", err
		}
		if _, err = pc.AddTrack(audioTrack); err != nil {
			pc.Close()
			return "", err
		}
	}

	// Video: attach when a /video sibling stream exists with H.264.
	var videoTrack *webrtc.TrackLocalStaticSample
	var videoStream *Stream
	if vs, ok := wm.relay.GetStream(mount + "/video"); ok {
		videoStream = vs
		videoTrack, err = webrtc.NewTrackLocalStaticSample(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264},
			"video", "tinyice-video")
		if err != nil {
			pc.Close()
			return "", err
		}
		if _, err = pc.AddTrack(videoTrack); err != nil {
			pc.Close()
			return "", err
		}
	}

	if audioTrack == nil && videoTrack == nil {
		pc.Close()
		return "", fmt.Errorf("mount has no Opus audio or H.264 video to egress")
	}

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdpOffer}
	if err = pc.SetRemoteDescription(offer); err != nil {
		pc.Close()
		return "", err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		return "", err
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		return "", err
	}
	<-gather

	if audioTrack != nil {
		go wm.streamToTrack(pc, audioTrack, stream)
	}
	if videoTrack != nil {
		go wm.streamVideoToTrack(pc, videoTrack, videoStream)
	}

	return pc.LocalDescription().SDP, nil
}

// streamVideoToTrack pulls per-frame Annex-B H.264 NALUs from the stream's
// FrameHub and hands them to the WebRTC sample track. TrackLocalStaticSample
// runs RTP packetization (FU-A fragmentation for NAL units larger than
// MTU) internally; we just need to feed it one full access unit per
// WriteSample call with a realistic Duration.
func (wm *WebRTCManager) streamVideoToTrack(pc *webrtc.PeerConnection, track *webrtc.TrackLocalStaticSample, stream *Stream) {
	if stream == nil || stream.Frames == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateClosed ||
			st == webrtc.PeerConnectionStateFailed ||
			st == webrtc.PeerConnectionStateDisconnected {
			cancel()
		}
	})

	frames := stream.Frames.Subscribe(ctx)
	var lastDTS int64 = -1
	// Wait for the first keyframe so the decoder has a valid IDR +
	// SPS / PPS to start from; without this Chrome shows a black
	// frame until the next GOP cycles around.
	gotKeyframe := false

	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-frames:
			if !ok {
				return
			}
			if !gotKeyframe {
				if !f.Keyframe {
					continue
				}
				gotKeyframe = true
			}
			dur := 33 * time.Millisecond // 30 fps sane default
			if lastDTS >= 0 {
				// Frame.DTS is in 90 kHz ticks.
				delta := f.DTS - lastDTS
				if delta > 0 && delta < 1800 { // < 20 ms..200 ms sanity
					dur = time.Duration(delta) * time.Second / 90000
				}
			}
			lastDTS = f.DTS
			if err := track.WriteSample(media.Sample{Data: f.Data, Duration: dur}); err != nil {
				return
			}
		}
	}
}

func (wm *WebRTCManager) DisconnectSource(mount string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	pc, ok := wm.sources[mount]
	if !ok {
		return fmt.Errorf("no WebRTC source for mount %s", mount)
	}
	delete(wm.sources, mount)
	return pc.Close()
}
