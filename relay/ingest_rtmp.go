package relay

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	flvtag "github.com/yutopp/go-flv/tag"
	rtmp "github.com/yutopp/go-rtmp"
	rtmpmsg "github.com/yutopp/go-rtmp/message"
)

// RTMPServer accepts RTMP publish connections and feeds audio data into TinyIce streams.
type RTMPServer struct {
	relay    *Relay
	config   *config.Config
	listener net.Listener
	server   *rtmp.Server
	mu       sync.Mutex
}

// NewRTMPServer creates a new RTMP ingest server.
func NewRTMPServer(r *Relay, cfg *config.Config) *RTMPServer {
	return &RTMPServer{
		relay:  r,
		config: cfg,
	}
}

// Start begins listening for RTMP connections on the configured port.
func (rs *RTMPServer) Start() error {
	port := rs.config.Ingest.RTMPPort
	if port == "" {
		port = "1935"
	}

	addr := fmt.Sprintf(":%s", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("RTMP listen on %s: %w", addr, err)
	}
	rs.mu.Lock()
	rs.listener = ln
	rs.mu.Unlock()

	rs.server = rtmp.NewServer(&rtmp.ServerConfig{
		OnConnect: func(conn net.Conn) (io.ReadWriteCloser, *rtmp.ConnConfig) {
			h := &rtmpHandler{
				relay:  rs.relay,
				config: rs.config,
				conn:   conn,
			}
			return conn, &rtmp.ConnConfig{
				Handler: h,
			}
		},
	})

	logger.L.Infof("RTMP server listening on %s", addr)

	go func() {
		if err := rs.server.Serve(ln); err != nil {
			rs.mu.Lock()
			closed := rs.listener == nil
			rs.mu.Unlock()
			if !closed {
				logger.L.Errorf("RTMP server error: %v", err)
			}
		}
	}()

	return nil
}

// Stop shuts down the RTMP server.
func (rs *RTMPServer) Stop() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.listener != nil {
		rs.listener.Close()
		rs.listener = nil
	}
	if rs.server != nil {
		rs.server.Close()
		rs.server = nil
	}
}

// rtmpHandler handles a single RTMP connection.
type rtmpHandler struct {
	rtmp.DefaultHandler
	relay   *Relay
	config  *config.Config
	conn    net.Conn
	mount   string
	stream  *Stream
	started time.Time

	// Video support
	videoStream *Stream // separate video stream
	videoMount  string  // e.g., "/live/video"
	sps         []byte  // cached SPS NALU
	pps         []byte  // cached PPS NALU
	naluLenSize int     // AVCC NALU length size (usually 4)
}

// OnServe is called when the connection is established.
func (h *rtmpHandler) OnServe(conn *rtmp.Conn) {
	logger.L.Infow("RTMP: Client connected", "remote", h.conn.RemoteAddr())
}

// OnConnect handles the RTMP connect command.
func (h *rtmpHandler) OnConnect(timestamp uint32, cmd *rtmpmsg.NetConnectionConnect) error {
	logger.L.Infow("RTMP: Connect", "remote", h.conn.RemoteAddr(), "app", cmd.Command.App)
	return nil
}

// OnCreateStream handles stream creation.
func (h *rtmpHandler) OnCreateStream(timestamp uint32, cmd *rtmpmsg.NetConnectionCreateStream) error {
	return nil
}

// OnPublish handles the RTMP publish command — this is where we set up the mount point.
func (h *rtmpHandler) OnPublish(_ *rtmp.StreamContext, timestamp uint32, cmd *rtmpmsg.NetStreamPublish) error {
	publishName := cmd.PublishingName

	// Parse mount and optional key from publish name
	mount, sourcePassword := parseStreamKey(publishName)

	// Validate source password
	requiredPass, found := getSourcePassword(h.config, mount)
	if !found {
		requiredPass = h.config.DefaultSourcePassword
	}
	if requiredPass != "" && !config.CheckPasswordHash(sourcePassword, requiredPass) {
		logger.L.Warnw("RTMP: Auth failed", "mount", mount, "remote", h.conn.RemoteAddr())
		return fmt.Errorf("authentication failed for mount %s", mount)
	}

	// Check if mount is disabled
	if h.config.DisabledMounts[mount] {
		return fmt.Errorf("mount %s is disabled", mount)
	}

	h.mount = mount
	h.stream = h.relay.GetOrCreateStream(mount)
	h.stream.SourceIP = h.conn.RemoteAddr().String()
	h.stream.ContentType = "audio/mpeg" // default, may be updated on first audio data
	h.started = time.Now()

	// Create a separate video stream
	h.videoMount = mount + "/video"
	h.videoStream = h.relay.GetOrCreateStream(h.videoMount)
	h.videoStream.SourceIP = h.conn.RemoteAddr().String()
	h.videoStream.ContentType = "video/h264"
	h.videoStream.Buffer = NewCircularBuffer(8 * 1024 * 1024) // 8MB for video

	logger.L.Infow("RTMP: Publishing started",
		"mount", mount,
		"remote", h.conn.RemoteAddr(),
	)
	return nil
}

// OnAudio handles incoming audio data from the RTMP stream.
func (h *rtmpHandler) OnAudio(timestamp uint32, payload io.Reader) error {
	if h.stream == nil {
		return nil
	}

	// Read the FLV audio tag header
	var audioTag flvtag.AudioData
	if err := flvtag.DecodeAudioData(payload, &audioTag); err != nil {
		return err
	}

	// Read the raw audio data
	data, err := io.ReadAll(audioTag.Data)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	// Determine content type from codec
	switch audioTag.SoundFormat {
	case flvtag.SoundFormatMP3:
		h.stream.ContentType = "audio/mpeg"
	case flvtag.SoundFormatAAC:
		h.stream.ContentType = "audio/aac"
		// Skip AAC sequence header (AudioSpecificConfig), only pass raw frames
		if audioTag.AACPacketType == flvtag.AACPacketTypeSequenceHeader {
			return nil
		}
	default:
		// Unknown format, pass through
	}

	// Broadcast the raw audio data to the stream
	h.stream.Broadcast(data, h.relay)
	return nil
}

// OnVideo handles incoming video data from the RTMP stream.
func (h *rtmpHandler) OnVideo(timestamp uint32, payload io.Reader) error {
	if h.videoStream == nil {
		_, _ = io.ReadAll(payload)
		return nil
	}

	var videoTag flvtag.VideoData
	if err := flvtag.DecodeVideoData(payload, &videoTag); err != nil {
		return err
	}

	data, err := io.ReadAll(videoTag.Data)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	// Handle AVC (H.264)
	if videoTag.CodecID == flvtag.CodecIDAVC {
		switch videoTag.AVCPacketType {
		case flvtag.AVCPacketTypeSequenceHeader:
			// Parse AVCDecoderConfigurationRecord to extract SPS/PPS
			h.parseAVCConfig(data)
			return nil
		case flvtag.AVCPacketTypeNALU:
			// Convert AVCC to Annex B and broadcast
			if h.naluLenSize == 0 {
				h.naluLenSize = 4
			}
			annexB := AVCCToAnnexB(data, h.naluLenSize)
			if len(annexB) == 0 {
				return nil
			}

			// Check for keyframe and record in buffer
			if ContainsKeyframe(annexB) {
				h.videoStream.Buffer.RecordKeyframe(h.videoStream.Buffer.Head)
			}

			h.videoStream.Broadcast(annexB, h.relay)
		}
	}

	return nil
}

// parseAVCConfig extracts SPS/PPS from AVCDecoderConfigurationRecord.
func (h *rtmpHandler) parseAVCConfig(data []byte) {
	if len(data) < 8 {
		return
	}
	// AVCDecoderConfigurationRecord structure:
	// [0] configurationVersion
	// [1] AVCProfileIndication
	// [2] profile_compatibility
	// [3] AVCLevelIndication
	// [4] lengthSizeMinusOne (lower 2 bits) + reserved
	h.naluLenSize = int(data[4]&0x03) + 1

	// [5] numOfSPS (lower 5 bits)
	numSPS := int(data[5] & 0x1F)
	offset := 6

	for i := 0; i < numSPS && offset+2 <= len(data); i++ {
		spsLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+spsLen <= len(data) {
			h.sps = make([]byte, spsLen)
			copy(h.sps, data[offset:offset+spsLen])
			offset += spsLen
		}
	}

	// numOfPPS
	if offset < len(data) {
		numPPS := int(data[offset])
		offset++
		for i := 0; i < numPPS && offset+2 <= len(data); i++ {
			ppsLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			if offset+ppsLen <= len(data) {
				h.pps = make([]byte, ppsLen)
				copy(h.pps, data[offset:offset+ppsLen])
				offset += ppsLen
			}
		}
	}

	logger.L.Infow("RTMP: Parsed AVC config",
		"mount", h.mount,
		"sps_len", len(h.sps),
		"pps_len", len(h.pps),
		"nalu_len_size", h.naluLenSize,
	)
}

// OnClose is called when the connection is closed.
func (h *rtmpHandler) OnClose() {
	if h.mount != "" {
		logger.L.Infow("RTMP: Source disconnected",
			"mount", h.mount,
			"remote", h.conn.RemoteAddr(),
			"duration", time.Since(h.started),
		)
		h.relay.RemoveStream(h.mount)
	}
	if h.videoMount != "" {
		h.relay.RemoveStream(h.videoMount)
	}
}

// parseStreamKey splits "mount" or "mount?key=password" into mount and password.
func parseStreamKey(key string) (string, string) {
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}

	parts := strings.SplitN(key, "?", 2)
	mount := parts[0]

	password := ""
	if len(parts) == 2 {
		for _, param := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 && kv[0] == "key" {
				password = kv[1]
				break
			}
		}
	}

	return mount, password
}

// getSourcePassword looks up the configured source password for a mount.
func getSourcePassword(cfg *config.Config, mount string) (string, bool) {
	if am, ok := cfg.AdvancedMounts[mount]; ok && am.Password != "" {
		return am.Password, true
	}
	if pw, ok := cfg.Mounts[mount]; ok {
		return pw, true
	}
	return "", false
}
