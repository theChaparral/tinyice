package relay

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	shine "github.com/braheezy/shine-mp3/pkg/mp3"
	"github.com/hajimehoshi/go-mp3"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/kazzmir/opus-go/opus"
	"github.com/sirupsen/logrus"
)

type TranscoderInstance struct {
	Config *config.TranscoderConfig
	cancel context.CancelFunc
	active bool
	mu     sync.Mutex

	// Stats
	FramesProcessed int64
	BytesEncoded    int64
	StartTime       time.Time
}

type TranscoderManager struct {
	instances map[string]*TranscoderInstance // key is Name
	mu        sync.RWMutex
	relay     *Relay
}

func NewTranscoderManager(r *Relay) *TranscoderManager {
	return &TranscoderManager{
		instances: make(map[string]*TranscoderInstance),
		relay:     r,
	}
}

func (tm *TranscoderManager) StartTranscoder(cfg *config.TranscoderConfig) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if inst, ok := tm.instances[cfg.Name]; ok {
		inst.Stop()
	}

	ctx, cancel := context.WithCancel(context.Background())
	inst := &TranscoderInstance{
		Config:    cfg,
		cancel:    cancel,
		active:    true,
		StartTime: time.Now(),
	}
	tm.instances[cfg.Name] = inst

	go tm.runTranscoder(ctx, inst)
}

func (tm *TranscoderManager) StopTranscoder(name string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if inst, ok := tm.instances[name]; ok {
		inst.Stop()
		delete(tm.instances, name)
	}
}

func (tm *TranscoderManager) StopAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, inst := range tm.instances {
		inst.Stop()
	}
	tm.instances = make(map[string]*TranscoderInstance)
}

func (inst *TranscoderInstance) Stop() {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.cancel != nil {
		inst.cancel()
		inst.active = false
	}
}

func (tm *TranscoderManager) runTranscoder(ctx context.Context, inst *TranscoderInstance) {
	logrus.Infof("Starting transcoder %s: %s -> %s (%s %dkbps)", 
		inst.Config.Name, inst.Config.InputMount, inst.Config.OutputMount, inst.Config.Format, inst.Config.Bitrate)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			tm.performTranscode(ctx, inst)
			// Wait before retry if input stream wasn't found
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (tm *TranscoderManager) performTranscode(ctx context.Context, inst *TranscoderInstance) {
	input, ok := tm.relay.GetStream(inst.Config.InputMount)
	if !ok {
		return
	}

	// 1. Subscribe to input
	id := fmt.Sprintf("transcoder-%s", inst.Config.Name)
	offset, signal := input.Subscribe(id, 0) // No burst for transcoder
	defer input.Unsubscribe(id)

	reader := &StreamReader{
		Stream: input,
		Offset: offset,
		Signal: signal,
		Ctx:    ctx,
		ID:     id,
	}

	// 2. Decode (assuming MP3 input for now as standard)
	decoder, err := mp3.NewDecoder(reader)
	if err != nil {
		logrus.WithError(err).Errorf("Transcoder %s: Failed to initialize decoder for input %s", inst.Config.Name, inst.Config.InputMount)
		return
	}

	// 3. Create Output Stream
	output := tm.relay.GetOrCreateStream(inst.Config.OutputMount)
	output.Name = fmt.Sprintf("%s (%s %dK)", input.Name, inst.Config.Format, inst.Config.Bitrate)
	output.Bitrate = fmt.Sprintf("%d", inst.Config.Bitrate)
	output.ContentType = "audio/mpeg"
	if inst.Config.Format == "opus" {
		output.ContentType = "audio/ogg"
	}

	// 4. Encode & Broadcast
	if inst.Config.Format == "mp3" {
		tm.encodeMP3(ctx, inst, decoder, output)
	} else if inst.Config.Format == "opus" {
		tm.encodeOpus(ctx, inst, decoder, output)
	} else {
		logrus.Warnf("Transcoding format %s not yet implemented", inst.Config.Format)
	}
}

func (tm *TranscoderManager) encodeMP3(ctx context.Context, inst *TranscoderInstance, decoder io.Reader, output *Stream) {
	// Shine MP3 initialization
	encoder := shine.NewEncoder(44100, 2)
	
	// Output buffer - shine Write uses int16 samples
	pcmBuf := make([]byte, 4608) // 1152 samples * 2 bytes * 2 channels
	samples := make([]int16, 2304)
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := io.ReadFull(decoder, pcmBuf)
			if err != nil {
				return
			}

			// Convert PCM bytes to int16 for Shine
			for i := 0; i < n/2; i++ {
				samples[i] = int16(pcmBuf[i*2]) | int16(pcmBuf[i*2+1])<<8
			}

			// Encode and broadcast
			// Shine writes directly to an io.Writer
			// We can wrap our broadcast in an io.Writer
			writer := &streamWriter{stream: output, relay: tm.relay, inst: inst}
			err = encoder.Write(writer, samples[:n/2])
			if err != nil {
				return
			}
			atomic.AddInt64(&inst.FramesProcessed, 1)
		}
	}
}

func (tm *TranscoderManager) encodeOpus(ctx context.Context, inst *TranscoderInstance, decoder io.Reader, output *Stream) {
	// 48kHz is standard for Opus
	const sampleRate = 48000
	const channels = 2
	const frameMS = 20
	const frameSize = sampleRate * frameMS / 1000

	enc, err := opus.NewEncoder(sampleRate, channels, opus.ApplicationAudio)
	if err != nil {
		logrus.WithError(err).Error("Failed to create Opus encoder")
		return
	}
	defer enc.Close()

	if inst.Config.Bitrate > 0 {
		enc.SetBitrate(inst.Config.Bitrate * 1000)
	}

	// Ogg encapsulation
	writer := &streamWriter{stream: output, relay: tm.relay, inst: inst}
	pw := ogg.NewPacketWriter(writer, uint32(time.Now().UnixNano()))

	// ID Header
	head := ogg.OpusHead{
		Version:         1,
		Channels:        uint8(channels),
		InputSampleRate: uint32(sampleRate),
	}
	headPacket, _ := ogg.BuildOpusHeadPacket(head)
	pw.WritePacket(headPacket, 0, true, false)

	// Tags Header
	tags := ogg.OpusTags{Vendor: "tinyice-opus"}
	tagsPacket, _ := ogg.BuildOpusTagsPacket(tags)
	pw.WritePacket(tagsPacket, 0, false, false)

	pcmBuf := make([]byte, frameSize*channels*2)
	pcmSamples := make([]int16, frameSize*channels)
	opusPacket := make([]byte, 4000) // Max opus packet size

	var granulePos uint64

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, err := io.ReadFull(decoder, pcmBuf)
			if err != nil {
				return
			}

			for i := 0; i < len(pcmSamples); i++ {
				pcmSamples[i] = int16(pcmBuf[i*2]) | int16(pcmBuf[i*2+1])<<8
			}

			n, err := enc.Encode(pcmSamples, frameSize, opusPacket)
			if err != nil {
				logrus.WithError(err).Error("Opus encode error")
				return
			}

			granulePos += uint64(frameSize)
			if err := pw.WritePacket(opusPacket[:n], granulePos, false, false); err != nil {
				return
			}
			
			atomic.AddInt64(&inst.FramesProcessed, 1)
		}
	}
}

type streamWriter struct {
	stream *Stream
	relay  *Relay
	inst   *TranscoderInstance
}

func (w *streamWriter) Write(p []byte) (n int, err error) {
	w.stream.Broadcast(p, w.relay)
	atomic.AddInt64(&w.inst.BytesEncoded, int64(len(p)))
	return len(p), nil
}

func (tm *TranscoderManager) GetInstance(name string) *TranscoderInstance {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.instances[name]
}

type TranscoderStats struct {
	Name            string `json:"name"`
	Input           string `json:"input"`
	Output          string `json:"output"`
	Format          string `json:"format"`
	Bitrate         int    `json:"bitrate"`
	Active          bool   `json:"active"`
	FramesProcessed int64  `json:"frames"`
	BytesEncoded    int64  `json:"bytes"`
	Uptime          string `json:"uptime"`
}
