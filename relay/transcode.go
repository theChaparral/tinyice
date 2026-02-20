package relay

import (
	"bytes"
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
	instances map[string]*TranscoderInstance // key is OutputMount
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

	if inst, ok := tm.instances[cfg.OutputMount]; ok {
		inst.Stop()
	}

	ctx, cancel := context.WithCancel(context.Background())
	inst := &TranscoderInstance{
		Config:    cfg,
		cancel:    cancel,
		active:    true,
		StartTime: time.Now(),
	}
	tm.instances[cfg.OutputMount] = inst

	go tm.runTranscoder(ctx, inst)
}

func (tm *TranscoderManager) StopTranscoder(outputMount string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if inst, ok := tm.instances[outputMount]; ok {
		inst.Stop()
		delete(tm.instances, outputMount)
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
	var input *Stream
	var ok bool

	// 1. Wait for input stream to become available
	for {
		input, ok = tm.relay.GetStream(inst.Config.InputMount)
		if ok {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
			// Keep waiting
		}
	}

	logrus.Infof("Transcoder %s: Input stream %s found, initializing...", inst.Config.Name, inst.Config.InputMount)

	// 2. Subscribe to input
	id := fmt.Sprintf("transcoder-%s", inst.Config.Name)
	// We use a small burst to ensure the decoder gets enough data to start
	offset, signal := input.Subscribe(id, 32*1024) 
	defer input.Unsubscribe(id)

	reader := &StreamReader{
		Stream: input,
		Offset: offset,
		Signal: signal,
		Ctx:    ctx,
		ID:     id,
	}

	// 3. Decode
	decoder, err := mp3.NewDecoder(reader)
	if err != nil {
		logrus.WithError(err).Errorf("Transcoder %s: Failed to initialize decoder for input %s", inst.Config.Name, inst.Config.InputMount)
		return
	}

	// 4. Create Output Stream
	output := tm.relay.GetOrCreateStream(inst.Config.OutputMount)
	output.Name = fmt.Sprintf("%s (%s %dK)", input.Name, inst.Config.Format, inst.Config.Bitrate)
	output.Bitrate = fmt.Sprintf("%d", inst.Config.Bitrate)
	output.IsTranscoded = true
	output.Visible = tm.relay.GetStreamVisibility(inst.Config.InputMount) // Follow input visibility
	
	if inst.Config.Format == "mp3" {
		output.ContentType = "audio/mpeg"
		tm.encodeMP3(ctx, inst, decoder, output)
	} else if inst.Config.Format == "opus" {
		output.ContentType = "audio/ogg"
		tm.encodeOpus(ctx, inst, decoder, output)
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
	serial := uint32(time.Now().UnixNano())
	pw := ogg.NewPacketWriter(writer, serial)

	// 1. Capture headers in a buffer using a temporary writer with SAME serial
	var headerBuf bytes.Buffer
	headerPW := ogg.NewPacketWriter(&headerBuf, serial)

	head := ogg.OpusHead{
		Version:         1,
		Channels:        uint8(channels),
		InputSampleRate: uint32(sampleRate),
	}
	headPacket, _ := ogg.BuildOpusHeadPacket(head)
	headerPW.WritePacket(headPacket, 0, true, false)

	tags := ogg.OpusTags{Vendor: "tinyice-opus"}
	tagsPacket, _ := ogg.BuildOpusTagsPacket(tags)
	headerPW.WritePacket(tagsPacket, 0, false, false)
	headerPW.Flush()

	// Store for mid-stream listeners
	output.OggHead = headerBuf.Bytes()

	// 2. Now write the same packets to the ACTUAL stream using the main writer
	// This ensures main writer 'seq' starts correctly at 0, 1...
	pw.WritePacket(headPacket, 0, true, false)
	pw.WritePacket(tagsPacket, 0, false, false)
	pw.Flush()

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

func (tm *TranscoderManager) GetInstance(outputMount string) *TranscoderInstance {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.instances[outputMount]
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
