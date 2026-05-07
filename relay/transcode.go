package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	shine "github.com/braheezy/shine-mp3/pkg/mp3"
	"github.com/kazzmir/opus-go/ogg"
	"github.com/kazzmir/opus-go/opus"
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
	logger.L.Infow("Starting transcoder",
		"name", inst.Config.Name,
		"input", inst.Config.InputMount,
		"output", inst.Config.OutputMount,
		"format", inst.Config.Format,
		"bitrate", inst.Config.Bitrate,
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			tm.safePerformTranscode(ctx, inst)
			// Wait before retry if input stream wasn't found
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// safePerformTranscode wraps performTranscode with a panic recovery. Some
// third-party decoders (e.g. go-mp3) can panic on malformed or non-MP3 input
// instead of returning an error. Recovering here prevents a bad input stream
// from taking down the whole server and lets the retry loop try again.
func (tm *TranscoderManager) safePerformTranscode(ctx context.Context, inst *TranscoderInstance) {
	defer func() {
		if r := recover(); r != nil {
			logger.L.Errorw("Transcoder: recovered from panic",
				"name", inst.Config.Name,
				"input", inst.Config.InputMount,
				"output", inst.Config.OutputMount,
				"panic", fmt.Sprintf("%v", r),
			)
		}
	}()
	tm.performTranscode(ctx, inst)
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

	logger.L.Infow("Transcoder: Input stream found, initializing...", "name", inst.Config.Name, "input", inst.Config.InputMount)

	// 2. Subscribe to input
	id := fmt.Sprintf("transcoder-%s", inst.Config.Name)
	// Burst 256 KiB so the decoder has several seconds of data to initialise
	// even when the source bitrate is low — 32 KiB left strict Opus / FLAC
	// decoders short on bytes at startup, producing a noisy first packet.
	offset, signal := input.SubscribeInternal(id, 256*1024)
	defer input.Unsubscribe(id)

	// For live Ogg inputs, the subscribe offset lands mid-stream. The decoder
	// needs the BOS + setup pages to initialise, so we prepend the captured
	// OggHead (stored by the Icecast SOURCE / WebRTC ingest) and align the
	// live reader to the next valid page boundary so the Ogg page parser
	// picks up from a clean edge.
	input.mu.RLock()
	isOgg := input.IsOggStream || strings.Contains(strings.ToLower(input.ContentType), "ogg") ||
		strings.Contains(strings.ToLower(input.ContentType), "opus") ||
		strings.Contains(strings.ToLower(input.ContentType), "vorbis") ||
		strings.Contains(strings.ToLower(input.ContentType), "flac")
	bufSize := input.Buffer.Size
	bufHead := input.Buffer.Head
	var headBytes []byte
	if len(input.OggHead) > 0 {
		headBytes = append(headBytes, input.OggHead...)
	}
	input.mu.RUnlock()

	var reader io.Reader
	if isOgg {
		// FindNextPageBoundaryLocked holds the buffer's mutex so it can run
		// safely while the ingest goroutine is still writing new bytes.
		aligned := input.Buffer.FindNextPageBoundaryLocked(offset)
		_ = bufSize
		_ = bufHead
		if aligned < input.Buffer.Head {
			offset = aligned
		}
		live := NewStreamReader(input.Buffer, offset, signal, ctx, id).WithOggSync(input)
		if len(headBytes) > 0 {
			reader = io.MultiReader(bytes.NewReader(headBytes), live)
		} else {
			// Without stored headers the decoder will likely fail to init;
			// log a hint so the operator knows to restart the source so we
			// can capture BOS/Tags next time.
			logger.L.Warnw("Transcoder: Ogg input has no captured headers; decoder may fail until source reconnects",
				"name", inst.Config.Name, "input", inst.Config.InputMount,
			)
			reader = live
		}
	} else {
		reader = NewStreamReader(input.Buffer, offset, signal, ctx, id).WithOggSync(input)
	}

	// 3. Decode — auto-detect MP3 / Ogg Opus / Ogg Vorbis / FLAC from the
	// first bytes of the input stream.
	decoder, err := OpenDecoder(reader)
	if err != nil {
		logger.L.Errorw("Transcoder: Failed to initialize decoder", "name", inst.Config.Name, "input", inst.Config.InputMount, "error", err)
		return
	}

	// 4. Create Output Stream. Take the stream mutex for the whole
	// metadata block so concurrent Snapshot / listener reads see a
	// coherent set of fields.
	output := tm.relay.GetOrCreateStream(inst.Config.OutputMount)
	input.mu.RLock()
	inputName := input.Name
	input.mu.RUnlock()
	output.mu.Lock()
	output.Name = fmt.Sprintf("%s (%s %dK)", inputName, inst.Config.Format, inst.Config.Bitrate)
	output.Bitrate = fmt.Sprintf("%d", inst.Config.Bitrate)
	output.IsTranscoded = true
	output.Visible = tm.relay.GetStreamVisibility(inst.Config.InputMount) // Follow input visibility
	output.mu.Unlock()

	go mirrorTranscodeMetadata(ctx, input, output)


	if inst.Config.Format == "mp3" {
		output.mu.Lock()
		output.ContentType = "audio/mpeg"
		output.mu.Unlock()
		sr := inst.Config.SampleRate
		if sr == 0 {
			sr = decoder.SampleRate()
		}
		// If the operator picked an explicit output rate different from
		// the decoder's native rate, resample before encoding so shine
		// sees the rate it was configured with.
		var pcm io.Reader = decoder
		if sr != decoder.SampleRate() {
			pcm = NewLinearResampler(decoder, decoder.SampleRate(), sr)
		}
		EncodeMP3(ctx, tm.relay, output, pcm, inst.Config.Bitrate, &inst.BytesEncoded, false, sr)
	} else if inst.Config.Format == "opus" {
		output.mu.Lock()
		output.ContentType = "audio/ogg"
		output.mu.Unlock()
		// Opus is always 48 kHz internally. Anything else needs a
		// resampler; without this the encoder plays 44.1 kHz MP3 input
		// ~8.8 % too fast (chipmunk voice).
		var pcm io.Reader = decoder
		if decoder.SampleRate() != 48000 {
			pcm = NewLinearResampler(decoder, decoder.SampleRate(), 48000)
			logger.L.Infow("Transcoder: resampling input for Opus",
				"name", inst.Config.Name,
				"from", decoder.SampleRate(),
				"to", 48000,
			)
		}
		EncodeOpus(ctx, tm.relay, output, pcm, inst.Config.Bitrate, &inst.BytesEncoded, false,
			OpusEncoderSettings{
				Application: inst.Config.OpusApplication,
				VBR:         inst.Config.OpusVBR,
				Complexity:  inst.Config.OpusComplexity,
				FrameSizeMS: inst.Config.OpusFrameSizeMS,
			})
	}
}

// OpusEncoderSettings carries optional Opus tuning. Zero / empty values fall
// back to encoder defaults.
type OpusEncoderSettings struct {
	Application string // "audio" | "voip" | "lowdelay"
	VBR         *bool  // nil = VBR on
	Complexity  int    // 0..10, 0 = encoder default
	FrameSizeMS int    // 2/5/10/20/40/60, 0 = 20
}

func resolveOpusApplication(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "voip":
		return opus.ApplicationVoIP
	case "lowdelay", "restricted_lowdelay", "restricted-lowdelay":
		return opus.ApplicationRestrictedLowDelay
	default:
		return opus.ApplicationAudio
	}
}

// shineBitRates mirrors the unexported bitRates table in shine-mp3. Indexed
// as [bitrate_index][mpegVersion], with:
//   - mpegVersion 0 = MPEG-2.5, 1 = reserved, 2 = MPEG-II, 3 = MPEG-I
//   - bitrate_index 0..14 correspond to kbps values (15 is "invalid").
// -1 entries are unsupported bitrate/version combinations.
var shineBitRates = [16][4]int64{
	{-1, -1, -1, -1}, {8, -1, 8, 32}, {16, -1, 16, 40}, {24, -1, 24, 48},
	{32, -1, 32, 56}, {40, -1, 40, 64}, {48, -1, 48, 80}, {56, -1, 56, 96},
	{64, -1, 64, 112}, {-1, -1, 80, 128}, {-1, -1, 96, 160}, {-1, -1, 112, 192},
	{-1, -1, 128, 224}, {-1, -1, 144, 256}, {-1, -1, 160, 320}, {-1, -1, -1, -1},
}

// applyShineBitrate reaches into a shine.Encoder and overrides the bitrate
// (and its derived BitrateIndex / WholeSlotsPerFrame / FracSlotsPerFrame /
// Slot_lag fields) so the encoded output actually respects the operator's
// bitrate choice. Returns false if the combination isn't supported by the
// MPEG bitrate table for this sample rate.
func applyShineBitrate(enc *shine.Encoder, sampleRate, bitrate int) bool {
	if shine.CheckConfig(sampleRate, bitrate) == -1 {
		return false
	}
	version := int(enc.Mpeg.Version)
	if version < 0 || version >= 4 {
		return false
	}
	bitrateIndex := -1
	for i := 0; i < 16; i++ {
		if shineBitRates[i][version] == int64(bitrate) {
			bitrateIndex = i
			break
		}
	}
	if bitrateIndex < 0 {
		return false
	}
	enc.Mpeg.Bitrate = int64(bitrate)
	enc.Mpeg.BitrateIndex = int64(bitrateIndex)
	// Recompute the frame-size constants from shine's own formula.
	avg := (float64(enc.Mpeg.GranulesPerFrame) * 576.0 / float64(enc.Wave.SampleRate)) *
		(float64(enc.Mpeg.Bitrate) * 1000.0 / float64(enc.Mpeg.BitsPerSlot))
	enc.Mpeg.WholeSlotsPerFrame = int64(avg)
	enc.Mpeg.FracSlotsPerFrame = avg - float64(enc.Mpeg.WholeSlotsPerFrame)
	enc.Mpeg.Slot_lag = -enc.Mpeg.FracSlotsPerFrame
	if enc.Mpeg.FracSlotsPerFrame == 0 {
		enc.Mpeg.Padding = 0
	}
	return true
}

func resolveOpusFrameSizeMS(ms int) int {
	switch ms {
	case 2, 5, 10, 20, 40, 60:
		return ms
	default:
		return 20
	}
}

func EncodeMP3(ctx context.Context, relay *Relay, output *Stream, decoder io.Reader, bitrate int, stats *int64, pace bool, sampleRate int) {
	if sampleRate <= 0 {
		sampleRate = 44100 // Fallback
	}
	// Shine MP3 initialization. NewEncoder hard-codes the bitrate at 128,
	// so we reach into the Mpeg field to pick up the caller's bitrate. If
	// the combination isn't valid for the MPEG bitrate table we fall back
	// to the 128 kbps default rather than producing a malformed stream.
	encoder := shine.NewEncoder(sampleRate, 2)
	if bitrate > 0 && bitrate != 128 {
		if !applyShineBitrate(encoder, sampleRate, bitrate) {
			logger.L.Warnw("EncodeMP3: requested bitrate not supported for sample rate, falling back to 128 kbps",
				"sample_rate", sampleRate, "requested_bitrate", bitrate)
		}
	}

	// Output buffer - shine Write uses int16 samples
	pcmBuf := make([]byte, 4608) // 1152 samples * 2 bytes * 2 channels
	samples := make([]int16, 2304)

	startTime := time.Now()
	totalSamples := int64(0)

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
			writer := &streamWriter{stream: output, relay: relay, stats: stats}
			err = encoder.Write(writer, samples[:n/2])
			if err != nil {
				return
			}

			if pace {
				totalSamples += int64(n / 4) // 2 channels, 2 bytes per sample
				elapsed := time.Since(startTime)
				expected := time.Duration(totalSamples) * time.Second / time.Duration(sampleRate)
				if expected > elapsed {
					time.Sleep(expected - elapsed)
				}
			}
		}
	}
}

func EncodeOpus(ctx context.Context, relay *Relay, output *Stream, decoder io.Reader, bitrate int, stats *int64, pace bool, settings ...OpusEncoderSettings) {
	// 48kHz is the canonical Opus sample rate.
	const sampleRate = 48000
	const channels = 2
	var cfg OpusEncoderSettings
	if len(settings) > 0 {
		cfg = settings[0]
	}
	frameMS := resolveOpusFrameSizeMS(cfg.FrameSizeMS)
	frameSize := sampleRate * frameMS / 1000

	enc, err := opus.NewEncoder(sampleRate, channels, resolveOpusApplication(cfg.Application))
	if err != nil {
		logger.L.Errorf("Failed to create Opus encoder: %v", err)
		return
	}
	defer enc.Close()

	if bitrate > 0 {
		enc.SetBitrate(bitrate * 1000)
	}
	if cfg.Complexity > 0 && cfg.Complexity <= 10 {
		_ = enc.SetComplexity(cfg.Complexity)
	}
	if cfg.VBR != nil {
		_ = enc.SetVBR(*cfg.VBR)
	}

	// Ogg encapsulation
	writer := &streamWriter{stream: output, relay: relay, stats: stats, capture: true}
	serial := uint32(time.Now().UnixNano())
	pw := ogg.NewPacketWriter(writer, serial)

	// 1. ID Header
	head := ogg.OpusHead{
		Version:         1,
		Channels:        uint8(channels),
		InputSampleRate: uint32(sampleRate),
	}
	headPacket, _ := ogg.BuildOpusHeadPacket(head)
	pw.WritePacket(headPacket, 0, true, false)
	pw.Flush()

	// 2. Tags Header
	tags := ogg.OpusTags{Vendor: "tinyice-opus"}
	tagsPacket, _ := ogg.BuildOpusTagsPacket(tags)
	pw.WritePacket(tagsPacket, 0, false, false)
	pw.Flush()

	// Store for mid-stream listeners
	// Store captured headers + the buffer offset at which the first audio
	// byte will be written, under the stream mutex so listeners that
	// subscribe concurrently see a consistent pair.
	output.StoreOggHead(writer.headerBuf.Bytes(), output.Buffer.Head)
	writer.capture = false // Stop capturing headers

	pcmBuf := make([]byte, frameSize*channels*2)
	pcmSamples := make([]int16, frameSize*channels)
	opusPacket := make([]byte, 4000) // Max opus packet size

	var granulePos uint64
	var sentCount int64 = 0
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, rerr := io.ReadFull(decoder, pcmBuf)
			if rerr != nil {
				return
			}

			for i := 0; i < len(pcmSamples); i++ {
				pcmSamples[i] = int16(pcmBuf[i*2]) | int16(pcmBuf[i*2+1])<<8
			}

			en, eerr := enc.Encode(pcmSamples, frameSize, opusPacket)
			if eerr != nil {
				logger.L.Errorf("Opus encode error: %v", eerr)
				return
			}

			granulePos += uint64(frameSize)
			if err := pw.WritePacket(opusPacket[:en], granulePos, false, false); err != nil {
				return
			}
			pw.Flush()

			if pace {
				sentCount++
				elapsed := time.Since(startTime)
				expected := time.Duration(sentCount*int64(frameMS)) * time.Millisecond
				if expected > elapsed {
					time.Sleep(expected - elapsed)
				}
			}
		}
	}
}

type streamWriter struct {
	stream    *Stream
	relay     *Relay
	stats     *int64
	headerBuf bytes.Buffer
	capture   bool
}

func (w *streamWriter) Write(p []byte) (n int, err error) {
	if w.capture {
		w.headerBuf.Write(p)
	}
	w.stream.Broadcast(p, w.relay)
	if w.stats != nil {
		atomic.AddInt64(w.stats, int64(len(p)))
	}
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


// mirrorTranscodeMetadata keeps the transcoded output stream's display
// metadata (current song, genre, URL, description, public/visible flags)
// in sync with the input stream while the transcode runs. Without this,
// listeners on /<mount>-128 never see StreamTitle updates from the
// upstream encoder, and the public Icecast directory listing shows
// generic info on the transcoded sibling.
func mirrorTranscodeMetadata(ctx context.Context, input, output *Stream) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastSong, lastGenre, lastURL, lastDesc string
	var lastPublic, lastVisible bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			input.mu.RLock()
			song := input.CurrentSong
			genre := input.Genre
			url := input.URL
			desc := input.Description
			pub := input.Public
			vis := input.Visible
			input.mu.RUnlock()

			if song != lastSong {
				output.mu.Lock()
				output.CurrentSong = song
				output.mu.Unlock()
				lastSong = song
			}
			if genre != lastGenre || url != lastURL || desc != lastDesc || pub != lastPublic || vis != lastVisible {
				output.mu.Lock()
				output.Genre = genre
				output.URL = url
				output.Description = desc
				output.Public = pub
				output.Visible = vis
				output.mu.Unlock()
				lastGenre, lastURL, lastDesc, lastPublic, lastVisible = genre, url, desc, pub, vis
			}
		}
	}
}


// EnsureAutoMP3Transcoders is called when a source connects on `inputMount`.
// For each bitrate in the list it spawns a temporary mp3 transcoder named
// `<inputMount>-mp3-<bitrate>` if no transcoder for that output is already
// running. Auto-spawned transcoders are not persisted to config; they go
// away with the source and reappear on the next connect. Manual entries
// in cfg.Transcoders take precedence (we don't clobber them).
func (tm *TranscoderManager) EnsureAutoMP3Transcoders(inputMount string, bitrates []int, manualConfigs []*config.TranscoderConfig) {
	if len(bitrates) == 0 {
		return
	}
	for _, br := range bitrates {
		if br < 32 || br > 320 {
			continue
		}
		outputMount := fmt.Sprintf("%s-mp3-%d", inputMount, br)
		if tm.GetInstance(outputMount) != nil {
			continue
		}
		skip := false
		for _, mc := range manualConfigs {
			if mc != nil && mc.OutputMount == outputMount {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		cfg := &config.TranscoderConfig{
			Name:        fmt.Sprintf("auto-%s-mp3-%d", strings.TrimPrefix(inputMount, "/"), br),
			InputMount:  inputMount,
			OutputMount: outputMount,
			Format:      "mp3",
			Bitrate:     br,
			Enabled:     true,
		}
		tm.StartTranscoder(cfg)
		logger.L.Infow("auto-spawned MP3 transcoder",
			"input", inputMount, "output", outputMount, "bitrate", br)
	}
}
