package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

type backoff struct {
	base    time.Duration
	max     time.Duration
	attempt int
}

func (b *backoff) next() time.Duration {
	exp := math.Pow(2, float64(b.attempt))
	delay := time.Duration(float64(b.base) * exp)
	if delay > b.max {
		delay = b.max
	}
	jitter := time.Duration(float64(delay) * (0.5 + rand.Float64()*0.5))
	b.attempt++
	return jitter
}

func (b *backoff) reset() {
	b.attempt = 0
}

type RelayState int

const (
	RelayConnecting   RelayState = iota
	RelayConnected
	RelayReconnecting
	RelayFailed
)

type RelayInstance struct {
	URL            string
	Mount          string
	Password       string
	BurstSize      int
	Visible        bool
	cancel         context.CancelFunc
	mu             sync.Mutex
	Active         bool
	State          RelayState
	LastConnected  time.Time
	LastError      string
	ReconnectCount int
}

type RelayManager struct {
	instances map[string]*RelayInstance
	mu        sync.RWMutex
	relay     *Relay
	client    *http.Client
}

func NewRelayManager(r *Relay) *RelayManager {
	return &RelayManager{
		instances: make(map[string]*RelayInstance),
		relay:     r,
		client: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}
}

func (rm *RelayManager) StartRelay(url, mount, password string, burstSize int, visible bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Stop existing if any
	if inst, ok := rm.instances[mount]; ok {
		inst.Stop()
	}

	ctx, cancel := context.WithCancel(context.Background())
	inst := &RelayInstance{
		URL:       url,
		Mount:     mount,
		Password:  password,
		BurstSize: burstSize,
		Visible:   visible,
		cancel:    cancel,
		Active:    true,
	}
	rm.instances[mount] = inst

	go rm.runRelay(ctx, inst)
}

func (rm *RelayManager) StopRelay(mount string) {

	rm.mu.Lock()

	defer rm.mu.Unlock()

	if inst, ok := rm.instances[mount]; ok {

		inst.Stop()

		delete(rm.instances, mount)

	}

}

func (rm *RelayManager) StopAll() {

	rm.mu.Lock()

	defer rm.mu.Unlock()

	for mount, inst := range rm.instances {

		inst.Stop()

		delete(rm.instances, mount)

	}

}

func (inst *RelayInstance) Stop() {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.cancel != nil {
		inst.cancel()
		inst.Active = false
	}
}

func (rm *RelayManager) runRelay(ctx context.Context, inst *RelayInstance) {
	bo := &backoff{base: 1 * time.Second, max: 60 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			inst.mu.Lock()
			inst.State = RelayConnecting
			inst.mu.Unlock()

			rm.performPull(ctx, inst)

			inst.mu.Lock()
			wasConnected := inst.State == RelayConnected
			inst.State = RelayReconnecting
			inst.ReconnectCount++
			inst.mu.Unlock()

			if wasConnected {
				bo.reset()
			}

			delay := bo.next()
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

func (rm *RelayManager) performPull(ctx context.Context, inst *RelayInstance) {
	logger.L.Infow("Attempting to pull relay stream", "url", inst.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", inst.URL, nil)
	if err != nil {
		inst.mu.Lock()
		inst.LastError = fmt.Sprintf("request creation failed: %v", err)
		inst.mu.Unlock()
		return
	}

	req.Header.Set("User-Agent", "TinyIce/0.1.0")
	req.Header.Set("Icy-MetaData", "1")
	req.Header.Set("Accept", "*/*")

	if inst.Password != "" {
		req.SetBasicAuth("source", inst.Password)
	}

	resp, err := rm.client.Do(req)
	if err != nil {
		logger.L.Errorf("Relay connection failed: %v", err)
		inst.mu.Lock()
		inst.LastError = fmt.Sprintf("connection failed: %v", err)
		inst.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.L.Errorw("Relay server returned non-200", "status", resp.Status)
		return
	}

	logger.L.Infow("Relay stream connected and pulling", "mount", inst.Mount)

	inst.mu.Lock()
	inst.State = RelayConnected
	inst.LastConnected = time.Now()
	inst.LastError = ""
	inst.mu.Unlock()

	stream := rm.relay.GetOrCreateStream(inst.Mount)
	stream.SourceIP = "relay-pull"

	// Metadata
	name := resp.Header.Get("Ice-Name")
	if name == "" {
		name = resp.Header.Get("Icy-Name")
	}
	desc := resp.Header.Get("Ice-Description")
	if desc == "" {
		desc = resp.Header.Get("Icy-Description")
	}
	genre := resp.Header.Get("Ice-Genre")
	if genre == "" {
		genre = resp.Header.Get("Icy-Genre")
	}
	bitrate := resp.Header.Get("Ice-Bitrate")
	if bitrate == "" {
		bitrate = resp.Header.Get("Icy-Br")
	}

	// Check for ICY metadata interval
	var metaInt int
	fmt.Sscanf(resp.Header.Get("Icy-Metaint"), "%d", &metaInt)

	stream.UpdateMetadata(name, desc, genre, resp.Header.Get("Ice-Url"), bitrate, resp.Header.Get("Content-Type"), false, inst.Visible)

	// In-stream metadata parsing
	if metaInt > 0 {
		rm.pullWithMetadata(ctx, resp.Body, stream, metaInt)
	} else {
		rm.pullSimple(ctx, resp.Body, stream)
	}
}

func (rm *RelayManager) pullSimple(ctx context.Context, body io.Reader, stream *Stream) {
	buf := make([]byte, 16384)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := body.Read(buf)
			if n > 0 {
				data := buf[:n]
				stream.Broadcast(data, rm.relay)

				// Sniff for Opus metadata (Vorbis comments) in Ogg pages
				// Look for "OpusTags" magic
				if idx := bytes.Index(data, []byte("OpusTags")); idx != -1 {
					// Found tags! Extract title if possible
					// Skip "OpusTags" (8 bytes)
					tagsData := data[idx+8:]
					if len(tagsData) > 8 {
						// Simple sniffer for "TITLE="
						tagsStr := string(tagsData)
						if strings.Contains(tagsStr, "TITLE=") {
							title := strings.Split(tagsStr, "TITLE=")[1]
							// Titles in Ogg are often null-terminated or limited by length
							// For simplicity, we just take a reasonable chunk and trim
							if len(title) > 100 {
								title = title[:100]
							}
							// Clean up
							title = strings.Map(func(r rune) rune {
								if r < 32 || r > 126 {
									return -1
								}
								return r
							}, title)
							if title != "" {
								stream.SetCurrentSong(title, rm.relay)
							}
						}
					}
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func (rm *RelayManager) pullWithMetadata(ctx context.Context, body io.Reader, stream *Stream, metaInt int) {
	audioBuf := make([]byte, metaInt)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// 1. Read Audio Data
			_, err := io.ReadFull(body, audioBuf)
			if err != nil {
				return
			}
			stream.Broadcast(audioBuf, rm.relay)

			// 2. Read Metadata Length Byte
			var metaLenByte [1]byte
			_, err = io.ReadFull(body, metaLenByte[:])
			if err != nil {
				return
			}

			metaLen := int(metaLenByte[0]) * 16
			if metaLen > 0 {
				// 3. Read Metadata String
				metaBuf := make([]byte, metaLen)
				_, err = io.ReadFull(body, metaBuf)
				if err != nil {
					return
				}

				// Parse StreamTitle='Artist - Title';
				metaStr := string(metaBuf)
				if strings.Contains(metaStr, "StreamTitle='") {
					title := strings.Split(metaStr, "StreamTitle='")[1]
					title = strings.Split(title, "';")[0]
					if title != "" {
						stream.SetCurrentSong(title, rm.relay)
					}
				}
			}
		}
	}
}
