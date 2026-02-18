package relay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type RelayInstance struct {
	URL       string
	Mount     string
	Password  string
	BurstSize int
	Visible   bool
	cancel    context.CancelFunc
	mu        sync.Mutex
	Active    bool
}

type RelayManager struct {
	instances map[string]*RelayInstance // key is mount
	mu        sync.RWMutex
	relay     *Relay
}

func NewRelayManager(r *Relay) *RelayManager {
	return &RelayManager{
		instances: make(map[string]*RelayInstance),
		relay:     r,
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

func (inst *RelayInstance) Stop() {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.cancel != nil {
		inst.cancel()
		inst.Active = false
	}
}

func (rm *RelayManager) runRelay(ctx context.Context, inst *RelayInstance) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			rm.performPull(ctx, inst)
			// Wait before retry
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (rm *RelayManager) performPull(ctx context.Context, inst *RelayInstance) {
	logrus.WithField("url", inst.URL).Info("Attempting to pull relay stream")

	req, err := http.NewRequestWithContext(ctx, "GET", inst.URL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "TinyIce/0.1.0")
	req.Header.Set("Icy-MetaData", "1")
	req.Header.Set("Accept", "*/*")

	if inst.Password != "" {
		req.SetBasicAuth("source", inst.Password)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Relay connection failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status", resp.Status).Error("Relay server returned non-200")
		return
	}

	logrus.WithField("mount", inst.Mount).Info("Relay stream connected and pulling")

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
	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := body.Read(buf)
			if n > 0 {
				stream.Broadcast(buf[:n], rm.relay)
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
