package relay

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/sirupsen/logrus"
)

type StreamerState int

const (
	StateStopped StreamerState = iota
	StatePlaying
	StatePaused
)

type Streamer struct {
	Name        string
	OutputMount string
	MusicDir    string
	Playlist    []string
	CurrentPos  int
	State       StreamerState
	Loop        bool

	relay  *Relay
	cancel context.CancelFunc
	mu     sync.RWMutex

	// Stats
	BytesStreamed   int64
	CurrentFile     string
	CurrentFileTime time.Time
}

type StreamerManager struct {
	instances map[string]*Streamer // key is OutputMount
	mu        sync.RWMutex
	relay     *Relay
	config    *config.Config
}

func NewStreamerManager(r *Relay, cfg *config.Config) *StreamerManager {
	return &StreamerManager{
		instances: make(map[string]*Streamer),
		relay:     r,
		config:    cfg,
	}
}

func (s *Streamer) Play() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StatePlaying
}

func (s *Streamer) TogglePlay() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State == StatePlaying {
		s.State = StateStopped
	} else {
		s.State = StatePlaying
	}
}

func (s *Streamer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StateStopped
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Streamer) ScanMusicDir() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.MusicDir == "" {
		return fmt.Errorf("music directory not configured")
	}

	files, err := os.ReadDir(s.MusicDir)
	if err != nil {
		return err
	}

	s.Playlist = []string{}
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".mp3" {
			s.Playlist = append(s.Playlist, filepath.Join(s.MusicDir, f.Name()))
		}
	}
	return nil
}

func (sm *StreamerManager) StartStreamer(name, mount, musicDir string, loop bool) (*Streamer, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.instances[mount]; ok {
		return nil, fmt.Errorf("streamer for mount %s already exists", mount)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Streamer{
		Name:        name,
		OutputMount: mount,
		MusicDir:    musicDir,
		State:       StateStopped,
		Loop:        loop,
		relay:       sm.relay,
		cancel:      cancel,
	}
	sm.instances[mount] = s

	go sm.runStreamerLoop(ctx, s)
	return s, nil
}

func (sm *StreamerManager) StopStreamer(mount string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.instances[mount]; ok {
		s.Stop()
		delete(sm.instances, mount)
	}
}

func (sm *StreamerManager) GetStreamers() []*Streamer {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	res := make([]*Streamer, 0, len(sm.instances))
	for _, s := range sm.instances {
		res = append(res, s)
	}
	return res
}

func (sm *StreamerManager) GetStreamer(mount string) *Streamer {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.instances[mount]
}

func (sm *StreamerManager) runStreamerLoop(ctx context.Context, s *Streamer) {
	logrus.Infof("Streamer %s starting for mount %s", s.Name, s.OutputMount)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if s.State != StatePlaying {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			s.mu.RLock()
			if len(s.Playlist) == 0 {
				s.mu.RUnlock()
				time.Sleep(1 * time.Second)
				continue
			}

			if s.CurrentPos >= len(s.Playlist) {
				if s.Loop {
					s.CurrentPos = 0
				} else {
					s.State = StateStopped
					s.mu.RUnlock()
					continue
				}
			}
			filePath := s.Playlist[s.CurrentPos]
			s.mu.RUnlock()

			err := sm.streamFile(ctx, s, filePath)
			if err != nil {
				logrus.WithError(err).Errorf("Streamer %s: Failed to stream %s", s.Name, filePath)
				time.Sleep(1 * time.Second)
			}

			s.mu.Lock()
			s.CurrentPos++
			s.mu.Unlock()
		}
	}
}

func (sm *StreamerManager) streamFile(ctx context.Context, s *Streamer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	s.mu.Lock()
	s.CurrentFile = filepath.Base(path)
	s.CurrentFileTime = time.Now()
	s.mu.Unlock()

	// Update stream metadata
	output := sm.relay.GetOrCreateStream(s.OutputMount)
	output.CurrentSong = s.CurrentFile
	output.Name = s.Name

	// For now, we only support MP3 files and we assume they are compatible
	// with our output settings.
	// TODO: Add proper decoding/encoding if formats mismatch.

	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if s.State != StatePlaying {
				return nil
			}

			n, err := f.Read(buf)
			if n > 0 {
				output.Broadcast(buf[:n], sm.relay)
				atomic.AddInt64(&s.BytesStreamed, int64(n))

				// Basic pacing for MP3 (very rough)
				// We should ideally use a proper pacer or decode to PCM to pace.
				// For now, let's just assume 128kbps for pacing estimation.
				time.Sleep(time.Duration(n) * 8 * time.Second / 128000)
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
}
