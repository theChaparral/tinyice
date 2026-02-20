package relay

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/hajimehoshi/go-mp3"
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
	Format      string
	Bitrate     int
	Playlist    []string
	Queue       []string
	CurrentPos  int
	State       StreamerState
	Loop        bool
	Shuffle     bool

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

func (s *Streamer) ToggleShuffle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Shuffle = !s.Shuffle
}

func (s *Streamer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StateStopped
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Streamer) PushToQueue(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Queue = append(s.Queue, path)
}

func (s *Streamer) RemoveFromQueue(index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.Queue) {
		return
	}
	s.Queue = append(s.Queue[:index], s.Queue[index+1:]...)
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

func (sm *StreamerManager) StartStreamer(name, mount, musicDir string, loop bool, format string, bitrate int) (*Streamer, error) {
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
		Format:      format,
		Bitrate:     bitrate,
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

func (s *Streamer) MovePlaylistItem(from, to int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from < 0 || from >= len(s.Playlist) || to < 0 || to >= len(s.Playlist) {
		return
	}
	item := s.Playlist[from]
	s.Playlist = append(s.Playlist[:from], s.Playlist[from+1:]...)
	
	// Adjust 'to' if it was after 'from'
	newPlaylist := make([]string, 0, len(s.Playlist)+1)
	newPlaylist = append(newPlaylist, s.Playlist[:to]...)
	newPlaylist = append(newPlaylist, item)
	newPlaylist = append(newPlaylist, s.Playlist[to:]...)
	s.Playlist = newPlaylist
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

			s.mu.Lock()
			var filePath string
			
			// 1. Check Queue first
			if len(s.Queue) > 0 {
				filePath = s.Queue[0]
				s.Queue = s.Queue[1:]
			} else if len(s.Playlist) > 0 {
				// 2. Handle Shuffle or Sequential Playlist
				if s.Shuffle {
					s.CurrentPos = rand.Intn(len(s.Playlist))
				} else {
					if s.CurrentPos >= len(s.Playlist) {
						if s.Loop {
							s.CurrentPos = 0
						} else {
							s.State = StateStopped
							s.mu.Unlock()
							continue
						}
					}
				}
				filePath = s.Playlist[s.CurrentPos]
				if !s.Shuffle {
					s.CurrentPos++
				}
			}
			s.mu.Unlock()

			if filePath == "" {
				time.Sleep(1 * time.Second)
				continue
			}

			err := sm.streamFile(ctx, s, filePath)
			if err != nil {
				logrus.WithError(err).Errorf("Streamer %s: Failed to stream %s", s.Name, filePath)
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func (sm *StreamerManager) streamFile(ctx context.Context, s *Streamer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder, err := mp3.NewDecoder(f)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.CurrentFile = filepath.Base(path)
	s.CurrentFileTime = time.Now()
	s.mu.Unlock()

	// Update stream metadata
	output := sm.relay.GetOrCreateStream(s.OutputMount)
	output.CurrentSong = s.CurrentFile
	output.Name = s.Name
	output.Bitrate = fmt.Sprintf("%d", s.Bitrate)

	if s.Format == "opus" {
		output.ContentType = "audio/ogg"
		EncodeOpus(ctx, sm.relay, output, decoder, s.Bitrate, &s.BytesStreamed)
	} else {
		output.ContentType = "audio/mpeg"
		EncodeMP3(ctx, sm.relay, output, decoder, s.Bitrate, &s.BytesStreamed)
	}

	return nil
}
