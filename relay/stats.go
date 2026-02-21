package relay

import (
	"fmt"
	"sync/atomic"
	"time"
)

// StreamStats is a point-in-time snapshot of a stream for the UI
type StreamStats struct {
	MountName      string
	ContentType    string
	Description    string
	Genre          string
	URL            string
	Name           string
	Bitrate        string
	Started        time.Time
	SourceIP       string
	Enabled        bool
	BytesIn        int64
	BytesOut       int64
	BytesDropped   int64
	CurrentSong    string
	Public         bool
	Visible        bool
	IsTranscoded   bool
	ListenersCount int
	Uptime         string
	Health         float64
}

// Snapshot returns a point-in-time copy of the stream's state
func (s *Stream) Snapshot() StreamStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bi := atomic.LoadInt64(&s.BytesIn)
	bd := atomic.LoadInt64(&s.BytesDropped)

	// Health calculation
	// 1. Loss-based health
	health := 100.0
	total := bi + bd
	if total > 0 {
		health = (float64(bi) / float64(total)) * 100.0
	}

	// 2. Source Stall Penalty (User Request)
	// If we haven't received data for more than 5 seconds, health starts dropping
	if !s.LastDataReceived.IsZero() {
		silence := time.Since(s.LastDataReceived)
		if silence > 5*time.Second {
			penalty := float64(silence/time.Second) * 2.0 // 2% per second of silence
			health -= penalty
		}
	} else if time.Since(s.Started) > 10*time.Second {
		// Never received data and stream started > 10s ago
		health = 0
	}

	if health < 0 {
		health = 0
	}

	return StreamStats{
		MountName:      s.MountName,
		ContentType:    s.ContentType,
		Description:    s.Description,
		Genre:          s.Genre,
		URL:            s.URL,
		Name:           s.Name,
		Bitrate:        s.Bitrate,
		Started:        s.Started,
		SourceIP:       s.SourceIP,
		Enabled:        s.Enabled,
		BytesIn:        bi,
		BytesOut:       atomic.LoadInt64(&s.BytesOut),
		BytesDropped:   bd,
		CurrentSong:    s.CurrentSong,
		Public:         s.Public,
		Visible:        s.Visible,
		IsTranscoded:   s.IsTranscoded,
		ListenersCount: len(s.listeners),
		Uptime:         s.uptimeLocked(),
		Health:         health,
	}
}

// uptimeLocked returns the formatted uptime string assuming the lock is already held
func (s *Stream) uptimeLocked() string {
	d := time.Since(s.Started).Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s_ := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s_)
}

// Uptime returns the duration since the stream started
func (s *Stream) Uptime() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.uptimeLocked()
}