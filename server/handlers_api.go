package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/relay"
	"github.com/pion/webrtc/v4"
	"github.com/sirupsen/logrus"
)

type streamEventInfo struct {
	Mount        string  `json:"mount"`
	Name         string  `json:"name"`
	Listeners    int     `json:"listeners"`
	Bitrate      string  `json:"bitrate"`
	Uptime       string  `json:"uptime"`
	ContentType  string  `json:"type"`
	SourceIP     string  `json:"ip"`
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
	BytesDropped int64   `json:"bytes_dropped"`
	CurrentSong  string  `json:"song"`
	Health       float64 `json:"health"`
	IsTranscoded bool    `json:"is_transcoded"`
}

type relayEventInfo struct {
	URL     string `json:"url"`
	Mount   string `json:"mount"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

type streamerEventInfo struct {
	Name         string   `json:"name"`
	Mount        string   `json:"mount"`
	State        int      `json:"state"`
	CurrentSong  string   `json:"song"`
	StartTime    int64    `json:"start_time"`
	Duration     float64  `json:"duration"`
	PlaylistPos  int      `json:"playlist_pos"`
	PlaylistLen  int      `json:"playlist_len"`
	Shuffle      bool     `json:"shuffle"`
	Loop         bool     `json:"loop"`
	Queue        []relay.PlaylistItem `json:"queue"`
	Playlist     []relay.PlaylistItem `json:"playlist"`
}

func (s *Server) collectStatsPayload(user *config.User) ([]byte, error) {
	bi, bo := s.Relay.GetMetrics()
	allStreams := s.Relay.Snapshot()
	tl := 0
	var info []streamEventInfo
	tr, ts := 0, 0
	for _, st := range allStreams {
		if s.hasAccess(user, st.MountName) {
			lc := st.ListenersCount
			tl += lc
			info = append(info, streamEventInfo{
				Mount: st.MountName, Name: st.Name, Listeners: lc, Bitrate: st.Bitrate,
				Uptime: st.Uptime, ContentType: st.ContentType, SourceIP: st.SourceIP,
				BytesIn: st.BytesIn, BytesOut: st.BytesOut, BytesDropped: st.BytesDropped,
				CurrentSong: st.CurrentSong, Health: st.Health, IsTranscoded: st.IsTranscoded,
			})
			if st.SourceIP == "relay-pull" {
				tr++
			} else {
				ts++
			}
		}
	}
	if user.Role != config.RoleSuperAdmin {
		var ubi, ubo int64
		for _, st := range info {
			ubi += st.BytesIn
			ubo += st.BytesOut
		}
		bi, bo = ubi, ubo
	}

	relays := make([]relayEventInfo, len(s.Config.Relays))
	for i, rc := range s.Config.Relays {
		relays[i] = relayEventInfo{URL: rc.URL, Mount: rc.Mount, Active: false, Enabled: rc.Enabled}
		if st, ok := s.Relay.GetStream(rc.Mount); ok && st.SourceIP == "relay-pull" {
			relays[i].Active = true
		}
	}

	activeStreamers := s.StreamerM.GetStreamers()
	streamers := make([]streamerEventInfo, 0, len(activeStreamers))
	for _, st := range activeStreamers {
		if s.hasAccess(user, st.OutputMount) {
			stats := st.GetStats()
			streamers = append(streamers, streamerEventInfo{
				Name:        stats.Name,
				Mount:       stats.Mount,
				State:       int(stats.State),
				CurrentSong: stats.CurrentSong,
				StartTime:   stats.StartTime.Unix(),
				Duration:    stats.Duration.Seconds(),
				PlaylistLen: stats.PlaylistLen,
				Shuffle:     stats.Shuffle,
				Loop:        stats.Loop,
				Queue:       st.GetQueueInfo(),
				Playlist:    st.GetPlaylistInfo(),
			})
		}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	totalDropped := int64(0)
	for _, st := range allStreams {
		totalDropped += st.BytesDropped
	}

	return json.Marshal(map[string]interface{}{
		"bytes_in":        bi,
		"bytes_out":       bo,
		"total_listeners": tl,
		"total_sources":   len(info),
		"total_relays":    tr,
		"total_streamers": ts,
		"streams":         info,
		"relays":          relays,
		"streamers":       streamers,
		"visible_mounts":  s.Config.VisibleMounts,
		"sys_ram":         m.Sys,
		"heap_alloc":      m.HeapAlloc,
		"stack_sys":       m.StackSys,
		"num_gc":          m.NumGC,
		"goroutines":      runtime.NumGoroutine(),
		"total_dropped":   totalDropped,
		"server_uptime":   time.Since(s.startTime).Round(time.Second).String(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	bi, bo := s.Relay.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"bytes_in": bi, "bytes_out": bo})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	send := func() error {
		payload, err := s.collectStatsPayload(user)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if err := send(); err != nil {
		return
	}
	for {
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := send(); err != nil {
				return
			}
		}
	}
}

func (s *Server) handlePublicEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher, _ := w.(http.Flusher)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	type PublicStreamInfo struct {
		Mount       string `json:"mount"`
		Name        string `json:"name"`
		Listeners   int    `json:"listeners"`
		Bitrate     string `json:"bitrate"`
		Uptime      string `json:"uptime"`
		Genre       string `json:"genre"`
		Description string `json:"description"`
		CurrentSong string `json:"song"`
	}
	send := func() error {
		allStreams := s.Relay.Snapshot()
		var info []PublicStreamInfo
		for _, st := range allStreams {
			if st.Visible {
				info = append(info, PublicStreamInfo{Mount: st.MountName, Name: st.Name, Listeners: st.ListenersCount, Bitrate: st.Bitrate, Uptime: st.Uptime, Genre: st.Genre, Description: st.Description, CurrentSong: st.CurrentSong})
			}
		}
		payload, _ := json.Marshal(info)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if err := send(); err != nil {
		return
	}
	for {
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := send(); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleLegacyStats(w http.ResponseWriter, r *http.Request) {
	streams := s.Relay.Snapshot()
	type IcecastSource struct {
		AudioInfo         string      `json:"audio_info"`
		Bitrate           interface{} `json:"bitrate"`
		Genre             string      `json:"genre"`
		Listeners         int         `json:"listeners"`
		ListenURL         string      `json:"listenurl"`
		Mount             string      `json:"mount"`
		ServerDescription string      `json:"server_description"`
		ServerName        string      `json:"server_name"`
		ServerType        string      `json:"server_type"`
		StreamStart       string      `json:"stream_start"`
		Title             string      `json:"title"`
		Dummy             interface{} `json:"dummy"`
	}
	sources := make([]IcecastSource, len(streams))
	host := s.Config.HostName
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, s.Config.Port)
	}
	proto := "http://"
	if s.Config.UseHTTPS {
		proto = "https://"
	}
	for i, st := range streams {
		sources[i] = IcecastSource{AudioInfo: fmt.Sprintf("bitrate=%s", st.Bitrate), Bitrate: st.Bitrate, Genre: st.Genre, Listeners: st.ListenersCount, ListenURL: proto + host + st.MountName, Mount: st.MountName, ServerDescription: st.Description, ServerName: st.Name, ServerType: st.ContentType, StreamStart: st.Started.Format(time.RFC1123), Title: st.CurrentSong, Dummy: nil}
	}
	resp := map[string]interface{}{"icestats": map[string]interface{}{"admin": s.Config.AdminEmail, "host": s.Config.HostName, "location": s.Config.Location, "server_id": "Icecast 2.4.4 (TinyIce)", "server_start": time.Now().Format(time.RFC1123), "source": sources}}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	bi, bo := s.Relay.GetMetrics()
	streams := s.Relay.Snapshot()
	tl := 0
	for _, st := range streams {
		tl += st.ListenersCount
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP tinyice_bandwidth_in_bytes_total Total bytes received\n# TYPE tinyice_bandwidth_in_bytes_total counter\ntinyice_bandwidth_in_bytes_total %d\n\n", bi)
	fmt.Fprintf(w, "# HELP tinyice_bandwidth_out_bytes_total Total bytes sent\n# TYPE tinyice_bandwidth_out_bytes_total counter\ntinyice_bandwidth_out_bytes_total %d\n\n", bo)
	fmt.Fprintf(w, "# HELP tinyice_listeners_total Total active listeners\n# TYPE tinyice_listeners_total gauge\ntinyice_listeners_total %d\n\n", tl)
	fmt.Fprintf(w, "# HELP tinyice_sources_total Total active sources\n# TYPE tinyice_sources_total gauge\ntinyice_sources_total %d\n\n", len(streams))
	for _, st := range streams {
		fmt.Fprintf(w, "tinyice_mount_listeners_current{mount=\"%s\",name=\"%s\"} %d\n", st.MountName, st.Name, st.ListenersCount)
	}
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	mount := r.URL.Query().Get("mount")
	history := s.Relay.History.Get(mount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allStreams := s.Relay.Snapshot()
	sort.Slice(allStreams, func(i, j int) bool {
		return allStreams[i].ListenersCount > allStreams[j].ListenersCount
	})

	topStreams := allStreams
	if len(topStreams) > 10 {
		topStreams = topStreams[:10]
	}

	topListenersUA := []relay.UAStat{}
	topSourcesUA := []relay.UAStat{}
	if s.Relay.History != nil {
		if uas := s.Relay.History.GetTopUAs("listener", 10); uas != nil {
			topListenersUA = uas
		}
		if uas := s.Relay.History.GetTopUAs("source", 10); uas != nil {
			topSourcesUA = uas
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"top_streams":      topStreams,
		"top_listeners_ua": topListenersUA,
		"top_sources_ua":   topSourcesUA,
	})
}

func (s *Server) handleInsights(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if s.Relay.History == nil {
		http.Error(w, "History disabled", http.StatusServiceUnavailable)
		return
	}

	stats := s.Relay.History.GetAllHistoricalStats(24 * time.Hour)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleWebRTCOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mount := r.URL.Query().Get("mount")
	if mount == "" {
		http.Error(w, "mount query param required", http.StatusBadRequest)
		return
	}

	var offer webrtc.SessionDescription
	if err := json.NewDecoder(r.Body).Decode(&offer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	answer, err := s.WebRTCM.HandleOffer(mount, offer)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answer)
}

func (s *Server) handleWebRTCSourceOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mount := r.URL.Query().Get("mount")
	if mount == "" {
		http.Error(w, "mount query param required", http.StatusBadRequest)
		return
	}

	var offer webrtc.SessionDescription
	if err := json.NewDecoder(r.Body).Decode(&offer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	answer, err := s.WebRTCM.HandleSourceOffer(mount, offer)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answer)
}

func (s *Server) handleGoLive(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	csrf := ""
	if cookie, err := r.Cookie("sid"); err == nil {
		s.sessionsMu.RLock()
		if sess, ok := s.sessions[cookie.Value]; ok {
			csrf = sess.CSRFToken
		}
		s.sessionsMu.RUnlock()
	}

	data := map[string]interface{}{
		"Config":    s.Config,
		"User":      user,
		"Version":   s.Version,
		"CSRFToken": csrf,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := s.tmpl.ExecuteTemplate(w, "go_live.html", data); err != nil {
		logrus.WithError(err).Error("Go Live template error")
	}
}

func (s *Server) handleGoLiveChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mount := r.URL.Query().Get("mount")
	if mount == "" {
		http.Error(w, "mount query param required", http.StatusBadRequest)
		return
	}

	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stream := s.Relay.GetOrCreateStream(mount)
	stream.SourceIP = "webaudio-http"
	stream.Broadcast(body, s.Relay)

	w.WriteHeader(http.StatusOK)
}
