package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

func (s *Server) apiGetStreams(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allStreams := s.Relay.Snapshot()
	type streamInfo struct {
		Mount       string  `json:"mount"`
		ContentType string  `json:"content_type"`
		Bitrate     string  `json:"bitrate"`
		Listeners   int     `json:"listeners"`
		SourceIP    string  `json:"source_ip"`
		Visible     bool    `json:"visible"`
		Enabled     bool    `json:"enabled"`
		Health      float64 `json:"health"`
		Uptime      string  `json:"uptime"`
		CurrentSong string  `json:"current_song"`
		Name        string  `json:"name"`
	}

	var result []streamInfo
	for _, st := range allStreams {
		if s.hasAccess(user, st.MountName) {
			result = append(result, streamInfo{
				Mount:       st.MountName,
				ContentType: st.ContentType,
				Bitrate:     st.Bitrate,
				Listeners:   st.ListenersCount,
				SourceIP:    st.SourceIP,
				Visible:     st.Visible,
				Enabled:     st.Enabled,
				Health:      st.Health,
				Uptime:      st.Uptime,
				CurrentSong: st.CurrentSong,
				Name:        st.Name,
			})
		}
	}
	if result == nil {
		result = []streamInfo{}
	}
	jsonResponse(w, result)
}

func (s *Server) apiCreateStream(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount    string `json:"mount"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Mount == "" || body.Password == "" {
		jsonError(w, "Mount and password are required", http.StatusBadRequest)
		return
	}
	if body.Mount[0] != '/' {
		body.Mount = "/" + body.Mount
	}

	// Check access or existence
	if !s.hasAccess(user, body.Mount) {
		exists := false
		if _, ok := s.Config.Mounts[body.Mount]; ok {
			exists = true
		}
		if !exists {
			for _, u := range s.Config.Users {
				if _, ok := u.Mounts[body.Mount]; ok {
					exists = true
					break
				}
			}
		}
		if exists {
			jsonError(w, "Mount taken", http.StatusConflict)
			return
		}
	}

	hashed, _ := config.HashPassword(body.Password)
	if user.Role == config.RoleSuperAdmin {
		s.Config.Mounts[body.Mount] = hashed
	} else {
		user.Mounts[body.Mount] = hashed
	}
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "created", "mount": body.Mount})
}

func (s *Server) apiDeleteStream(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount := r.URL.Query().Get("mount")
	if mount == "" {
		jsonError(w, "Mount is required", http.StatusBadRequest)
		return
	}
	if !s.hasAccess(user, mount) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	delete(s.Config.Mounts, mount)
	delete(s.Config.DisabledMounts, mount)
	delete(s.Config.VisibleMounts, mount)
	delete(user.Mounts, mount)
	s.Relay.RemoveStream(mount)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "deleted"})
}

func (s *Server) apiKickStream(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount string `json:"mount"`
		Type  string `json:"type"` // "source" or "listeners"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Mount == "" {
		jsonError(w, "Mount is required", http.StatusBadRequest)
		return
	}
	if !s.hasAccess(user, body.Mount) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch body.Type {
	case "listeners":
		if st, ok := s.Relay.GetStream(body.Mount); ok {
			st.DisconnectListeners()
		}
	default: // "source" or empty — kick the whole stream
		s.Relay.RemoveStream(body.Mount)
	}
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// AutoDJ
// ---------------------------------------------------------------------------

func (s *Server) apiGetAutoDJ(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type autoDJInfo struct {
		Name           string               `json:"name"`
		Mount          string               `json:"mount"`
		State          int                  `json:"state"`
		CurrentSong    string               `json:"current_song"`
		StartTime      int64                `json:"start_time"`
		Duration       float64              `json:"duration"`
		PlaylistPos    int                  `json:"playlist_pos"`
		PlaylistLen    int                  `json:"playlist_len"`
		Shuffle        bool                 `json:"shuffle"`
		Loop           bool                 `json:"loop"`
		InjectMetadata bool                 `json:"inject_metadata"`
		Visible        bool                 `json:"visible"`
		MusicDir       string               `json:"music_dir"`
		Format         string               `json:"format"`
		Bitrate        int                  `json:"bitrate"`
		Enabled        bool                 `json:"enabled"`
		MPDEnabled     bool                 `json:"mpd_enabled"`
		MPDPort        string               `json:"mpd_port"`
		LastPlaylist   string               `json:"last_playlist"`
		Queue          []relay.PlaylistItem `json:"queue"`
	}

	var result []autoDJInfo
	streamers := s.StreamerM.GetStreamers()

	// Build map of streamer by mount for quick lookup
	streamerMap := make(map[string]*relay.Streamer)
	for _, st := range streamers {
		streamerMap[st.OutputMount] = st
	}

	for _, adj := range s.Config.AutoDJs {
		if !s.hasAccess(user, adj.Mount) {
			continue
		}
		info := autoDJInfo{
			Name:           adj.Name,
			Mount:          adj.Mount,
			Format:         adj.Format,
			Bitrate:        adj.Bitrate,
			Enabled:        adj.Enabled,
			MusicDir:       adj.MusicDir,
			MPDEnabled:     adj.MPDEnabled,
			MPDPort:        adj.MPDPort,
			LastPlaylist:   adj.LastPlaylist,
			Loop:           adj.Loop,
			InjectMetadata: adj.InjectMetadata,
			Visible:        adj.Visible,
		}
		if st, ok := streamerMap[adj.Mount]; ok {
			stats := st.GetStats()
			info.State = int(stats.State)
			info.CurrentSong = stats.CurrentSong
			info.StartTime = stats.StartTime.Unix()
			info.Duration = stats.Duration.Seconds()
			info.PlaylistPos = stats.PlaylistPos
			info.PlaylistLen = stats.PlaylistLen
			info.Shuffle = stats.Shuffle
			info.Loop = stats.Loop
			info.InjectMetadata = stats.InjectMetadata
			info.Visible = stats.Visible
			info.Queue = st.GetQueueInfo()
		}
		if info.Queue == nil {
			info.Queue = []relay.PlaylistItem{}
		}
		result = append(result, info)
	}
	if result == nil {
		result = []autoDJInfo{}
	}
	jsonResponse(w, result)
}

func (s *Server) apiCreateAutoDJ(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Name           string `json:"name"`
		Mount          string `json:"mount"`
		MusicDir       string `json:"music_dir"`
		Format         string `json:"format"`
		Bitrate        int    `json:"bitrate"`
		Loop           bool   `json:"loop"`
		InjectMetadata bool   `json:"inject_metadata"`
		MPDEnabled     bool   `json:"mpd_enabled"`
		MPDPort        string `json:"mpd_port"`
		MPDPassword    string `json:"mpd_password"`
		Visible        bool   `json:"visible"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.Mount == "" || body.MusicDir == "" {
		jsonError(w, "Name, mount, and music_dir are required", http.StatusBadRequest)
		return
	}
	if body.Mount[0] != '/' {
		body.Mount = "/" + body.Mount
	}
	if body.Format == "" {
		body.Format = "mp3"
	}
	if body.Bitrate == 0 {
		body.Bitrate = 128
	}

	absMusicDir, _ := filepath.Abs(body.MusicDir)

	adj := &config.AutoDJConfig{
		Name:           body.Name,
		Mount:          body.Mount,
		MusicDir:       absMusicDir,
		Format:         body.Format,
		Bitrate:        body.Bitrate,
		Enabled:        true,
		Loop:           body.Loop,
		InjectMetadata: body.InjectMetadata,
		MPDEnabled:     body.MPDEnabled,
		MPDPort:        body.MPDPort,
		MPDPassword:    body.MPDPassword,
		Visible:        body.Visible,
	}

	s.Config.AutoDJs = append(s.Config.AutoDJs, adj)
	s.Config.SaveConfig()

	streamer, err := s.StreamerM.StartStreamer(adj.Name, adj.Mount, adj.MusicDir, adj.Loop, adj.Format, adj.Bitrate, adj.InjectMetadata, nil, adj.MPDEnabled, adj.MPDPort, adj.MPDPassword, adj.Visible, "")
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to start AutoDJ: %v", err), http.StatusInternalServerError)
		return
	}
	if adj.InjectMetadata {
		if st, ok := s.Relay.GetStream(adj.Mount); ok {
			st.SetVisible(adj.Visible)
		}
	}
	streamer.ScanMusicDir()
	streamer.Play()
	jsonResponse(w, map[string]string{"status": "created", "mount": adj.Mount})
}

func (s *Server) apiDeleteAutoDJ(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	if mount == "" {
		jsonError(w, "Mount is required", http.StatusBadRequest)
		return
	}

	newADJs := []*config.AutoDJConfig{}
	found := false
	for _, adj := range s.Config.AutoDJs {
		if adj.Mount != mount {
			newADJs = append(newADJs, adj)
		} else {
			s.StreamerM.StopStreamer(mount)
			found = true
		}
	}
	if !found {
		jsonError(w, "AutoDJ not found", http.StatusNotFound)
		return
	}
	s.Config.AutoDJs = newADJs
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "deleted"})
}

func (s *Server) apiAutoDJPlay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.Play()
	jsonResponse(w, map[string]string{"status": "playing"})
}

func (s *Server) apiAutoDJPause(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.Stop()
	jsonResponse(w, map[string]string{"status": "paused"})
}

func (s *Server) apiAutoDJNext(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.Next()
	jsonResponse(w, map[string]string{"status": "skipped"})
}

func (s *Server) apiAutoDJShuffle(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.ToggleShuffle()
	stats := streamer.GetStats()
	jsonResponse(w, map[string]interface{}{"status": "ok", "shuffle": stats.Shuffle})
}

func (s *Server) apiAutoDJLoop(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.ToggleLoop()
	stats := streamer.GetStats()

	for _, adj := range s.Config.AutoDJs {
		if adj.Mount == mount {
			adj.Loop = stats.Loop
			s.Config.SaveConfig()
			break
		}
	}
	jsonResponse(w, map[string]interface{}{"status": "ok", "loop": stats.Loop})
}

// ---------------------------------------------------------------------------
// Playlist
// ---------------------------------------------------------------------------

func (s *Server) apiGetPlaylist(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	jsonResponse(w, streamer.GetPlaylistInfo())
}

func (s *Server) apiAddToPlaylist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount string   `json:"mount"`
		Files []string `json:"files"`
		Path  string   `json:"path"`
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Support frontend format: path (single) or paths (array) alongside files
	if body.Path != "" {
		body.Files = append(body.Files, body.Path)
	}
	if len(body.Paths) > 0 {
		body.Files = append(body.Files, body.Paths...)
	}

	// Fall back to query param for mount if not in body
	mount := body.Mount
	if mount == "" {
		mount = r.URL.Query().Get("mount")
	}

	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}

	musicDir := streamer.GetMusicDir()
	for _, file := range body.Files {
		// If path is relative (not absolute), resolve it relative to music dir
		if !filepath.IsAbs(file) {
			file = filepath.Join(musicDir, file)
		}
		fullPath, err := s.validatePathInMusicDir(musicDir, file)
		if err != nil {
			logger.L.Warnw("Security: Blocked playlist addition", "path", file, "mount", mount, "error", err)
			continue
		}
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		if info.IsDir() {
			filepath.Walk(fullPath, func(p string, i os.FileInfo, e error) error {
				if e != nil {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(p))
				if !i.IsDir() && (ext == ".mp3" || ext == ".ogg" || ext == ".opus" || ext == ".flac" || ext == ".wav") {
					streamer.AddToPlaylist(p)
				}
				return nil
			})
		} else {
			streamer.AddToPlaylist(fullPath)
		}
	}

	// Persist
	playlistCopy := streamer.GetPlaylist()
	lastPl := streamer.GetStats().LastPlaylist
	if lastPl == "" {
		lastPl = streamer.Name + ".pls"
		streamer.SetLastPlaylist(lastPl)
	}
	streamer.SavePlaylist()
	for _, adj := range s.Config.AutoDJs {
		if adj.Mount == body.Mount {
			adj.Playlist = playlistCopy
			adj.LastPlaylist = lastPl
			s.Config.SaveConfig()
			break
		}
	}
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) apiRemoveFromPlaylist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	var idx int
	fmt.Sscanf(r.URL.Query().Get("id"), "%d", &idx)

	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.RemoveFromPlaylist(idx)

	playlistCopy := streamer.GetPlaylist()
	for _, adj := range s.Config.AutoDJs {
		if adj.Mount == mount {
			adj.Playlist = playlistCopy
			s.Config.SaveConfig()
			break
		}
	}
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) apiClearPlaylist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount string `json:"mount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		mount := r.URL.Query().Get("mount")
		if mount == "" {
			jsonError(w, "Mount is required", http.StatusBadRequest)
			return
		}
		body.Mount = mount
	}

	streamer := s.StreamerM.GetStreamer(body.Mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.ClearPlaylist()

	for _, adj := range s.Config.AutoDJs {
		if adj.Mount == body.Mount {
			adj.Playlist = []string{}
			s.Config.SaveConfig()
			break
		}
	}
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) apiReorderPlaylist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount string `json:"mount"`
		From  int    `json:"from"`
		To    int    `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	streamer := s.StreamerM.GetStreamer(body.Mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	streamer.MovePlaylistItem(body.From, body.To)

	playlistCopy := streamer.GetPlaylist()
	for _, adj := range s.Config.AutoDJs {
		if adj.Mount == body.Mount {
			adj.Playlist = playlistCopy
			s.Config.SaveConfig()
			break
		}
	}
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

func (s *Server) apiGetQueue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}
	jsonResponse(w, streamer.GetQueueInfo())
}

func (s *Server) apiAddToQueue(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Mount string `json:"mount"`
		Path  string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	streamer := s.StreamerM.GetStreamer(body.Mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}

	musicDir := streamer.GetMusicDir()
	fullPath, err := s.validatePathInMusicDir(musicDir, body.Path)
	if err != nil {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	streamer.PushToQueue(fullPath)
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Library / Files
// ---------------------------------------------------------------------------

func (s *Server) apiGetFiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	mount := r.URL.Query().Get("mount")
	subDir := r.URL.Query().Get("path")
	streamer := s.StreamerM.GetStreamer(mount)
	if streamer == nil {
		jsonError(w, "Streamer not found", http.StatusNotFound)
		return
	}

	musicDir := streamer.GetMusicDir()
	fullPath, err := s.validatePathInMusicDir(musicDir, filepath.Join(musicDir, subDir))
	if err != nil {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type fileEntry struct {
		Name    string `json:"name"`
		Title   string `json:"title"`
		IsDir   bool   `json:"is_dir"`
		Path    string `json:"path"`
		AbsPath string `json:"abs_path"`
		IsPLS   bool   `json:"is_pls"`
	}
	var res []fileEntry

	// Show playlist files at root level
	if subDir == "" {
		if plsEntries, err := os.ReadDir("playlists"); err == nil {
			for _, f := range plsEntries {
				if !f.IsDir() && strings.HasSuffix(f.Name(), ".pls") {
					abs, _ := filepath.Abs(filepath.Join("playlists", f.Name()))
					res = append(res, fileEntry{
						Name:    f.Name(),
						Title:   "Playlist: " + f.Name(),
						IsDir:   false,
						Path:    f.Name(),
						AbsPath: abs,
						IsPLS:   true,
					})
				}
			}
		}
	}

	supportedExts := map[string]bool{".mp3": true, ".ogg": true, ".opus": true, ".flac": true, ".wav": true}
	for _, f := range entries {
		ext := strings.ToLower(filepath.Ext(f.Name()))
		if f.IsDir() || supportedExts[ext] {
			title := f.Name()
			full := filepath.Join(fullPath, f.Name())
			if !f.IsDir() {
				title = streamer.GetSongTitle(full)
			}
			abs, _ := filepath.Abs(full)
			res = append(res, fileEntry{
				Name:    f.Name(),
				Title:   title,
				IsDir:   f.IsDir(),
				Path:    filepath.Join(subDir, f.Name()),
				AbsPath: abs,
				IsPLS:   false,
			})
		}
	}
	if res == nil {
		res = []fileEntry{}
	}
	jsonResponse(w, res)
}

// ---------------------------------------------------------------------------
// Relays
// ---------------------------------------------------------------------------

func (s *Server) apiGetRelays(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	type relayInfo struct {
		URL       string `json:"url"`
		Mount     string `json:"mount"`
		BurstSize int    `json:"burst_size"`
		Enabled   bool   `json:"enabled"`
		Active    bool   `json:"active"`
	}

	var result []relayInfo
	for _, rc := range s.Config.Relays {
		active := false
		if st, ok := s.Relay.GetStream(rc.Mount); ok && st.SourceIP == "relay-pull" {
			active = true
		}
		result = append(result, relayInfo{
			URL:       rc.URL,
			Mount:     rc.Mount,
			BurstSize: rc.BurstSize,
			Enabled:   rc.Enabled,
			Active:    active,
		})
	}
	if result == nil {
		result = []relayInfo{}
	}
	jsonResponse(w, result)
}

func (s *Server) apiCreateRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		URL       string `json:"url"`
		Mount     string `json:"mount"`
		Password  string `json:"password"`
		BurstSize int    `json:"burst_size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.URL == "" || body.Mount == "" {
		jsonError(w, "URL and mount are required", http.StatusBadRequest)
		return
	}
	if body.Mount[0] != '/' {
		body.Mount = "/" + body.Mount
	}
	if body.BurstSize == 0 {
		body.BurstSize = 20
	}

	// Update existing or create new
	found := false
	for _, rc := range s.Config.Relays {
		if rc.Mount == body.Mount {
			rc.URL = body.URL
			rc.Password = body.Password
			rc.BurstSize = body.BurstSize
			found = true
			break
		}
	}
	if !found {
		s.Config.Relays = append(s.Config.Relays, &config.RelayConfig{
			URL: body.URL, Mount: body.Mount, Password: body.Password, BurstSize: body.BurstSize, Enabled: true,
		})
	}
	s.Config.SaveConfig()
	s.RelayM.StartRelay(body.URL, body.Mount, body.Password, body.BurstSize, s.Config.VisibleMounts[body.Mount])
	jsonResponse(w, map[string]string{"status": "created"})
}

func (s *Server) apiDeleteRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	mount := r.URL.Query().Get("mount")
	if mount == "" {
		jsonError(w, "Mount is required", http.StatusBadRequest)
		return
	}

	newRelays := []*config.RelayConfig{}
	found := false
	for _, rc := range s.Config.Relays {
		if rc.Mount != mount {
			newRelays = append(newRelays, rc)
		} else {
			found = true
		}
	}
	if !found {
		jsonError(w, "Relay not found", http.StatusNotFound)
		return
	}
	s.Config.Relays = newRelays
	s.Config.SaveConfig()
	s.RelayM.StopRelay(mount)
	jsonResponse(w, map[string]string{"status": "deleted"})
}

func (s *Server) apiToggleRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		Mount string `json:"mount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	for _, rc := range s.Config.Relays {
		if rc.Mount == body.Mount {
			rc.Enabled = !rc.Enabled
			if rc.Enabled {
				s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[body.Mount])
			} else {
				s.RelayM.StopRelay(body.Mount)
			}
			s.Config.SaveConfig()
			jsonResponse(w, map[string]interface{}{"status": "ok", "enabled": rc.Enabled})
			return
		}
	}
	jsonError(w, "Relay not found", http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// Transcoders
// ---------------------------------------------------------------------------

func (s *Server) apiGetTranscoders(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var stats []relay.TranscoderStats
	for _, tc := range s.Config.Transcoders {
		inst := s.TranscoderM.GetInstance(tc.OutputMount)
		uptime := "OFF"
		var frames, bytes int64
		active := false
		if inst != nil {
			active = true
			uptime = time.Since(inst.StartTime).Round(time.Second).String()
			frames = atomic.LoadInt64(&inst.FramesProcessed)
			bytes = atomic.LoadInt64(&inst.BytesEncoded)
		}
		stats = append(stats, relay.TranscoderStats{
			Name:            tc.Name,
			Input:           tc.InputMount,
			Output:          tc.OutputMount,
			Format:          tc.Format,
			Bitrate:         tc.Bitrate,
			Active:          active,
			FramesProcessed: frames,
			BytesEncoded:    bytes,
			Uptime:          uptime,
		})
	}
	if stats == nil {
		stats = []relay.TranscoderStats{}
	}
	jsonResponse(w, stats)
}

func (s *Server) apiCreateTranscoder(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Name        string `json:"name"`
		InputMount  string `json:"input_mount"`
		OutputMount string `json:"output_mount"`
		Format      string `json:"format"`
		Bitrate     int    `json:"bitrate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.InputMount == "" || body.OutputMount == "" {
		jsonError(w, "Name, input_mount, and output_mount are required", http.StatusBadRequest)
		return
	}

	tc := &config.TranscoderConfig{
		Name:        body.Name,
		InputMount:  body.InputMount,
		OutputMount: body.OutputMount,
		Format:      body.Format,
		Bitrate:     body.Bitrate,
		Enabled:     true,
	}
	s.Config.Transcoders = append(s.Config.Transcoders, tc)
	s.Config.SaveConfig()
	s.TranscoderM.StartTranscoder(tc)
	jsonResponse(w, map[string]string{"status": "created"})
}

func (s *Server) apiDeleteTranscoder(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	newTCs := []*config.TranscoderConfig{}
	found := false
	for _, tc := range s.Config.Transcoders {
		if tc.Name != name {
			newTCs = append(newTCs, tc)
		} else {
			s.TranscoderM.StopTranscoder(tc.OutputMount)
			found = true
		}
	}
	if !found {
		jsonError(w, "Transcoder not found", http.StatusNotFound)
		return
	}
	s.Config.Transcoders = newTCs
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "deleted"})
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func (s *Server) apiGetUsers(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	type userInfo struct {
		Username string   `json:"username"`
		Role     string   `json:"role"`
		Mounts   []string `json:"mounts"`
	}
	var result []userInfo
	for _, u := range s.Config.Users {
		mounts := make([]string, 0, len(u.Mounts))
		for m := range u.Mounts {
			mounts = append(mounts, m)
		}
		result = append(result, userInfo{Username: u.Username, Role: u.Role, Mounts: mounts})
	}
	if result == nil {
		result = []userInfo{}
	}
	jsonResponse(w, result)
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Username == "" || body.Password == "" {
		jsonError(w, "Username and password are required", http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = config.RoleAdmin
	}

	hp, _ := config.HashPassword(body.Password)
	s.Config.Users[body.Username] = &config.User{
		Username: body.Username,
		Password: hp,
		Role:     body.Role,
		Mounts:   make(map[string]string),
	}
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "created", "username": body.Username})
}

func (s *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password,omitempty"`
		Role     string `json:"role,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if body.Username == "" {
		jsonError(w, "Username is required", http.StatusBadRequest)
		return
	}

	u, exists := s.Config.Users[body.Username]
	if !exists {
		jsonError(w, "User not found", http.StatusNotFound)
		return
	}
	if body.Password != "" {
		hp, _ := config.HashPassword(body.Password)
		u.Password = hp
	}
	if body.Role != "" {
		u.Role = body.Role
	}
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "updated"})
}

func (s *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		jsonError(w, "Username is required", http.StatusBadRequest)
		return
	}
	if username == user.Username {
		jsonError(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}
	if _, exists := s.Config.Users[username]; !exists {
		jsonError(w, "User not found", http.StatusNotFound)
		return
	}
	delete(s.Config.Users, username)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "deleted"})
}

// ---------------------------------------------------------------------------
// Security — Bans & Whitelist
// ---------------------------------------------------------------------------

func (s *Server) apiGetBans(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	jsonResponse(w, s.Config.BannedIPs)
}

func (s *Server) apiAddBan(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "IP is required", http.StatusBadRequest)
		return
	}
	s.Config.AddBannedIP(body.IP)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "added", "ip": body.IP})
}

func (s *Server) apiRemoveBan(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonError(w, "IP is required", http.StatusBadRequest)
		return
	}
	s.Config.RemoveBannedIP(ip)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "removed", "ip": ip})
}

func (s *Server) apiGetWhitelist(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	jsonResponse(w, s.Config.WhitelistedIPs)
}

func (s *Server) apiAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "IP is required", http.StatusBadRequest)
		return
	}
	s.Config.AddWhitelistedIP(body.IP)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "added", "ip": body.IP})
}

func (s *Server) apiRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonError(w, "IP is required", http.StatusBadRequest)
		return
	}
	s.Config.RemoveWhitelistedIP(ip)
	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "removed", "ip": ip})
}

// ---------------------------------------------------------------------------
// Branding
// ---------------------------------------------------------------------------

func (s *Server) apiGetBranding(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"page_title":       s.Config.PageTitle,
		"page_subtitle":    s.Config.PageSubtitle,
		"accent_color":     s.Config.AccentColor,
		"logo_path":        s.Config.LogoPath,
		"landing_markdown": s.Config.LandingMarkdown,
	})
}

func (s *Server) apiUpdateBranding(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		PageTitle       *string `json:"page_title"`
		PageSubtitle    *string `json:"page_subtitle"`
		AccentColor     *string `json:"accent_color"`
		LogoPath        *string `json:"logo_path"`
		LandingMarkdown *string `json:"landing_markdown"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if body.PageTitle != nil {
		s.Config.PageTitle = *body.PageTitle
	}
	if body.PageSubtitle != nil {
		s.Config.PageSubtitle = *body.PageSubtitle
	}
	if body.AccentColor != nil {
		s.Config.AccentColor = *body.AccentColor
	}
	if body.LogoPath != nil {
		s.Config.LogoPath = *body.LogoPath
	}
	if body.LandingMarkdown != nil {
		s.Config.LandingMarkdown = *body.LandingMarkdown
	}

	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "updated"})
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

func (s *Server) apiGetSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"bind_host":         s.Config.BindHost,
		"port":              s.Config.Port,
		"hostname":          s.Config.HostName,
		"base_url":          s.Config.BaseURL,
		"location":          s.Config.Location,
		"admin_email":       s.Config.AdminEmail,
		"admin_user":        s.Config.AdminUser,
		"low_latency_mode":  s.Config.LowLatencyMode,
		"max_listeners":     s.Config.MaxListeners,
		"use_https":         s.Config.UseHTTPS,
		"auto_https":        s.Config.AutoHTTPS,
		"https_port":        s.Config.HTTPSPort,
		"acme_email":        s.Config.ACMEEmail,
		"domains":           s.Config.Domains,
		"directory_listing": s.Config.DirectoryListing,
		"directory_server":  s.Config.DirectoryServer,
		"auto_update":       s.Config.AutoUpdate,
	})
}

func (s *Server) apiUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != config.RoleSuperAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if v, ok := body["hostname"]; ok {
		s.Config.HostName = fmt.Sprintf("%v", v)
	}
	if v, ok := body["base_url"]; ok {
		s.Config.BaseURL = fmt.Sprintf("%v", v)
	}
	if v, ok := body["location"]; ok {
		s.Config.Location = fmt.Sprintf("%v", v)
	}
	if v, ok := body["admin_email"]; ok {
		s.Config.AdminEmail = fmt.Sprintf("%v", v)
	}
	if v, ok := body["low_latency_mode"]; ok {
		if b, ok := v.(bool); ok {
			s.Config.LowLatencyMode = b
			s.Relay.LowLatency = b
		}
	}
	if v, ok := body["max_listeners"]; ok {
		if n, ok := v.(float64); ok {
			s.Config.MaxListeners = int(n)
		}
	}
	if v, ok := body["directory_listing"]; ok {
		if b, ok := v.(bool); ok {
			s.Config.DirectoryListing = b
		}
	}
	if v, ok := body["auto_update"]; ok {
		if b, ok := v.(bool); ok {
			s.Config.AutoUpdate = b
		}
	}

	s.Config.SaveConfig()
	jsonResponse(w, map[string]string{"status": "updated"})
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func (s *Server) apiGetStats(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bi, bo := s.Relay.GetMetrics()
	allStreams := s.Relay.Snapshot()
	totalListeners := 0
	totalDropped := int64(0)

	type streamStat struct {
		Mount       string  `json:"mount"`
		Name        string  `json:"name"`
		Listeners   int     `json:"listeners"`
		Bitrate     string  `json:"bitrate"`
		Uptime      string  `json:"uptime"`
		ContentType string  `json:"content_type"`
		SourceIP    string  `json:"source_ip"`
		BytesIn     int64   `json:"bytes_in"`
		BytesOut    int64   `json:"bytes_out"`
		CurrentSong string  `json:"current_song"`
		Health      float64 `json:"health"`
	}

	var streams []streamStat
	for _, st := range allStreams {
		if !s.hasAccess(user, st.MountName) {
			continue
		}
		totalListeners += st.ListenersCount
		totalDropped += st.BytesDropped
		streams = append(streams, streamStat{
			Mount:       st.MountName,
			Name:        st.Name,
			Listeners:   st.ListenersCount,
			Bitrate:     st.Bitrate,
			Uptime:      st.Uptime,
			ContentType: st.ContentType,
			SourceIP:    st.SourceIP,
			BytesIn:     st.BytesIn,
			BytesOut:    st.BytesOut,
			CurrentSong: st.CurrentSong,
			Health:      st.Health,
		})
	}
	if streams == nil {
		streams = []streamStat{}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	jsonResponse(w, map[string]interface{}{
		"bytes_in":        bi,
		"bytes_out":       bo,
		"total_listeners": totalListeners,
		"total_streams":   len(streams),
		"total_dropped":   totalDropped,
		"streams":         streams,
		"server_uptime":   time.Since(s.startTime).Round(time.Second).String(),
		"goroutines":      runtime.NumGoroutine(),
		"sys_ram":         m.Sys,
		"heap_alloc":      m.HeapAlloc,
		"num_gc":          m.NumGC,
		"version":         s.Version,
		"commit":          s.Commit,
	})
}
