package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

func (s *Server) handlePlayer(w http.ResponseWriter, r *http.Request) {
	mount := strings.TrimPrefix(r.URL.Path, "/player")
	if mount == "" || mount == "/" {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		fallback, hasFallback := s.Config.FallbackMounts[mount]
		if hasFallback {
			stream, ok = s.Relay.GetStream(fallback)
		}
	}

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{
		"Stream": stream.Snapshot(),
		"Config": s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "player.html", data); err != nil {
		if !strings.Contains(err.Error(), "broken pipe") {
			logger.L.Errorf("Template error: %v", err)
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleWebRTCPlayer(w http.ResponseWriter, r *http.Request) {
	mount := strings.TrimPrefix(r.URL.Path, "/player-webrtc")
	if mount == "" || mount == "/" {
		http.Redirect(w, r, "/explore", http.StatusSeeOther)
		return
	}

	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	data := map[string]interface{}{
		"Stream": stream,
		"Config": s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "webrtc_player.html", data); err != nil {
		logger.L.Errorf("Template error: %v", err)
	}
}

func (s *Server) handleEmbed(w http.ResponseWriter, r *http.Request) {
	mount := strings.TrimPrefix(r.URL.Path, "/embed")
	if mount == "" || mount == "/" {
		http.NotFound(w, r)
		return
	}

	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		fallback, hasFallback := s.Config.FallbackMounts[mount]
		if hasFallback {
			stream, ok = s.Relay.GetStream(fallback)
		}
	}

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Frame-Options", "ALLOWALL")
	data := map[string]interface{}{
		"Stream": stream.Snapshot(),
		"Config": s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "embed.html", data); err != nil {
		logger.L.Errorf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleExplore(w http.ResponseWriter, r *http.Request) {
	allStreams := s.Relay.Snapshot()
	var visibleStreams []relay.StreamStats
	for _, st := range allStreams {
		if st.Visible {
			visibleStreams = append(visibleStreams, st)
		}
	}
	sort.Slice(visibleStreams, func(i, j int) bool {
		return visibleStreams[i].ListenersCount > visibleStreams[j].ListenersCount
	})

	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{
		"Streams": visibleStreams,
		"Config":  s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "explore.html", data); err != nil {
		logger.L.Errorf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
