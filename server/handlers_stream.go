package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	logger.L.Debugw("Root handler request", "method", r.Method, "path", r.URL.Path)
	if r.Method == "PUT" || r.Method == "SOURCE" {
		s.handleSource(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".m3u8") || strings.HasSuffix(r.URL.Path, ".m3u") {
		s.handlePlaylist(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".pls") {
		s.handlePLS(w, r)
		return
	}
	if r.Method == "GET" && r.URL.Path != "/" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/admin" && !strings.HasPrefix(r.URL.Path, "/player") {
		s.handleListener(w, r)
		return
	}
	s.handleStatus(w, r)
}

func (s *Server) handlePLS(w http.ResponseWriter, r *http.Request) {
	mount := strings.TrimSuffix(r.URL.Path, ".pls")
	st, ok := s.Relay.GetStream(mount)
	if !ok {
		http.NotFound(w, r)
		return
	}

	baseURL := s.Config.BaseURL
	if baseURL == "" {
		proto := "http://"
		if s.Config.UseHTTPS || r.Header.Get("X-Forwarded-Proto") == "https" {
			proto = "https://"
		}
		baseURL = proto + r.Host
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	w.Header().Set("Content-Type", "audio/x-scpls")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.pls\"", st.Name))
	fmt.Fprintf(w, "[playlist]\nNumberOfEntries=1\nFile1=%s%s\nTitle1=%s\nLength1=-1\nVersion=2\n", baseURL, mount, st.Name)
}

func (s *Server) handlePlaylist(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	ext := ".m3u8"
	if strings.HasSuffix(path, ".m3u") {
		ext = ".m3u"
	}
	mount := strings.TrimSuffix(path, ext)

	st, ok := s.Relay.GetStream(mount)
	if !ok {
		http.NotFound(w, r)
		return
	}

	baseURL := s.Config.BaseURL
	if baseURL == "" {
		proto := "http://"
		if s.Config.UseHTTPS || r.Header.Get("X-Forwarded-Proto") == "https" {
			proto = "https://"
		}
		baseURL = proto + r.Host
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	w.Header().Set("Content-Type", "audio/x-mpegurl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s%s\"", st.Name, ext))
	fmt.Fprintf(w, "#EXTM3U\n#EXTINF:-1,%s\n%s%s\n", st.Name, baseURL, mount)
}

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		logger.L.Warnw("Banned IP source connection", "ip", r.RemoteAddr)
		return
	}
	mount := r.URL.Path
	requiredPass, found := s.getSourcePassword(mount)
	if !found {
		requiredPass = s.Config.DefaultSourcePassword
	}

	if s.Config.DisabledMounts[mount] {
		logger.L.Warnw("Disabled mount connection", "mount", mount)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	_, p, ok := r.BasicAuth()
	if !ok || !config.CheckPasswordHash(p, requiredPass) {
		u, _, _ := r.BasicAuth()
		if u == "" {
			u = "unknown"
		}
		s.logAuthFailed(u, r.RemoteAddr, "source password mismatch")
		w.Header().Set("WWW-Authenticate", `Basic realm="Icecast"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.logAuth().Infow("Source auth successful", "mount", mount, "ip", host)

	if s.Relay.History != nil {
		s.Relay.History.RecordUA(r.Header.Get("User-Agent"), "source")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		logger.L.Errorf("Hijack failed: %v", err)
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.0 200 OK\r\nServer: Icecast 2.4.4\r\nConnection: Keep-Alive\r\n\r\n")
	bufrw.Flush()

	logger.L.Infow("Source connected", "mount", mount, "ip", r.RemoteAddr, "ua", r.Header.Get("User-Agent"))
	s.dispatchWebhook("source_connect", map[string]interface{}{
		"mount": mount,
		"ip":    r.RemoteAddr,
		"ua":    r.Header.Get("User-Agent"),
		"name":  r.Header.Get("Ice-Name"),
	})

	stream := s.Relay.GetOrCreateStream(mount)
	stream.SourceIP = r.RemoteAddr

	s.updateSourceMetadata(stream, mount, r)

	buf := make([]byte, 8192)
	for {
		n, err := bufrw.Read(buf)
		if n > 0 {
			stream.Broadcast(buf[:n], s.Relay)
		}
		if err != nil {
			break
		}
	}
	logger.L.Infow("Source disconnected", "mount", mount)
	s.dispatchWebhook("source_disconnect", map[string]interface{}{
		"mount": mount,
	})
	s.Relay.RemoveStream(mount)
}

func (s *Server) updateSourceMetadata(stream *relay.Stream, mount string, r *http.Request) {
	bitrate := r.Header.Get("Ice-Bitrate")
	if bitrate == "" || bitrate == "N/A" {
		audioInfo := r.Header.Get("Ice-Audio-Info")
		if audioInfo != "" {
			parts := strings.Split(audioInfo, ";")
			for _, part := range parts {
				if strings.HasPrefix(strings.TrimSpace(part), "bitrate=") {
					bitrate = strings.TrimPrefix(strings.TrimSpace(part), "bitrate=")
					break
				}
			}
		}
	}
	isPublic := r.Header.Get("Ice-Public") == "1"
	isVisible := s.Config.VisibleMounts[mount]
	if stream.UpdateMetadata(r.Header.Get("Ice-Name"), r.Header.Get("Ice-Description"), r.Header.Get("Ice-Genre"), r.Header.Get("Ice-Url"), bitrate, r.Header.Get("Content-Type"), isPublic, isVisible) {
		s.dispatchWebhook("metadata_update", map[string]interface{}{
			"mount":        mount,
			"name":         stream.Name,
			"description":  stream.Description,
			"genre":        stream.Genre,
			"current_song": stream.CurrentSong,
		})
	}
}

func (s *Server) handleListener(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	originalMount := r.URL.Path
	mount := originalMount

	if s.Relay.History != nil {
		s.Relay.History.RecordUA(r.Header.Get("User-Agent"), "listener")
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s.Config.LowLatencyMode {
		w.Header().Set("X-Accel-Buffering", "no")
	}

	flusher, _ := w.(http.Flusher)
	id := r.RemoteAddr + "-" + fmt.Sprintf("%d", time.Now().UnixNano())
	logger.L.Infow("Listener connected", "mount", mount, "ip", r.RemoteAddr, "ua", r.Header.Get("User-Agent"))
	defer logger.L.Infow("Listener disconnected", "mount", mount, "ip", r.RemoteAddr)

	recoveryTicker := time.NewTicker(10 * time.Second)
	defer recoveryTicker.Stop()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		if mount != originalMount {
			if _, ok := s.Relay.GetStream(originalMount); ok {
				logger.L.Infow("Primary stream returned, recovering from fallback", "mount", originalMount)
				mount = originalMount
			}
		}

		stream, ok := s.Relay.GetStream(mount)
		if !ok {
			fallback, hasFallback := s.Config.FallbackMounts[mount]
			if hasFallback && fallback != mount {
				logger.L.Infow("Primary stream down, falling back", "from", mount, "to", fallback)
				mount = fallback
				continue
			}
			if mount != originalMount {
				mount = originalMount
				time.Sleep(1 * time.Second)
				continue
			}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			s.recordScanAttempt(host, mount)
			http.NotFound(w, r)
			return
		}

		metaint := 0
		if r.Header.Get("Icy-MetaData") == "1" && !stream.IsOgg() {
			metaint = 16000
			w.Header().Set("icy-metaint", "16000")
			w.Header().Set("icy-name", s.Config.PageTitle)
		}

		if s.Config.MaxListeners > 0 && stream.ListenersCount() >= s.Config.MaxListeners {
			http.Error(w, "Server Full", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", stream.ContentType)
		if flusher != nil {
			flusher.Flush()
		}

		if !s.serveStreamData(w, r, stream, id, originalMount, mount, recoveryTicker, metaint) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Server) serveStreamData(w http.ResponseWriter, r *http.Request, stream *relay.Stream, id, originalMount, currentMount string, recoveryTicker *time.Ticker, metaint int) bool {
	offset, signal := stream.Subscribe(id, 128*1024)
	defer stream.Unsubscribe(id)

	if stream.OggHead != nil {
		if _, err := w.Write(stream.OggHead); err != nil {
			return false
		}
		logger.L.Debugf("Ogg Listener %s: Sending stored headers (%d bytes), then starting burst at %d", id, len(stream.OggHead), offset)
	}

	// was 16384
	buf := make([]byte, 4096)
	flusher, _ := w.(http.Flusher)

	bytesSentSinceMeta := 0
	lastSong := ""

	consecutiveSkips := 0
	maxConsecutiveSkips := 5

	for {
		select {
		case <-s.done:
			return false
		case <-r.Context().Done():
			return false
		case <-recoveryTicker.C:
			if currentMount != originalMount {
				if _, ok := s.Relay.GetStream(originalMount); ok {
					return true
				}
			}
		case _, ok := <-signal:
			if !ok {
				return true
			}
			for {
				readLimit := len(buf)
				if metaint > 0 {
					remaining := metaint - bytesSentSinceMeta
					if remaining < readLimit {
						readLimit = remaining
					}
				}

				n, next, skipped := stream.Buffer.ReadAt(offset, buf[:readLimit])
				if skipped && stream.IsOggStream {
					consecutiveSkips++
					if consecutiveSkips >= maxConsecutiveSkips {
						logger.L.Warnw("Slow listener disconnected (ogg sync skip)",
							"id", id, "mount", currentMount,
							"consecutive_skips", consecutiveSkips,
						)
						return false
					}
					offset = relay.FindNextPageBoundary(stream.Buffer.Data, stream.Buffer.Size, stream.Buffer.Head, next)
					continue
				}
				if n == 0 {
					break
				}
				if skipped {
					atomic.AddInt64(&stream.BytesDropped, next-offset)
					consecutiveSkips++
					if consecutiveSkips >= maxConsecutiveSkips {
						logger.L.Warnw("Slow listener disconnected",
							"id", id, "mount", currentMount,
							"consecutive_skips", consecutiveSkips,
						)
						return false
					}
				} else {
					consecutiveSkips = 0
				}
				offset = next

				if _, err := w.Write(buf[:n]); err != nil {
					return false
				}

				if metaint > 0 {
					bytesSentSinceMeta += n
					if bytesSentSinceMeta >= metaint {
						currentSong := stream.GetCurrentSong()
						meta := ""
						if currentSong != lastSong {
							meta = fmt.Sprintf("StreamTitle='%s';", currentSong)
							lastSong = currentSong
						}

						l := (len(meta) + 15) / 16
						res := make([]byte, 1+l*16)
						res[0] = byte(l)
						copy(res[1:], meta)

						if _, err := w.Write(res); err != nil {
							return false
						}
						bytesSentSinceMeta = 0
					}
				}

				atomic.AddInt64(&s.Relay.BytesOut, int64(n))
				atomic.AddInt64(&stream.BytesOut, int64(n))
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Build stream list for the landing page
	allStreams := s.Relay.Snapshot()
	var streamList []map[string]interface{}
	for _, st := range allStreams {
		if st.Visible {
			streamList = append(streamList, map[string]interface{}{
				"mount":     st.MountName,
				"title":     st.CurrentSong,
				"artist":    st.Name,
				"format":    st.ContentType,
				"bitrate":   st.Bitrate,
				"listeners": st.ListenersCount,
				"live":      st.SourceIP != "",
			})
		}
	}

	pageData := s.BasePageData("")
	pageData["streams"] = streamList
	s.shell.Render(w, "landing", s.Config.PageTitle, pageData)
}
