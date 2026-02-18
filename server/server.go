package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/syso/tinyice/config"
	"github.com/syso/tinyice/relay"
)

//go:embed all:templates
var templateFS embed.FS

type Server struct {
	Config *config.Config
	Relay  *relay.Relay
	tmpl   *template.Template
}

func NewServer(cfg *config.Config) *Server {
	// Load templates from embedded FS with manual initialization
	tmpl := template.New("base")
	tmpl, err := tmpl.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("Error loading embedded templates: %v", err)
	}

	return &Server{
		Config: cfg,
		Relay:  relay.NewRelay(cfg.LowLatencyMode),
		tmpl:   tmpl,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	
	// Admin routes
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/add-mount", s.handleAddMount)
	mux.HandleFunc("/admin/toggle-latency", s.handleToggleLatency)
	mux.HandleFunc("/admin/stats", s.handleStats)
	mux.HandleFunc("/admin/events", s.handleEvents)
	mux.HandleFunc("/admin/metadata", s.handleMetadata)
	mux.HandleFunc("/admin/kick", s.handleKick)
	mux.HandleFunc("/admin/remove-mount", s.handleRemoveMount)
	mux.HandleFunc("/admin/kick-all-listeners", s.handleKickAllListeners)
	mux.HandleFunc("/admin/toggle-mount", s.handleToggleMount)

	// Status (public)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handlePublicEvents)

	// Start server
	addr := ":" + s.Config.Port
	log.Printf("Starting TinyIce on %s", addr)
	return http.ListenAndServe(addr, mux)
}

// Basic Auth helper
func (s *Server) checkAuth(r *http.Request, user, pass string) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if user != "" && u != user {
		return false
	}
	// Compare SHA-256 hashes
	return config.HashPassword(p) == pass
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Check if this is a source connection (PUT or SOURCE method)
	if r.Method == "PUT" || r.Method == "SOURCE" {
		s.handleSource(w, r)
		return
	}

	// Check if this is a listener (GET with a path that isn't just /)
	if r.Method == "GET" && r.URL.Path != "/" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/admin" {
		s.handleListener(w, r)
		return
	}

	// Otherwise, show status page
	s.handleStatus(w, r)
}

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	mount := r.URL.Path
	
	requiredPass := s.Config.DefaultSourcePassword
	if specificPass, ok := s.Config.Mounts[mount]; ok {
		requiredPass = specificPass
	}

	if s.Config.DisabledMounts[mount] {
		log.Printf("Rejected source connection to disabled mount: %s", mount)
		http.Error(w, "Mount is disabled", http.StatusForbidden)
		return
	}

	if !s.checkAuth(r, "", requiredPass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Icecast Source"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported for %s", mount)
		http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.0 200 OK\r\n")
	bufrw.WriteString("Server: Icecast 2.4.4\r\n")
	bufrw.WriteString("Connection: Keep-Alive\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	log.Printf("Source connected (hijacked): %s", mount)

	stream := s.Relay.GetOrCreateStream(mount)
	stream.SourceIP = r.RemoteAddr

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

	stream.UpdateMetadata(
		r.Header.Get("Ice-Name"),
		r.Header.Get("Ice-Description"),
		r.Header.Get("Ice-Genre"),
		r.Header.Get("Ice-Url"),
		bitrate,
		r.Header.Get("Content-Type"),
	)

	buf := make([]byte, 8192)
	for {
		n, err := bufrw.Read(buf)
		if n > 0 {
			stream.Broadcast(buf[:n], s.Relay)
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("Source read error on %s: %v", mount, err)
			} else {
				log.Printf("Source closed connection (EOF): %s", mount)
			}
			break
		}
	}

	log.Printf("Source disconnected: %s", mount)
	s.Relay.RemoveStream(mount)
}

func (s *Server) handleListener(w http.ResponseWriter, r *http.Request) {
	mount := r.URL.Path
	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		http.NotFound(w, r)
		return
	}

	currentListeners := stream.ListenersCount()
	if s.Config.MaxListeners > 0 && currentListeners >= s.Config.MaxListeners {
		http.Error(w, "Server Full", http.StatusServiceUnavailable)
		return
	}

	id := r.RemoteAddr + "-" + fmt.Sprintf("%d", time.Now().UnixNano())
	ch, burst := stream.Subscribe(id)
	defer stream.Unsubscribe(id)

	w.Header().Set("Content-Type", stream.ContentType)
	w.Header().Set("Ice-Name", stream.Name)
	w.Header().Set("Ice-Description", stream.Description)
	w.Header().Set("Ice-Genre", stream.Genre)
	w.Header().Set("Ice-Url", stream.URL)
	w.Header().Set("Ice-Bitrate", stream.Bitrate)
	
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "keep-alive")

	if s.Config.LowLatencyMode {
		w.Header().Set("X-Accel-Buffering", "no")
	}

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	for _, chunk := range burst {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	for chunk := range ch {
		if _, err := w.Write(chunk); err != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	streams := s.Relay.Snapshot()
	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{
		"Streams": streams,
		"Config":  s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	streams := s.Relay.Snapshot()
	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{
		"Streams": streams,
		"Config":  s.Config,
	}
	if err := s.tmpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		log.Printf("Template error: %v", err)
	}
}

func (s *Server) handleAddMount(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	mount := r.FormValue("mount")
	password := r.FormValue("password")
	if mount == "" || password == "" {
		http.Error(w, "Mount and Password are required", http.StatusBadRequest)
		return
	}
	if mount[0] != '/' {
		mount = "/" + mount
	}
	s.Config.Mounts[mount] = config.HashPassword(password)
	if err := s.Config.SaveConfig(); err != nil {
		log.Printf("Error saving config: %v", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	log.Printf("Admin added new mount: %s", mount)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveMount(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount := r.FormValue("mount")
	if mount != "" {
		delete(s.Config.Mounts, mount)
		delete(s.Config.DisabledMounts, mount)
		s.Relay.RemoveStream(mount)
		s.Config.SaveConfig()
		log.Printf("Admin removed mount point: %s", mount)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleLatency(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.Config.LowLatencyMode = !s.Config.LowLatencyMode
	s.Relay.LowLatency = s.Config.LowLatencyMode
	if err := s.Config.SaveConfig(); err != nil {
		log.Printf("Error saving config: %v", err)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	// Standard Icecast metadata update: /admin/metadata?mount=/live&mode=updinfo&song=Artist+-+Title
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		// Also check Source Password for metadata updates from clients
		_, p, ok := r.BasicAuth()
		if !ok || config.HashPassword(p) != s.Config.DefaultSourcePassword {
			// Check specific mount password if possible, but mount is in query
			mount := r.URL.Query().Get("mount")
			if mount != "" && config.HashPassword(p) == s.Config.Mounts[mount] {
				// OK
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Metadata"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}

	mount := r.URL.Query().Get("mount")
	song := r.URL.Query().Get("song")

	if mount != "" && song != "" {
		if st, ok := s.Relay.GetStream(mount); ok {
			st.SetCurrentSong(song)
			log.Printf("Metadata update for %s: %s", mount, song)
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "<?xml version=\"1.0\"?>\n<iceresponse><message>Metadata update successful</message><return>1</return></iceresponse>\n")
}

func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount := r.FormValue("mount")
	if mount != "" {
		s.Relay.RemoveStream(mount)
		log.Printf("Admin kicked source on: %s", mount)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleKickAllListeners(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.Relay.DisconnectAllListeners()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleMount(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount := r.FormValue("mount")
	if mount != "" {
		s.Config.DisabledMounts[mount] = !s.Config.DisabledMounts[mount]
		if s.Config.DisabledMounts[mount] {
			s.Relay.RemoveStream(mount)
		}
		s.Config.SaveConfig()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handlePublicEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
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

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			streams := s.Relay.Snapshot()
			info := make([]PublicStreamInfo, len(streams))
			for i, st := range streams {
				info[i] = PublicStreamInfo{
					Mount:       st.MountName,
					Name:        st.Name,
					Listeners:   st.ListenersCount(),
					Bitrate:     st.Bitrate,
					Uptime:      st.Uptime(),
					Genre:       st.Genre,
					Description: st.Description,
					CurrentSong: st.CurrentSong,
				}
			}
			payload, _ := json.Marshal(info)
			fmt.Fprintf(w, "data: %s\n\n", string(payload))
			flusher.Flush()
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	bytesIn, bytesOut := s.Relay.GetMetrics()
	stats := map[string]interface{}{
		"bytes_in":  bytesIn,
		"bytes_out": bytesOut,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	type StreamInfo struct {
		Mount       string `json:"mount"`
		Name        string `json:"name"`
		Listeners   int    `json:"listeners"`
		Bitrate     string `json:"bitrate"`
		Uptime      string `json:"uptime"`
		ContentType string `json:"type"`
		SourceIP    string `json:"ip"`
		BytesIn     int64  `json:"bytes_in"`
		BytesOut    int64  `json:"bytes_out"`
		CurrentSong string `json:"song"`
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			bytesIn, bytesOut := s.Relay.GetMetrics()
			streams := s.Relay.Snapshot()
			
			totalListeners := 0
			info := make([]StreamInfo, len(streams))
			for i, st := range streams {
				lCount := st.ListenersCount()
				totalListeners += lCount
				info[i] = StreamInfo{
					Mount:       st.MountName,
					Name:        st.Name,
					Listeners:   lCount,
					Bitrate:     st.Bitrate,
					Uptime:      st.Uptime(),
					ContentType: st.ContentType,
					SourceIP:    st.SourceIP,
					BytesIn:     atomic.LoadInt64(&st.BytesIn),
					BytesOut:    atomic.LoadInt64(&st.BytesOut),
					CurrentSong: st.CurrentSong,
				}
			}

			data := map[string]interface{}{
				"bytes_in":        bytesIn,
				"bytes_out":       bytesOut,
				"total_listeners": totalListeners,
				"total_sources":   len(streams),
				"streams":         info,
			}
			
			payload, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", string(payload))
			flusher.Flush()
		}
	}
}
