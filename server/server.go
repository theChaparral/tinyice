package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"github.com/syso/tinyice/config"
	"github.com/syso/tinyice/relay"
)

//go:embed all:templates
var templateFS embed.FS

type Server struct {
	Config *config.Config
	Relay  *relay.Relay
	RelayM *relay.RelayManager
	tmpl   *template.Template
}

func NewServer(cfg *config.Config) *Server {
	tmpl := template.New("base")
	tmpl, err := tmpl.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		logrus.Fatalf("Error loading embedded templates: %v", err)
	}

	r := relay.NewRelay(cfg.LowLatencyMode)
	return &Server{
		Config: cfg,
		Relay:  r,
		RelayM: relay.NewRelayManager(r),
		tmpl:   tmpl,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
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
	mux.HandleFunc("/admin/toggle-hidden", s.handleToggleHidden)
	mux.HandleFunc("/admin/add-user", s.handleAddUser)
	mux.HandleFunc("/admin/remove-user", s.handleRemoveUser)
	mux.HandleFunc("/admin/add-banned-ip", s.handleAddBannedIP)
	mux.HandleFunc("/admin/remove-banned-ip", s.handleRemoveBannedIP)
	mux.HandleFunc("/admin/add-relay", s.handleAddRelay)
	mux.HandleFunc("/admin/remove-relay", s.handleRemoveRelay)
	mux.HandleFunc("/admin/restart-relay", s.handleRestartRelay)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handlePublicEvents)
	mux.HandleFunc("/status-json.xsl", s.handleLegacyStats)
	mux.HandleFunc("/metrics", s.handleMetrics)

	addr := s.Config.BindHost + ":" + s.Config.Port
	
	if !s.Config.UseHTTPS {
		logrus.Infof("Starting TinyIce on %s (HTTP)", addr)
		srv := &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 0,
			IdleTimeout:  120 * time.Second,
		}
		return srv.ListenAndServe()
	}

	httpsAddr := s.Config.BindHost + ":" + s.Config.HTTPSPort
	var certManager *autocert.Manager

	if s.Config.AutoHTTPS {
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Config.Domains...),
			Cache:      autocert.DirCache("certs"),
			Email:      s.Config.ACMEEmail,
		}
	}

	httpsSrv := &http.Server{
		Addr:         httpsAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	if certManager != nil {
		httpsSrv.TLSConfig = certManager.TLSConfig()
	}

	httpSrv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" || r.Method == "SOURCE" {
				mux.ServeHTTP(w, r)
				return
			}
			if certManager != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				certManager.HTTPHandler(nil).ServeHTTP(w, r)
				return
			}
			target := "https://" + r.Host + r.URL.Path
			if len(r.URL.RawQuery) > 0 {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		logrus.Infof("Starting HTTP listener on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("HTTP server failed: %v", err)
		}
	}()

	if s.Config.DirectoryListing {
		go s.directoryReportingTask()
	}

	// Start Pull Relays
	for _, rc := range s.Config.Relays {
		s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize)
	}

	logrus.Infof("Starting HTTPS server on %s", httpsAddr)
	if certManager != nil {
		return httpsSrv.ListenAndServeTLS("", "")
	}
	return httpsSrv.ListenAndServeTLS(s.Config.CertFile, s.Config.KeyFile)
}

func (s *Server) checkAuth(r *http.Request) (*config.User, bool) {
	u, p, ok := r.BasicAuth()
	if !ok { return nil, false }
	user, exists := s.Config.Users[u]
	if !exists { return nil, false }
	return user, config.CheckPasswordHash(p, user.Password)
}

func (s *Server) hasAccess(user *config.User, mount string) bool {
	if user.Role == config.RoleSuperAdmin { return true }
	_, exists := user.Mounts[mount]
	return exists
}

func (s *Server) isCSRFSafe(r *http.Request) bool {
	if r.Method != http.MethodPost { return true }
	origin := r.Header.Get("Origin")
	if origin == "" { origin = r.Header.Get("Referer") }
	if origin == "" { return false }
	return true
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" || r.Method == "SOURCE" {
		s.handleSource(w, r)
		return
	}
	if r.Method == "GET" && r.URL.Path != "/" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/admin" {
		s.handleListener(w, r)
		return
	}
	s.handleStatus(w, r)
}

func (s *Server) isBanned(ip string) bool {
	// RemoteAddr usually includes port, strip it
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	for _, banned := range s.Config.BannedIPs {
		if banned == ip { return true }
	}
	return false
}

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		logrus.WithField("ip", r.RemoteAddr).Warn("Banned IP attempted source connection")
		return
	}
	mount := r.URL.Path
	var requiredPass string
	found := false
	for _, user := range s.Config.Users {
		if pass, ok := user.Mounts[mount]; ok {
			requiredPass = pass; found = true; break
		}
	}
	if !found {
		if pass, ok := s.Config.Mounts[mount]; ok {
			requiredPass = pass; found = true
		}
	}
	if !found { requiredPass = s.Config.DefaultSourcePassword }

	if s.Config.DisabledMounts[mount] {
		logrus.WithField("mount", mount).Warn("Rejected source connection to disabled mount")
		http.Error(w, "Mount is disabled", http.StatusForbidden)
		return
	}

	_, p, ok := r.BasicAuth()
	if !ok || !config.CheckPasswordHash(p, requiredPass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Icecast Source"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		logrus.WithField("mount", mount).Error("Webserver doesn't support hijacking")
		http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil { logrus.WithError(err).Error("Hijack failed"); return }
	defer conn.Close()

	bufrw.WriteString("HTTP/1.0 200 OK\r\nServer: Icecast 2.4.4\r\nConnection: Keep-Alive\r\n\r\n")
	bufrw.Flush()

	logrus.WithField("mount", mount).Info("Source connected (hijacked)")
	stream := s.Relay.GetOrCreateStream(mount)
	stream.SourceIP = r.RemoteAddr

	bitrate := r.Header.Get("Ice-Bitrate")
	if bitrate == "" || bitrate == "N/A" {
		audioInfo := r.Header.Get("Ice-Audio-Info")
		if audioInfo != "" {
			parts := strings.Split(audioInfo, ";")
			for _, part := range parts {
				if strings.HasPrefix(strings.TrimSpace(part), "bitrate=") {
					bitrate = strings.TrimPrefix(strings.TrimSpace(part), "bitrate="); break
				}
			}
		}
	}

	isPublic := r.Header.Get("Ice-Public") == "1"
	isHidden := s.Config.HiddenMounts[mount]
	stream.UpdateMetadata(r.Header.Get("Ice-Name"), r.Header.Get("Ice-Description"), r.Header.Get("Ice-Genre"), r.Header.Get("Ice-Url"), bitrate, r.Header.Get("Content-Type"), isPublic, isHidden)

	buf := make([]byte, 8192)
	for {
		n, err := bufrw.Read(buf)
		if n > 0 { stream.Broadcast(buf[:n], s.Relay) }
		if err != nil {
			if err != io.EOF { logrus.WithField("mount", mount).WithError(err).Error("Source read error")
			} else { logrus.WithField("mount", mount).Info("Source closed connection (EOF)") }
			break
		}
	}
	logrus.WithField("mount", mount).Info("Source disconnected")
	s.Relay.RemoveStream(mount)
}

func (s *Server) handleListener(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		logrus.WithField("ip", r.RemoteAddr).Warn("Banned IP attempted to listen")
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	mount := r.URL.Path
	stream, ok := s.Relay.GetStream(mount)
	if !ok { http.NotFound(w, r); return }

	if s.Config.MaxListeners > 0 && stream.ListenersCount() >= s.Config.MaxListeners {
		http.Error(w, "Server Full", http.StatusServiceUnavailable); return
	}

	id := r.RemoteAddr + "-" + fmt.Sprintf("%d", time.Now().UnixNano())
	ch, burst := stream.Subscribe(id)
	defer stream.Unsubscribe(id)

	w.Header().Set("Content-Type", stream.ContentType)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	if s.Config.LowLatencyMode { w.Header().Set("X-Accel-Buffering", "no") }

	if f, ok := w.(http.Flusher); ok { f.Flush() }
	for _, chunk := range burst {
		if _, err := w.Write(chunk); err != nil { return }
	}
	if f, ok := w.(http.Flusher); ok { f.Flush() }

	for chunk := range ch {
		if _, err := w.Write(chunk); err != nil { return }
		if f, ok := w.(http.Flusher); ok { f.Flush() }
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	allStreams := s.Relay.Snapshot()
	var streams []relay.StreamStats
	for _, st := range allStreams {
		if !st.Hidden { streams = append(streams, st) }
	}
	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{"Streams": streams, "Config": s.Config}
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		logrus.WithError(err).Error("Template error")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized); return
	}
	allStreams := s.Relay.Snapshot()
	var streams []relay.StreamStats
	for _, st := range allStreams {
		if s.hasAccess(user, st.MountName) { streams = append(streams, st) }
	}
	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{"Streams": streams, "Config": s.Config, "User": user}
	if err := s.tmpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		logrus.WithError(err).Error("Template error")
	}
}

func (s *Server) handleAddMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { http.Error(w, "Forbidden", http.StatusForbidden); return }
	user, ok := s.checkAuth(r)
	if !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
	mount, password := r.FormValue("mount"), r.FormValue("password")
	if mount == "" || password == "" { http.Error(w, "Required fields missing", http.StatusBadRequest); return }
	if mount[0] != '/' { mount = "/" + mount }

	// Check if mount is already owned by someone else or exists globally
	if user.Role != config.RoleSuperAdmin {
		// Is it already ours?
		_, isOurs := user.Mounts[mount]
		if !isOurs {
			// Check global mounts
			if _, exists := s.Config.Mounts[mount]; exists {
				http.Error(w, "Mount point already exists", http.StatusConflict); return
			}
			// Check other users
			for _, otherUser := range s.Config.Users {
				if _, exists := otherUser.Mounts[mount]; exists {
					http.Error(w, "Mount point already exists", http.StatusConflict); return
				}
			}
		}
	}

	hashed, _ := config.HashPassword(password)
	if user.Role == config.RoleSuperAdmin { s.Config.Mounts[mount] = hashed } else { user.Mounts[mount] = hashed }
	s.Config.SaveConfig()
	logrus.WithField("mount", mount).Info("Admin updated mount")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { http.Error(w, "Forbidden", http.StatusForbidden); return }
	user, ok := s.checkAuth(r)
	if !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
	mount := r.FormValue("mount")
	if !s.hasAccess(user, mount) { http.Error(w, "Forbidden", http.StatusForbidden); return }
	delete(s.Config.Mounts, mount)
	delete(s.Config.DisabledMounts, mount)
	delete(user.Mounts, mount)
	s.Relay.RemoveStream(mount)
	s.Config.SaveConfig()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleLatency(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	s.Config.LowLatencyMode = !s.Config.LowLatencyMode
	s.Relay.LowLatency = s.Config.LowLatencyMode
	s.Config.SaveConfig()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	mount, song := r.URL.Query().Get("mount"), r.URL.Query().Get("song")
	if !ok {
		_, p, okAuth := r.BasicAuth()
		if !okAuth { w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce"`); http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
		allowed := false
		if config.CheckPasswordHash(p, s.Config.DefaultSourcePassword) || config.CheckPasswordHash(p, s.Config.Mounts[mount]) { allowed = true }
		if !allowed { for _, u := range s.Config.Users { if config.CheckPasswordHash(p, u.Mounts[mount]) { allowed = true; break } } }
		if !allowed { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
	} else { if !s.hasAccess(user, mount) { http.Error(w, "Forbidden", http.StatusForbidden); return } }
	if mount != "" && song != "" {
		if st, ok := s.Relay.GetStream(mount); ok { st.SetCurrentSong(song); logrus.WithFields(logrus.Fields{"mount": mount, "song": song}).Info("Metadata updated") }
	}
	fmt.Fprint(w, "<?xml version=\"1.0\"?>\n<iceresponse><message>OK</message><return>1</return></iceresponse>\n")
}

func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r); if !ok { return }
	mount := r.FormValue("mount"); if !s.hasAccess(user, mount) { return }
	s.Relay.RemoveStream(mount); http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleKickAllListeners(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r); if !ok || user.Role != config.RoleSuperAdmin { return }
	s.Relay.DisconnectAllListeners(); http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleMount(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r); if !ok { return }
	mount := r.FormValue("mount"); if !s.hasAccess(user, mount) { return }
	s.Config.DisabledMounts[mount] = !s.Config.DisabledMounts[mount]
	if s.Config.DisabledMounts[mount] { s.Relay.RemoveStream(mount) }
	s.Config.SaveConfig(); http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleHidden(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r); if !ok { return }
	mount := r.FormValue("mount"); if !s.hasAccess(user, mount) { return }
	s.Config.HiddenMounts[mount] = !s.Config.HiddenMounts[mount]
	if st, ok := s.Relay.GetStream(mount); ok { st.SetHidden(s.Config.HiddenMounts[mount]) }
	s.Config.SaveConfig(); http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { http.Error(w, "Forbidden", http.StatusForbidden); return }
	username, password := r.FormValue("username"), r.FormValue("password")
	if username == "" || password == "" { return }
	hashed, _ := config.HashPassword(password)
	s.Config.Users[username] = &config.User{Username: username, Password: hashed, Role: config.RoleAdmin, Mounts: make(map[string]string)}
	s.Config.SaveConfig(); http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	username := r.FormValue("username")
	if username != user.Username { delete(s.Config.Users, username); s.Config.SaveConfig() }
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddBannedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	ip := r.FormValue("ip")
	if ip != "" {
		s.Config.BannedIPs = append(s.Config.BannedIPs, ip)
		s.Config.SaveConfig()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveBannedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	ip := r.FormValue("ip")
	for i, b := range s.Config.BannedIPs {
		if b == ip {
			s.Config.BannedIPs = append(s.Config.BannedIPs[:i], s.Config.BannedIPs[i+1:]...)
			s.Config.SaveConfig()
			break
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	
	urlStr := r.FormValue("url")
	mount := r.FormValue("mount")
	password := r.FormValue("password")
	if urlStr == "" || mount == "" { return }
	if mount[0] != '/' { mount = "/" + mount }

	relay := &config.RelayConfig{
		URL:      urlStr,
		Mount:    mount,
		Password: password,
	}
	s.Config.Relays = append(s.Config.Relays, relay)
	s.Config.SaveConfig()
	
	// Start it immediately
	s.RelayM.StartRelay(relay.URL, relay.Mount, relay.Password, 20)
	
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	
	mount := r.FormValue("mount")
	for i, rc := range s.Config.Relays {
		if rc.Mount == mount {
			s.Config.Relays = append(s.Config.Relays[:i], s.Config.Relays[i+1:]...)
			s.Config.SaveConfig()
			s.RelayM.StopRelay(mount)
			break
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRestartRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) { return }
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin { return }
	
	mount := r.FormValue("mount")
	for _, rc := range s.Config.Relays {
		if rc.Mount == mount {
			s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize)
			break
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLegacyStats(w http.ResponseWriter, r *http.Request) {
	streams := s.Relay.Snapshot()
	type IcecastSource struct {
		AudioInfo string `json:"audio_info"`; Bitrate interface{} `json:"bitrate"`; Genre string `json:"genre"`; 
		Listeners int `json:"listeners"`; ListenURL string `json:"listenurl"`; Mount string `json:"mount"`; 
		ServerDescription string `json:"server_description"`; ServerName string `json:"server_name"`; 
		ServerType string `json:"server_type"`; StreamStart string `json:"stream_start"`; 
		Title string `json:"title"`; Dummy interface{} `json:"dummy"`
	}
	sources := make([]IcecastSource, len(streams))
	host := s.Config.HostName
	if !strings.Contains(host, ":") { host = host + ":" + s.Config.Port }
	proto := "http://"
	if s.Config.UseHTTPS { proto = "https://" }
	for i, st := range streams {
		sources[i] = IcecastSource{AudioInfo: fmt.Sprintf("bitrate=%s", st.Bitrate), Bitrate: st.Bitrate, Genre: st.Genre, Listeners: st.ListenersCount, ListenURL: proto + host + st.MountName, Mount: st.MountName, ServerDescription: st.Description, ServerName: st.Name, ServerType: st.ContentType, StreamStart: st.Started.Format(time.RFC1123), Title: st.CurrentSong, Dummy: nil}
	}
	resp := map[string]interface{}{"icestats": map[string]interface{}{"admin": s.Config.AdminEmail, "host": s.Config.HostName, "location": s.Config.Location, "server_id": "Icecast 2.4.4 (TinyIce)", "server_start": time.Now().Format(time.RFC1123), "source": sources}}
	w.Header().Set("Content-Type", "application/json"); w.Header().Set("Access-Control-Allow-Origin", "*"); json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	bi, bo := s.Relay.GetMetrics()
	streams := s.Relay.Snapshot()
	
	tl := 0
	for _, st := range streams {
		tl += st.ListenersCount
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	fmt.Fprintf(w, "# HELP tinyice_bandwidth_in_bytes_total Total bytes received from sources\n")
	fmt.Fprintf(w, "# TYPE tinyice_bandwidth_in_bytes_total counter\n")
	fmt.Fprintf(w, "tinyice_bandwidth_in_bytes_total %d\n\n", bi)

	fmt.Fprintf(w, "# HELP tinyice_bandwidth_out_bytes_total Total bytes sent to listeners\n")
	fmt.Fprintf(w, "# TYPE tinyice_bandwidth_out_bytes_total counter\n")
	fmt.Fprintf(w, "tinyice_bandwidth_out_bytes_total %d\n\n", bo)

	fmt.Fprintf(w, "# HELP tinyice_listeners_total Total number of active listeners\n")
	fmt.Fprintf(w, "# TYPE tinyice_listeners_total gauge\n")
	fmt.Fprintf(w, "tinyice_listeners_total %d\n\n", tl)

	fmt.Fprintf(w, "# HELP tinyice_sources_total Total number of active sources\n")
	fmt.Fprintf(w, "# TYPE tinyice_sources_total gauge\n")
	fmt.Fprintf(w, "tinyice_sources_total %d\n\n", len(streams))

	fmt.Fprintf(w, "# HELP tinyice_mount_listeners_current Listeners per mount point\n")
	fmt.Fprintf(w, "# TYPE tinyice_mount_listeners_current gauge\n")
	for _, st := range streams {
		fmt.Fprintf(w, "tinyice_mount_listeners_current{mount=\"%s\",name=\"%s\"} %d\n", st.MountName, st.Name, st.ListenersCount)
	}
}

func (s *Server) handlePublicEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream"); w.Header().Set("Cache-Control", "no-cache"); w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher); ticker := time.NewTicker(time.Second); defer ticker.Stop()
	type PublicStreamInfo struct { Mount string `json:"mount"`; Name string `json:"name"`; Listeners int `json:"listeners"`; Bitrate string `json:"bitrate"`; Uptime string `json:"uptime"`; Genre string `json:"genre"`; Description string `json:"description"`; CurrentSong string `json:"song"` }
	for {
		select {
		case <-r.Context().Done(): return
		case <-ticker.C:
			allStreams := s.Relay.Snapshot()
			var info []PublicStreamInfo
			for _, st := range allStreams {
				if st.Hidden { continue }
				info = append(info, PublicStreamInfo{Mount: st.MountName, Name: st.Name, Listeners: st.ListenersCount, Bitrate: st.Bitrate, Uptime: st.Uptime, Genre: st.Genre, Description: st.Description, CurrentSong: st.CurrentSong})
			}
			payload, _ := json.Marshal(info); fmt.Fprintf(w, "data: %s\n\n", payload); flusher.Flush()
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
	bi, bo := s.Relay.GetMetrics()
	w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(map[string]interface{}{"bytes_in": bi, "bytes_out": bo})
}

func (s *Server) directoryReportingTask() {
	ticker := time.NewTicker(3 * time.Minute); defer ticker.Stop()
	for range ticker.C {
		streams := s.Relay.Snapshot()
		for _, st := range streams { if st.Public { s.reportToDirectory(st) } }
	}
}

func (s *Server) reportToDirectory(st relay.StreamStats) {
	proto := "http://"; if s.Config.UseHTTPS { proto = "https://" }
	listenURL := proto + s.Config.HostName + ":" + s.Config.Port + st.MountName
	if s.Config.UseHTTPS { listenURL = proto + s.Config.HostName + ":" + s.Config.HTTPSPort + st.MountName }
	data := url.Values{}
	data.Set("action", "add"); data.Set("sn", st.Name); data.Set("genre", st.Genre); data.Set("cps", st.Bitrate); data.Set("url", st.URL); data.Set("desc", st.Description); data.Set("st", st.ContentType); data.Set("listenurl", listenURL); data.Set("type", "audio/mpeg")
	resp, err := http.PostForm(s.Config.DirectoryServer, data)
	if err != nil { logrus.WithError(err).Warn("Failed to report to directory server"); return }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { logrus.WithField("status", resp.Status).Warn("Directory server rejected update") } else { logrus.WithField("mount", st.MountName).Debug("Reported to directory server") }
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r); if !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
	w.Header().Set("Content-Type", "text/event-stream"); w.Header().Set("Cache-Control", "no-cache"); w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher); ticker := time.NewTicker(time.Second); defer ticker.Stop()
	type StreamInfo struct { Mount string `json:"mount"`; Name string `json:"name"`; Listeners int `json:"listeners"`; Bitrate string `json:"bitrate"`; Uptime string `json:"uptime"`; ContentType string `json:"type"`; SourceIP string `json:"ip"`; BytesIn int64 `json:"bytes_in"`; BytesOut int64 `json:"bytes_out"`; CurrentSong string `json:"song"` }
	for {
		select {
		case <-r.Context().Done(): return
		case <-ticker.C:
			bi, bo := s.Relay.GetMetrics(); allStreams := s.Relay.Snapshot(); tl := 0; var info []StreamInfo
			for _, st := range allStreams {
				if s.hasAccess(user, st.MountName) {
					lc := st.ListenersCount; tl += lc
					info = append(info, StreamInfo{Mount: st.MountName, Name: st.Name, Listeners: lc, Bitrate: st.Bitrate, Uptime: st.Uptime, ContentType: st.ContentType, SourceIP: st.SourceIP, BytesIn: st.BytesIn, BytesOut: st.BytesOut, CurrentSong: st.CurrentSong})
				}
			}
			if user.Role != config.RoleSuperAdmin { var userBi, userBo int64; for _, st := range info { userBi += st.BytesIn; userBo += st.BytesOut }; bi, bo = userBi, userBo }
			payload, _ := json.Marshal(map[string]interface{}{"bytes_in": bi, "bytes_out": bo, "total_listeners": tl, "total_sources": len(info), "streams": info})
			fmt.Fprintf(w, "data: %s\n\n", payload); flusher.Flush()
		}
	}
}
