package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/relay"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

//go:embed all:templates
var templateFS embed.FS

//go:embed all:assets
var assetFS embed.FS

type Server struct {
	Config      *config.Config
	Relay       *relay.Relay
	RelayM      *relay.RelayManager
	tmpl        *template.Template
	httpServers []*http.Server
}

func NewServer(cfg *config.Config) *Server {
	tmpl := template.New("base")
	tmpl, err := tmpl.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		logrus.Fatalf("Error loading embedded templates: %v", err)
	}

	hm, err := relay.NewHistoryManager("history.db")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize history manager")
	}

	r := relay.NewRelay(cfg.LowLatencyMode, hm)
	return &Server{
		Config: cfg,
		Relay:  r,
		RelayM: relay.NewRelayManager(r),
		tmpl:   tmpl,
	}
}

func (s *Server) setupRoutes() *http.ServeMux {
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
	mux.HandleFunc("/admin/toggle-visible", s.handleToggleVisible)
	mux.HandleFunc("/admin/add-user", s.handleAddUser)
	mux.HandleFunc("/admin/remove-user", s.handleRemoveUser)
	mux.HandleFunc("/admin/add-banned-ip", s.handleAddBannedIP)
	mux.HandleFunc("/admin/remove-banned-ip", s.handleRemoveBannedIP)
	mux.HandleFunc("/admin/add-relay", s.handleAddRelay)
	mux.HandleFunc("/admin/toggle-relay", s.handleToggleRelay)
	mux.HandleFunc("/admin/restart-relay", s.handleRestartRelay)
	mux.HandleFunc("/admin/delete-relay", s.handleDeleteRelay)
	mux.HandleFunc("/admin/history", s.handleHistory)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handlePublicEvents)
	mux.HandleFunc("/status-json.xsl", s.handleLegacyStats)
	mux.HandleFunc("/metrics", s.handleMetrics)
	subFS, _ := fs.Sub(assetFS, "assets")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(subFS))))
	return mux
}

func (s *Server) listenWithReuse(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			err2 := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					return
				}
				// SO_REUSEPORT is not available on all systems, but we try it
				// On Linux/Darwin it allows multiple processes to bind to the same port
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x0f, 1) // 0x0f is SO_REUSEPORT on most systems
			})
			if err2 != nil {
				return err2
			}
			return err
		},
	}
	return lc.Listen(context.Background(), network, address)
}

func (s *Server) Shutdown(ctx context.Context) error {
	logrus.Info("Server shutting down gracefully...")
	
	// Stop relays immediately to prevent dual-pulling if a new instance starts
	s.RelayM.StopAll()

	for _, srv := range s.httpServers {
		if err := srv.Shutdown(ctx); err != nil {
			logrus.Errorf("Error during HTTP server shutdown: %v", err)
		}
	}
	return nil
}

func (s *Server) ReloadConfig(cfg *config.Config) {
	s.Config = cfg
	// Re-sync relays
	s.RelayM.StopAll()
	for _, rc := range s.Config.Relays {
		if rc.Enabled {
			s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[rc.Mount])
		}
	}
	logrus.Info("Configuration reloaded successfully")
}

func (s *Server) Start() error {
	mux := s.setupRoutes()
	addr := s.Config.BindHost + ":" + s.Config.Port

	if s.Config.DirectoryListing {
		go s.directoryReportingTask()
	}

	for _, rc := range s.Config.Relays {
		if rc.Enabled {
			s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[rc.Mount])
		}
	}

	if !s.Config.UseHTTPS {
		logrus.Infof("Starting TinyIce on %s (HTTP)", addr)
		srv := &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 0,
			IdleTimeout:  120 * time.Second,
		}
		s.httpServers = append(s.httpServers, srv)
		
		ln, err := s.listenWithReuse("tcp", addr)
		if err != nil {
			return err
		}
		return srv.Serve(ln)
	}

	return s.startHTTPS(mux, addr)
}

func (s *Server) startHTTPS(mux *http.ServeMux, addr string) error {
	httpsAddr := s.Config.BindHost + ":" + s.Config.HTTPSPort
	var certManager *autocert.Manager

	if s.Config.AutoHTTPS {
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Config.Domains...),
			Cache:      autocert.DirCache("certs"),
			Email:      s.Config.ACMEEmail,
		}
		if s.Config.ACMEDirectoryURL != "" {
			certManager.Client = &acme.Client{DirectoryURL: s.Config.ACMEDirectoryURL}
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
	s.httpServers = append(s.httpServers, httpsSrv)

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
	s.httpServers = append(s.httpServers, httpSrv)

	go func() {
		logrus.Infof("Starting HTTP listener on %s", addr)
		ln, err := s.listenWithReuse("tcp", addr)
		if err != nil {
			logrus.Fatalf("HTTP listen failed: %v", err)
		}
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("HTTP server failed: %v", err)
		}
	}()

	logrus.Infof("Starting HTTPS server on %s", httpsAddr)
	ln, err := s.listenWithReuse("tcp", httpsAddr)
	if err != nil {
		return err
	}
	
	if certManager != nil {
		return httpsSrv.ServeTLS(ln, "", "")
	}
	return httpsSrv.ServeTLS(ln, s.Config.CertFile, s.Config.KeyFile)
}

func (s *Server) checkAuth(r *http.Request) (*config.User, bool) {
	u, p, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	user, exists := s.Config.Users[u]
	if !exists {
		logrus.WithFields(logrus.Fields{"user": u, "ip": r.RemoteAddr}).Warn("Admin auth failed: user not found")
		return nil, false
	}
	if !config.CheckPasswordHash(p, user.Password) {
		logrus.WithFields(logrus.Fields{"user": u, "ip": r.RemoteAddr}).Warn("Admin auth failed: invalid password")
		return nil, false
	}
	logrus.WithFields(logrus.Fields{"user": u, "ip": r.RemoteAddr}).Info("Admin auth successful")
	return user, true
}

func (s *Server) hasAccess(user *config.User, mount string) bool {
	if user.Role == config.RoleSuperAdmin {
		return true
	}
	_, exists := user.Mounts[mount]
	return exists
}

func (s *Server) isCSRFSafe(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	return true
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
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
	if r.Method == "GET" && r.URL.Path != "/" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/admin" {
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

func (s *Server) isBanned(ipStr string) bool {
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, banned := range s.Config.BannedIPs {
		// Try parsing as CIDR
		if strings.Contains(banned, "/") {
			_, ipnet, err := net.ParseCIDR(banned)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		}
		// Fallback to exact match
		if banned == host {
			return true
		}
	}
	return false
}

func (s *Server) getSourcePassword(mount string) (string, bool) {
	for _, user := range s.Config.Users {
		if pass, ok := user.Mounts[mount]; ok {
			return pass, true
		}
	}
	if pass, ok := s.Config.Mounts[mount]; ok {
		return pass, true
	}
	return s.Config.DefaultSourcePassword, s.Config.DefaultSourcePassword != ""
}

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		logrus.WithField("ip", r.RemoteAddr).Warn("Banned IP source connection")
		return
	}
	mount := r.URL.Path
	requiredPass, found := s.getSourcePassword(mount)
	if !found {
		requiredPass = s.Config.DefaultSourcePassword
	}

	if s.Config.DisabledMounts[mount] {
		logrus.WithField("mount", mount).Warn("Disabled mount connection")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	_, p, ok := r.BasicAuth()
	if !ok || !config.CheckPasswordHash(p, requiredPass) {
		logrus.WithFields(logrus.Fields{"mount": mount, "ip": r.RemoteAddr}).Warn("Source auth failed")
		w.Header().Set("WWW-Authenticate", `Basic realm="Icecast"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	logrus.WithFields(logrus.Fields{"mount": mount, "ip": r.RemoteAddr}).Info("Source auth successful")

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		logrus.WithError(err).Error("Hijack failed")
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.0 200 OK\r\nServer: Icecast 2.4.4\r\nConnection: Keep-Alive\r\n\r\n")
	bufrw.Flush()

	logrus.WithField("mount", mount).Info("Source connected")
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
	logrus.WithField("mount", mount).Info("Source disconnected")
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
	stream.UpdateMetadata(r.Header.Get("Ice-Name"), r.Header.Get("Ice-Description"), r.Header.Get("Ice-Genre"), r.Header.Get("Ice-Url"), bitrate, r.Header.Get("Content-Type"), isPublic, isVisible)
}

func (s *Server) handleListener(w http.ResponseWriter, r *http.Request) {
	if s.isBanned(r.RemoteAddr) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	mount := r.URL.Path
	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s.Config.MaxListeners > 0 && stream.ListenersCount() >= s.Config.MaxListeners {
		http.Error(w, "Server Full", http.StatusServiceUnavailable)
		return
	}
	id := r.RemoteAddr + "-" + fmt.Sprintf("%d", time.Now().UnixNano())
	offset, signal := stream.Subscribe(id)
	defer stream.Unsubscribe(id)

	w.Header().Set("Content-Type", stream.ContentType)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	if s.Config.LowLatencyMode {
		w.Header().Set("X-Accel-Buffering", "no")
	}
	
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	buf := make([]byte, 16384)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-signal:
			// Read all available data from the buffer
			for {
				n, next, skipped := stream.Buffer.ReadAt(offset, buf)
				if n == 0 {
					break
				}
				if skipped {
					atomic.AddInt64(&stream.BytesDropped, next-offset)
				}
				offset = next
				if _, err := w.Write(buf[:n]); err != nil {
					return
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
	allStreams := s.Relay.Snapshot()
	var streams []relay.StreamStats
	for _, st := range allStreams {
		if st.Visible {
			streams = append(streams, st)
		}
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	allStreams := s.Relay.Snapshot()
	var streams []relay.StreamStats
	mountMap := make(map[string]bool)
	for _, st := range allStreams {
		if s.hasAccess(user, st.MountName) {
			streams = append(streams, st)
			mountMap[st.MountName] = true
		}
	}

	// Collect all possible history sources
	for m := range user.Mounts {
		mountMap[m] = true
	}
	if user.Role == config.RoleSuperAdmin {
		for m := range s.Config.Mounts {
			mountMap[m] = true
		}
		for _, rc := range s.Config.Relays {
			mountMap[rc.Mount] = true
		}
	}
	var allMounts []string
	for m := range mountMap {
		allMounts = append(allMounts, m)
	}
	sort.Strings(allMounts)

	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{"Streams": streams, "Config": s.Config, "User": user, "Mounts": allMounts}
	if err := s.tmpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		logrus.WithError(err).Error("Template error")
	}
}

func (s *Server) handleAddMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount, password := r.FormValue("mount"), r.FormValue("password")
	if mount == "" || password == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}
	if mount[0] != '/' {
		mount = "/" + mount
	}
	if !s.hasAccess(user, mount) {
		exists := false
		if _, ok := s.Config.Mounts[mount]; ok {
			exists = true
		}
		if !exists {
			for _, u := range s.Config.Users {
				if _, ok := u.Mounts[mount]; ok {
					exists = true
					break
				}
			}
		}
		if exists {
			http.Error(w, "Mount taken", http.StatusConflict)
			return
		}
	}
	hashed, _ := config.HashPassword(password)
	if user.Role == config.RoleSuperAdmin {
		s.Config.Mounts[mount] = hashed
	} else {
		user.Mounts[mount] = hashed
	}
	s.Config.SaveConfig()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		return
	}
	mount := r.FormValue("mount")
	if !s.hasAccess(user, mount) {
		return
	}
	delete(s.Config.Mounts, mount)
	delete(s.Config.DisabledMounts, mount)
	delete(s.Config.VisibleMounts, mount)
	delete(user.Mounts, mount)
	s.Relay.RemoveStream(mount)
	s.Config.SaveConfig()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleLatency(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if !ok || user.Role != config.RoleSuperAdmin {
		return
	}
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
		if !okAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		allowed := false
		if config.CheckPasswordHash(p, s.Config.DefaultSourcePassword) || config.CheckPasswordHash(p, s.Config.Mounts[mount]) {
			allowed = true
		}
		if !allowed {
			for _, u := range s.Config.Users {
				if config.CheckPasswordHash(p, u.Mounts[mount]) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		if !s.hasAccess(user, mount) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}
	if mount != "" && song != "" {
		if st, ok := s.Relay.GetStream(mount); ok {
			st.SetCurrentSong(song, s.Relay)
		}
	}
	fmt.Fprint(w, "<?xml version=\"1.0\"?>\n<iceresponse><message>OK</message><return>1</return></iceresponse>\n")
}

func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	mount := r.FormValue("mount")
	if ok && s.hasAccess(user, mount) {
		s.Relay.RemoveStream(mount)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleKickAllListeners(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		s.Relay.DisconnectAllListeners()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleMount(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	mount := r.FormValue("mount")
	if ok && s.hasAccess(user, mount) {
		s.Config.DisabledMounts[mount] = !s.Config.DisabledMounts[mount]
		if s.Config.DisabledMounts[mount] {
			s.Relay.RemoveStream(mount)
		}
		s.Config.SaveConfig()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleVisible(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		return
	}
	mount := r.FormValue("mount")
	if ok && s.hasAccess(user, mount) {
		s.Config.VisibleMounts[mount] = !s.Config.VisibleMounts[mount]
		if st, ok := s.Relay.GetStream(mount); ok {
			st.SetVisible(s.Config.VisibleMounts[mount])
		}
		s.Config.SaveConfig()
		logrus.WithFields(logrus.Fields{"mount": mount, "visible": s.Config.VisibleMounts[mount]}).Info("Admin toggled visibility")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		un, pw := r.FormValue("username"), r.FormValue("password")
		if un != "" && pw != "" {
			hp, _ := config.HashPassword(pw)
			s.Config.Users[un] = &config.User{Username: un, Password: hp, Role: config.RoleAdmin, Mounts: make(map[string]string)}
			s.Config.SaveConfig()
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		un := r.FormValue("username")
		if un != user.Username {
			delete(s.Config.Users, un)
			s.Config.SaveConfig()
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddBannedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		ip := r.FormValue("ip")
		if ip != "" {
			s.Config.BannedIPs = append(s.Config.BannedIPs, ip)
			s.Config.SaveConfig()
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveBannedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		ip := r.FormValue("ip")
		for i, b := range s.Config.BannedIPs {
			if b == ip {
				s.Config.BannedIPs = append(s.Config.BannedIPs[:i], s.Config.BannedIPs[i+1:]...)
				s.Config.SaveConfig()
				break
			}
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAddRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		u, m, pw, bs := r.FormValue("url"), r.FormValue("mount"), r.FormValue("password"), r.FormValue("burst_size")
		if u != "" && m != "" {
			if m[0] != '/' {
				m = "/" + m
			}
			burst := 20
			fmt.Sscanf(bs, "%d", &burst)

			found := false
			for _, rc := range s.Config.Relays {
				if rc.Mount == m {
					rc.URL = u
					rc.Password = pw
					rc.BurstSize = burst
					found = true
					break
				}
			}

			if !found {
				rc := &config.RelayConfig{URL: u, Mount: m, Password: pw, BurstSize: burst, Enabled: true}
				s.Config.Relays = append(s.Config.Relays, rc)
			}

			s.Config.SaveConfig()
			s.RelayM.StartRelay(u, m, pw, burst, s.Config.VisibleMounts[m])
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	mount := r.FormValue("mount")
	if ok && user.Role == config.RoleSuperAdmin {
		for _, rc := range s.Config.Relays {
			if rc.Mount == mount {
				rc.Enabled = !rc.Enabled
				if rc.Enabled {
					s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[mount])
				} else {
					s.RelayM.StopRelay(mount)
				}
				s.Config.SaveConfig()
				break
			}
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleDeleteRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	mount := r.FormValue("mount")
	if ok && user.Role == config.RoleSuperAdmin {
		for i, rc := range s.Config.Relays {
			if rc.Mount == mount {
				s.Config.Relays = append(s.Config.Relays[:i], s.Config.Relays[i+1:]...)
				s.Config.SaveConfig()
				s.RelayM.StopRelay(mount)
				break
			}
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRestartRelay(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	mount := r.FormValue("mount")
	if ok && user.Role == config.RoleSuperAdmin {
		for _, rc := range s.Config.Relays {
			if rc.Mount == mount {
				s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[mount])
				break
			}
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	mount := r.URL.Query().Get("mount")
	history := s.Relay.History.Get(mount)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
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
		host = host + ":" + s.Config.Port
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

func (s *Server) handlePublicEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
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
	send := func() {
		allStreams := s.Relay.Snapshot()
		var info []PublicStreamInfo
		for _, st := range allStreams {
			if st.Visible {
				info = append(info, PublicStreamInfo{Mount: st.MountName, Name: st.Name, Listeners: st.ListenersCount, Bitrate: st.Bitrate, Uptime: st.Uptime, Genre: st.Genre, Description: st.Description, CurrentSong: st.CurrentSong})
			}
		}
		payload, _ := json.Marshal(info)
		fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
	}
	send()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			send()
		}
	}
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

func (s *Server) directoryReportingTask() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		streams := s.Relay.Snapshot()
		for _, st := range streams {
			if st.Public {
				s.reportToDirectory(st)
			}
		}
	}
}

func (s *Server) reportToDirectory(st relay.StreamStats) {
	proto := "http://"
	if s.Config.UseHTTPS {
		proto = "https://"
	}
	listenURL := proto + s.Config.HostName + ":" + s.Config.Port + st.MountName
	if s.Config.UseHTTPS {
		listenURL = proto + s.Config.HostName + ":" + s.Config.HTTPSPort + st.MountName
	}
	data := url.Values{}
	data.Set("action", "add")
	data.Set("sn", st.Name)
	data.Set("genre", st.Genre)
	data.Set("cps", st.Bitrate)
	data.Set("url", st.URL)
	data.Set("desc", st.Description)
	data.Set("st", st.ContentType)
	data.Set("listenurl", listenURL)
	data.Set("type", "audio/mpeg")
	resp, err := http.PostForm(s.Config.DirectoryServer, data)
	if err != nil {
		logrus.WithError(err).Warn("Failed to report to directory server")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status", resp.Status).Warn("Directory server rejected update")
	} else {
		logrus.WithField("mount", st.MountName).Debug("Reported to directory server")
	}
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
	type StreamInfo struct {
		Mount        string `json:"mount"`
		Name         string `json:"name"`
		Listeners    int    `json:"listeners"`
		Bitrate      string `json:"bitrate"`
		Uptime       string `json:"uptime"`
		ContentType  string `json:"type"`
		SourceIP     string `json:"ip"`
		BytesIn      int64  `json:"bytes_in"`
		BytesOut     int64  `json:"bytes_out"`
		BytesDropped int64  `json:"bytes_dropped"`
		CurrentSong  string `json:"song"`
	}
	send := func() {
		bi, bo := s.Relay.GetMetrics()
		allStreams := s.Relay.Snapshot()
		tl := 0
		var info []StreamInfo
		tr, ts := 0, 0
		for _, st := range allStreams {
			if s.hasAccess(user, st.MountName) {
				lc := st.ListenersCount
				tl += lc
				info = append(info, StreamInfo{Mount: st.MountName, Name: st.Name, Listeners: lc, Bitrate: st.Bitrate, Uptime: st.Uptime, ContentType: st.ContentType, SourceIP: st.SourceIP, BytesIn: st.BytesIn, BytesOut: st.BytesOut, BytesDropped: st.BytesDropped, CurrentSong: st.CurrentSong})
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
		type RelayInfo struct {
			URL     string `json:"url"`
			Mount   string `json:"mount"`
			Active  bool   `json:"active"`
			Enabled bool   `json:"enabled"`
		}
		relays := make([]RelayInfo, len(s.Config.Relays))
		for i, rc := range s.Config.Relays {
			relays[i] = RelayInfo{URL: rc.URL, Mount: rc.Mount, Active: false, Enabled: rc.Enabled}
			if st, ok := s.Relay.GetStream(rc.Mount); ok && st.SourceIP == "relay-pull" {
				relays[i].Active = true
			}
		}
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				
				payload, _ := json.Marshal(map[string]interface{}{
					"bytes_in":        bi,
					"bytes_out":       bo,
					"total_listeners": tl,
					"total_sources":   len(info),
					"total_relays":    tr,
					"total_streamers": ts,
					"streams":         info,
					"relays":          relays,
					"visible_mounts":  s.Config.VisibleMounts,
					"sys_ram":         m.Sys / 1024 / 1024,
					"goroutines":      runtime.NumGoroutine(),
				})
		
		fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
	}
	send()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			send()
		}
	}
}
