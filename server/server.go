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
	tmpl   *template.Template
}

func NewServer(cfg *config.Config) *Server {
	tmpl := template.New("base")
	tmpl, err := tmpl.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		logrus.Fatalf("Error loading embedded templates: %v", err)
	}

	return &Server{
		Config: cfg,
		Relay:  relay.NewRelay(cfg.LowLatencyMode),
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
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handlePublicEvents)
	mux.HandleFunc("/status-json.xsl", s.handleLegacyStats)

	addr := ":" + s.Config.Port
	
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

	httpsAddr := ":" + s.Config.HTTPSPort
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

	logrus.Infof("Starting HTTPS server on %s", httpsAddr)
	if certManager != nil {
		return httpsSrv.ListenAndServeTLS("", "")
	}
	return httpsSrv.ListenAndServeTLS(s.Config.CertFile, s.Config.KeyFile)
}

func (s *Server) checkAuth(r *http.Request, user, pass string) bool {
	u, p, ok := r.BasicAuth()
	if !ok { return false }
	if user != "" && u != user { return false }
	return config.CheckPasswordHash(p, pass)
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

func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	mount := r.URL.Path
	requiredPass := s.Config.DefaultSourcePassword
	if specificPass, ok := s.Config.Mounts[mount]; ok {
		requiredPass = specificPass
	}

	if s.Config.DisabledMounts[mount] {
		logrus.WithField("mount", mount).Warn("Rejected source connection to disabled mount")
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
		logrus.WithField("mount", mount).Error("Webserver doesn't support hijacking")
		http.Error(w, "Webserver doesn't support hijacking", http.StatusInternalServerError)
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
					bitrate = strings.TrimPrefix(strings.TrimSpace(part), "bitrate=")
					break
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
		if n > 0 {
			stream.Broadcast(buf[:n], s.Relay)
		}
		if err != nil {
			if err != io.EOF {
				logrus.WithField("mount", mount).WithError(err).Error("Source read error")
			} else {
				logrus.WithField("mount", mount).Info("Source closed connection (EOF)")
			}
			break
		}
	}
	logrus.WithField("mount", mount).Info("Source disconnected")
	s.Relay.RemoveStream(mount)
}

func (s *Server) handleListener(w http.ResponseWriter, r *http.Request) {
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
		if !st.Hidden {
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
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	streams := s.Relay.Snapshot()
	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{"Streams": streams, "Config": s.Config}
	if err := s.tmpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		logrus.WithError(err).Error("Template error")
	}
}

func (s *Server) handleAddMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount, password := r.FormValue("mount"), r.FormValue("password")
	if mount == "" || password == "" {
		http.Error(w, "Mount and Password required", http.StatusBadRequest)
		return
	}
	if mount[0] != '/' { mount = "/" + mount }
	hashed, _ := config.HashPassword(password)
	s.Config.Mounts[mount] = hashed
	if err := s.Config.SaveConfig(); err != nil {
		logrus.WithError(err).Error("Error saving config")
	}
	logrus.WithField("mount", mount).Info("Admin added/updated mount")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveMount(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
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
		logrus.WithField("mount", mount).Info("Admin removed mount point")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleLatency(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.Config.LowLatencyMode = !s.Config.LowLatencyMode
	s.Relay.LowLatency = s.Config.LowLatencyMode
	s.Config.SaveConfig()
	logrus.WithField("low_latency", s.Config.LowLatencyMode).Info("Admin toggled latency mode")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		_, p, ok := r.BasicAuth()
		mount := r.URL.Query().Get("mount")
		if !ok || (!config.CheckPasswordHash(p, s.Config.DefaultSourcePassword) && !config.CheckPasswordHash(p, s.Config.Mounts[mount])) {
			w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Metadata"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	mount, song := r.URL.Query().Get("mount"), r.URL.Query().Get("song")
	if mount != "" && song != "" {
		if st, ok := s.Relay.GetStream(mount); ok {
			st.SetCurrentSong(song)
			logrus.WithFields(logrus.Fields{"mount": mount, "song": song}).Info("Metadata updated")
		}
	}
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
		logrus.WithField("mount", mount).Info("Admin kicked source")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleKickAllListeners(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.Relay.DisconnectAllListeners()
	logrus.Info("Admin kicked all listeners")
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
		if s.Config.DisabledMounts[mount] { s.Relay.RemoveStream(mount) }
		s.Config.SaveConfig()
		logrus.WithFields(logrus.Fields{"mount": mount, "disabled": s.Config.DisabledMounts[mount]}).Info("Admin toggled mount")
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleToggleHidden(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mount := r.FormValue("mount")
	if mount != "" {
		s.Config.HiddenMounts[mount] = !s.Config.HiddenMounts[mount]
		
		// Update active stream if it exists
		if st, ok := s.Relay.GetStream(mount); ok {
			st.SetHidden(s.Config.HiddenMounts[mount])
		}
		
		s.Config.SaveConfig()
		logrus.WithFields(logrus.Fields{"mount": mount, "hidden": s.Config.HiddenMounts[mount]}).Info("Admin toggled visibility")
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
			sources[i] = IcecastSource{
				AudioInfo:         fmt.Sprintf("bitrate=%s", st.Bitrate),
				Bitrate:           st.Bitrate,
				Genre:             st.Genre,
				Listeners:         st.ListenersCount,
				ListenURL:         proto + host + st.MountName,
				Mount:             st.MountName,
				ServerDescription: st.Description,
				ServerName:        st.Name,
				ServerType:        st.ContentType,
				StreamStart:       st.Started.Format(time.RFC1123),
				Title:             st.CurrentSong,
				Dummy:             nil,
			}
		}
	
	resp := map[string]interface{}{"icestats": map[string]interface{}{"admin": s.Config.AdminEmail, "host": s.Config.HostName, "location": s.Config.Location, "server_id": "Icecast 2.4.4 (TinyIce)", "server_start": time.Now().Format(time.RFC1123), "source": sources}}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePublicEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	type PublicStreamInfo struct {
		Mount string `json:"mount"`; Name string `json:"name"`; Listeners int `json:"listeners"`; 
		Bitrate string `json:"bitrate"`; Uptime string `json:"uptime"`; Genre string `json:"genre"`; 
		Description string `json:"description"`; CurrentSong string `json:"song"`
	}
	for {
		select {
		case <-r.Context().Done(): return
		case <-ticker.C:
			allStreams := s.Relay.Snapshot()
			var info []PublicStreamInfo
			for _, st := range allStreams {
				if st.Hidden {
					continue
				}
				info = append(info, PublicStreamInfo{
					Mount:       st.MountName,
					Name:        st.Name,
					Listeners:   st.ListenersCount,
					Bitrate:     st.Bitrate,
					Uptime:      st.Uptime,
					Genre:       st.Genre,
					Description: st.Description,
					CurrentSong: st.CurrentSong,
				})
			}
			payload, _ := json.Marshal(info)
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {
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
			if st.Public { s.reportToDirectory(st) }
		}
	}
}

func (s *Server) reportToDirectory(st relay.StreamStats) {

	proto := "http://"

	if s.Config.UseHTTPS { proto = "https://" }

	listenURL := proto + s.Config.HostName + ":" + s.Config.Port + st.MountName

	if s.Config.UseHTTPS { listenURL = proto + s.Config.HostName + ":" + s.Config.HTTPSPort + st.MountName }

	data := url.Values{}

	data.Set("action", "add")

	data.Set("sn", st.Name); data.Set("genre", st.Genre); data.Set("cps", st.Bitrate)

	data.Set("url", st.URL); data.Set("desc", st.Description); data.Set("st", st.ContentType)

	data.Set("listenurl", listenURL); data.Set("type", "audio/mpeg")

	resp, err := http.PostForm(s.Config.DirectoryServer, data)

	if err != nil { logrus.WithError(err).Warn("Failed to report to directory server"); return }

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { logrus.WithField("status", resp.Status).Warn("Directory server rejected update")

	} else { logrus.WithField("mount", st.MountName).Debug("Reported to directory server") }

}



func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {

	if !s.checkAuth(r, s.Config.AdminUser, s.Config.AdminPassword) {

		http.Error(w, "Unauthorized", http.StatusUnauthorized)

		return

	}

	w.Header().Set("Content-Type", "text/event-stream")

	w.Header().Set("Cache-Control", "no-cache")

	w.Header().Set("Connection", "keep-alive")

	flusher, _ := w.(http.Flusher)

	ticker := time.NewTicker(time.Second)

	defer ticker.Stop()



	type StreamInfo struct {

		Mount string `json:"mount"`; Name string `json:"name"`; Listeners int `json:"listeners"`; Bitrate string `json:"bitrate"`; 

		Uptime string `json:"uptime"`; ContentType string `json:"type"`; SourceIP string `json:"ip"`; 

		BytesIn int64 `json:"bytes_in"`; BytesOut int64 `json:"bytes_out"`; CurrentSong string `json:"song"`

	}



	for {

		select {

		case <-r.Context().Done(): return

		case <-ticker.C:

			bi, bo := s.Relay.GetMetrics()

			streams := s.Relay.Snapshot()

			tl := 0

			info := make([]StreamInfo, len(streams))

			for i, st := range streams {

				lc := st.ListenersCount; tl += lc

				info[i] = StreamInfo{

					Mount: st.MountName, 

					Name: st.Name, 

					Listeners: lc, 

					Bitrate: st.Bitrate, 

					Uptime: st.Uptime, 

					ContentType: st.ContentType, 

					SourceIP: st.SourceIP, 

					BytesIn: st.BytesIn, 

					BytesOut: st.BytesOut, 

					CurrentSong: st.CurrentSong,

				}

			}

			payload, _ := json.Marshal(map[string]interface{}{"bytes_in": bi, "bytes_out": bo, "total_listeners": tl, "total_sources": len(streams), "streams": info})

			fmt.Fprintf(w, "data: %s\n\n", payload)

			flusher.Flush()

		}

	}

}


