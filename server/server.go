package server

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
)

//go:embed all:templates
var templateFS embed.FS

//go:embed all:assets
var assetFS embed.FS

// Server is the main HTTP server and application coordinator for TinyIce.
//
// The Server handles all HTTP requests, manages WebSocket connections, serves
// the web interface, and coordinates between the various subsystems (relay,
// transcoders, streamers, etc.).
//
// Key responsibilities:
//   - HTTP request routing and handling
//   - Web interface rendering (templates, assets)
//   - WebSocket connections for real-time updates
//   - Source client authentication and authorization
//   - Listener connection management
//   - Admin interface and API endpoints
//
// Lifecycle:
//   - Created with NewServer()
//   - Configured with routes and middleware
//   - Started with Start()
//   - Stopped gracefully with Stop()
//
// Thread Safety:
// The Server is designed to be thread-safe. HTTP handlers are called from
// multiple goroutines concurrently, so all handler methods must be safe
// for concurrent access.
type Server struct {
	Config      *config.Config           // Application configuration
	Relay       *relay.Relay             // Core relay/streaming engine
	RelayM      *relay.RelayManager      // Relay stream management
	TranscoderM *relay.TranscoderManager // Transcoding management
	WebRTCM     *relay.WebRTCManager     // WebRTC connection management
	StreamerM   *relay.StreamerManager   // AutoDJ/streamer management
	mpdServer   *relay.MPDServer         // MPD protocol server (optional)
	tmpl        *template.Template       // HTML template for web interface (legacy)
	shell       *ShellRenderer           // New Preact frontend renderer
	Version     string                   // TinyIce version
	Commit      string                   // Git commit hash
	httpServers []*http.Server           // Active HTTP servers
	startTime   time.Time                // Server start time
	AuthLog     *zap.SugaredLogger

	sessions   map[string]*session
	sessionsMu sync.RWMutex

	authAttempts   map[string]*authAttempt
	authAttemptsMu sync.Mutex

	certManager *autocert.Manager

	scanAttempts   map[string]*scanAttempt
	scanAttemptsMu sync.Mutex

	done chan struct{}
}

func NewServer(cfg *config.Config, authLog *zap.SugaredLogger, version, commit string) *Server {
	tmpl := template.New("base")
	tmpl, err := tmpl.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		logger.L.Fatalf("Error loading embedded templates: %v", err)
	}

	hm, err := relay.NewHistoryManager("history.db")
	if err != nil {
		logger.L.Fatalf("Failed to initialize history manager: %v", err)
	}

	r := relay.NewRelay(cfg.LowLatencyMode, hm)
	return &Server{
		Config:       cfg,
		Relay:        r,
		RelayM:       relay.NewRelayManager(r),
		TranscoderM:  relay.NewTranscoderManager(r),
		WebRTCM:      relay.NewWebRTCManager(r),
		StreamerM:    relay.NewStreamerManager(r, cfg),
		tmpl:         tmpl,
		shell:        NewShellRenderer(),
		Version:      version,
		Commit:       commit,
		startTime:    time.Now(),
		AuthLog:      authLog,
		sessions:     make(map[string]*session),
		authAttempts: make(map[string]*authAttempt),
		scanAttempts: make(map[string]*scanAttempt),
		done:         make(chan struct{}),
	}
}

func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/golive", s.handleGoLive)
	mux.HandleFunc("/admin/golive/chunk", s.handleGoLiveChunk)
	mux.HandleFunc("/admin/add-mount", s.handleAddMount)
	mux.HandleFunc("/admin/toggle-latency", s.handleToggleLatency)
	mux.HandleFunc("/admin/stats", s.handleStats)
	mux.HandleFunc("/admin/events", s.handleEvents)
	mux.HandleFunc("/admin/metadata", s.handleMetadata)
	mux.HandleFunc("/admin/kick", s.handleKick)
	mux.HandleFunc("/admin/remove-mount", s.handleRemoveMount)
	mux.HandleFunc("/admin/hotswap", s.handleHotSwap)
	mux.HandleFunc("/admin/kick-all-listeners", s.handleKickAllListeners)
	mux.HandleFunc("/admin/toggle-mount", s.handleToggleMount)
	mux.HandleFunc("/admin/toggle-visible", s.handleToggleVisible)
	mux.HandleFunc("/admin/update-fallback", s.handleUpdateFallback)
	mux.HandleFunc("/admin/add-user", s.handleAddUser)
	mux.HandleFunc("/admin/remove-user", s.handleRemoveUser)
	mux.HandleFunc("/admin/add-banned-ip", s.handleAddBannedIP)
	mux.HandleFunc("/admin/remove-banned-ip", s.handleRemoveBannedIP)
	mux.HandleFunc("/admin/add-whitelisted-ip", s.handleAddWhitelistedIP)
	mux.HandleFunc("/admin/remove-whitelisted-ip", s.handleRemoveWhitelistedIP)
	mux.HandleFunc("/admin/clear-auth-lockout", s.handleClearAuthLockout)
	mux.HandleFunc("/admin/clear-scan-lockout", s.handleClearScanLockout)
	mux.HandleFunc("/admin/add-webhook", s.handleAddWebhook)
	mux.HandleFunc("/admin/delete-webhook", s.handleDeleteWebhook)
	mux.HandleFunc("/admin/player/toggle", s.handlePlayerToggle)
	mux.HandleFunc("/admin/player/restart", s.handlePlayerRestart)
	mux.HandleFunc("/admin/player/scan", s.handlePlayerScan)
	mux.HandleFunc("/admin/player/clear-playlist", s.handlePlayerClearPlaylist)
	mux.HandleFunc("/admin/player/clear-queue", s.handlePlayerClearQueue)
	mux.HandleFunc("/admin/player/save-playlist", s.handlePlayerSavePlaylist)
	mux.HandleFunc("/admin/player/playlist-info", s.handlePlayerPlaylistInfo)
	mux.HandleFunc("/admin/player/load-playlist", s.handlePlayerLoadPlaylist)
	mux.HandleFunc("/admin/player/reorder", s.handlePlayerReorder)
	mux.HandleFunc("/admin/player/queue", s.handlePlayerQueue)
	mux.HandleFunc("/admin/player/shuffle", s.handlePlayerShuffle)
	mux.HandleFunc("/admin/player/loop", s.handlePlayerLoop)
	mux.HandleFunc("/admin/player/metadata", s.handlePlayerMetadata)
	mux.HandleFunc("/admin/player/next", s.handlePlayerNext)
	mux.HandleFunc("/admin/player/files", s.handlePlayerFiles)
	mux.HandleFunc("/admin/player/playlist-action", s.handlePlayerPlaylistAction)
	mux.HandleFunc("/admin/autodj/add", s.handleAddAutoDJ)
	mux.HandleFunc("/admin/autodj/delete", s.handleDeleteAutoDJ)
	mux.HandleFunc("/admin/autodj/toggle", s.handleToggleAutoDJ)
	mux.HandleFunc("/admin/autodj/studio", s.handleAutoDJStudio)
	mux.HandleFunc("/admin/autodj/update", s.handleUpdateAutoDJ)
	mux.HandleFunc("/admin/add-relay", s.handleAddRelay)
	mux.HandleFunc("/admin/toggle-relay", s.handleToggleRelay)
	mux.HandleFunc("/admin/restart-relay", s.handleRestartRelay)
	mux.HandleFunc("/admin/delete-relay", s.handleDeleteRelay)
	mux.HandleFunc("/admin/add-transcoder", s.handleAddTranscoder)
	mux.HandleFunc("/admin/toggle-transcoder", s.handleToggleTranscoder)
	mux.HandleFunc("/admin/delete-transcoder", s.handleDeleteTranscoder)
	mux.HandleFunc("/admin/transcoder-stats", s.handleTranscoderStats)
	mux.HandleFunc("/admin/security-stats", s.handleGetSecurityStats)
	mux.HandleFunc("/admin/history", s.handleHistory)
	mux.HandleFunc("/admin/statistics", s.handleGetStats)
	mux.HandleFunc("/admin/insights", s.handleInsights)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/explore", s.handleExplore)
	mux.HandleFunc("/webrtc/offer", s.handleWebRTCOffer)
	mux.HandleFunc("/webrtc/source-offer", s.handleWebRTCSourceOffer)
	mux.HandleFunc("/player/", s.handlePlayer)
	mux.HandleFunc("/player-webrtc/", s.handleWebRTCPlayer)
	mux.HandleFunc("/embed/", s.handleEmbed)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handlePublicEvents)
	mux.HandleFunc("/status-json.xsl", s.handleLegacyStats)
	mux.HandleFunc("/metrics", s.handleMetrics)
	// Serve frontend assets (Vite build output) at /assets/ — takes priority
	// Falls back to legacy assets (logo, lucide, sortable) if not found in dist
	mux.Handle("/assets/", http.StripPrefix("/assets/", s.shell.AssetHandler()))

	// Developer portal (new page)
	mux.HandleFunc("/developers", s.handleDevelopers)

	// JSON REST API v2
	mux.HandleFunc("/api/streams", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetStreams(w, r)
		case http.MethodPost:
			s.apiCreateStream(w, r)
		case http.MethodDelete:
			s.apiDeleteStream(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/streams/kick", s.apiKickStream)

	mux.HandleFunc("/api/autodj", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetAutoDJ(w, r)
		case http.MethodPost:
			s.apiCreateAutoDJ(w, r)
		case http.MethodDelete:
			s.apiDeleteAutoDJ(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/autodj/play", s.apiAutoDJPlay)
	mux.HandleFunc("/api/autodj/pause", s.apiAutoDJPause)
	mux.HandleFunc("/api/autodj/next", s.apiAutoDJNext)
	mux.HandleFunc("/api/autodj/shuffle", s.apiAutoDJShuffle)
	mux.HandleFunc("/api/autodj/loop", s.apiAutoDJLoop)

	mux.HandleFunc("/api/autodj/playlist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetPlaylist(w, r)
		case http.MethodPost:
			s.apiAddToPlaylist(w, r)
		case http.MethodDelete:
			s.apiRemoveFromPlaylist(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/autodj/playlist/clear", s.apiClearPlaylist)
	mux.HandleFunc("/api/autodj/playlist/reorder", s.apiReorderPlaylist)

	mux.HandleFunc("/api/autodj/queue", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetQueue(w, r)
		case http.MethodPost:
			s.apiAddToQueue(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/autodj/files", s.apiGetFiles)

	mux.HandleFunc("/api/relays", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetRelays(w, r)
		case http.MethodPost:
			s.apiCreateRelay(w, r)
		case http.MethodDelete:
			s.apiDeleteRelay(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/relays/toggle", s.apiToggleRelay)

	mux.HandleFunc("/api/transcoders", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetTranscoders(w, r)
		case http.MethodPost:
			s.apiCreateTranscoder(w, r)
		case http.MethodDelete:
			s.apiDeleteTranscoder(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetUsers(w, r)
		case http.MethodPost:
			s.apiCreateUser(w, r)
		case http.MethodPut:
			s.apiUpdateUser(w, r)
		case http.MethodDelete:
			s.apiDeleteUser(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/security/bans", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetBans(w, r)
		case http.MethodPost:
			s.apiAddBan(w, r)
		case http.MethodDelete:
			s.apiRemoveBan(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/security/whitelist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetWhitelist(w, r)
		case http.MethodPost:
			s.apiAddWhitelist(w, r)
		case http.MethodDelete:
			s.apiRemoveWhitelist(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/branding", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetBranding(w, r)
		case http.MethodPut:
			s.apiUpdateBranding(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiGetSettings(w, r)
		case http.MethodPut:
			s.apiUpdateSettings(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/stats", s.apiGetStats)

	return mux
}

func (s *Server) Shutdown(ctx context.Context) error {
	logger.L.Info("Server shutting down gracefully...")

	close(s.done)

	s.Relay.DisconnectAllListeners()

	s.RelayM.StopAll()
	s.TranscoderM.StopAll()

	for _, st := range s.StreamerM.GetStreamers() {
		s.StreamerM.StopStreamer(st.OutputMount)
	}

	var wg sync.WaitGroup
	for _, srv := range s.httpServers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(shCtx); err != nil {
				logger.L.Errorf("Error during HTTP server shutdown: %v", err)
			}
		}(srv)
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		logger.L.Info("All servers shut down successfully")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) HotSwap() error {
	logger.L.Info("Initiating zero-downtime hot swap...")

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	process, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
		Dir:   ".",
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return fmt.Errorf("failed to start new process: %v", err)
	}

	logger.L.Infof("New process started with PID %d. Waiting for health check...", process.Pid)

	time.Sleep(5 * time.Second)

	logger.L.Info("Handoff period complete. Shutting down old process...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		s.Shutdown(ctx)
		os.Exit(0)
	}()

	return nil
}

func (s *Server) ReloadConfig(cfg *config.Config) {
	s.Config = cfg
	s.RelayM.StopAll()
	for _, rc := range s.Config.Relays {
		if rc.Enabled {
			s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[rc.Mount])
		}
	}
	s.TranscoderM.StopAll()
	for _, tc := range s.Config.Transcoders {
		if tc.Enabled {
			s.TranscoderM.StartTranscoder(tc)
		}
	}
	logger.L.Info("Configuration reloaded successfully")
}

func (s *Server) Start() error {
	mux := s.setupRoutes()

	if s.Config.DirectoryListing {
		go s.directoryReportingTask()
	}
	go s.statsRecordingTask()

	for _, rc := range s.Config.Relays {
		if rc.Enabled {
			s.RelayM.StartRelay(rc.URL, rc.Mount, rc.Password, rc.BurstSize, s.Config.VisibleMounts[rc.Mount])
		}
	}
	for _, tc := range s.Config.Transcoders {
		if tc.Enabled {
			s.TranscoderM.StartTranscoder(tc)
		}
	}
	for _, adj := range s.Config.AutoDJs {
		absMusicDir, _ := filepath.Abs(adj.MusicDir)
		streamer, err := s.StreamerM.StartStreamer(adj.Name, adj.Mount, absMusicDir, adj.Loop, adj.Format, adj.Bitrate, adj.InjectMetadata, adj.Playlist, adj.MPDEnabled, adj.MPDPort, adj.MPDPassword, adj.Visible, adj.LastPlaylist)
		if err == nil {
			if adj.LastPlaylist != "" {
				streamer.LoadPlaylist(adj.LastPlaylist)
			}
			if adj.Enabled {
				if adj.LastPlaylist != "" {
					streamer.LoadPlaylist(adj.LastPlaylist)
				}
				if adj.InjectMetadata {
					if st, ok := s.Relay.GetStream(adj.Mount); ok {
						st.SetVisible(adj.Visible)
					}
				}
				if len(adj.Playlist) == 0 {
					streamer.ScanMusicDir()
				}
				streamer.Play()
			}
		} else {
			logger.L.Errorf("Failed to initialize AutoDJ %s: %v", adj.Name, err)
		}
	}

	port := s.Config.Port

	if s.Config.UseHTTPS {
		addr := net.JoinHostPort(s.Config.BindHost, port)
		return s.startHTTPS(mux, addr)
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	s.httpServers = append(s.httpServers, srv)

	listeners, err := s.buildListeners(port)
	if err != nil {
		return err
	}

	if len(listeners) == 1 {
		logger.L.Infof("Starting TinyIce on %s (HTTP)", listeners[0].Addr())
		return srv.Serve(listeners[0])
	}

	logger.L.Infof("Starting TinyIce on [::]:%s and 0.0.0.0:%s (HTTP)", port, port)
	combined := newMultiListener(listeners)
	return srv.Serve(combined)
}
