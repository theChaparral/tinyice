package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/relay"
	"github.com/sirupsen/logrus"
)

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.checkAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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

	csrf := ""
	if cookie, err := r.Cookie("sid"); err == nil {
		s.sessionsMu.RLock()
		if sess, ok := s.sessions[cookie.Value]; ok {
			csrf = sess.CSRFToken
		}
		s.sessionsMu.RUnlock()
	}

	w.Header().Set("Content-Type", "text/html")
	data := map[string]interface{}{
		"Streams":        streams,
		"Config":         s.Config,
		"User":           user,
		"Mounts":         allMounts,
		"FallbackMounts": s.Config.FallbackMounts,
		"CSRFToken":      csrf,
		"Streamers":      s.StreamerM.GetStreamers(),
		"Version":        s.Version,
		"Commit":         s.Commit,
	}
	if err := s.tmpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		if !strings.Contains(err.Error(), "broken pipe") {
			logrus.WithError(err).Error("Template error")
		}
	}
}

func (s *Server) handleUpdateFallback(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	user, ok := s.checkAuth(r)
	if !ok {
		return
	}
	mount := r.FormValue("mount")
	fallback := r.FormValue("fallback")
	if !s.hasAccess(user, mount) {
		return
	}

	if fallback == "" {
		delete(s.Config.FallbackMounts, mount)
	} else {
		if fallback[0] != '/' {
			fallback = "/" + fallback
		}
		s.Config.FallbackMounts[mount] = fallback
	}
	s.Config.SaveConfig()
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
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

func (s *Server) handleAddWhitelistedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		ip := r.FormValue("ip")
		if ip != "" {
			s.Config.WhitelistedIPs = append(s.Config.WhitelistedIPs, ip)
			s.Config.SaveConfig()
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRemoveWhitelistedIP(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		return
	}
	user, ok := s.checkAuth(r)
	if ok && user.Role == config.RoleSuperAdmin {
		ip := r.FormValue("ip")
		for i, b := range s.Config.WhitelistedIPs {
			if b == ip {
				s.Config.WhitelistedIPs = append(s.Config.WhitelistedIPs[:i], s.Config.WhitelistedIPs[i+1:]...)
				s.Config.SaveConfig()
				break
			}
		}
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleClearAuthLockout(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		return
	}
	ip := r.FormValue("ip")
	s.authAttemptsMu.Lock()
	delete(s.authAttempts, ip)
	s.authAttemptsMu.Unlock()
	http.Redirect(w, r, "/admin#tab-security", http.StatusSeeOther)
}

func (s *Server) handleClearScanLockout(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		return
	}
	ip := r.FormValue("ip")
	s.scanAttemptsMu.Lock()
	delete(s.scanAttempts, ip)
	s.scanAttemptsMu.Unlock()
	http.Redirect(w, r, "/admin#tab-security", http.StatusSeeOther)
}

func (s *Server) handleAddWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		return
	}

	url := r.FormValue("url")
	events := r.Form["events"]

	if url == "" || len(events) == 0 {
		http.Error(w, "URL and at least one event required", http.StatusBadRequest)
		return
	}

	s.Config.Webhooks = append(s.Config.Webhooks, &config.WebhookConfig{
		URL:     url,
		Events:  events,
		Enabled: true,
	})
	s.Config.SaveConfig()

	http.Redirect(w, r, "/admin#tab-webhooks", http.StatusSeeOther)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		return
	}

	url := r.FormValue("url")
	newWHs := []*config.WebhookConfig{}
	for _, wh := range s.Config.Webhooks {
		if wh.URL != url {
			newWHs = append(newWHs, wh)
		}
	}
	s.Config.Webhooks = newWHs
	s.Config.SaveConfig()

	http.Redirect(w, r, "/admin#tab-webhooks", http.StatusSeeOther)
}

func (s *Server) handleGetSecurityStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	type ipStat struct {
		IP        string `json:"ip"`
		Count     int    `json:"count"`
		Locked    bool   `json:"locked"`
		ExpiresIn string `json:"expires_in"`
	}

	authStats := []ipStat{}
	s.authAttemptsMu.Lock()
	for ip, att := range s.authAttempts {
		expires := "0s"
		locked := time.Now().Before(att.LockoutBy)
		if locked {
			expires = time.Until(att.LockoutBy).Round(time.Second).String()
		}
		authStats = append(authStats, ipStat{ip, att.Count, locked, expires})
	}
	s.authAttemptsMu.Unlock()

	scanStats := []ipStat{}
	s.scanAttemptsMu.Lock()
	for ip, att := range s.scanAttempts {
		expires := "0s"
		locked := time.Now().Before(att.LockoutBy)
		if locked {
			expires = time.Until(att.LockoutBy).Round(time.Second).String()
		}
		scanStats = append(scanStats, ipStat{ip, att.Count, locked, expires})
	}
	s.scanAttemptsMu.Unlock()

	sort.Slice(authStats, func(i, j int) bool { return authStats[i].Count > authStats[j].Count })
	sort.Slice(scanStats, func(i, j int) bool { return scanStats[i].Count > scanStats[j].Count })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_fails": authStats,
		"scanners":   scanStats,
	})
}

func (s *Server) handleHotSwap(w http.ResponseWriter, r *http.Request) {
	if !s.isCSRFSafe(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if _, ok := s.checkAuth(r); !ok {
		return
	}

	if err := s.HotSwap(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
