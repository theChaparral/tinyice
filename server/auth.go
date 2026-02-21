package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/sirupsen/logrus"
)

type scanAttempt struct {
	Count     int
	Paths     map[string]bool
	LockoutBy time.Time
}

type authAttempt struct {
	Count     int
	LockoutBy time.Time
}

type session struct {
	User      *config.User
	CSRFToken string
}

func (s *Server) logAuth() *logrus.Entry {
	if s.AuthLog != nil {
		return s.AuthLog.WithField("subsystem", "auth")
	}
	return logrus.WithField("subsystem", "auth")
}

func (s *Server) logAuthFailed(user, ip, reason string) {
	host, _, _ := net.SplitHostPort(ip)
	s.logAuth().WithFields(logrus.Fields{
		"user":   user,
		"ip":     host,
		"reason": reason,
	}).Warnf("Authentication failed for user '%s' from %s: %s", user, host, reason)
}

func (s *Server) checkAuthLimit(ip string) error {
	s.authAttemptsMu.Lock()
	defer s.authAttemptsMu.Unlock()

	attempt, exists := s.authAttempts[ip]
	if !exists {
		return nil
	}

	if time.Now().Before(attempt.LockoutBy) {
		return fmt.Errorf("too many failed attempts. locked out until %s", attempt.LockoutBy.Format("15:04:05"))
	}

	if time.Now().After(attempt.LockoutBy) && attempt.Count >= 5 {
		attempt.Count = 0
	}

	return nil
}

func (s *Server) recordAuthFailure(ip string) {
	s.authAttemptsMu.Lock()
	defer s.authAttemptsMu.Unlock()

	attempt, exists := s.authAttempts[ip]
	if !exists {
		attempt = &authAttempt{}
		s.authAttempts[ip] = attempt
	}

	attempt.Count++
	if attempt.Count >= 5 {
		attempt.LockoutBy = time.Now().Add(15 * time.Minute)
		logrus.Warnf("IP %s locked out for 15 minutes due to 5 failed auth attempts", ip)
		s.dispatchWebhook("security_lockout", map[string]interface{}{
			"ip":      ip,
			"reason":  "brute_force_auth",
			"until":   attempt.LockoutBy.Format(time.RFC3339),
			"details": "5 failed authentication attempts",
		})
	}
}

func (s *Server) recordAuthSuccess(ip string) {
	s.authAttemptsMu.Lock()
	defer s.authAttemptsMu.Unlock()
	delete(s.authAttempts, ip)
}

func (s *Server) recordScanAttempt(ip, path string) {
	s.scanAttemptsMu.Lock()
	defer s.scanAttemptsMu.Unlock()

	attempt, exists := s.scanAttempts[ip]
	if !exists {
		attempt = &scanAttempt{Paths: make(map[string]bool)}
		s.scanAttempts[ip] = attempt
	}

	if !attempt.Paths[path] {
		attempt.Paths[path] = true
		attempt.Count++
	}

	if attempt.Count >= 10 {
		attempt.LockoutBy = time.Now().Add(15 * time.Minute)
		logrus.Warnf("IP %s locked out for 15 minutes due to 10 scanning attempts (404s)", ip)
		s.dispatchWebhook("security_lockout", map[string]interface{}{
			"ip":      ip,
			"reason":  "connection_scanning",
			"until":   attempt.LockoutBy.Format(time.RFC3339),
			"details": "10 connection scanning attempts (404s)",
		})
	}
}

func (s *Server) checkAuth(r *http.Request) (*config.User, bool) {
	if cookie, err := r.Cookie("sid"); err == nil {
		s.sessionsMu.RLock()
		sess, ok := s.sessions[cookie.Value]
		s.sessionsMu.RUnlock()
		if ok {
			return sess.User, true
		}
	}

	u, p, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if err := s.checkAuthLimit(host); err != nil {
		s.logAuthFailed(u, r.RemoteAddr, err.Error())
		return nil, false
	}

	user, exists := s.Config.Users[u]
	if !exists {
		s.recordAuthFailure(host)
		s.logAuthFailed(u, r.RemoteAddr, "user not found")
		return nil, false
	}
	if !config.CheckPasswordHash(p, user.Password) {
		s.recordAuthFailure(host)
		s.logAuthFailed(u, r.RemoteAddr, "invalid password")
		return nil, false
	}

	s.recordAuthSuccess(host)
	s.logAuth().WithFields(logrus.Fields{"user": u, "ip": host}).Info("Admin auth successful (Basic)")
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

	cookie, err := r.Cookie("sid")
	if err != nil {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}

	s.sessionsMu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.sessionsMu.RUnlock()

	if !ok {
		return true
	}

	providedToken := r.FormValue("csrf")
	if providedToken != sess.CSRFToken {
		logrus.Warnf("CSRF Mismatch: provided=[%s] expected=[%s] remote=%s path=%s", providedToken, sess.CSRFToken, r.RemoteAddr, r.URL.Path)
		return false
	}

	return true
}

func (s *Server) isBanned(ipStr string) bool {
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr
	}

	s.authAttemptsMu.Lock()
	if att, ok := s.authAttempts[host]; ok && time.Now().Before(att.LockoutBy) {
		s.authAttemptsMu.Unlock()
		return true
	}
	s.authAttemptsMu.Unlock()

	s.scanAttemptsMu.Lock()
	if att, ok := s.scanAttempts[host]; ok && time.Now().Before(att.LockoutBy) {
		s.scanAttemptsMu.Unlock()
		return true
	}
	s.scanAttemptsMu.Unlock()

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, banned := range s.Config.BannedIPs {
		if strings.Contains(banned, "/") {
			_, ipnet, err := net.ParseCIDR(banned)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		}
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)

	if r.Method == http.MethodPost {
		u := r.FormValue("username")
		p := r.FormValue("password")

		if err := s.checkAuthLimit(host); err != nil {
			data := map[string]interface{}{"Error": err.Error(), "Config": s.Config}
			s.tmpl.ExecuteTemplate(w, "login.html", data)
			return
		}

		user, exists := s.Config.Users[u]
		if !exists || !config.CheckPasswordHash(p, user.Password) {
			s.recordAuthFailure(host)
			s.logAuthFailed(u, r.RemoteAddr, "invalid credentials")
			data := map[string]interface{}{"Error": "Invalid username or password", "Config": s.Config}
			s.tmpl.ExecuteTemplate(w, "login.html", data)
			return
		}

		s.recordAuthSuccess(host)
		b := make([]byte, 32)
		rand.Read(b)
		sid := hex.EncodeToString(b)

		cb := make([]byte, 32)
		rand.Read(cb)
		csrf := hex.EncodeToString(cb)

		s.sessionsMu.Lock()
		s.sessions[sid] = &session{User: user, CSRFToken: csrf}
		s.sessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "sid",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   86400 * 7,
		})

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{"Config": s.Config}
	s.tmpl.ExecuteTemplate(w, "login.html", data)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("sid"); err == nil {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
