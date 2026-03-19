package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
	"go.uber.org/zap"
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

func (s *Server) logAuth() *zap.SugaredLogger {
	if s.AuthLog != nil {
		return s.AuthLog
	}
	return logger.L
}

func (s *Server) logAuthFailed(user, ip, reason string) {
	host, _, _ := net.SplitHostPort(ip)
	s.logAuth().Warnw(fmt.Sprintf("Authentication failed for user '%s' from %s: %s", user, host, reason),
		"user", user,
		"ip", host,
		"reason", reason,
	)
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

	if s.isWhitelisted(ip) {
		return nil
	}
	return nil
}

func (s *Server) recordAuthFailure(ip string) {
	if s.isWhitelisted(ip) {
		return
	}
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
		logger.L.Warnf("IP %s locked out for 15 minutes due to 5 failed auth attempts", ip)
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
	if s.isWhitelisted(ip) {
		return
	}
	s.scanAttemptsMu.Lock()
	defer s.scanAttemptsMu.Unlock()

	attempt, exists := s.scanAttempts[ip]
	if !exists {
		attempt = &scanAttempt{Paths: make(map[string]bool)}
		s.scanAttempts[ip] = attempt
	}

	attempt.Paths[path] = true
	attempt.Count++

	if attempt.Count >= 10 {
		attempt.LockoutBy = time.Now().Add(15 * time.Minute)
		logger.L.Warnf("IP %s locked out for 15 minutes due to 10 scanning attempts (404s)", ip)
		s.dispatchWebhook("security_lockout", map[string]interface{}{
			"ip":      ip,
			"reason":  "connection_scanning",
			"until":   attempt.LockoutBy.Format(time.RFC3339),
			"details": "10 connection scanning attempts (404s)",
		})
	}
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ti_" + hex.EncodeToString(b), nil
}

func (s *Server) touchToken(tok *config.APIToken, remoteAddr string) {
	tok.LastUsedAt = time.Now().Format(time.RFC3339)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		tok.LastUsedIP = host
	}
	s.tokenSaveMu.Lock()
	if s.tokenSaveTimer == nil {
		s.tokenSaveTimer = time.AfterFunc(60*time.Second, func() {
			s.Config.SaveConfig()
			s.tokenSaveMu.Lock()
			s.tokenSaveTimer = nil
			s.tokenSaveMu.Unlock()
		})
	}
	s.tokenSaveMu.Unlock()
}

func (s *Server) checkAuth(r *http.Request) (*config.User, bool) {
	// Bearer token auth
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		raw := strings.TrimPrefix(auth, "Bearer ")
		hash := hashToken(raw)
		for _, tok := range s.Config.APITokens {
			if tok.TokenHash == hash {
				// Check expiry
				if tok.ExpiresAt != "" {
					if exp, err := time.Parse(time.RFC3339, tok.ExpiresAt); err == nil && time.Now().After(exp) {
						return nil, false
					}
				}
				user, exists := s.Config.Users[tok.Username]
				if !exists {
					return nil, false
				}
				// Update last-used tracking (debounced save)
				s.touchToken(tok, r.RemoteAddr)
				return user, true
			}
		}
		return nil, false
	}

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
	s.logAuth().Infow("Admin auth successful (Basic)", "user", u, "ip", host)
	return user, true
}

func (s *Server) hasAccess(user *config.User, mount string) bool {
	if user.Role == config.RoleSuperAdmin {
		return true
	}
	_, exists := user.Mounts[mount]
	return exists
}

func (s *Server) isWhitelisted(ipStr string) bool {
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		host = ipStr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	for _, whitelisted := range s.Config.WhitelistedIPs {
		if strings.Contains(whitelisted, "/") {
			_, ipnet, err := net.ParseCIDR(whitelisted)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		}
		if whitelisted == host {
			return true
		}
	}
	return false
}

func (s *Server) isCSRFSafe(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}

	// JSON API endpoints are inherently CSRF-safe: the Content-Type: application/json
	// header cannot be sent cross-origin without a CORS preflight, and we don't set
	// permissive CORS headers. Session auth still applies via checkAuth.
	if strings.HasPrefix(r.URL.Path, "/api/") &&
		strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}

	// Also allow multipart uploads to /api/ (e.g. logo upload)
	if strings.HasPrefix(r.URL.Path, "/api/") &&
		strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		return true
	}

	cookie, err := r.Cookie("sid")
	if err != nil {
		return true
	}

	s.sessionsMu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.sessionsMu.RUnlock()

	if !ok {
		return true
	}

	providedToken := r.FormValue("csrf")
	if providedToken == "" {
		providedToken = r.Header.Get("X-CSRF-Token")
	}
	if providedToken != sess.CSRFToken {
		logger.L.Warnf("CSRF Mismatch: provided=[%s] expected=[%s] remote=%s path=%s", providedToken, sess.CSRFToken, r.RemoteAddr, r.URL.Path)
		return false
	}

	return true
}

func (s *Server) isBanned(ipStr string) bool {
	if s.isWhitelisted(ipStr) {
		return false
	}
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

// createSession generates a new session for the given user and sets the sid cookie.
// Returns the CSRF token for the new session.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request, user *config.User) string {
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

	return csrf
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)

	if r.Method == http.MethodPost {
		u := r.FormValue("username")
		p := r.FormValue("password")

		if err := s.checkAuthLimit(host); err != nil {
			if r.Header.Get("Accept") == "application/json" {
				jsonError(w, err.Error(), http.StatusUnauthorized)
				return
			}
			pageData := s.BasePageData("")
			pageData["error"] = err.Error()
			s.shell.Render(w, "login", "Login — "+s.Config.PageTitle, pageData)
			return
		}

		user, exists := s.Config.Users[u]
		if !exists || !config.CheckPasswordHash(p, user.Password) {
			s.recordAuthFailure(host)
			s.logAuthFailed(u, r.RemoteAddr, "invalid credentials")
			if r.Header.Get("Accept") == "application/json" {
				jsonError(w, "Invalid username or password", http.StatusUnauthorized)
				return
			}
			pageData := s.BasePageData("")
			pageData["error"] = "Invalid username or password"
			s.shell.Render(w, "login", "Login — "+s.Config.PageTitle, pageData)
			return
		}

		s.recordAuthSuccess(host)
		s.createSession(w, r, user)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	pageData := s.BasePageData("")
	s.shell.Render(w, "login", "Login — "+s.Config.PageTitle, pageData)
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
