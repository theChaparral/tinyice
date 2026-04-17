package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/DatanoiseTV/tinyice/logger"
)

// requireMountAccess wraps the common auth + mount-parameter + hasAccess
// pattern used by AutoDJ / playlist / queue / files API handlers. On failure
// it writes the appropriate JSON error and returns ok=false; callers should
// just `return` immediately.
//
// The mount is taken from the "mount" query parameter by default, or from
// mountOverride if non-empty (for the path-based routes).
func (s *Server) requireMountAccess(w http.ResponseWriter, r *http.Request, mountOverride string) (mount string, ok bool) {
	user, authed := s.checkAuth(r)
	if !authed {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	mount = mountOverride
	if mount == "" {
		mount = r.URL.Query().Get("mount")
	}
	if mount == "" {
		jsonError(w, "Mount is required", http.StatusBadRequest)
		return "", false
	}
	if !s.hasAccess(user, mount) {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return "", false
	}
	return mount, true
}

// validateOutboundURL rejects URLs that we shouldn't allow users to point
// outbound HTTP clients at — loopback, RFC1918 private ranges, link-local,
// multicast, unspecified addresses. Used to keep webhook + relay URL fields
// from being turned into SSRF vectors.
//
// Hosts given as names are not resolved here (DNS rebinding would defeat
// that anyway); we check only literal IP addresses. Callers that want
// stronger protection should additionally wrap their http.Client with a
// DialContext that blocks internal ranges at connect time.
func validateOutboundURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("scheme %q not allowed (only http/https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	// If the host is a literal IP, refuse private / loopback / link-local / multicast.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("URL points at a non-routable address (%s)", ip)
		}
	}
	// Block localhost by name — a common footgun.
	switch strings.ToLower(host) {
	case "localhost", "localhost.localdomain", "ip6-localhost":
		return fmt.Errorf("URL points at localhost")
	}
	return nil
}

func (s *Server) validatePathInMusicDir(musicDir, targetPath string) (string, error) {
	absMusicDir, err := filepath.Abs(musicDir)
	if err != nil {
		return "", fmt.Errorf("invalid music directory: %w", err)
	}

	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("invalid target path: %w", err)
	}

	rel, err := filepath.Rel(absMusicDir, absTargetPath)

	logger.L.Debugf("PATH_VALIDATION: absMusicDir=[%s] absTargetPath=[%s] rel=[%s]", absMusicDir, absTargetPath, rel)

	if err != nil {
		logger.L.Debugf("validatePathInMusicDir: filepath.Rel error: %v", err)
		return "", fmt.Errorf("path not within music directory: %w", err)
	}

	if strings.HasPrefix(rel, "..") || rel == ".." {
		logger.L.Warnf("PATH_VALIDATION_FAILED: Traversal detected. rel=[%s]", rel)
		return "", fmt.Errorf("security: path traversal attempt detected: %s", targetPath)
	}

	return absTargetPath, nil
}

func (s *Server) safeJoin(base, rel string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	joined := filepath.Join(absBase, rel)

	validatedPath, err := s.validatePathInMusicDir(absBase, joined)
	if err != nil {
		return "", err
	}

	return validatedPath, nil
}
