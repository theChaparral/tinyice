package server

import (
	"fmt"
	"testing"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
)

func init() {
	logger.Init("error", false, "")
}

func TestIPWhitelistAndBanning(t *testing.T) {
	cfg := &config.Config{
		BannedIPs:      []string{"1.2.3.4", "10.0.0.0/24"},
		WhitelistedIPs: []string{"1.2.3.4", "192.168.1.1"},
	}
	s := &Server{
		Config:       cfg,
		authAttempts: make(map[string]*authAttempt),
		scanAttempts: make(map[string]*scanAttempt),
	}

	// 1.2.3.4 is both banned and whitelisted. Whitelist should win.
	if s.isBanned("1.2.3.4:1234") {
		t.Errorf("1.2.3.4 should NOT be banned as it is whitelisted")
	}

	// 10.0.0.5 is banned (range) and NOT whitelisted.
	if !s.isBanned("10.0.0.5:1234") {
		t.Errorf("10.0.0.5 should be banned")
	}

	// 192.168.1.1 is whitelisted.
	if !s.isWhitelisted("192.168.1.1:1234") {
		t.Errorf("192.168.1.1 should be whitelisted")
	}

	// 127.0.0.1 should be always whitelisted
	if !s.isWhitelisted("127.0.0.1:1234") {
		t.Errorf("127.0.0.1 should be always whitelisted")
	}
	if !s.isWhitelisted("[::1]:1234") {
		t.Errorf("::1 should be always whitelisted")
	}

	// Verify scan attempt lockout behavior: a legit listener hammering a
	// single offline mount path should *never* trigger the ban — only a
	// scanner touching many distinct paths should.
	ip := "8.8.8.8"

	for i := 0; i < 200; i++ {
		s.recordScanAttempt(ip, "/live")
	}
	if s.isBanned(ip) {
		t.Errorf("IP %s should NOT be banned for repeated 404s on the same path", ip)
	}

	// 25 distinct paths is the scanner threshold.
	scanner := "8.8.4.4"
	for i := 0; i < 24; i++ {
		s.recordScanAttempt(scanner, fmt.Sprintf("/probe-%d", i))
	}
	if s.isBanned(scanner) {
		t.Errorf("IP %s should not be banned yet after 24 distinct paths", scanner)
	}
	s.recordScanAttempt(scanner, "/probe-24")
	if !s.isBanned(scanner) {
		t.Errorf("IP %s should be banned after 25 distinct paths", scanner)
	}

	// Verify whitelisted IP is NOT banned even after many attempts
	wip := "192.168.1.1"
	for i := 0; i < 50; i++ {
		s.recordScanAttempt(wip, fmt.Sprintf("/wp-%d", i))
	}
	if s.isBanned(wip) {
		t.Errorf("Whitelisted IP %s should NOT be banned even after many attempts", wip)
	}
}
