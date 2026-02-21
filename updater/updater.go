package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/sirupsen/logrus"
)

type Swapper interface {
	HotSwap() error
}

type Updater struct {
	config  *config.Config
	swapper Swapper
	lastHash string
}

func NewUpdater(cfg *config.Config, s Swapper) *Updater {
	return &Updater{
		config:  cfg,
		swapper: s,
	}
}

func (u *Updater) Start(ctx context.Context) {
	if !u.config.AutoUpdate {
		return
	}

	logrus.Info("AutoUpdate enabled, checking for updates periodically...")
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Check immediately on start
	u.CheckAndApply()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.CheckAndApply()
		}
	}
}

func (u *Updater) CheckAndApply() {
	newHash, err := u.getLatestChecksum()
	if err != nil {
		logrus.WithError(err).Error("Failed to check for updates")
		return
	}

	if u.lastHash == "" {
		u.lastHash = newHash
		logrus.Debugf("Initial checksum recorded: %s", newHash)
		return
	}

	if newHash != u.lastHash {
		logrus.Infof("New update detected! Checksum changed: %s -> %s", u.lastHash, newHash)
		if err := u.applyUpdate(); err != nil {
			logrus.WithError(err).Error("Failed to apply update")
		} else {
			u.lastHash = newHash
			logrus.Info("Update applied successfully, triggering hot swap...")
			if err := u.swapper.HotSwap(); err != nil {
				logrus.WithError(err).Error("Failed to trigger hot swap after update")
			}
		}
	}
}

func (u *Updater) getLatestChecksum() (string, error) {
	resp, err := http.Get(u.config.ChecksumURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch checksums: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Find the hash for our specific binary
	targetName := u.getBinaryName()
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, targetName) {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				return parts[0], nil
			}
		}
	}

	// If not found in checksums.txt, just use the whole file content as hash
	// (GitHub's checksums.txt format varies)
	return string(body), nil
}

func (u *Updater) applyUpdate() error {
	url := u.config.UpdateURL
	url = strings.ReplaceAll(url, "{{os}}", runtime.GOOS)
	url = strings.ReplaceAll(url, "{{arch}}", runtime.GOARCH)

	logrus.Infof("Downloading update from %s...", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download update: %s", resp.Status)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Use a temporary file to download
	tmpFile := exe + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	f.Close()

	// Atomically replace binary
	if err := os.Rename(tmpFile, exe); err != nil {
		// On windows rename might fail if file is locked, but on unix it works
		return err
	}

	return nil
}

func (u *Updater) getBinaryName() string {
	return fmt.Sprintf("tinyice-%s-%s", runtime.GOOS, runtime.GOARCH)
}
