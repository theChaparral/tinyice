package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
)

type Swapper interface {
	HotSwap() error
}

type Updater struct {
	config   *config.Config
	swapper  Swapper
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

	logger.L.Info("AutoUpdate enabled, checking for updates periodically...")
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
		logger.L.Errorf("Failed to check for updates: %v", err)
		return
	}

	if u.lastHash == "" {
		u.lastHash = newHash
		logger.L.Debugf("Initial checksum recorded: %s", newHash)
		return
	}

	if newHash != u.lastHash {
		logger.L.Infof("New update detected! Checksum changed: %s -> %s", u.lastHash, newHash)
		// Pass the expected sha256 to applyUpdate so the downloaded bytes
		// are verified before they replace the running binary. Previously
		// we blindly renamed whatever showed up at UpdateURL — a
		// man-in-the-middle or a compromised CDN could drop in anything.
		if err := u.applyUpdate(newHash); err != nil {
			logger.L.Errorf("Failed to apply update: %v", err)
		} else {
			u.lastHash = newHash
			logger.L.Info("Update applied successfully, triggering hot swap...")
			if err := u.swapper.HotSwap(); err != nil {
				logger.L.Errorf("Failed to trigger hot swap after update: %v", err)
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

	// Find the hash for our specific binary. We refuse to fall back to
	// "use the whole file as a hash" here: without a specific row for
	// this GOOS/GOARCH we can't verify the downloaded binary later, and
	// applying an unverified update is exactly the bug we're closing.
	targetName := u.getBinaryName()
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// Accept either "<hex>  filename" or "filename  <hex>" layouts,
		// and tolerate GNU coreutils' binary-mode "*" prefix on the
		// filename.
		name := strings.TrimPrefix(parts[1], "*")
		if name == targetName || parts[0] == targetName {
			if parts[0] == targetName {
				return strings.ToLower(parts[1]), nil
			}
			return strings.ToLower(parts[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum row for %s in checksums.txt", targetName)
}

func (u *Updater) applyUpdate(expectedHash string) error {
	url := u.config.UpdateURL
	url = strings.ReplaceAll(url, "{{os}}", runtime.GOOS)
	url = strings.ReplaceAll(url, "{{arch}}", runtime.GOARCH)

	logger.L.Infof("Downloading update from %s...", url)
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

	// Stream the download into a temp file while simultaneously hashing
	// it. Delete the temp file if we bail for any reason — we refuse to
	// overwrite the running binary with unverified bytes.
	tmpFile := exe + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hasher), resp.Body); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}

	gotHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(gotHash, expectedHash) {
		os.Remove(tmpFile)
		return fmt.Errorf("checksum mismatch: expected %s, got %s — refusing to install", expectedHash, gotHash)
	}

	// Verified — atomically replace the binary.
	if err := os.Rename(tmpFile, exe); err != nil {
		os.Remove(tmpFile)
		return err
	}
	logger.L.Infow("Update verified and installed", "sha256", gotHash)
	return nil
}

func (u *Updater) getBinaryName() string {
	return fmt.Sprintf("tinyice-%s-%s", runtime.GOOS, runtime.GOARCH)
}
