package server

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

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
	
	logrus.Debugf("PATH_VALIDATION: absMusicDir=[%s] absTargetPath=[%s] rel=[%s]", absMusicDir, absTargetPath, rel)

	if err != nil {
		logrus.Debugf("validatePathInMusicDir: filepath.Rel error: %v", err)
		return "", fmt.Errorf("path not within music directory: %w", err)
	}

	if strings.HasPrefix(rel, "..") || rel == ".." {
		logrus.Warnf("PATH_VALIDATION_FAILED: Traversal detected. rel=[%s]", rel)
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
