package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

func (s *Server) handleHLSPlaylist(w http.ResponseWriter, r *http.Request) {
	// Path: /{mount}/playlist.m3u8 — extract mount
	path := r.URL.Path
	mount := strings.TrimSuffix(path, "/playlist.m3u8")
	if mount == "" {
		http.NotFound(w, r)
		return
	}

	hls := s.getHLSOutput(mount)
	if hls == nil {
		http.NotFound(w, r)
		return
	}

	playlist := hls.Playlist()

	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(playlist))
}

func (s *Server) handleHLSSegment(w http.ResponseWriter, r *http.Request) {
	// Path: /{mount}/segment-{n}.ts — extract mount and sequence
	path := r.URL.Path

	// Find the last path component
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		http.NotFound(w, r)
		return
	}

	mount := path[:lastSlash]
	segPart := path[lastSlash+1:] // "segment-N.ts"

	if !strings.HasPrefix(segPart, "segment-") || !strings.HasSuffix(segPart, ".ts") {
		http.NotFound(w, r)
		return
	}

	seqStr := strings.TrimPrefix(segPart, "segment-")
	seqStr = strings.TrimSuffix(seqStr, ".ts")
	seq, err := strconv.Atoi(seqStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	hls := s.getHLSOutput(mount)
	if hls == nil {
		http.NotFound(w, r)
		return
	}

	segment := hls.Ring().Get(seq)
	if segment == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(segment.Data)))
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(segment.Data)
}

// getHLSOutput finds the HLS output for a given mount.
func (s *Server) getHLSOutput(mount string) *relay.HLSOutput {
	s.hlsMu.RLock()
	defer s.hlsMu.RUnlock()
	return s.hlsOutputs[mount]
}

// RegisterHLS creates and starts an HLS output for a stream mount.
func (s *Server) RegisterHLS(mount string) *relay.HLSOutput {
	stream, ok := s.Relay.GetStream(mount)
	if !ok {
		return nil
	}

	config := relay.DefaultHLSConfig()
	hls := relay.NewHLSOutput(mount, config)

	// Determine codec from content type
	codec := "mp3"
	if stream.IsOgg() {
		codec = "opus"
	}

	track := relay.NewAudioTrack(stream, codec)
	hls.Start(s.hlsCtx, []*relay.Track{track})

	s.hlsMu.Lock()
	s.hlsOutputs[mount] = hls
	s.hlsMu.Unlock()

	logger.L.Infow("HLS: Registered output", "mount", mount)
	return hls
}

// UnregisterHLS stops and removes an HLS output.
func (s *Server) UnregisterHLS(mount string) {
	s.hlsMu.Lock()
	if hls, ok := s.hlsOutputs[mount]; ok {
		hls.Stop()
		delete(s.hlsOutputs, mount)
	}
	s.hlsMu.Unlock()
}
