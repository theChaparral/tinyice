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

	// Lazily register an HLS output on first request. This keeps us from
	// segmenting mounts nobody ever asks for, and lets ingest paths
	// (RTMP, SRT, Icecast SOURCE) just broadcast bytes without caring
	// about HLS. If the mount has a sibling /video sub-mount, the
	// registered output automatically runs in A/V mode.
	hls := s.getHLSOutput(mount)
	if hls == nil {
		hls = s.RegisterHLS(mount)
	}
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
		hls = s.RegisterHLS(mount)
	}
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

// RegisterHLS creates and starts an HLS output for a stream mount. If a
// sibling "/video" sub-mount exists for this mount (created by the RTMP or
// SRT ingest when an H.264 track is present), the output is started with
// both tracks and the resulting segments interleave audio + video.
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

	tracks := []*relay.Track{relay.NewAudioTrack(stream, codec)}
	if vs, ok := s.Relay.GetStream(mount + "/video"); ok {
		tracks = append(tracks, relay.NewTrackFromStream(relay.MediaVideo, "h264", vs))
	}
	hls.Start(s.hlsCtx, tracks)

	s.hlsMu.Lock()
	s.hlsOutputs[mount] = hls
	s.hlsMu.Unlock()

	logger.L.Infow("HLS: Registered output", "mount", mount, "has_video", len(tracks) > 1)
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
