package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

// directoryReportingTask keeps the configured YP-style directory server in
// sync with the set of currently-public mounts. Each tick it sends:
//   - "add"    for mounts that just went public / are newly present,
//   - "touch"  for mounts already advertised (required as a heartbeat so
//              the directory doesn't age them out),
//   - "remove" for mounts that were advertised last tick but have gone
//              away (source disconnected or went non-public).
// The previous implementation only sent "add", so directory listings went
// stale and dead entries lingered forever.
func (s *Server) directoryReportingTask() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	type advertEntry struct {
		st  relay.StreamStats
		sid string
	}
	advertised := make(map[string]advertEntry)
	for {
		select {
		case <-s.done:
			for mount, e := range advertised {
				s.reportToDirectoryAction(e.st, "remove", e.sid)
				delete(advertised, mount)
			}
			return
		case <-ticker.C:
			next := make(map[string]relay.StreamStats)
			for _, st := range s.Relay.Snapshot() {
				if st.Public {
					next[st.MountName] = st
				}
			}
			for mount, st := range next {
				if e, had := advertised[mount]; had {
					s.reportToDirectoryAction(st, "touch", e.sid)
					advertised[mount] = advertEntry{st, e.sid}
				} else {
					sid := s.reportToDirectoryAction(st, "add", "")
					if sid != "" {
						advertised[mount] = advertEntry{st, sid}
					}
				}
			}
			for mount, e := range advertised {
				if _, still := next[mount]; !still {
					s.reportToDirectoryAction(e.st, "remove", e.sid)
					delete(advertised, mount)
				}
			}
		}
	}
}

// sessionReaperTask sweeps expired / idle sessions out of memory on a
// schedule. Without this, checkAuth still rejects an expired session, but
// the map grows unboundedly across a long-lived process.
func (s *Server) sessionReaperTask() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.reapSessions()
		}
	}
}

func (s *Server) statsRecordingTask() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.Relay.History == nil {
				continue
			}
			streams := s.Relay.Snapshot()
			for _, st := range streams {
				s.Relay.History.RecordStats(st.MountName, st.ListenersCount, st.BytesIn, st.BytesOut)
			}
		}
	}
}

// reportToDirectoryAction sends a single YP request. action is "add",
// "touch" or "remove". The legacy reportToDirectory wrapper always used
// "add", which isn't a lifecycle.
// reportToDirectoryAction registers / refreshes / removes one stream
// with the configured Icecast YP directory. Returns the SID assigned by
// the directory on a successful "add" so the caller can include it in
// subsequent "touch"/"remove" calls (the YP protocol requires it).
// 201 Created is a normal success response; only non-2xx is "rejected".
func (s *Server) reportToDirectoryAction(st relay.StreamStats, action, sid string) string {
	proto := "http://"
	if s.Config.UseHTTPS {
		proto = "https://"
	}
	listenURL := proto + net.JoinHostPort(s.Config.HostName, s.Config.Port) + st.MountName
	if s.Config.UseHTTPS {
		listenURL = proto + net.JoinHostPort(s.Config.HostName, s.Config.HTTPSPort) + st.MountName
	}
	mime := st.ContentType
	if mime == "" {
		mime = "audio/mpeg"
	}
	data := url.Values{}
	data.Set("action", action)
	if sid != "" {
		data.Set("sid", sid)
	}
	data.Set("sn", st.Name)
	data.Set("genre", normaliseYPGenre(st.Genre))
	data.Set("cps", st.Bitrate)
	data.Set("url", st.URL)
	data.Set("desc", st.Description)
	data.Set("listenurl", listenURL)
	data.Set("type", mime)
	data.Set("stype", "Icecast2")
	// Current-song title: lets the public directory show "On Air:" /
	// "Now playing:" without the operator having to use the admin
	// metadata API. Updated on every touch.
	if st.CurrentSong != "" {
		data.Set("title", st.CurrentSong)
	}

	resp, err := http.PostForm(s.Config.DirectoryServer, data)
	if err != nil {
		logger.L.Warnw("Failed to report to directory server", "error", err, "action", action, "mount", st.MountName)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		newSID := resp.Header.Get("SID")
		logger.L.Infow("Reported to directory server",
			"mount", st.MountName, "action", action, "status", resp.Status, "sid", newSID)
		if action == "add" && newSID != "" {
			return newSID
		}
		return sid
	}
	logger.L.Warnw("Directory server rejected update",
		"status", resp.Status, "action", action, "mount", st.MountName)
	return ""
}

// normaliseYPGenre prepares an Icecast YP `genre` field for dir.xiph.org.
// The directory tokenises this field on whitespace, so a multi-word
// genre like "drum and bass" would otherwise show up as three separate
// tags. Convention: comma-separated entries are kept as distinct tags,
// and inside each entry internal whitespace is hyphenated.
//
//	"drum and bass"           -> "drum-and-bass"
//	"techno, house"           -> "techno house"
//	"techno, drum and bass"   -> "techno drum-and-bass"
func normaliseYPGenre(g string) string {
	g = strings.TrimSpace(g)
	if g == "" {
		return ""
	}
	parts := strings.Split(g, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Collapse runs of whitespace into a single hyphen.
		p = strings.Join(strings.Fields(p), "-")
		out = append(out, p)
	}
	return strings.Join(out, " ")
}
