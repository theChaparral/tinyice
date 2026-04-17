package server

import (
	"net"
	"net/http"
	"net/url"
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
	advertised := make(map[string]relay.StreamStats)
	for {
		select {
		case <-s.done:
			for mount, st := range advertised {
				s.reportToDirectoryAction(st, "remove")
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
				if _, had := advertised[mount]; had {
					s.reportToDirectoryAction(st, "touch")
				} else {
					s.reportToDirectoryAction(st, "add")
				}
			}
			for mount, st := range advertised {
				if _, still := next[mount]; !still {
					s.reportToDirectoryAction(st, "remove")
				}
			}
			advertised = next
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
func (s *Server) reportToDirectoryAction(st relay.StreamStats, action string) {
	proto := "http://"
	if s.Config.UseHTTPS {
		proto = "https://"
	}
	listenURL := proto + net.JoinHostPort(s.Config.HostName, s.Config.Port) + st.MountName
	if s.Config.UseHTTPS {
		listenURL = proto + net.JoinHostPort(s.Config.HostName, s.Config.HTTPSPort) + st.MountName
	}
	data := url.Values{}
	data.Set("action", action)
	data.Set("sn", st.Name)
	data.Set("genre", st.Genre)
	data.Set("cps", st.Bitrate)
	data.Set("url", st.URL)
	data.Set("desc", st.Description)
	data.Set("st", st.ContentType)
	data.Set("listenurl", listenURL)
	data.Set("type", "audio/mpeg")
	resp, err := http.PostForm(s.Config.DirectoryServer, data)
	if err != nil {
		logger.L.Warnw("Failed to report to directory server", "error", err, "action", action)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.L.Warnw("Directory server rejected update", "status", resp.Status, "action", action)
	} else {
		logger.L.Debugw("Reported to directory server", "mount", st.MountName, "action", action)
	}
}
