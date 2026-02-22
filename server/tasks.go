package server

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
	"github.com/DatanoiseTV/tinyice/relay"
)

func (s *Server) directoryReportingTask() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			streams := s.Relay.Snapshot()
			for _, st := range streams {
				if st.Public {
					s.reportToDirectory(st)
				}
			}
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

func (s *Server) reportToDirectory(st relay.StreamStats) {
	proto := "http://"
	if s.Config.UseHTTPS {
		proto = "https://"
	}
	listenURL := proto + net.JoinHostPort(s.Config.HostName, s.Config.Port) + st.MountName
	if s.Config.UseHTTPS {
		listenURL = proto + net.JoinHostPort(s.Config.HostName, s.Config.HTTPSPort) + st.MountName
	}
	data := url.Values{}
	data.Set("action", "add")
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
		logger.L.Warnw("Failed to report to directory server", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.L.Warnw("Directory server rejected update", "status", resp.Status)
	} else {
		logger.L.Debugw("Reported to directory server", "mount", st.MountName)
	}
}
