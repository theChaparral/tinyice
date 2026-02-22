package server

import (
	"net/http"
	"runtime"
	"time"
)

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.checkAuth(r); !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="TinyIce Metrics"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	bi, bo := s.Relay.GetMetrics()
	allStreams := s.Relay.Snapshot()
	tl := 0
	totalDropped := int64(0)
	for _, st := range allStreams {
		tl += st.ListenersCount
		totalDropped += st.BytesDropped
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	reg := NewPrometheusRegistry()

	// Global metrics
	reg.Add("tinyice_bandwidth_in_bytes_total", "Total bytes received", Counter, nil, bi)
	reg.Add("tinyice_bandwidth_out_bytes_total", "Total bytes sent", Counter, nil, bo)
	reg.Add("tinyice_listeners_total", "Total active listeners", Gauge, nil, tl)
	reg.Add("tinyice_sources_total", "Total active sources", Gauge, nil, len(allStreams))
	reg.Add("tinyice_total_dropped_bytes", "Total bytes dropped across all streams", Counter, nil, totalDropped)

	// System metrics
	reg.Add("tinyice_mem_sys_bytes", "Total bytes of memory obtained from the OS", Gauge, nil, m.Sys)
	reg.Add("tinyice_heap_alloc_bytes", "Bytes of allocated heap objects", Gauge, nil, m.HeapAlloc)
	reg.Add("tinyice_stack_sys_bytes", "Bytes of stack memory obtained from the OS", Gauge, nil, m.StackSys)
	reg.Add("tinyice_num_gc", "Number of completed GC cycles", Counter, nil, m.NumGC)
	reg.Add("tinyice_goroutines", "Number of running goroutines", Gauge, nil, runtime.NumGoroutine())
	reg.Add("tinyice_server_uptime_seconds", "Server uptime in seconds", Gauge, nil, time.Since(s.startTime).Seconds())

	// Per-stream metrics
	for _, st := range allStreams {
		labels := map[string]string{"mount": st.MountName, "name": st.Name}
		reg.Add("tinyice_stream_listeners_current", "Current number of listeners for this stream", Gauge, labels, st.ListenersCount)
		reg.Add("tinyice_stream_bytes_in_total", "Total bytes received for this stream", Counter, labels, st.BytesIn)
		reg.Add("tinyice_stream_bytes_out_total", "Total bytes sent for this stream", Counter, labels, st.BytesOut)
		reg.Add("tinyice_stream_bytes_dropped_total", "Total bytes dropped for this stream", Counter, labels, st.BytesDropped)
		reg.Add("tinyice_stream_health_ratio", "Current health ratio of the stream (0.0 to 1.0)", Gauge, labels, st.Health/100.0)

		val := 0
		if st.IsTranscoded {
			val = 1
		}
		reg.Add("tinyice_stream_is_transcoded", "Whether the stream is being transcoded (1 for yes, 0 for no)", Gauge, labels, val)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(reg.Render()))
}
