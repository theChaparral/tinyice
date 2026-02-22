package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/DatanoiseTV/tinyice/logger"
)

func (s *Server) dispatchWebhook(event string, data map[string]interface{}) {
	if len(s.Config.Webhooks) == 0 {
		return
	}

	payload := map[string]interface{}{
		"event":     event,
		"timestamp": time.Now().Format(time.RFC3339),
		"hostname":  s.Config.HostName,
		"data":      data,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.L.Errorf("Failed to marshal webhook payload: %v", err)
		return
	}

	for _, wh := range s.Config.Webhooks {
		if !wh.Enabled {
			continue
		}

		interested := false
		for _, e := range wh.Events {
			if e == event {
				interested = true
				break
			}
		}

		if !interested {
			continue
		}

		go func(url string, body []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "TinyIce-Webhook/1.0")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				logger.L.Warnw("Webhook delivery failed", "url", url, "error", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				logger.L.Warnw("Webhook returned non-2xx status", "url", url, "status", resp.StatusCode)
			}
		}(wh.URL, jsonPayload)
	}
}
