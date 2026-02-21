package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
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
		logrus.WithError(err).Error("Failed to marshal webhook payload")
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
				logrus.Warnf("Webhook delivery failed to %s: %v", url, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				logrus.Warnf("Webhook returned non-2xx status from %s: %d", url, resp.StatusCode)
			}
		}(wh.URL, jsonPayload)
	}
}
