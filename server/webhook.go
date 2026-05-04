package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/DatanoiseTV/tinyice/config"
	"github.com/DatanoiseTV/tinyice/logger"
)

// WebhookEvents is the canonical list of event names the server emits.
// Kept in one place so the API can advertise it to the admin UI and
// dispatchWebhook can validate / log against the same set.
var WebhookEvents = []string{
	"source_connect",
	"source_disconnect",
	"metadata_update",
	"now_playing",
	"security_lockout",
}

// SampleEventData returns a representative payload for each event,
// used to power the admin "Test" button and the placeholder reference
// shown in the editor. The values here must match what the runtime
// dispatchers actually pass for that event — keep them in sync.
func SampleEventData(event string) map[string]interface{} {
	switch event {
	case "now_playing":
		return map[string]interface{}{
			"mount":  "/live",
			"name":   "My Station",
			"artist": "Aphex Twin",
			"title":  "Xtal",
			"album":  "Selected Ambient Works 85-92",
			"file":   "/music/aphex-twin/saw1/01-xtal.flac",
		}
	case "source_connect":
		return map[string]interface{}{
			"mount": "/live",
			"ip":    "203.0.113.42:51234",
			"ua":    "BUTT/0.1.40",
			"name":  "BUTT",
		}
	case "source_disconnect":
		return map[string]interface{}{
			"mount":   "/live",
			"ip":      "203.0.113.42:51234",
			"reason":  "client closed connection",
			"seconds": 1834,
		}
	case "metadata_update":
		return map[string]interface{}{
			"mount":  "/live",
			"title":  "Aphex Twin - Xtal",
			"artist": "Aphex Twin",
			"song":   "Xtal",
		}
	case "security_lockout":
		return map[string]interface{}{
			"ip":       "198.51.100.7",
			"reason":   "too many failed login attempts",
			"duration": "15m",
		}
	default:
		return map[string]interface{}{}
	}
}

// webhookFuncs are the helpers exposed inside body templates. We keep the
// surface intentionally small — anything that could exfiltrate config or
// touch the filesystem stays out. `urlquery` is built into text/template;
// we add `json` for embedding raw payloads, and `lower`/`upper` because
// receivers like Discord/Slack often want lowercased event tags.
var webhookFuncs = template.FuncMap{
	"json": func(v interface{}) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil
	},
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"urlencode": url.QueryEscape,
}

// renderWebhookBody runs a user-supplied template against a context that
// merges the event metadata (Event, Timestamp, Hostname) with the
// per-event payload promoted to top-level fields. So a now_playing
// template can reference {{.Artist}} directly while still having
// {{.Event}} and {{.Hostname}} available for routing/labelling.
//
// The map keys are exposed both lower-cased (as written by the dispatcher)
// and TitleCased so users can write whichever feels natural — Go's
// text/template field lookup is case-sensitive, so {{.artist}} would
// otherwise fail for callers used to JSON conventions.
func renderWebhookBody(tmpl string, event, hostname string, data map[string]interface{}) (string, error) {
	t, err := template.New("webhook").Funcs(webhookFuncs).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	ctx := map[string]interface{}{
		"Event":     event,
		"Timestamp": time.Now().UTC().Format(time.RFC3339),
		"Hostname":  hostname,
	}
	for k, v := range data {
		ctx[k] = v
		if len(k) > 0 {
			ctx[strings.ToUpper(k[:1])+k[1:]] = v
		}
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ctx); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}

// defaultEnvelope is the legacy JSON body shape used when a webhook has
// no custom BodyTemplate set. Kept identical to the pre-templating
// version so existing receivers don't break after upgrade.
func defaultEnvelope(event, hostname string, data map[string]interface{}) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"hostname":  hostname,
		"data":      data,
	})
}

func (s *Server) dispatchWebhook(event string, data map[string]interface{}) {
	if len(s.Config.Webhooks) == 0 {
		return
	}
	for _, wh := range s.Config.Webhooks {
		if !wh.Enabled {
			continue
		}
		if !webhookSubscribedTo(wh, event) {
			continue
		}
		go s.deliverWebhook(wh, event, data)
	}
}

func webhookSubscribedTo(wh *config.WebhookConfig, event string) bool {
	for _, e := range wh.Events {
		if e == event {
			return true
		}
	}
	return false
}

// deliverWebhook performs a single outbound HTTP request for one webhook
// and one event. Blocking — call from a goroutine. Logs failures but
// never retries; webhooks here are best-effort notifications, not a
// durable queue. Operators who need at-least-once should put a queue
// (e.g. Pipedream, n8n, a small relay) between tinyice and the receiver.
func (s *Server) deliverWebhook(wh *config.WebhookConfig, event string, data map[string]interface{}) {
	// Re-validate the URL on every send. The config writer also validates
	// on write, but a config edited by hand could bypass that, and we
	// don't want such an entry to become an SSRF vector at runtime.
	if err := validateOutboundURL(wh.URL); err != nil {
		logger.L.Warnw("Webhook rejected (URL validation)", "id", wh.ID, "url", wh.URL, "error", err)
		return
	}

	method := strings.ToUpper(strings.TrimSpace(wh.Method))
	if method == "" {
		method = http.MethodPost
	}
	contentType := wh.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	var body []byte
	if strings.TrimSpace(wh.BodyTemplate) == "" {
		b, err := defaultEnvelope(event, s.Config.HostName, data)
		if err != nil {
			logger.L.Errorw("Webhook envelope marshal failed", "id", wh.ID, "error", err)
			return
		}
		body = b
	} else {
		rendered, err := renderWebhookBody(wh.BodyTemplate, event, s.Config.HostName, data)
		if err != nil {
			logger.L.Warnw("Webhook template render failed", "id", wh.ID, "event", event, "error", err)
			return
		}
		body = []byte(rendered)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// For GET / HEAD we don't send a body; instead, if the user wrote a
	// template (typically a query-string fragment for an endpoint like
	// TuneIn AIR's Playing.ashx), append it to the URL. This lets a
	// single template form work for both POST receivers and GET-style
	// "ping" endpoints without forcing the user to bake variables into
	// the URL field.
	targetURL := wh.URL
	var reqBody *bytes.Buffer
	if method == http.MethodGet || method == http.MethodHead {
		reqBody = bytes.NewBuffer(nil)
		if rendered := strings.TrimSpace(string(body)); rendered != "" && wh.BodyTemplate != "" {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			targetURL = targetURL + sep + rendered
		}
	} else {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)
	if err != nil {
		logger.L.Warnw("Webhook request build failed", "id", wh.ID, "error", err)
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "TinyIce-Webhook/2.0")
	req.Header.Set("X-TinyIce-Event", event)
	req.Header.Set("X-TinyIce-Webhook-ID", wh.ID)
	// Custom headers also run through the template engine so users can put
	// dynamic data (like ntfy's Title:) in headers without baking it into
	// the URL or body. Render failures are logged but don't drop the
	// request — we send the raw value so a typo'd header still ships.
	for k, v := range wh.Headers {
		if k == "" {
			continue
		}
		out := v
		if strings.Contains(v, "{{") {
			if rendered, err := renderWebhookBody(v, event, s.Config.HostName, data); err == nil {
				out = rendered
			} else {
				logger.L.Warnw("Webhook header template render failed", "id", wh.ID, "header", k, "error", err)
			}
		}
		req.Header.Set(k, out)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.L.Warnw("Webhook delivery failed", "id", wh.ID, "url", wh.URL, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.L.Warnw("Webhook returned non-2xx status",
			"id", wh.ID, "url", wh.URL, "status", resp.StatusCode)
	}
}
