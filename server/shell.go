package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/DatanoiseTV/tinyice/logger"
)

//go:embed frontend/dist
var frontendDistFS embed.FS

// shellTemplateHTML is the single HTML template for all pages.
// Go renders this with the appropriate entry point JS/CSS files from the Vite manifest.
const shellTemplateHTML = `<!DOCTYPE html>
<html lang="en" style="color-scheme:dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — TinyIce</title>
{{range .CSSFiles}}<link rel="stylesheet" href="/static/{{.}}">
{{end}}</head>
<body>
<div id="app"></div>
<script>window.__TINYICE__ = {{.InitialDataJSON}}</script>
{{range .JSFiles}}<script type="module" src="/static/{{.}}"></script>
{{end}}</body>
</html>`

// ShellData is the data passed to the shell template.
type ShellData struct {
	Title           string
	CSSFiles        []string
	JSFiles         []string
	InitialDataJSON template.JS
}

// ShellRenderer serves the new Preact-based frontend.
// It reads the Vite manifest to map entry names to hashed filenames,
// and renders a thin HTML shell that loads the appropriate JS/CSS bundles.
type ShellRenderer struct {
	tmpl     *template.Template
	manifest map[string]manifestEntry
	distFS   fs.FS
}

type manifestEntry struct {
	File    string   `json:"file"`
	CSS     []string `json:"css"`
	IsEntry bool     `json:"isEntry"`
	Src     string   `json:"src"`
}

// NewShellRenderer creates a ShellRenderer from the embedded frontend dist.
func NewShellRenderer() *ShellRenderer {
	tmpl := template.Must(template.New("shell").Parse(shellTemplateHTML))

	distFS, err := fs.Sub(frontendDistFS, "frontend/dist")
	if err != nil {
		logger.L.Fatalf("Failed to access frontend dist: %v", err)
	}

	manifest := make(map[string]manifestEntry)
	manifestData, err := fs.ReadFile(distFS, ".vite/manifest.json")
	if err != nil {
		// During development or if frontend hasn't been built yet
		logger.L.Warnf("No Vite manifest found — frontend not built? %v", err)
	} else {
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			logger.L.Fatalf("Failed to parse Vite manifest: %v", err)
		}
	}

	return &ShellRenderer{tmpl: tmpl, manifest: manifest, distFS: distFS}
}

// Render serves an HTML shell for the given page, injecting initial data as JSON.
// The page name maps to an entry in the Vite manifest (e.g., "landing" → "src/entries/landing.html").
func (sr *ShellRenderer) Render(w http.ResponseWriter, page string, title string, data any) {
	var jsFiles, cssFiles []string

	// Try to find the entry in the Vite manifest
	// Vite uses the HTML file as the entry key
	entryKey := fmt.Sprintf("src/entries/%s.html", page)
	if entry, ok := sr.manifest[entryKey]; ok {
		jsFiles = []string{entry.File}
		cssFiles = entry.CSS
	} else {
		// Try TSX entry directly
		entryKey = fmt.Sprintf("src/entries/%s.tsx", page)
		if entry, ok := sr.manifest[entryKey]; ok {
			jsFiles = []string{entry.File}
			cssFiles = entry.CSS
		}
	}

	// If no manifest entry found, try to find files by convention
	if len(jsFiles) == 0 {
		// Scan for matching files in the assets directory
		entries, _ := fs.ReadDir(sr.distFS, "assets")
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, page) && strings.HasSuffix(name, ".js") {
				jsFiles = append(jsFiles, "assets/"+name)
			}
			if strings.HasPrefix(name, page) && strings.HasSuffix(name, ".css") {
				cssFiles = append(cssFiles, "assets/"+name)
			}
		}
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	shell := ShellData{
		Title:           title,
		CSSFiles:        cssFiles,
		JSFiles:         jsFiles,
		InitialDataJSON: template.JS(jsonBytes),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := sr.tmpl.Execute(w, shell); err != nil {
		logger.L.Errorf("Shell render error: %v", err)
	}
}

// FileServer returns an http.Handler that serves the frontend dist files.
func (sr *ShellRenderer) FileServer() http.Handler {
	return http.FileServer(http.FS(sr.distFS))
}

// BrandingData returns the branding data structure for injection into page data.
func (s *Server) BrandingData() map[string]any {
	logoURL := interface{}(nil)
	if s.Config.LogoPath != "" {
		logoURL = "/branding/logo"
	}
	return map[string]any{
		"logoUrl":         logoURL,
		"accentColor":     s.Config.AccentColor,
		"landingMarkdown": s.Config.LandingMarkdown,
	}
}

// BasePageData returns the common data injected into all pages.
func (s *Server) BasePageData(csrfToken string) map[string]any {
	return map[string]any{
		"csrfToken":    csrfToken,
		"version":      s.Version,
		"pageTitle":    s.Config.PageTitle,
		"pageSubtitle": s.Config.PageSubtitle,
		"branding":     s.BrandingData(),
	}
}
