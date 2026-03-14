# TinyIce v2 Product Redesign — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework TinyIce's entire web UI/UX into a world-class, TE-inspired product with Preact+Tailwind frontend, JSON REST API, developer portal, and premium design system — while preserving single-binary deployment.

**Architecture:** Go server serves thin HTML shells that load Preact bundles compiled by Vite. Public pages get individual entry points for minimal bundle size. Admin is a single SPA with client-side routing. All admin actions become JSON REST endpoints. Existing form-POST endpoints preserved for backward compatibility.

**Tech Stack:** Go (backend), Preact + @preact/signals (UI), Tailwind CSS v4 (styling), Vite (build), TypeScript (language), uPlot (charts), Canvas 2D + Web Audio API (visualizer), highlight.js (syntax highlighting)

**Spec:** `docs/superpowers/specs/2026-03-14-tinyice-v2-product-redesign.md`

---

## Chunk 1: Foundation — Frontend Build Pipeline

### Task 1: Initialize Vite + Preact project

**Files:**
- Create: `server/frontend/package.json`
- Create: `server/frontend/vite.config.ts`
- Create: `server/frontend/tsconfig.json`
- Create: `server/frontend/.gitignore`

- [ ] **Step 1: Create `server/frontend/` directory and `package.json`**

```bash
cd /Users/dev/dev/tinyice
mkdir -p server/frontend
```

```json
// server/frontend/package.json
{
  "name": "tinyice-frontend",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview"
  }
}
```

- [ ] **Step 2: Install dependencies**

```bash
cd server/frontend
npm install preact @preact/signals
npm install -D vite @preactjs/preset-vite typescript @tailwindcss/vite tailwindcss
```

- [ ] **Step 3: Create `vite.config.ts`**

Multi-page entry points: one per public page, one SPA for admin.

```typescript
// server/frontend/vite.config.ts
import { defineConfig } from 'vite'
import preact from '@preactjs/preset-vite'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'

export default defineConfig({
  plugins: [preact(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        landing: resolve(__dirname, 'src/entries/landing.html'),
        player: resolve(__dirname, 'src/entries/player.html'),
        explore: resolve(__dirname, 'src/entries/explore.html'),
        embed: resolve(__dirname, 'src/entries/embed.html'),
        developers: resolve(__dirname, 'src/entries/developers.html'),
        login: resolve(__dirname, 'src/entries/login.html'),
        admin: resolve(__dirname, 'src/entries/admin.html'),
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/admin/events': 'http://localhost:8000',
      '/events': 'http://localhost:8000',
      '/webrtc': 'http://localhost:8000',
    },
  },
})
```

- [ ] **Step 4: Create `tsconfig.json`**

```json
// server/frontend/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "jsxImportSource": "preact",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src"]
}
```

- [ ] **Step 5: Create `.gitignore`**

```
node_modules/
dist/
```

- [ ] **Step 6: Verify Vite starts without errors**

```bash
cd server/frontend && npx vite --version
```

Expected: Vite version number printed without error.

- [ ] **Step 7: Commit**

```bash
git add server/frontend/package.json server/frontend/vite.config.ts server/frontend/tsconfig.json server/frontend/.gitignore server/frontend/package-lock.json
git commit -m "feat: initialize Vite + Preact + Tailwind frontend project"
```

---

### Task 2: Design System — Tailwind config and global CSS

**Files:**
- Create: `server/frontend/src/globals.css`
- Create: `server/frontend/src/types.ts`

- [ ] **Step 1: Create `globals.css` with Tailwind directives and design tokens**

```css
/* server/frontend/src/globals.css */
@import "tailwindcss";

@theme {
  /* Surface system */
  --color-surface-base: oklch(0.10 0 0);
  --color-surface-raised: oklch(0.15 0 0);
  --color-surface-overlay: oklch(0.20 0 0);
  --color-surface-hover: oklch(0.14 0 0);

  /* Text hierarchy */
  --color-text-primary: rgba(255, 255, 255, 0.87);
  --color-text-secondary: rgba(255, 255, 255, 0.60);
  --color-text-tertiary: rgba(255, 255, 255, 0.38);

  /* Accent — overridable via branding */
  --color-accent: var(--accent-override, #ff6600);
  --color-accent-subtle: color-mix(in oklch, var(--accent-override, #ff6600) 8%, transparent);
  --color-accent-glow: color-mix(in oklch, var(--accent-override, #ff6600) 15%, transparent);

  /* Semantic */
  --color-live: #22c55e;
  --color-danger: #ef4444;
  --color-info: #3b82f6;

  /* Borders */
  --color-border: rgba(255, 255, 255, 0.06);
  --color-border-hover: rgba(255, 255, 255, 0.12);
  --color-border-accent: color-mix(in oklch, var(--accent-override, #ff6600) 20%, transparent);

  /* Typography */
  --font-heading: 'Space Grotesk', system-ui, sans-serif;
  --font-mono: 'Space Mono', monospace;
  --font-code: 'JetBrains Mono', monospace;
  --font-body: 'Space Grotesk', system-ui, sans-serif;

  /* Motion */
  --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);

  /* Radii */
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-lg: 10px;
  --radius-xl: 12px;
  --radius-full: 9999px;
}

/* Base styles */
html {
  color-scheme: dark;
}

body {
  background: var(--color-surface-base);
  color: var(--color-text-secondary);
  font-family: var(--font-body);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* Grain overlay */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 9999;
  opacity: 0.03;
  mix-blend-mode: overlay;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
}

/* Scrollbar styling */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.12); }

/* Focus rings */
:focus-visible {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

/* Reduced motion */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

- [ ] **Step 2: Create shared TypeScript types**

```typescript
// server/frontend/src/types.ts

// Data injected by Go server into window.__TINYICE__
export interface TinyIceBase {
  csrfToken: string
  version: string
  pageTitle: string
  pageSubtitle: string
  branding: {
    logoUrl: string | null
    accentColor: string
    landingMarkdown: string
  }
}

export interface PlayerData extends TinyIceBase {
  mount: string
  title: string
  artist: string
  format: 'mp3' | 'opus'
  bitrate: number
  listeners: number
  hasWebRTC: boolean
}

export interface AdminData extends TinyIceBase {
  user: { username: string; role: 'superadmin' | 'admin' }
  mounts: string[]
}

export interface LandingData extends TinyIceBase {
  streams: StreamInfo[]
}

export interface StreamInfo {
  mount: string
  title: string
  artist: string
  format: string
  bitrate: number
  listeners: number
  live: boolean
}

// SSE Events
export interface StatsEvent {
  listeners: number
  streams: number
  bandwidth: number
  uptime: number
  goroutines: number
  memory: number
  gc: number
}

export interface StreamEvent {
  mount: string
  title: string
  artist: string
  format: string
  bitrate: number
  listeners: number
  health: number
}

export interface AutoDJEvent {
  mount: string
  state: 'playing' | 'paused' | 'stopped'
  currentTrack: { title: string; artist: string; file: string }
  position: number
  duration: number
  queue: string[]
}

// API types
export interface PlaylistItem {
  id: string
  file: string
  title: string
  artist: string
  duration: number
}

export interface FileInfo {
  name: string
  path: string
  isDir: boolean
  title?: string
  artist?: string
  duration?: number
  bitrate?: number
}

declare global {
  interface Window {
    __TINYICE__: TinyIceBase | PlayerData | AdminData | LandingData
  }
}
```

- [ ] **Step 3: Commit**

```bash
git add server/frontend/src/globals.css server/frontend/src/types.ts
git commit -m "feat: add design system tokens and shared TypeScript types"
```

---

### Task 3: HTML entry points and first render

**Files:**
- Create: `server/frontend/src/entries/landing.html`
- Create: `server/frontend/src/entries/admin.html`
- Create: `server/frontend/src/entries/player.html`
- Create: `server/frontend/src/entries/explore.html`
- Create: `server/frontend/src/entries/embed.html`
- Create: `server/frontend/src/entries/developers.html`
- Create: `server/frontend/src/entries/login.html`
- Create: `server/frontend/src/entries/landing.tsx`
- Create: `server/frontend/src/entries/admin.tsx`

- [ ] **Step 1: Create HTML entry points**

Each entry point is a minimal HTML shell. In production, Go replaces these by serving `shell.html` with the appropriate entry JS. During dev, Vite serves these directly.

```html
<!-- server/frontend/src/entries/landing.html -->
<!DOCTYPE html>
<html lang="en" style="color-scheme:dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TinyIce</title>
</head>
<body>
  <div id="app"></div>
  <script>
    window.__TINYICE__ = {
      csrfToken: 'dev',
      version: 'dev',
      pageTitle: 'TinyIce',
      pageSubtitle: 'Live Streaming Server',
      branding: { logoUrl: null, accentColor: '#ff6600', landingMarkdown: '' },
      streams: []
    }
  </script>
  <script type="module" src="./landing.tsx"></script>
</body>
</html>
```

Create identical HTML files for: `admin.html`, `player.html`, `explore.html`, `embed.html`, `developers.html`, `login.html` — each pointing to its own `.tsx` entry.

- [ ] **Step 2: Create landing entry TSX**

```tsx
// server/frontend/src/entries/landing.tsx
import { render } from 'preact'
import '../globals.css'

function App() {
  const data = window.__TINYICE__
  return (
    <div class="min-h-screen">
      <div class="max-w-5xl mx-auto px-8 py-20">
        <p class="font-mono text-xs tracking-[3px] text-accent mb-4">
          AUDIO STREAMING SERVER
        </p>
        <h1 class="text-5xl font-bold text-text-primary tracking-tight leading-none">
          {data.pageTitle}
        </h1>
        <p class="text-text-tertiary mt-4">{data.pageSubtitle}</p>
      </div>
    </div>
  )
}

render(<App />, document.getElementById('app')!)
```

- [ ] **Step 3: Create admin entry TSX (placeholder)**

```tsx
// server/frontend/src/entries/admin.tsx
import { render } from 'preact'
import '../globals.css'

function App() {
  return (
    <div class="min-h-screen flex items-center justify-center">
      <p class="font-mono text-xs tracking-widest text-text-tertiary">
        ADMIN CONSOLE — LOADING
      </p>
    </div>
  )
}

render(<App />, document.getElementById('app')!)
```

- [ ] **Step 4: Run Vite dev server and verify landing page renders**

```bash
cd server/frontend && npm run dev
```

Open `http://localhost:5173/src/entries/landing.html` in browser. Expected: dark background, orange "AUDIO STREAMING SERVER" label, "TinyIce" heading, subtitle text.

- [ ] **Step 5: Run `npm run build` and verify dist output**

```bash
cd server/frontend && npm run build && ls -la dist/
```

Expected: `dist/` directory with hashed JS/CSS files and HTML files.

- [ ] **Step 6: Commit**

```bash
git add server/frontend/src/entries/
git commit -m "feat: add HTML entry points and first Preact render"
```

---

### Task 4: Go server shell rendering

**Files:**
- Create: `server/frontend/dist/.gitkeep`
- Create: `server/shell.go`
- Modify: `server/server.go:23-27` (embed directives)
- Modify: `server/server.go:82-112` (NewServer)
- Modify: `server/server.go:114-187` (setupRoutes)

- [ ] **Step 1: Create `server/shell.go` — shell rendering logic**

This file handles the new rendering approach: serving a thin HTML shell that loads Preact bundles.

```go
// server/shell.go
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

// shellTemplate is the single HTML template for all pages
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

type ShellData struct {
	Title           string
	CSSFiles        []string
	JSFiles         []string
	InitialDataJSON template.JS
}

type ShellRenderer struct {
	tmpl     *template.Template
	manifest map[string]ManifestEntry
	distFS   fs.FS
}

type ManifestEntry struct {
	File string   `json:"file"`
	CSS  []string `json:"css"`
}

func NewShellRenderer() *ShellRenderer {
	tmpl := template.Must(template.New("shell").Parse(shellTemplateHTML))

	distFS, err := fs.Sub(frontendDistFS, "frontend/dist")
	if err != nil {
		logger.L.Fatalf("Failed to access frontend dist: %v", err)
	}

	// Parse Vite manifest to map entry names to hashed filenames
	manifest := make(map[string]ManifestEntry)
	manifestData, err := fs.ReadFile(distFS, ".vite/manifest.json")
	if err != nil {
		// During development, manifest may not exist yet
		logger.L.Warnf("No Vite manifest found — frontend not built? %v", err)
	} else {
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			logger.L.Fatalf("Failed to parse Vite manifest: %v", err)
		}
	}

	return &ShellRenderer{tmpl: tmpl, manifest: manifest, distFS: distFS}
}

func (sr *ShellRenderer) Render(w http.ResponseWriter, page string, title string, data any) {
	entry, ok := sr.manifest[fmt.Sprintf("src/entries/%s.tsx", page)]
	if !ok {
		// Fallback: try .html entry
		entry, ok = sr.manifest[fmt.Sprintf("src/entries/%s.html", page)]
	}

	var jsFiles, cssFiles []string
	if ok {
		jsFiles = []string{entry.File}
		cssFiles = entry.CSS
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Internal Server Error", 500)
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

// FileServer returns an http.Handler that serves the frontend dist files
func (sr *ShellRenderer) FileServer() http.Handler {
	return http.FileServer(http.FS(sr.distFS))
}
```

- [ ] **Step 2: Add `ShellRenderer` to Server struct**

In `server/server.go`, add `shell *ShellRenderer` field to Server struct and initialize it in NewServer:

```go
// Add to Server struct (after tmpl field, around line 61):
shell *ShellRenderer

// Add to NewServer (after tmpl initialization, around line 102):
shell: NewShellRenderer(),
```

- [ ] **Step 3: Add new routes alongside existing ones**

In `server/server.go` `setupRoutes()`, add the new `/static/` file server and `/api/` routes. Keep ALL existing routes for backward compatibility:

```go
// Add after the existing /assets/ handler (around line 187):

// New frontend static assets (Vite output)
mux.Handle("/static/", http.StripPrefix("/static/", sr.shell.FileServer()))

// New JSON API endpoints (add incrementally in later tasks)
mux.HandleFunc("/api/streams", s.handleAPIStreams)
mux.HandleFunc("/api/stats", s.handleAPIStats)

// Developers page (new)
mux.HandleFunc("/developers", s.handleDevelopers)
```

- [ ] **Step 4: Create a placeholder `handleDevelopers` handler**

In `server/handlers_public.go`, add:

```go
func (s *Server) handleDevelopers(w http.ResponseWriter, r *http.Request) {
	s.shell.Render(w, "developers", "Developers", map[string]any{
		"csrfToken":    "",
		"version":      s.Version,
		"pageTitle":    s.Config.PageTitle,
		"pageSubtitle": s.Config.PageSubtitle,
		"branding": map[string]any{
			"logoUrl":         nil,
			"accentColor":     "#ff6600",
			"landingMarkdown": "",
		},
	})
}
```

- [ ] **Step 5: Ensure dist/ directory exists with `.gitkeep` for initial builds**

```bash
mkdir -p server/frontend/dist && touch server/frontend/dist/.gitkeep
```

- [ ] **Step 6: Build frontend and verify Go still compiles**

```bash
cd server/frontend && npm run build
cd /Users/dev/dev/tinyice && go build -o /dev/null .
```

Expected: both commands succeed without errors.

- [ ] **Step 7: Commit**

```bash
git add server/shell.go server/frontend/dist/.gitkeep
git add -p server/server.go server/handlers_public.go
git commit -m "feat: add shell renderer for Preact frontend integration"
```

---

### Task 5: Branding config additions

**Files:**
- Modify: `config/config.go`

- [ ] **Step 1: Add branding fields to Config struct**

In `config/config.go`, add to the Config struct (after `PageSubtitle`):

```go
// Branding
AccentColor     string `json:"accent_color"`
LogoPath        string `json:"logo_path"`
LandingMarkdown string `json:"landing_markdown"`
```

- [ ] **Step 2: Add defaults in `setBasicDefaults()`**

```go
if config.AccentColor == "" {
    config.AccentColor = "#ff6600"
}
```

- [ ] **Step 3: Verify Go compiles**

```bash
go build -o /dev/null .
```

- [ ] **Step 4: Commit**

```bash
git add config/config.go
git commit -m "feat: add branding config fields (accent color, logo, landing markdown)"
```

---

## Chunk 2: Core Components

### Task 6: Shared lib — SSE client and API wrapper

**Files:**
- Create: `server/frontend/src/lib/sse.ts`
- Create: `server/frontend/src/lib/api.ts`

- [ ] **Step 1: Create typed SSE client**

```typescript
// server/frontend/src/lib/sse.ts
import type { StatsEvent, StreamEvent, AutoDJEvent } from '../types'

type SSEEventMap = {
  stats: StatsEvent
  stream: StreamEvent
  autodj: AutoDJEvent
  streams: Array<{ mount: string; title: string; artist: string; format: string; bitrate: number; listeners: number; live: boolean }>
  metadata: { mount: string; title: string; artist: string }
}

type SSECallback<K extends keyof SSEEventMap> = (data: SSEEventMap[K]) => void

export function createSSE(url: string) {
  let source: EventSource | null = null
  const listeners = new Map<string, Set<Function>>()
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectDelay = 1000

  function connect() {
    source = new EventSource(url)

    source.onopen = () => {
      reconnectDelay = 1000
    }

    source.onerror = () => {
      source?.close()
      reconnectTimer = setTimeout(connect, reconnectDelay)
      reconnectDelay = Math.min(reconnectDelay * 2, 30000)
    }

    // Legacy: untyped data events (current TinyIce format)
    source.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        listeners.get('message')?.forEach(cb => cb(data))
      } catch { /* ignore */ }
    }

    // Typed events
    for (const type of listeners.keys()) {
      if (type === 'message') continue
      source.addEventListener(type, (e: Event) => {
        try {
          const data = JSON.parse((e as MessageEvent).data)
          listeners.get(type)?.forEach(cb => cb(data))
        } catch { /* ignore */ }
      })
    }
  }

  function on<K extends keyof SSEEventMap>(event: K, callback: SSECallback<K>): () => void
  function on(event: 'message', callback: (data: any) => void): () => void
  function on(event: string, callback: Function): () => void {
    if (!listeners.has(event)) listeners.set(event, new Set())
    listeners.get(event)!.add(callback)

    // If already connected, add listener to source
    if (source && event !== 'message') {
      source.addEventListener(event, (e: Event) => {
        try {
          const data = JSON.parse((e as MessageEvent).data)
          callback(data)
        } catch { /* ignore */ }
      })
    }

    return () => { listeners.get(event)?.delete(callback) }
  }

  function close() {
    source?.close()
    if (reconnectTimer) clearTimeout(reconnectTimer)
  }

  connect()
  return { on, close }
}
```

- [ ] **Step 2: Create API wrapper**

```typescript
// server/frontend/src/lib/api.ts

const csrf = () => window.__TINYICE__?.csrfToken ?? ''

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    'X-CSRF-Token': csrf(),
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || res.statusText)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
}
```

- [ ] **Step 3: Commit**

```bash
git add server/frontend/src/lib/
git commit -m "feat: add typed SSE client and API wrapper"
```

---

### Task 7: Core UI components — Layout, Sidebar, StreamCard, StatCard

**Files:**
- Create: `server/frontend/src/components/Nav.tsx`
- Create: `server/frontend/src/components/Sidebar.tsx`
- Create: `server/frontend/src/components/StreamCard.tsx`
- Create: `server/frontend/src/components/StatCard.tsx`
- Create: `server/frontend/src/components/EqBars.tsx`
- Create: `server/frontend/src/components/Toggle.tsx`
- Create: `server/frontend/src/components/Skeleton.tsx`

- [ ] **Step 1: Create `Nav.tsx` — public page navigation**

```tsx
// server/frontend/src/components/Nav.tsx
import type { TinyIceBase } from '../types'

export function Nav({ branding }: { branding: TinyIceBase['branding'] }) {
  return (
    <nav class="flex items-center px-8 py-5 border-b border-border">
      <a href="/" class="flex items-center gap-3">
        {branding.logoUrl ? (
          <img src={branding.logoUrl} alt="" class="w-7 h-7 rounded-md" />
        ) : (
          <div class="w-7 h-7 bg-accent rounded-md flex items-center justify-center shadow-[0_0_16px_var(--color-accent-glow)]">
            <span class="font-mono font-bold text-xs text-surface-base">Ti</span>
          </div>
        )}
        <span class="font-mono font-bold text-sm tracking-[2px] text-text-primary">TINYICE</span>
      </a>
      <div class="ml-auto flex gap-7 font-mono text-xs tracking-[1px]">
        <a href="/explore" class="text-text-tertiary hover:text-text-secondary transition-colors">EXPLORE</a>
        <a href="/developers" class="text-text-tertiary hover:text-text-secondary transition-colors">DEVELOPERS</a>
        <a href="/admin" class="text-accent">ADMIN</a>
      </div>
    </nav>
  )
}
```

- [ ] **Step 2: Create `EqBars.tsx` — animated equalizer indicator**

```tsx
// server/frontend/src/components/EqBars.tsx
export function EqBars({ bars = 5, color = 'bg-accent' }: { bars?: number; color?: string }) {
  return (
    <div class="flex gap-[2px] h-4 items-end">
      {Array.from({ length: bars }, (_, i) => (
        <div
          key={i}
          class={`w-[3px] rounded-sm ${color} origin-bottom`}
          style={{
            animation: `eq-bar 0.5s ease-in-out ${i * 0.08}s infinite`,
            height: '100%',
          }}
        />
      ))}
    </div>
  )
}
```

Add the `eq-bar` keyframe to `globals.css`:

```css
@keyframes eq-bar {
  0%, 100% { transform: scaleY(0.3); }
  50% { transform: scaleY(1); }
}

@keyframes pulse-glow {
  0%, 100% { opacity: 1; box-shadow: 0 0 4px var(--color-live); }
  50% { opacity: 0.5; box-shadow: 0 0 8px color-mix(in oklch, var(--color-live) 50%, transparent); }
}
```

- [ ] **Step 3: Create `StreamCard.tsx`**

```tsx
// server/frontend/src/components/StreamCard.tsx
import type { StreamInfo } from '../types'
import { EqBars } from './EqBars'

export function StreamCard({ stream, onPlay }: { stream: StreamInfo; onPlay?: () => void }) {
  return (
    <div
      class="bg-[rgba(255,255,255,0.015)] border border-border rounded-xl p-[18px] cursor-pointer transition-all duration-150 hover:border-border-accent hover:shadow-[0_0_20px_var(--color-accent-glow)] relative overflow-hidden"
      onClick={onPlay}
    >
      {stream.live && (
        <div class="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-accent/30 to-transparent" />
      )}
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <span class="font-mono font-bold text-sm text-text-primary">{stream.mount}</span>
          <span class="font-mono text-[9px] tracking-[0.5px] text-text-tertiary">
            {stream.format.toUpperCase()} {stream.bitrate}K
          </span>
        </div>
        <button class="w-8 h-8 bg-accent rounded-full flex items-center justify-center shadow-[0_0_12px_var(--color-accent-glow)] shrink-0">
          <svg width="10" height="10" viewBox="0 0 12 12" fill="var(--color-surface-base)">
            <polygon points="3.5,1 10.5,6 3.5,11" />
          </svg>
        </button>
      </div>
      <div class="text-text-primary text-sm">{stream.title || 'No title'}</div>
      <div class="text-text-tertiary text-xs mt-0.5">{stream.artist || 'Unknown artist'}</div>
      <div class="flex items-center gap-2.5 mt-3.5 pt-3.5 border-t border-border">
        {stream.live && <EqBars />}
        <span class="font-mono text-[10px] text-text-tertiary tracking-[0.5px] ml-auto">
          {stream.listeners.toLocaleString()} LISTENING
        </span>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Create `StatCard.tsx`**

```tsx
// server/frontend/src/components/StatCard.tsx
export function StatCard({
  label,
  value,
  subtitle,
  gauge,
}: {
  label: string
  value: string
  subtitle?: string
  gauge?: number // 0-100
}) {
  return (
    <div class="bg-[rgba(255,255,255,0.02)] border border-border rounded-lg p-[18px] relative overflow-hidden">
      {gauge !== undefined && (
        <div class="absolute top-0 inset-x-0 h-0.5">
          <div
            class="h-full bg-accent transition-[width] duration-500"
            style={{ width: `${Math.min(gauge, 100)}%` }}
          />
        </div>
      )}
      <div class="font-mono text-[10px] tracking-[1px] text-text-tertiary mb-2.5">{label}</div>
      <div class="font-mono text-[28px] font-bold text-text-primary tracking-tight leading-none">{value}</div>
      {subtitle && <div class="font-mono text-[10px] text-text-tertiary mt-1">{subtitle}</div>}
    </div>
  )
}
```

- [ ] **Step 5: Create `Toggle.tsx` and `Skeleton.tsx`**

```tsx
// server/frontend/src/components/Toggle.tsx
export function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      class={`w-8 h-[18px] rounded-full relative cursor-pointer transition-colors ${on ? 'bg-accent' : 'bg-[rgba(255,255,255,0.08)]'}`}
      onClick={() => onChange(!on)}
    >
      <div
        class={`w-3.5 h-3.5 rounded-full absolute top-0.5 transition-all ${on ? 'right-0.5 bg-surface-base' : 'left-0.5 bg-text-tertiary'}`}
      />
    </button>
  )
}
```

```tsx
// server/frontend/src/components/Skeleton.tsx
export function Skeleton({ class: cls = '', ...props }: { class?: string; [k: string]: any }) {
  return (
    <div
      class={`bg-surface-raised rounded-md animate-pulse ${cls}`}
      {...props}
    />
  )
}
```

- [ ] **Step 6: Verify components compile**

```bash
cd server/frontend && npx tsc --noEmit
```

Expected: no TypeScript errors.

- [ ] **Step 7: Commit**

```bash
git add server/frontend/src/components/ server/frontend/src/globals.css
git commit -m "feat: add core UI components (Nav, StreamCard, StatCard, EqBars, Toggle, Skeleton)"
```

---

### Task 8: Sidebar component for admin

**Files:**
- Create: `server/frontend/src/components/Sidebar.tsx`

- [ ] **Step 1: Create icon-only sidebar with tooltips**

```tsx
// server/frontend/src/components/Sidebar.tsx
import { signal } from '@preact/signals'

const ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid', path: '/admin' },
  { id: 'streams', label: 'Streams', icon: 'radio', path: '/admin/streams' },
  { id: 'autodj', label: 'AutoDJ', icon: 'disc', path: '/admin/autodj' },
  { id: 'golive', label: 'Go Live', icon: 'mic', path: '/admin/golive' },
  { id: 'relays', label: 'Relays', icon: 'link', path: '/admin/relays' },
  { id: 'transcoders', label: 'Transcoders', icon: 'zap', path: '/admin/transcoders' },
  { id: 'studio', label: 'Studio', icon: 'monitor', path: '/admin/studio' },
  { id: 'divider' },
  { id: 'users', label: 'Users', icon: 'users', path: '/admin/users' },
  { id: 'security', label: 'Security', icon: 'shield', path: '/admin/security' },
  { id: 'settings', label: 'Settings', icon: 'settings', path: '/admin/settings' },
] as const

// Simple SVG icon set (inline, no external dependency for sidebar)
const ICONS: Record<string, string> = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  radio: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  disc: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/>',
  mic: '<path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/>',
  link: '<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/>',
  zap: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/>',
  shield: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>',
}

function Icon({ name, active }: { name: string; active?: boolean }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke={active ? 'var(--color-text-primary)' : 'var(--color-text-tertiary)'}
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      dangerouslySetInnerHTML={{ __html: ICONS[name] || '' }}
    />
  )
}

export function Sidebar({ activePath }: { activePath: string }) {
  return (
    <aside class="w-16 border-r border-border flex flex-col items-center py-4 gap-1 bg-[rgba(255,255,255,0.01)] shrink-0">
      {/* Logo */}
      <a href="/admin" class="w-9 h-9 bg-accent rounded-lg flex items-center justify-center mb-3 shadow-[0_0_16px_var(--color-accent-glow)]">
        <span class="font-mono font-bold text-xs text-surface-base">Ti</span>
      </a>

      {ITEMS.map(item => {
        if (item.id === 'divider') {
          return <div class="w-6 h-px bg-border my-2" />
        }
        const active = activePath === item.path
        return (
          <a
            key={item.id}
            href={item.path}
            class={`w-10 h-10 rounded-lg flex items-center justify-center transition-colors group relative ${active ? 'bg-[rgba(255,255,255,0.04)]' : 'hover:bg-[rgba(255,255,255,0.02)]'}`}
            title={item.label}
          >
            <Icon name={item.icon!} active={active} />
            {/* Tooltip */}
            <div class="absolute left-14 bg-surface-overlay text-text-primary text-xs px-2 py-1 rounded-md opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap font-mono tracking-wide z-50">
              {item.label}
            </div>
          </a>
        )
      })}
    </aside>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add server/frontend/src/components/Sidebar.tsx
git commit -m "feat: add admin sidebar component with icon navigation"
```

---

## Chunk 3: Public Pages

### Task 9: Landing page

**Files:**
- Rewrite: `server/frontend/src/entries/landing.tsx`
- Create: `server/frontend/src/pages/Landing.tsx`

- [ ] **Step 1: Create `Landing.tsx` page component**

Full landing page with hero, live streams, dot-grid background, stats strip. Uses `Nav`, `StreamCard`, and `EqBars` components. Connects to SSE `/events` for live stream data updates.

Implementation notes from spec:
- Dot-grid background via CSS `background-image: radial-gradient(...)`
- Ambient orange glow via positioned radial gradient div
- Hero: left column (category label, headline with gradient text, CTAs, stats strip), right column (stream cards)
- Stats strip: 100K+ concurrent, <1ms latency, ~8MB binary
- Footer: "TINYICE // PURE GO" left, version right

- [ ] **Step 2: Update landing entry to render page**

```tsx
// server/frontend/src/entries/landing.tsx
import { render } from 'preact'
import '../globals.css'
import { Landing } from '../pages/Landing'

render(<Landing />, document.getElementById('app')!)
```

- [ ] **Step 3: Verify in browser**

```bash
cd server/frontend && npm run dev
```

Open `http://localhost:5173/src/entries/landing.html`. Expected: full landing page with TE aesthetic.

- [ ] **Step 4: Commit**

```bash
git add server/frontend/src/pages/Landing.tsx server/frontend/src/entries/landing.tsx
git commit -m "feat: implement landing page with TE-inspired design"
```

---

### Task 10: Player page with circular visualizer

**Files:**
- Create: `server/frontend/src/lib/audio.ts`
- Create: `server/frontend/src/lib/visualizer.ts`
- Create: `server/frontend/src/components/Visualizer.tsx`
- Create: `server/frontend/src/components/VolumeKnob.tsx`
- Create: `server/frontend/src/components/ModeToggle.tsx`
- Create: `server/frontend/src/components/TransportControls.tsx`
- Create: `server/frontend/src/pages/Player.tsx`
- Rewrite: `server/frontend/src/entries/player.tsx`

- [ ] **Step 1: Create `audio.ts` — Web Audio helpers**

Sets up AudioContext and AnalyserNode for FFT data. Provides `connectStream(audioElement)` and `getFrequencyData()`.

- [ ] **Step 2: Create `visualizer.ts` — Canvas 2D circular spectrum renderer**

48 radial bars, rotation at 12°/s, frequency-reactive heights, orange color with opacity mapping. Uses `requestAnimationFrame`, skips when `document.hidden`.

- [ ] **Step 3: Create `Visualizer.tsx` component**

Wraps a `<canvas>` element, instantiates the visualizer on mount, cleans up on unmount.

- [ ] **Step 4: Create `VolumeKnob.tsx`**

Rotary knob with gradient sheen and orange indicator line. Responds to mouse drag and scroll wheel.

- [ ] **Step 5: Create `ModeToggle.tsx`**

Segmented control: HTTP / WEBRTC. Space Mono uppercase. Orange background on active segment.

- [ ] **Step 6: Create `TransportControls.tsx`**

Shuffle, Prev, Play (large orange circle), Next, Repeat. Play button has layered box-shadow glow.

- [ ] **Step 7: Create `Player.tsx` page**

Full-viewport centered layout. Uses all components above. Connects to SSE for metadata updates. Supports both HTTP (`<audio>` element) and WebRTC playback modes.

- [ ] **Step 8: Update player entry**

- [ ] **Step 9: Verify in browser**

- [ ] **Step 10: Commit**

```bash
git add server/frontend/src/lib/audio.ts server/frontend/src/lib/visualizer.ts
git add server/frontend/src/components/Visualizer.tsx server/frontend/src/components/VolumeKnob.tsx
git add server/frontend/src/components/ModeToggle.tsx server/frontend/src/components/TransportControls.tsx
git add server/frontend/src/pages/Player.tsx server/frontend/src/entries/player.tsx
git commit -m "feat: implement player page with circular spectrum visualizer"
```

---

### Task 11: Explore, Embed, Login pages

**Files:**
- Create: `server/frontend/src/pages/Explore.tsx`
- Create: `server/frontend/src/pages/Embed.tsx`
- Create: `server/frontend/src/pages/Login.tsx`
- Rewrite: `server/frontend/src/entries/explore.tsx`
- Rewrite: `server/frontend/src/entries/embed.tsx`
- Rewrite: `server/frontend/src/entries/login.tsx`

- [ ] **Step 1: Create `Explore.tsx`** — grid of StreamCards with search/filter

- [ ] **Step 2: Create `Embed.tsx`** — minimal 80px player for iframes

- [ ] **Step 3: Create `Login.tsx`** — centered card, username/password, orange sign-in button

- [ ] **Step 4: Wire up entry points**

- [ ] **Step 5: Commit**

```bash
git add server/frontend/src/pages/Explore.tsx server/frontend/src/pages/Embed.tsx server/frontend/src/pages/Login.tsx
git add server/frontend/src/entries/explore.tsx server/frontend/src/entries/embed.tsx server/frontend/src/entries/login.tsx
git commit -m "feat: implement explore, embed, and login pages"
```

---

## Chunk 4: JSON API Layer (Go Backend)

### Task 12: JSON API handlers — Streams, Stats

**Files:**
- Create: `server/handlers_api_v2.go`
- Modify: `server/server.go` (add routes)

- [ ] **Step 1: Create `handlers_api_v2.go`** with JSON request/response helpers and initial endpoints

Endpoints to implement:
- `GET /api/streams` — list all streams with status
- `GET /api/stats` — full server statistics
- `POST /api/streams` — create mount
- `DELETE /api/streams/:mount` — remove mount
- `POST /api/streams/:mount/kick` — kick source/listeners

Each endpoint reads JSON body, validates, performs action, returns JSON response. CSRF validation via `X-CSRF-Token` header on mutating requests.

- [ ] **Step 2: Register routes in `setupRoutes()`**

- [ ] **Step 3: Verify with curl**

```bash
curl -s http://localhost:8000/api/streams | jq .
curl -s http://localhost:8000/api/stats | jq .
```

- [ ] **Step 4: Commit**

```bash
git add server/handlers_api_v2.go server/server.go
git commit -m "feat: add JSON API endpoints for streams and stats"
```

---

### Task 13: JSON API — AutoDJ, Playlist, Queue, Library

**Files:**
- Modify: `server/handlers_api_v2.go`
- Modify: `server/server.go` (add routes)

- [ ] **Step 1: Implement AutoDJ CRUD endpoints**

- GET/POST/PUT/DELETE `/api/autodj`
- POST `/api/autodj/:mount/play|pause|next|prev`
- PUT `/api/autodj/:mount/shuffle|loop`

- [ ] **Step 2: Implement Playlist endpoints**

- GET/POST/DELETE `/api/autodj/:mount/playlist`
- PUT `/api/autodj/:mount/playlist/reorder`
- POST `/api/autodj/:mount/playlist/clear|save|load`
- GET `/api/autodj/:mount/playlist/saved`

- [ ] **Step 3: Implement Queue endpoints**

- GET/POST/DELETE `/api/autodj/:mount/queue`
- PUT `/api/autodj/:mount/queue/reorder`

- [ ] **Step 4: Implement Library file browser endpoint**

- GET `/api/autodj/:mount/files?path=`

Extend file filter to support `.mp3`, `.ogg`, `.opus`, `.flac`, `.wav`.

- [ ] **Step 5: Commit**

```bash
git add server/handlers_api_v2.go server/server.go
git commit -m "feat: add JSON API endpoints for AutoDJ, playlist, queue, library"
```

---

### Task 14: JSON API — Relays, Transcoders, Users, Security, Branding, Settings

**Files:**
- Modify: `server/handlers_api_v2.go`
- Modify: `server/server.go`

- [ ] **Step 1: Implement Relay endpoints** (GET/POST/DELETE/PUT toggle)

- [ ] **Step 2: Implement Transcoder endpoints** (GET/POST/DELETE)

- [ ] **Step 3: Implement User endpoints** (GET/POST/PUT/DELETE)

- [ ] **Step 4: Implement Security endpoints** (bans + whitelist CRUD)

- [ ] **Step 5: Implement Branding endpoints** (GET/PUT branding, POST/DELETE logo)

- [ ] **Step 6: Implement Settings endpoints** (GET/PUT config, POST restart)

- [ ] **Step 7: Commit**

```bash
git add server/handlers_api_v2.go server/server.go
git commit -m "feat: add JSON API endpoints for relays, transcoders, users, security, branding, settings"
```

---

### Task 15: SSE typed events

**Files:**
- Modify: `server/handlers_public.go` (handlePublicEvents)
- Modify: `server/handlers_admin.go` (handleEvents)

- [ ] **Step 1: Update `handleEvents` to send typed `event:` fields**

Add `event: stats`, `event: stream`, `event: autodj` prefixes to SSE messages. Keep backward-compatible `data:` format for the main payload.

- [ ] **Step 2: Update `handlePublicEvents` to send typed events**

Add `event: streams` and `event: metadata` prefixes.

- [ ] **Step 3: Commit**

```bash
git add server/handlers_public.go server/handlers_admin.go
git commit -m "feat: add typed event fields to SSE endpoints"
```

---

## Chunk 5: Admin Console

### Task 16: Admin SPA shell with router

**Files:**
- Rewrite: `server/frontend/src/entries/admin.tsx`
- Create: `server/frontend/src/pages/admin/AdminLayout.tsx`
- Create: `server/frontend/src/pages/admin/Dashboard.tsx`

- [ ] **Step 1: Install preact-router**

```bash
cd server/frontend && npm install preact-router
```

- [ ] **Step 2: Create `AdminLayout.tsx`** — sidebar + main content area with `<Router>`

- [ ] **Step 3: Create `Dashboard.tsx`** — stats row, traffic chart (uPlot), streams table. Connects to SSE `/admin/events`.

Install uPlot:
```bash
cd server/frontend && npm install uplot
```

- [ ] **Step 4: Wire admin entry point**

- [ ] **Step 5: Commit**

---

### Task 17: Admin pages — Streams, Relays, Transcoders, Users, Security, Settings

**Files:**
- Create: `server/frontend/src/pages/admin/Streams.tsx`
- Create: `server/frontend/src/pages/admin/Relays.tsx`
- Create: `server/frontend/src/pages/admin/Transcoders.tsx`
- Create: `server/frontend/src/pages/admin/Users.tsx`
- Create: `server/frontend/src/pages/admin/Security.tsx`
- Create: `server/frontend/src/pages/admin/Settings.tsx`

- [ ] **Step 1: Implement each page** using the API wrapper and component library. Each page follows the same pattern: fetch data on mount, render with components, handle mutations via `api.post/put/del`.

- [ ] **Step 2: Add branding tab to Settings** with markdown editor (simple textarea + preview toggle) and accent color picker.

- [ ] **Step 3: Commit per page or batch**

---

### Task 18: AutoDJ management and Studio

**Files:**
- Create: `server/frontend/src/pages/admin/AutoDJ.tsx`
- Create: `server/frontend/src/pages/admin/Studio.tsx`
- Create: `server/frontend/src/components/PlaylistItem.tsx`
- Create: `server/frontend/src/components/FileItem.tsx`

- [ ] **Step 1: Create `AutoDJ.tsx`** — instance cards with inline transport controls, queue preview

- [ ] **Step 2: Install drag-and-drop library**

```bash
cd server/frontend && npm install sortablejs @types/sortablejs
```

(Using SortableJS instead of @dnd-kit — no React dependency, already used in current codebase)

- [ ] **Step 3: Create `PlaylistItem.tsx`** — draggable track row with EQ bars for playing track

- [ ] **Step 4: Create `FileItem.tsx`** — library file/folder with add-to-playlist button

- [ ] **Step 5: Create `Studio.tsx`** — 3-column layout (Library, Now Playing with visualizer, Playlist/Queue/History tabs). Drag-to-reorder via SortableJS. Multi-select with shift/cmd-click. Save/load/clear playlist actions.

- [ ] **Step 6: Commit**

---

### Task 19: Go Live page

**Files:**
- Create: `server/frontend/src/pages/admin/GoLive.tsx`
- Create: `server/frontend/src/lib/webrtc.ts`

- [ ] **Step 1: Create `webrtc.ts`** — WebRTC source helpers (getUserMedia, createOffer, signaling)

- [ ] **Step 2: Create `GoLive.tsx`** — spectrum analyzer, input device selector, mount selector, level meters, GO LIVE button

- [ ] **Step 3: Commit**

---

## Chunk 6: Developer Portal

### Task 20: Developer portal page

**Files:**
- Create: `server/frontend/src/pages/Developers.tsx`
- Create: `server/frontend/src/components/CodeBlock.tsx`
- Rewrite: `server/frontend/src/entries/developers.tsx`

- [ ] **Step 1: Install highlight.js**

```bash
cd server/frontend && npm install highlight.js
```

- [ ] **Step 2: Create `CodeBlock.tsx`** — syntax highlighting with language tabs (TS/JS/cURL), copy button, line numbers

- [ ] **Step 3: Create `Developers.tsx`** — sidebar nav + content area. Sections: Quick Start, WebRTC Source, HTTP Listening, WebRTC Playback, Metadata SSE, REST API, Embed Widget. Each section has code snippets with `CodeBlock`.

- [ ] **Step 4: Wire entry point**

- [ ] **Step 5: Commit**

---

## Chunk 7: Go Server Migration

### Task 21: Update Go handlers to serve new frontend

**Files:**
- Modify: `server/handlers_public.go`
- Modify: `server/handlers_admin.go`
- Modify: `server/handlers_player.go`
- Modify: `server/server.go`

- [ ] **Step 1: Update public handlers** (`handleRoot`, `handleExplore`, `handlePlayer`, `handleEmbed`) to use `s.shell.Render()` alongside old template rendering. Use a query param or config flag to toggle between old and new UI during migration.

- [ ] **Step 2: Update admin handler** to serve the SPA shell for all `/admin*` routes.

- [ ] **Step 3: Add redirect** from `/player-webrtc/:mount` to `/player/:mount?mode=webrtc`

- [ ] **Step 4: Update `/login` handler** to serve new login page shell.

- [ ] **Step 5: Verify all routes work**

```bash
go build && ./tinyice
```

Test each page in browser.

- [ ] **Step 6: Commit**

---

### Task 22: Build pipeline integration

**Files:**
- Modify: `.github/workflows/` (CI files)
- Modify: `.gitignore`

- [ ] **Step 1: Add `server/frontend/dist/` build to CI**

Before `go build`, run `cd server/frontend && npm ci && npm run build`.

- [ ] **Step 2: Update `.gitignore`**

Add `server/frontend/node_modules/` but NOT `server/frontend/dist/` (dist needs to be committed for `go install` to work without Node.js).

- [ ] **Step 3: Build and verify single binary**

```bash
cd server/frontend && npm run build
cd /Users/dev/dev/tinyice && go build -o tinyice .
./tinyice --help
```

- [ ] **Step 4: Commit**

---

## Chunk 8: Polish

### Task 23: Premium micro-interactions

**Files:**
- Modify: various component files

- [ ] **Step 1: Add cursor-reactive glow** — `useMouse.ts` hook, radial gradient follows cursor on dark surfaces

- [ ] **Step 2: Add skeleton loading states** to Dashboard, AutoDJ, and Streams pages

- [ ] **Step 3: Add error toast component** and SSE disconnect banner

- [ ] **Step 4: Add scroll-driven reveals** on landing page (fade+slide on scroll)

- [ ] **Step 5: Commit**

---

### Task 24: Responsive design

**Files:**
- Modify: various component and page files

- [ ] **Step 1: Add mobile bottom tab bar** (replaces sidebar below 768px)

- [ ] **Step 2: Make Studio 2-column on tablet** (library slides out), single-column on mobile

- [ ] **Step 3: Make stream card grid responsive** (1 column on mobile, 2 on tablet, 2-3 on desktop)

- [ ] **Step 4: Commit**

---

### Task 25: Final build and cleanup

- [ ] **Step 1: Run full build**

```bash
cd server/frontend && npm run build
cd /Users/dev/dev/tinyice && go build -o tinyice .
```

- [ ] **Step 2: Check bundle sizes against budgets**

```bash
cd server/frontend && du -sh dist/assets/*.js dist/assets/*.css
```

- [ ] **Step 3: Remove old template files** (or keep as fallback behind a config flag)

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: TinyIce v2 — complete product redesign"
```
