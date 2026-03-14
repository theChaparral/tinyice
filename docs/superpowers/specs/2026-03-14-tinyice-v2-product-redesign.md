# TinyIce v2 — Product Redesign Spec

## Overview

Rework TinyIce's web UI/UX into a world-class, professional product that serves two audiences equally: **broadcasters** (radio operators, streamers) and **developers** (building streaming into their apps). The redesign covers every page, introduces a new frontend build pipeline, and establishes a premium design system inspired by Teenage Engineering's hardware aesthetic.

TinyIce's competitive advantage — single-binary, zero-config deployment — is preserved. The new frontend compiles into embedded assets via `go:embed`.

## Audiences

| Audience | Primary needs | Key pages |
|----------|--------------|-----------|
| Broadcasters | Manage streams, AutoDJ, Go Live, monitor health | Admin dashboard, Studio, Go Live |
| Developers | Integrate streaming into web apps via WebRTC/HTTP | Developer portal, API reference, code snippets |

Both audiences share: Landing, Explore, Player, Embed.

## Design System — "Signal Orange"

### Philosophy

Teenage Engineering meets Linear. Hardware-inspired precision, monospaced data, single accent color, visible system state. Every pixel earns its place.

### Color Palette (OKLCH)

```
Surface system (3-tier depth):
  --surface-base:    oklch(0.10 0 0)    #0a0a0a   Page background
  --surface-raised:  oklch(0.15 0 0)    ~#18181b   Cards, panels
  --surface-overlay: oklch(0.20 0 0)    ~#27272a   Modals, dropdowns
  --surface-hover:   base + 0.04                   Interactive states

Text hierarchy (87/60/38 opacity rule):
  --text-primary:    rgba(255,255,255, 0.87)       Headlines, values
  --text-secondary:  rgba(255,255,255, 0.60)       Body, descriptions
  --text-tertiary:   rgba(255,255,255, 0.38)       Disabled, timestamps

Accent:
  --accent:          #ff6600                        THE color. CTAs, active states, logo, visualizer
  --accent-subtle:   rgba(255,102,0, 0.08)         Hover backgrounds, selected items
  --accent-glow:     rgba(255,102,0, 0.15)         Box-shadow glows

Semantic:
  --live:            #22c55e                        Live/healthy/connected
  --danger:          #ef4444                        Errors, destructive actions
  --info:            #3b82f6                        HTTP method badges, links

Borders:
  --border:          rgba(255,255,255, 0.06)        Default
  --border-hover:    rgba(255,255,255, 0.12)        Hover state
  --border-accent:   rgba(255,102,0, 0.20)         Active/selected
```

### Typography

```
Headings:    Space Grotesk (variable, 300-700)
             Letter-spacing: -0.5px to -2px (scales with size)

Data/Labels: Space Mono (400, 700)
             Letter-spacing: 1-3px, uppercase
             Used for: stats, mount paths, timestamps, nav labels

Code:        JetBrains Mono (400, 500)
             Used for: code blocks, API endpoints, config values

Body:        Space Grotesk (400, 500)
             Line-height: 1.6-1.7
```

Text rendering: `-webkit-font-smoothing: antialiased` globally. `text-rendering: optimizeLegibility` on headings only.

### Depth & Texture

- **No drop shadows** — depth via surface tiers and 1px borders at low opacity
- **SVG grain overlay** — `feTurbulence` noise at `opacity: 0.03-0.05`, `mix-blend-mode: overlay`. Adds analog warmth fitting for an audio product
- **Ambient glow** — radial gradient (`rgba(255,102,0, 0.04-0.06)`) behind hero sections and the player visualizer
- **Top accent lines** — 1px gradient (`#ff6600` → transparent) on card tops for subtle warmth
- **Dot-grid texture** — `radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)` at 20px intervals on landing page

### Motion

- **Easing**: `cubic-bezier(0.16, 1, 0.3, 1)` for all transitions (deceleration curve)
- **Duration**: 150ms for hover states, 200-300ms for page transitions. Never exceed 500ms
- **Hover states**: Border lightens to `--border-hover`. Cards get subtle `box-shadow: 0 0 20px rgba(255,102,0, 0.05)` on hover
- **Cursor-reactive glow**: Subtle radial gradient follows mouse position on dark surfaces
- **Skeleton loading**: Shimmer gradient sweep for async data (dashboard stats, playlist loading)
- **Live indicators**: `animation: pulse-glow 2s infinite` on green dots (opacity + box-shadow)
- **EQ bars**: Animated `scaleY` on playing streams — 3-5 bars per indicator

### Interaction Patterns

- **Magnetic buttons**: Primary CTAs slightly pull toward cursor on approach (8px range)
- **Physical knobs**: Volume control rendered as a rotary knob with gradient sheen and indicator line
- **Transport controls**: Play button is always #ff6600 with layered glow rings. Other buttons are ghost-style
- **Toggle switches**: #ff6600 when on, `rgba(255,255,255,0.08)` when off. Knob is dark on orange, gray on off
- **Drag handles**: Three horizontal lines, visible on hover. Drag preview shows orange border

## Tech Stack

### Frontend Build Pipeline

```
Tool        | Choice                   | Why
------------|--------------------------|----------------------------------------
Framework   | Preact + @preact/signals | 4KB, component model, signals for state
Styling     | Tailwind CSS v4          | Utility-first, tree-shaken, CSS-native
Build       | Vite + @preactjs/preset  | Fast HMR, asset hashing, tiny output
Language    | TypeScript (TSX)         | Type safety for components and API calls
Icons       | Lucide (tree-shaken)     | Only import used icons, no full bundle
Syntax HL   | Shiki                    | Accurate highlighting for dev portal
Charts      | uPlot                    | Tiny (<30KB), fast canvas charts
Drag & Drop | @dnd-kit/core            | Preact-compatible, accessible
Visualizer  | Canvas 2D + Web Audio    | 60fps circular spectrum, FFT data
Embedding   | go:embed dist/*          | Single binary preserved
```

### Rendering Strategy

1. **Go serves HTML shell** — minimal template with `<div id="app">`, initial data as `window.__TINYICE__` JSON, bundled JS/CSS from Vite
2. **Preact mounts client-side** — reads initial data, renders page, connects SSE
3. **Admin uses client-side routing** — `preact-router` for sidebar navigation without full page reloads
4. **Public pages are separate entry points** — Landing, Player, Explore, Developers each get their own minimal bundle for fast initial load
5. **View Transitions API** — for smooth page-to-page navigation where supported

### Project Structure

```
server/frontend/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html                    # Dev entry point
├── src/
│   ├── main.tsx                  # Entry, route mounting
│   ├── globals.css               # Tailwind directives, grain overlay, OKLCH tokens
│   ├── lib/
│   │   ├── sse.ts                # Typed SSE client
│   │   ├── api.ts                # Fetch wrapper for admin API
│   │   ├── webrtc.ts             # WebRTC helpers (source + playback)
│   │   ├── audio.ts              # Web Audio context, FFT analyzer
│   │   └── visualizer.ts         # Canvas 2D circular spectrum renderer
│   ├── components/
│   │   ├── Layout.tsx            # Shell with nav/sidebar
│   │   ├── Sidebar.tsx           # Icon sidebar (64px) + expanded state
│   │   ├── StreamCard.tsx        # Reusable stream card with EQ bars
│   │   ├── Visualizer.tsx        # Rotating circular spectrum (Canvas)
│   │   ├── StatCard.tsx          # Metric card with gauge bar
│   │   ├── TrafficChart.tsx      # uPlot wrapper
│   │   ├── CodeBlock.tsx         # Shiki syntax highlighting + copy
│   │   ├── ModeToggle.tsx        # HTTP/WebRTC segmented control
│   │   ├── TransportControls.tsx # Play/pause/next/prev/shuffle/loop
│   │   ├── VolumeKnob.tsx        # Rotary knob component
│   │   ├── Toggle.tsx            # On/off switch
│   │   ├── PlaylistItem.tsx      # Draggable track row
│   │   ├── FileItem.tsx          # Library browser file/folder
│   │   └── Skeleton.tsx          # Loading shimmer
│   ├── pages/
│   │   ├── Landing.tsx
│   │   ├── Explore.tsx
│   │   ├── Player.tsx            # Unified HTTP + WebRTC player
│   │   ├── Embed.tsx             # Minimal embeddable player
│   │   ├── Developers.tsx        # Dev portal with code tabs
│   │   ├── Login.tsx
│   │   └── admin/
│   │       ├── Dashboard.tsx     # Stats, chart, stream table
│   │       ├── Streams.tsx       # Mount management
│   │       ├── AutoDJ.tsx        # Instance management cards
│   │       ├── Studio.tsx        # 3-column deck (library, player, playlist)
│   │       ├── GoLive.tsx        # WebRTC broadcast UI
│   │       ├── Relays.tsx        # Upstream connections
│   │       ├── Transcoders.tsx   # Format conversion
│   │       ├── Users.tsx         # User management
│   │       ├── Security.tsx      # IP bans, whitelist, audit log
│   │       └── Settings.tsx      # Server config, HTTPS, webhooks
│   └── hooks/
│       ├── useSSE.ts             # SSE subscription with typed events
│       ├── useAudio.ts           # Audio context + analyser node
│       └── useMouse.ts           # Mouse position for cursor glow
├── dist/                         # Vite output → go:embed
```

## Page Designs

### 1. Landing Page (/)

**Layout**: Full-width. Nav bar → Hero → Live Streams → Footer.

**Nav**: Logo mark (orange rounded square with "Ti") + "TINYICE" in Space Mono. Right: EXPLORE, DEVELOPERS, ADMIN links. Admin link is orange.

**Hero**: Left column has category label ("AUDIO STREAMING SERVER" in orange monospace with dash prefix), headline (48px, "One binary. Pure audio." with gradient text on second line), description paragraph, two CTA buttons (orange primary "GET STARTED", ghost "VIEW DOCS"), stats strip below (100K+ concurrent, <1ms latency, ~8MB binary).

Right column shows live stream cards with animated EQ bars, mount name, now-playing metadata, listener count. Play button on each card.

**Background**: Dot-grid texture. Ambient orange radial glow in top-right corner.

**Footer**: "TINYICE // PURE GO" left, "V2.0.0" right. Space Mono, barely visible.

### 2. Player (/player/:mount)

**Layout**: Full-viewport, centered content. Minimal nav at top (logo + LIVE indicator).

**The Visualizer**: 260px diameter. 48 radial bars around a vinyl-style center disc. The ring rotates slowly (30s/revolution) via CSS `animation: spin-slow 30s linear infinite` in the static mockup, but in production uses Canvas 2D with real FFT data from `AnalyserNode.getByteFrequencyData()`. Bars map to frequency bins. Inner disc has groove lines (concentric circles at decreasing opacity) and a center label ("TINYICE" in 7px Space Mono).

**Track Info**: Title in 22px Space Grotesk bold. Artist in 12px Space Mono. Below the visualizer.

**Transport**: Shuffle, Prev, Play (64px orange circle with triple-layer glow shadow), Next, Repeat. Ghost buttons for all except Play.

**Mode Toggle**: Segmented control — HTTP (orange active) / WEBRTC. Rounded corners, Space Mono uppercase.

**Volume**: Physical rotary knob with gradient sheen, indicator line pointing to current level, flanked by volume icons.

**Bottom strip**: Mount, bitrate, listener count, latency — all in 9px Space Mono, barely visible.

**Ambient glow**: Large `radial-gradient(rgba(255,102,0, 0.06))` centered behind the visualizer.

### 3. Admin Dashboard (/admin)

**Layout**: 64px icon sidebar + main content area.

**Sidebar**: Orange logo mark at top. Icon-only navigation with tooltips on hover. Active item has `rgba(255,255,255,0.04)` background. Sections separated by 1px divider. Icons: Dashboard (grid), Streams (eye), AutoDJ (play circle), Go Live (mic), Relays (link), Transcoders (zap), Studio (monitor), divider, Users (user-plus), Security (lock), Settings (gear).

**Dashboard header**: "DASHBOARD" label in Space Mono + "System Overview" title. Right: green pulsing dot + "ALL SYSTEMS OK".

**Stats row**: 4 cards in a grid. Each has a gauge bar at top (orange fill showing utilization), label in Space Mono uppercase, value in 28px Space Mono bold, subtitle. Cards: Listeners (with % change), Streams (active/total), Bandwidth (MB/s), Uptime (with % availability).

**Traffic chart**: uPlot area chart with orange line, gradient fill below. Time selector: 1H / 24H / 7D segmented control (orange active). Grid lines as dashed at `rgba(255,255,255,0.03)`. Axis labels in 9px Space Mono.

**Streams table**: Header row in 9px Space Mono uppercase. Rows: green/orange dot, mount name (Space Mono bold), format, listener count, health bar (thin gauge with percentage), actions menu (three dots). AutoDJ instances get an orange "ADJ" badge.

### 4. AutoDJ Management (/admin/autodj)

**Layout**: Main content area (via sidebar nav).

**Header**: "AutoDJ" title + "New AutoDJ" button (orange outline with plus icon).

**Instance cards**: Each AutoDJ is a card showing:
- Status dot (green = playing, gray = stopped) + mount name (Space Mono bold) + format/bitrate
- Now Playing: track name, artist, album + progress bar (orange fill with glowing scrubber dot)
- Listener count (large number + "listeners" label)
- Inline transport controls: prev, play/pause (orange or ghost), next, separator, open studio button, settings button
- Queue preview strip at bottom: "UP NEXT" label + next 3 track names with arrows

Stopped instances show "Stopped — N tracks in playlist" with a ghost play button.

### 5. AutoDJ Studio (/admin/studio?mount=)

**Layout**: Full-width 3-column layout within the admin shell.

**Top bar**: Back arrow + "Back to AutoDJ" link, mount status dot, mount name (Space Mono bold), format info. Right: listener count (orange number), uptime.

**Column 1 — Library (260px)**:
- Header: "LIBRARY" label + search input with magnifying glass icon
- Breadcrumb: Folder path in Space Mono (e.g., "MUSIC / ELECTRONIC") with clickable segments
- File list: Folders show orange-tinted folder icon. Files show music note icon with metadata (artist, duration, bitrate in 9px Space Mono). Active/selected file has orange background tint + orange border + orange "+" button. Inactive files have ghost "+" button on hover
- Footer: "ADD ALL TO PLAYLIST" button (orange outline)

**Column 2 — Now Playing (flex)**:
- Circular visualizer (140px, same design as Player but smaller)
- Track title (18px bold) + artist (Space Mono)
- Progress scrubber: timestamps in Space Mono, orange fill with glowing dot handle
- Transport controls: shuffle, prev, play (52px orange circle with glow), next, loop
- Volume knob (rotary style)
- Bottom bar: "METADATA" label + toggle switch

**Column 3 — Playlist/Queue/History (300px)**:
- Tabs: PLAYLIST / QUEUE / HISTORY in Space Mono with orange bottom border on active tab
- Actions bar: SAVE, LOAD, CLEAR buttons (ghost style) + track count/duration in Space Mono
- Track list:
  - Currently playing track has orange background tint, animated EQ bars instead of number, orange text
  - Other tracks show number in Space Mono, title, artist/duration metadata, drag handle (three lines)
  - Drag handle visible on hover, draggable for reorder
  - Tracks support: drag to reorder, right-click context menu (play next, remove, move to top/bottom), multi-select with shift/cmd-click, bulk operations

**Playlist management features**:
- Save: Opens modal to name and save current playlist (PLS format)
- Load: Shows saved playlists list with track counts
- Clear: Confirmation dialog before clearing
- Import: Drag-and-drop PLS/M3U files onto the playlist area
- Multi-select: Shift-click for range, Cmd-click for individual. Selected items show orange border. Bulk delete, bulk move to top/bottom
- Queue tab: Shows priority queue. "Play next" inserts at position 0. Queue auto-fills from playlist when empty
- History tab: Shows recently played tracks with timestamps

### 6. Developer Portal (/developers)

**Layout**: 210px sidebar + content area. No admin auth required.

**Sidebar**: Dev icon + "DEVELOPERS" label in orange Space Mono. Sections: Getting Started (Quick Start, Installation), Streaming (WebRTC Source, HTTP Listening, WebRTC Playback, Metadata SSE), Reference (REST API, Embed Widget, Icecast Compat). Active item has orange left border.

**Content**:
- Section label ("GETTING STARTED" in orange Space Mono with dash prefix)
- Page title (26px bold)
- Description paragraph
- Code blocks: Dark background (`#050505`), top bar with language tabs (TS/JS/CURL in Space Mono, active has orange bottom border), copy button. Line numbers in left gutter. Syntax highlighting with orange for class/constructor names, purple for keywords, blue for strings
- Flow cards: 01 → 02 → 03 connected by arrow icons. Each has large orange number, title, description
- API endpoint list: Cards with colored method badge (POST green, GET blue), monospace path, description, chevron arrow. Orange border on hover

**Code snippets to include**:
- WebRTC source streaming (mic → server)
- WebRTC playback (server → speakers)
- HTTP stream listening with `<audio>` element
- SSE metadata subscription
- Embed widget integration (`<iframe>`)
- REST API: get stats, list mounts, get listeners

### 7. Explore (/explore)

Grid of stream cards (same component as landing). Search/filter bar at top. Cards show mount, format, now-playing, listener count, play button with EQ bars. Clicking a card navigates to the Player page.

### 8. Go Live (/admin/golive)

Spectrum analyzer (horizontal bars, not circular). Input device selector dropdown. Mount point selector. Level meters (L/R with peak hold). Large "GO LIVE" button (red when broadcasting). Status badge. WebRTC mode indicator.

### 9. Login (/login)

Centered card on dark background. Logo mark, "TINYICE" text, username/password fields (Space Mono placeholders), orange "SIGN IN" button. Error message area with red accent. Minimal — no decoration.

### 10. Embed (/embed/:mount)

80px height. Dark background. Play button (orange, small), track title, artist. Thin visualizer bar at bottom. Designed for `<iframe>` embedding on external sites. Minimal JS bundle.

### 11. Settings (/admin/settings)

Form-based config editor. Sections: Server (bind host, port, HTTPS), HTTPS/ACME (domains, email, certs), Mounts (global settings, burst size), Webhooks (URL, events), UI (page title, subtitle, location). Input fields with Space Mono values. Toggle switches for boolean options. Orange "Save Changes" button.

## Visualizer Specification

### Circular Spectrum (Player + Studio)

- **Technology**: Canvas 2D API
- **Data source**: `AnalyserNode.getByteFrequencyData()` from Web Audio API
- **Bars**: 48 radial bars evenly distributed (7.5° apart)
- **Bar dimensions**: 3px wide, 10-36px height (mapped from frequency data)
- **Color**: `#ff6600` with opacity mapped to bar height (0.15 → 0.9)
- **Rotation**: Entire ring rotates at 12°/second (30s per revolution)
- **Center**: Vinyl disc with groove lines (concentric circles) and label
- **Frame rate**: 60fps via `requestAnimationFrame`
- **Responsive**: Scales to container width, max 260px on Player, 140px in Studio
- **Performance**: Use `OffscreenCanvas` where supported. Skip rendering when tab is not visible (`document.hidden`)

### EQ Bar Indicators (Stream cards, playlist items)

- **Bars**: 3-5 vertical bars, 2.5-3px wide
- **Animation**: CSS `scaleY` with staggered delays (0.05s between bars)
- **Color**: `#ff6600`
- **Context**: Shows on any "currently playing" indicator

## Responsive Design

- **Desktop** (>1024px): Full sidebar, 3-column studio layout
- **Tablet** (768-1024px): Collapsed sidebar (icon only), 2-column studio (library slides out)
- **Mobile** (<768px): Bottom tab bar replaces sidebar, single-column studio with tab switching, full-width cards

## Accessibility

- All interactive elements keyboard-accessible
- Focus rings: 2px orange outline offset by 2px
- ARIA labels on icon-only buttons
- Reduced motion: respect `prefers-reduced-motion` — disable visualizer rotation, EQ animations, cursor glow
- Color contrast: all text passes WCAG AA against its background surface

## Build & Deployment

### Development
```bash
cd server/frontend
npm install
npm run dev          # Vite dev server with HMR on :5173
                     # Proxies API calls to Go server on :8000
```

### Production
```bash
cd server/frontend
npm run build        # Output to dist/
cd ../..
go build             # Embeds dist/ via go:embed
```

### CI Integration
- `npm run build` added before `go build` in GitHub Actions
- Built assets committed to repo (or built in CI) — keeps `go install` working without Node.js

## Go Server Integration

### Handler Changes

The Go server transitions from rendering full HTML templates to serving thin HTML shells that load Preact bundles. Key changes:

**Embed path change**:
```go
// Before (current):
//go:embed templates/*
var templateFS embed.FS
//go:embed assets/*
var assetFS embed.FS

// After:
//go:embed frontend/dist/*
var frontendFS embed.FS
```

**Shell template**: A single `shell.html` Go template replaces all 9 current templates. It renders:
```html
<!DOCTYPE html>
<html lang="en" style="color-scheme:dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{.PageTitle}} — TinyIce</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div id="app"></div>
  <script>window.__TINYICE__ = {{.InitialData}}</script>
  <script type="module" src="/assets/{{.EntryPoint}}"></script>
</body>
</html>
```

**Handler pattern** — each handler becomes a shell renderer:
```go
func (s *Server) handlePlayer(w http.ResponseWriter, r *http.Request) {
    mount := extractMount(r)
    stream := s.relay.GetStream(mount)
    data := PlayerInitialData{
        Mount:     mount,
        Title:     stream.Title,
        Artist:    stream.Artist,
        Format:    stream.Format,
        Bitrate:   stream.Bitrate,
        Listeners: stream.Listeners,
        CSRFToken: s.getCSRFToken(r),
    }
    s.renderShell(w, "player", data)
}
```

**Route mapping**:
| Route | Handler | Entry Point | Auth |
|-------|---------|-------------|------|
| `/` | `handleLanding` | `landing.js` | No |
| `/explore` | `handleExplore` | `explore.js` | No |
| `/player/:mount` | `handlePlayer` | `player.js` | No |
| `/player-webrtc/:mount` | redirect → `/player/:mount?mode=webrtc` | — | No |
| `/embed/:mount` | `handleEmbed` | `embed.js` | No |
| `/developers` | `handleDevelopers` | `developers.js` | No |
| `/login` | `handleLogin` | `login.js` | No |
| `/admin` | `handleAdmin` | `admin.js` | Yes |
| `/admin/*` | `handleAdmin` (SPA catch-all) | `admin.js` | Yes |

**Vite multi-page setup**: Each public page gets its own entry point for minimal bundle size. Admin is a single SPA entry point with client-side routing.

### `window.__TINYICE__` Schema

Per-page initial data injected by Go:

```typescript
// Base (all pages)
interface TinyIceBase {
  csrfToken: string;
  version: string;
  pageTitle: string;
  pageSubtitle: string;
  branding: {
    logoUrl: string | null;
    accentColor: string;  // hex, default "#ff6600"
    landingMarkdown: string;
  };
}

// Player page
interface PlayerData extends TinyIceBase {
  mount: string;
  title: string;
  artist: string;
  format: "mp3" | "opus";
  bitrate: number;
  listeners: number;
  hasWebRTC: boolean;
}

// Admin pages
interface AdminData extends TinyIceBase {
  user: { username: string; role: "superadmin" | "admin" };
  mounts: string[];
}

// Landing page
interface LandingData extends TinyIceBase {
  streams: Array<{
    mount: string;
    title: string;
    artist: string;
    format: string;
    bitrate: number;
    listeners: number;
    live: boolean;
  }>;
}
```

### API Contract

All admin actions become JSON REST endpoints. The existing form-POST endpoints are preserved for backward compatibility but marked deprecated.

**Authentication**: Cookie-based sessions (unchanged). CSRF token passed via `X-CSRF-Token` header on mutating requests. The token comes from `window.__TINYICE__.csrfToken`.

**Request/Response format**: JSON in, JSON out. Errors return `{ "error": "message" }` with appropriate HTTP status.

**Endpoint groups**:

```
Streams:
  GET    /api/streams              → StreamInfo[]
  POST   /api/streams              → create mount { mount, password, burstSize }
  DELETE /api/streams/:mount       → remove mount
  POST   /api/streams/:mount/kick  → kick source/listeners

AutoDJ:
  GET    /api/autodj               → AutoDJInfo[]
  POST   /api/autodj               → create { mount, format, bitrate, musicDir }
  PUT    /api/autodj/:mount        → update settings
  DELETE /api/autodj/:mount        → remove
  POST   /api/autodj/:mount/play   → play
  POST   /api/autodj/:mount/pause  → pause
  POST   /api/autodj/:mount/next   → skip to next
  POST   /api/autodj/:mount/prev   → restart/previous
  PUT    /api/autodj/:mount/shuffle → toggle shuffle
  PUT    /api/autodj/:mount/loop    → toggle loop

Playlist:
  GET    /api/autodj/:mount/playlist      → PlaylistItem[]
  POST   /api/autodj/:mount/playlist      → add items { files: string[] }
  DELETE /api/autodj/:mount/playlist/:id  → remove item
  PUT    /api/autodj/:mount/playlist/reorder → { ids: string[] }
  POST   /api/autodj/:mount/playlist/clear  → clear all
  GET    /api/autodj/:mount/playlist/saved  → saved playlist names
  POST   /api/autodj/:mount/playlist/save   → { name: string }
  POST   /api/autodj/:mount/playlist/load   → { name: string }

Queue:
  GET    /api/autodj/:mount/queue          → QueueItem[]
  POST   /api/autodj/:mount/queue          → add to queue { file, position? }
  DELETE /api/autodj/:mount/queue/:id      → remove from queue
  PUT    /api/autodj/:mount/queue/reorder  → { ids: string[] }

Library:
  GET    /api/autodj/:mount/files?path=    → FileInfo[] (dir listing)
  GET    /api/autodj/:mount/files/search?q= → FileInfo[] (search)

Relays:
  GET    /api/relays               → RelayInfo[]
  POST   /api/relays               → add { url, mount, password }
  DELETE /api/relays/:id           → remove
  PUT    /api/relays/:id/toggle    → enable/disable

Transcoders:
  GET    /api/transcoders          → TranscoderInfo[]
  POST   /api/transcoders         → add { inputMount, outputMount, format, bitrate }
  DELETE /api/transcoders/:id     → remove

Users:
  GET    /api/users                → UserInfo[]
  POST   /api/users                → add { username, password, role }
  DELETE /api/users/:username      → remove
  PUT    /api/users/:username      → update { password?, role? }

Security:
  GET    /api/security/bans        → BannedIP[]
  POST   /api/security/bans        → add { ip, cidr? }
  DELETE /api/security/bans/:ip    → unban
  GET    /api/security/whitelist   → WhitelistedIP[]
  POST   /api/security/whitelist   → add { ip, cidr? }
  DELETE /api/security/whitelist/:ip → remove

Branding:
  GET    /api/branding             → BrandingConfig
  PUT    /api/branding             → update { pageTitle, pageSubtitle, accentColor, landingMarkdown }
  POST   /api/branding/logo        → upload logo (multipart)
  DELETE /api/branding/logo        → remove custom logo

Settings:
  GET    /api/settings             → ServerConfig (safe subset)
  PUT    /api/settings             → update config fields
  POST   /api/settings/restart     → graceful restart (HTTPS/ACME changes)

Stats:
  GET    /api/stats                → full server stats (existing endpoint)
  GET    /metrics                  → Prometheus (existing endpoint)
```

### SSE Event Contract

Two endpoints (unchanged), but events now have typed `event:` fields:

```
GET /admin/events (authenticated)
  event: stats       → { listeners, streams, bandwidth, uptime, goroutines, memory, gc }
  event: stream      → { mount, title, artist, format, bitrate, listeners, health }
  event: autodj      → { mount, state, currentTrack, position, duration, queue }
  event: alert       → { type, message, severity }

GET /events (public)
  event: streams     → Array<{ mount, title, artist, format, bitrate, listeners, live }>
  event: metadata    → { mount, title, artist }
```

Interval: 500ms for admin, 2s for public.

## Branding & Customization

### Landing Page Editor

The landing page supports a customizable content section via Markdown. Accessed from `/admin/settings` under a "Branding" tab.

**Editor component**: Split-pane markdown editor (left: editor, right: live preview). Uses a lightweight markdown editor component (e.g., `@uiw/react-md-editor` with Preact compat, or a simple `<textarea>` with preview toggle for smaller bundle).

**Storage**: The markdown content is stored in the config file as `landing_markdown` field. Rendered client-side in the Landing page hero section below the headline/subtitle.

**Default content**: Ships with a sensible default describing the server. Users can customize to add station info, schedule, rules, etc.

### Branding Options (Admin → Settings → Branding)

Configurable via the web UI without editing config files:

```
Page Title        [text input]     "My Radio Station"
Page Subtitle     [text input]     "24/7 electronic music"
Accent Color      [color picker]   #ff6600 (default)
Logo              [file upload]    PNG/SVG, max 512KB, replaces the "Ti" mark
Landing Content   [markdown editor] Custom landing page content
Location          [text input]     "Berlin, Germany"
Admin Email       [email input]    "admin@example.com"
```

**Accent color** propagates to CSS custom properties via `window.__TINYICE__.branding.accentColor`. The Preact app sets `--accent` dynamically on mount. All orange elements automatically adopt the custom color.

**Logo upload**: Stored on disk alongside the config file. Served via `/branding/logo`. Falls back to the default "Ti" mark if no custom logo is set.

### Config Schema Addition

```go
type BrandingConfig struct {
    PageTitle       string `json:"page_title"`
    PageSubtitle    string `json:"page_subtitle"`
    AccentColor     string `json:"accent_color"`      // hex, default "#ff6600"
    LogoPath        string `json:"logo_path"`          // path to uploaded logo
    LandingMarkdown string `json:"landing_markdown"`   // markdown content
    Location        string `json:"location"`
    AdminEmail      string `json:"admin_email"`
}
```

## Additional Page Designs

### Streams Management (/admin/streams)

**Header**: "Streams" title + "Add Mount" button (orange).

**Mount list**: Table with columns: Status dot, Mount (Space Mono bold), Source (connected source IP or "No source"), Format, Listeners, Burst Size, Actions (kick source, kick listeners, remove).

**Add Mount modal**: Mount path input, source password, burst size slider, format selector.

### Relays (/admin/relays)

**Header**: "Relays" title + "Add Relay" button.

**Relay cards**: Each relay shows: upstream URL, local mount, connection status (connected/disconnected/reconnecting with colored dot), uptime, listener count, toggle switch to enable/disable, remove button.

**Add Relay form**: Upstream URL, local mount path, password (optional), burst size.

### Transcoders (/admin/transcoders)

**Header**: "Transcoders" title + "Add Transcoder" button.

**Transcoder cards**: Visual flow: Input mount → [format badge] → Output mount. Shows status, listener count per output. Toggle to enable/disable.

**Add form**: Input mount selector, output mount path, format (MP3/Opus), bitrate slider.

### Users (/admin/users)

**Header**: "Users" title + "Add User" button.

**User table**: Username, Role badge (superadmin=orange, admin=gray), Assigned Mounts (tags), Actions (edit, remove). Edit opens a slide-out panel with password change, role selector, mount assignment checkboxes.

### Security (/admin/security)

**Two sections**:

1. **Banned IPs**: Table with IP/CIDR, ban reason (if any), timestamp, unban button. Add form at top.
2. **Whitelisted IPs**: Same layout. "Whitelist bypasses all rate limiting and ban checks."

**Auth log** (optional section): Recent authentication attempts showing IP, username, success/failure, timestamp. Sourced from the existing auth log file.

## Error States

All pages must handle:

- **SSE disconnect**: Yellow banner "Connection lost — reconnecting..." with auto-retry (exponential backoff). Dashboard stats freeze with a "stale" indicator
- **API error**: Toast notification (bottom-right) with error message, auto-dismiss after 5s. Red accent
- **404 stream**: Player shows "Stream not found" with a link back to Explore
- **Auth expired**: Redirect to `/login?expired=1` with a message "Session expired, please sign in again"
- **Network offline**: Gray banner "You are offline" — persists until connectivity restored

## Performance Budgets

| Asset | Budget | Notes |
|-------|--------|-------|
| Admin JS bundle | <150KB gzip | Largest bundle (SPA with charts, drag-drop) |
| Player JS bundle | <30KB gzip | Visualizer + audio + mode toggle |
| Landing JS bundle | <15KB gzip | Mostly static with SSE for live data |
| Developers JS bundle | <40KB gzip | Shiki is heavy — consider highlight.js |
| Embed JS bundle | <8KB gzip | Absolute minimum |
| CSS (all pages) | <15KB gzip | Tailwind tree-shaken |
| Fonts (total) | <100KB gzip | Subset to Latin + used weights only |
| Total embedded assets | <500KB gzip | Added to ~8MB Go binary |

If Shiki exceeds the Developers budget, switch to `highlight.js` with only `typescript`, `javascript`, `bash`, and `json` language packs (~15KB vs ~200KB).

Font subsetting: Use `unicode-range` and `font-display: swap`. Subset to Latin characters. Self-host all fonts (no CDN — contradicts zero-dependency deployment).

## Accessibility Additions

- Magnetic button effect disabled when `prefers-reduced-motion: reduce`
- `cursor-reactive glow` throttled to 60fps via `requestAnimationFrame`, uses `will-change: background` for compositor promotion
- View Transitions API: graceful fallback to instant navigation when unsupported (Firefox)
- `surface-hover` resolves to `oklch(0.14 0 0)` (base 0.10 + 0.04)
- Embed player: fluid width, recommended min-width 280px, height 80px
- File browser in Studio supports `.mp3`, `.ogg`, `.opus`, `.flac`, `.wav` (extend `handlePlayerFiles` filter)

## Migration Strategy

### Phase 1: Foundation
- Set up Vite project in `server/frontend/`
- Configure Tailwind with OKLCH design tokens
- Create base components (Layout, Sidebar, StatCard, etc.)
- Implement the Go template shell that loads Preact bundles

### Phase 2: Public Pages
- Landing page with dot-grid, hero, live stream cards
- Player with Canvas visualizer
- Explore page
- Embed player
- Login page

### Phase 3: Admin Console
- Dashboard with SSE integration
- Streams management
- AutoDJ management + Studio (3-column layout with playlist editing)
- Go Live
- Relays + Transcoders
- Users + Security + Settings

### Phase 4: Developer Portal
- Quick Start with code tabs
- WebRTC streaming guides with copy-paste snippets
- REST API reference
- Embed widget docs

### Phase 5: Polish
- Scroll-driven animations on landing
- View Transitions API for navigation
- Cursor-reactive glow effect
- Animated mesh gradient in hero
- Skeleton loading states
- Performance optimization (code splitting, lazy loading)
