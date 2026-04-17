# TinyIce

![TinyIce Logo](https://raw.githubusercontent.com/DatanoiseTV/tinyice/main/assets/logo.png?v=2)

**One binary. Audio + video.**

> High-performance Icecast-compatible streaming server with RTMP/SRT/WebRTC ingest, AutoDJ, live audio transcoding, HLS audio/video output, and a built-in admin SPA. Deploy anywhere in seconds.

### Landing Page
![Landing Page](assets/screenshots/landing.png)

### Admin Dashboard
![Admin Dashboard](assets/screenshots/admin-dashboard.png)

### AutoDJ Management
![AutoDJ](assets/screenshots/admin-autodj.png)

### Developer Portal
![Developer Portal](assets/screenshots/developers.png)


[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## What's New in v2.0.0-beta.5 — Video

This release turns TinyIce from an audio-only streaming server into an
A/V one, and does a security / correctness pass on top.

### Video streaming

- **RTMP with H.264 video** — OBS / FFmpeg / any RTMP publisher can push
  H.264 + MP3 or H.264 + AAC into a `/mount`. The RTMP app name is
  honoured as the tinyice mount and the stream key as the source
  password, matching the UX OBS expects.
- **SRT video ingest** — MPEG-TS A/V publishers land in the same
  `/mount` + `/mount/video` layout as RTMP.
- **HLS audio + video output** — every mount exposes
  `/mount/playlist.m3u8`; when a `/mount/video` sub-mount exists the
  segments are muxed A/V. PCR is emitted; `TARGETDURATION` is tight;
  `EXTINF` / PTS advance by the configured segment duration. MP3 and
  AAC audio codecs are both supported (AAC is ADTS-wrapped and the
  PMT `stream_type` switches to `0x0F`).
- **Keyframe-aware raw video listeners** — a direct
  `GET /mount/video` seeks back to the latest IDR and prepends the
  cached SPS/PPS so `mpv http://host/mount/video` plays immediately.
- **Browser player** — the in-page Player automatically switches from
  `<audio>` to `<video>` when the mount has video. Safari / iOS play
  HLS natively; Chromium / Firefox get `hls.js` dynamically loaded.

### Audio correctness

- Pure-Go multi-codec decode for the transcoder + AutoDJ — MP3, Ogg
  Opus, Ogg Vorbis, FLAC, FLAC-in-Ogg, WAV (8/16/24/32-bit PCM + IEEE
  float, mono/stereo).
- Automatic resampler so **MP3 / Vorbis / FLAC / WAV → Opus** plays at
  the right speed (the Opus encoder is locked at 48 kHz).
- **MP3 bitrate** is actually honoured (the bundled `shine` encoder
  has its bitrate index / slots-per-frame reached into explicitly).
- **Ogg page rewriter per listener** — BOS / Tags / granule are
  regenerated so late joiners don't see the minutes-long granule jump
  that strict decoders fill with silence (the "robotic voice" bug).
- **Icecast SOURCE** captures the initial Ogg BOS + setup pages so
  new listeners get a playable start.

### Operations & security

- OIDC state is session-bound, nonce-validated, and rejects OIDC
  accounts whose email isn't verified. GitHub `/user/emails` is
  consulted; only primary+verified addresses log in.
- Sessions have absolute and sliding expiry with a periodic reaper;
  login rotates the cookie (no session fixation); deleted users have
  their active sessions purged.
- Login timing is constant — always runs bcrypt so unknown usernames
  don't return faster than known ones.
- `TrustedProxies` config + `X-Forwarded-For` handling so scan
  detection / bans work behind nginx / Caddy / Traefik without
  auto-whitelisting loopback.
- Auto-updater verifies SHA-256 from `checksums.txt` before
  overwriting the running binary.
- RTMP shutdown closes live publisher connections so `Ctrl+C` quits
  within seconds even mid-stream.
- CSRF on every mutating admin form; super-admin gates on transcoder
  + webhook CRUD; webhook / relay URLs reject loopback / RFC1918
  targets (SSRF).
- `SaveConfig` is serialised across goroutines so concurrent admin
  writes can't shred the JSON.
- Auto-remove dormant streams after 2 min of silence (was defined
  but never enabled).
- YP directory reporter emits proper `add` / `touch` / `remove`
  lifecycle instead of repeated `add`s.

### Admin UI

- **Edit** for Streams, Transcoders, Relays, AutoDJ (in-place updates,
  no more destroy-and-recreate on edit).
- Transcoder editor surfaces Opus application / frame size / complexity
  / VBR, plus a custom sample rate override.
- Landing markdown is DOMPurified before it hits the DOM (was an
  admin → visitor XSS).
- Error toasts on every mutation path so 403 / 500 don't silently
  disappear.
- SSE reconnect no longer duplicates event delivery.

### Build / packaging

- Multi-stage `Dockerfile` (+ `.dockerignore`) for container deploys.
- `make build` rebuilds frontend + binary; `go generate ./server/...`
  pulls in hls.js + dompurify as lazy chunks.

## Why TinyIce?

Traditional streaming servers can be complex to configure and resource-heavy. TinyIce aims to solve this by providing:

-   **Massive Scalability**: Built with a **Shared Circular Buffer** architecture that allows a single stream to be broadcast to hundreds of thousands of listeners with near-zero memory allocations.
-   **Instant Deployment**: A single binary with all assets (templates, icons, frontend) embedded.
-   **Zero-Config Security**: Unique secure credentials automatically generated on first run.
-   **Multi-Tenant Ready**: Create multiple admin users who can only manage their own mount points.
-   **Edge-Ready Relaying**: Pull streams from other servers with automatic reconnection and in-stream ICY metadata parsing.
-   **Secure & Hardened**: Salted **bcrypt** password hashing, rate limiting, and HTTP resource hardening.
-   **Auto-HTTPS**: Built-in support for **ACME (Let's Encrypt)** for zero-configuration SSL certificates. Supports custom ACME CAs (e.g., Step-CA) for homelab environments.
-   **Real-time Insights**: SSE-powered dashboards with live traffic charts.
-   **Playback History**: Persistent song history stored in a lightweight SQLite database.
-   **Observability**: Built-in **Prometheus** metrics endpoint and structured logging.

## Features

### Streaming & Protocols
-   **Icecast2 Compatible**: Works with standard source clients (BUTT, OBS, Mixxx, LadioCast) and players (VLC, web browsers).
-   **RTMP Ingest**: OBS / ffmpeg / any RTMP publisher can push H.264 + MP3 or H.264 + AAC. OBS's Server-path = mount, Stream-key = password UX just works.
-   **SRT Ingest**: Low-latency SRT with MPEG-TS demux for both audio and video.
-   **WebRTC Source & Playback**: Ultra-low-latency browser-based broadcasting and listening via the Go Live page.
-   **HLS A/V Output**: `/mount/playlist.m3u8` serves audio-only or audio+video segments depending on what the source pushes. PMT advertises MP3 or ADTS-AAC correctly; PCR is emitted; SPS/PPS are injected on every keyframe so late joiners can decode.
-   **High-Performance Distribution**: Shared circular buffer architecture designed for 100,000+ concurrent listeners per stream.
-   **Instant Start**: Listeners receive a 64KB audio burst upon connection, eliminating the "buffering" delay.
-   **Multi-Codec Transcoding**: Pure-Go transcoder and AutoDJ accept MP3 / Ogg Opus / Ogg Vorbis / FLAC / FLAC-in-Ogg / WAV as input and re-encode to MP3 or Opus with automatic resampling. No FFmpeg required.
-   **Edge Relaying**: Pull streams from upstream servers with automatic reconnection.
-   **Smart Fallback & Auto-Recovery**: Automatically switch listeners to a backup stream if the primary drops.
-   **Outbound ICY Metadata**: Injects song titles into the audio stream for traditional radio players.
-   **Playlist Support**: `.m3u8`, `.m3u`, and `.pls` playlists for VLC, Winamp, mobile apps.

### AutoDJ
-   **Multi-Instance Orchestration**: Multiple independent AutoDJs on different mounts from a single server.
-   **Precision Pacing**: Frame-accurate bitstream pacing ensures file-based streams behave exactly like live broadcasts.
-   **Studio Interface**: Full 3-column studio view with library browser, transport controls, visualizer, and playlist management.
-   **Smart Shuffle & Queue**: Priority queue, shuffle mode, loop mode, and drag-to-reorder.
-   **MPD Protocol Support**: Per-instance Music Player Daemon for remote control via standard MPD clients.
-   **Dynamic Metadata**: Automatic ID3 tag extraction and real-time ICY metadata injection.

### Admin Web UI
-   **Modern SPA Dashboard**: Real-time stats (inbound/outbound bandwidth, listeners, streams, system health).
-   **Stream Management**: Create, edit, delete mounts. Kick sources or listeners.
-   **AutoDJ Management**: Create, edit, delete AutoDJ instances with inline editing.
-   **Studio**: Full-featured studio page with mount selector, library browser, playlist editor, and transport controls.
-   **Go Live**: Browser-based WebRTC broadcasting with audio device selection, spectrum analyzer, level meters with headroom display (dB), and peak hold indicators.
-   **Relay & Transcoder Management**: Create and manage relay pulls and live transcoders.
-   **User Management**: Create, edit, delete users with role-based access control.
-   **Security**: IP banning and whitelisting with CIDR support.
-   **Pending Users**: Approve or deny OIDC-authenticated users waiting for access.
-   **Full Branding**: Customize site name, tagline, accent color (with visual picker), logo upload, and landing page content (full Markdown support).
-   **Settings**: Server configuration, HTTPS, directory listing, auto-update toggles.

### API & Developer Experience
-   **REST API**: Full JSON API for all management operations (streams, autodj, relays, transcoders, users, security, branding, settings, stats).
-   **Bearer Token Auth**: Create API access tokens in the admin panel for scripts, CI/CD, and external integrations. Tokens support optional expiry and track last-used time/IP.
-   **Session Auth**: Standard cookie-based session authentication via login form.
-   **No CSRF for API**: JSON API requests are inherently CSRF-safe — no token management needed for API consumers.
-   **Interactive API Docs**: Built-in Swagger UI at `/api/docs` with full OpenAPI 3.0 specification.
-   **OpenAPI Spec**: Downloadable at `/api/openapi.yaml` for code generation and client libraries.
-   **SSE Events**: Real-time Server-Sent Events for metadata changes, stream status, and listener counts.
-   **Embeddable Player**: Minimal iframe-based player for external websites.
-   **Developer Portal**: Built-in documentation page at `/developers` with code examples and endpoint reference.

### Authentication
-   **Username/Password**: Standard login with bcrypt-hashed passwords.
-   **Passkeys (WebAuthn)**: Passwordless authentication with hardware security keys or biometrics.
-   **OIDC/OAuth2**: External identity providers (GitHub, Google, etc.) with pending user approval workflow.
-   **API Tokens**: Bearer tokens for programmatic access with expiry and usage tracking.

### Operations
-   **Zero-Downtime Updates**: `SO_REUSEPORT` support for seamless binary upgrades.
-   **Prometheus Metrics**: `/metrics` endpoint with per-stream and system metrics.
-   **Stream Health Monitoring**: Real-time detection of packet loss and buffer skips.
-   **Structured Logging**: JSON logs with separate auth audit log support.
-   **Auto-Update**: Optional automatic update checking.
-   **`go generate` Build**: `go generate ./server/...` rebuilds the frontend automatically.

## Getting Started

### 1. Install (Pre-built Binary)

```bash
# Download latest release
curl -LJO "https://github.com/DatanoiseTV/tinyice/releases/latest/download/tinyice-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"

# Make executable
chmod +x tinyice-*
mv tinyice-* tinyice

# Run
./tinyice
```

### 2. Build from Source

Requires Go 1.21+ and Node.js 18+.

```bash
git clone https://github.com/DatanoiseTV/tinyice.git
cd tinyice

# Full build (frontend + Go binary)
make build

# Or manually:
go generate ./server/...   # Rebuild frontend
go build -o tinyice .
```

### 3. First Run

On first run, TinyIce generates `tinyice.json` and prints secure credentials:

```
  FIRST RUN: SECURE CREDENTIALS GENERATED
  Admin Password:  your_admin_password_here
  Default Source Password: your_source_password_here
  Live Mount Password:   your_livemount_password_here
```

**Save these passwords!** Then open `http://localhost:8000` in your browser.

### 4. Stream

Point your encoder (BUTT, OBS, Mixxx) to:
-   **Server Type**: Icecast 2
-   **Address**: your-server-ip
-   **Port**: 8000
-   **Password**: [The generated source password]
-   **Mount**: /live

Or use the **Go Live** page in the admin panel to broadcast directly from your browser via WebRTC.

## Streaming video from OBS

TinyIce accepts H.264 + AAC (or H.264 + MP3) over RTMP and produces
HLS audio+video at `/<mount>/playlist.m3u8`.

1. **Enable RTMP** in `tinyice.json`:

   ```json
   "ingest": {
       "rtmp_enabled": true,
       "rtmp_port": "1935"
   }
   ```

2. **Create a mount** in the admin UI (Streams → Add Mount). Give it
   a password — that password becomes your OBS Stream Key.

3. **OBS → Settings → Stream** (Service: Custom):

   - **Server**: `rtmp://<your-host>/<mount>` — e.g. `rtmp://radio.example.com/live`
   - **Stream Key**: your mount's source password

   (The classic layout `rtmp://<host>/` + Stream Key `mount?key=password`
   also works.)

4. **OBS → Settings → Output** — set Video Encoder to `x264` (or a
   hardware H.264 encoder) and Audio Encoder to AAC (default) or
   MP3. 2-second keyframe interval is a good default for HLS latency.

5. **Click Start Streaming.** The server log will show
   `RTMP: Publishing started mount=/live` followed by
   `RTMP: Parsed AVC config` and `RTMP: Parsed AAC ASC`.

6. **Watch it** three ways:

   - **Built-in player**: `https://<your-host>/player/<mount>`. If the
     source has video, the player renders an HTML5 `<video>`; Safari
     plays HLS natively, other browsers get `hls.js` loaded on
     demand.
   - **Direct HLS**: `https://<your-host>/<mount>/playlist.m3u8` —
     works in VLC, mpv, ffplay, and any HLS-capable client.
   - **Raw video**: `http://<your-host>/<mount>/video` plays the
     H.264 Annex-B bytes directly (useful for debugging with mpv).

## API Usage

### Authentication

Two methods are supported:

**Session cookie** — Log in via the web UI or `POST /login`.

**Bearer token** — Create a token in the admin panel at `/admin/tokens`, then use it in API requests:

```bash
# Create a token in the admin UI, then:
curl -H "Authorization: Bearer ti_your_token_here" http://localhost:8000/api/stats
```

### Example API Calls

```bash
TOKEN="ti_your_token_here"

# List streams
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/streams

# Create a mount
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mount": "/radio", "password": "secret"}' \
  http://localhost:8000/api/streams

# Get server stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/stats

# List AutoDJ instances
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/autodj
```

### Interactive API Docs

Visit `/api/docs` for the full Swagger UI, or download the OpenAPI spec at `/api/openapi.yaml`.

## Configuration

TinyIce uses a JSON configuration file (`tinyice.json`):

```json
{
    "bind_host": "0.0.0.0",
    "port": "8000",
    "base_url": "https://radio.example.com",
    "page_title": "My Radio",
    "page_subtitle": "Broadcasting 24/7",
    "accent_color": "#ff6600",
    "max_listeners": 100,
    "directory_listing": true,
    "autodjs": [
        {
            "name": "24/7 Chill",
            "mount": "/chill",
            "music_dir": "/music/chill",
            "format": "mp3",
            "bitrate": 128,
            "enabled": true,
            "loop": true,
            "inject_metadata": true
        }
    ]
}
```

### Auto-HTTPS (Let's Encrypt)

```json
{
    "use_https": true,
    "auto_https": true,
    "port": "80",
    "https_port": "443",
    "domains": ["radio.example.com"],
    "acme_email": "admin@example.com"
}
```

Ports 80/443 required for ACME challenges. On Linux without root:
```bash
sudo setcap 'cap_net_bind_service=+ep' ./tinyice
```

### Branding

Customize the landing page through the admin Settings > Branding tab:
- **Site Name**: Shown in the nav bar and browser tab
- **Tagline**: Shown on the landing page
- **Accent Color**: Primary color with visual picker and presets
- **Logo**: Upload PNG/JPG/SVG (served at `/branding/logo`)
- **Landing Content**: Full Markdown support for the hero section

When branding is customized, the default TinyIce marketing content is replaced with your content.

## Monitoring & Observability

TinyIce provides built-in Prometheus metrics at `/metrics` (requires Basic Auth):

- **Listeners**: Total and per-mount counts
- **Throughput**: Bytes in/out per stream
- **System**: Memory usage, goroutines, GC stats, uptime

### Grafana Dashboard

Example configurations in the repository:
- [monitoring/grafana-dashboard.json](monitoring/grafana-dashboard.json)
- [monitoring/prometheus.yml](monitoring/prometheus.yml)

## Command Line Usage

```bash
./tinyice [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `0.0.0.0` | Network interface to bind to |
| `-port` | `8000` | HTTP/Icecast port |
| `-https-port` | `443` | HTTPS port |
| `-use-https` | `false` | Enable HTTPS |
| `-auto-https` | `false` | Automatic SSL via Let's Encrypt |
| `-domains` | | Comma-separated domains for SSL |
| `-config` | `tinyice.json` | Config file path |
| `-log-file` | | Log output file |
| `-auth-log-file` | | Separate auth audit log |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-json-logs` | `false` | Structured JSON logging |
| `-daemon` | `false` | Run in background |
| `-pid-file` | | PID file path |

## Makefile

```bash
make build     # Full build: frontend + Go binary
make generate  # Rebuild frontend only (go generate)
make quick     # Go-only build (skip frontend)
make dev       # Run frontend dev server
make clean     # Remove build artifacts
```

## Embedding the Player

```html
<iframe
    src="https://your-server.com/embed/live"
    width="100%"
    height="80"
    frameborder="0"
    allow="autoplay"
></iframe>
```

## Performance

See [PERFORMANCE.md](PERFORMANCE.md) for detailed hardware and traffic estimates.

## Contributing

Contributions are welcome! Please see [DEVELOPERS.md](DEVELOPERS.md) for an architectural overview and onboarding guide.

## License

Distributed under the Apache License 2.0. See `LICENSE` for more information.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
