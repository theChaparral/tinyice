<div align="center">

# TinyIce

![TinyIce Logo](https://raw.githubusercontent.com/DatanoiseTV/tinyice/main/assets/logo.png?v=2)

**One binary. Audio and video. Scales to six figures of listeners.**

Icecast-compatible streaming server with RTMP/SRT/WebRTC ingest, pure-Go
audio transcoding, HLS audio+video output, an AutoDJ with MPD remote
control, and a built-in admin SPA. Deploy anywhere in seconds.

[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go)](https://go.dev)

[Quick start](#quick-start) · [Stream from OBS](#stream-video-from-obs) · [Configuration](#configuration) · [API](#http-api) · [Admin UI](#admin-ui) · [Develop](#developing)

</div>

---

## Screenshots

<table>
  <tr>
    <td><img src="assets/screenshots/landing.png" alt="Landing page" /></td>
    <td><img src="assets/screenshots/admin-dashboard.png" alt="Admin dashboard" /></td>
  </tr>
  <tr>
    <td><img src="assets/screenshots/admin-autodj.png" alt="AutoDJ" /></td>
    <td><img src="assets/screenshots/developers.png" alt="Developer portal" /></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/243914ac-edb5-472c-aba7-699af987da9f" alt="Video Stream" /></td>
    <td></td>
  </tr>
</table>

---

## At a glance

| | |
|---|---|
| **Ingest** | Icecast2 SOURCE/PUT · RTMP (H.264 + AAC/MP3) · SRT MPEG-TS · WebRTC browser broadcasting · Icecast relay pull |
| **Output** | Icecast passthrough · HLS audio · **HLS audio + video** · WebRTC playback · embeddable player |
| **Codecs** | MP3 · Ogg Opus · Ogg Vorbis · FLAC / FLAC-in-Ogg · WAV (8/16/24/32-bit & float) · H.264 · AAC-LC |
| **Transcoder** | Pure-Go multi-codec decode → MP3 or Opus with automatic resampling. No FFmpeg dependency. |
| **AutoDJ** | Multi-instance, keyframe-accurate pacing, shuffle/loop/queue, MPD protocol per instance, external `song_command` hook |
| **Auth** | Username + bcrypt password · Passkeys (WebAuthn) · OIDC/OAuth2 · Bearer API tokens · per-mount source passwords |
| **Ops** | Prometheus metrics · structured logging · ACME auto-HTTPS (Let's Encrypt) · zero-downtime hot-swap · Docker image |
| **Deploy** | One static Go binary (≈25 MB) with all assets embedded · `make build` also produces multi-stage Docker image |

---

## What's new in v2.0.0-beta.6

Video streaming + a round of audio/auth/ops hardening.

<details>
<summary><strong>Video pipeline end-to-end</strong> — RTMP/SRT → HLS A/V → browser or mpv</summary>

- RTMP H.264 + AAC or H.264 + MP3 ingest. OBS's Server-path = mount, Stream-key = password, exactly as OBS expects.
- SRT MPEG-TS demux now delivers both audio *and* video (the video callback was never registered previously).
- HLS A/V at `/<mount>/playlist.m3u8`: one PES per frame, real 90 kHz PTS + DTS from the FLV composition-time field (no more "boomeranging" on B-frame streams), AAC emitted as ADTS with PMT `stream_type = 0x0F`, PCR on every PES, keyframe-aligned segment boundaries, accurate `EXTINF` / `TARGETDURATION`.
- Encoder-reconfig checkpoint: when OBS restarts its encoder mid-session, the buffer keyframe index is cleared and new listeners are fast-forwarded past the pre-reconfig bytes, so a viewer tuning in post-reconfig doesn't crash the decoder.
- Raw `/<mount>/video` seeks to the latest IDR and prepends cached SPS/PPS for debug-friendly playback with `mpv http://host/<mount>/video`.
- Built-in browser player switches to a dedicated 16 : 9 video layout when the mount has video. Safari/iOS play HLS natively; Chromium/Firefox load `hls.js` only when needed (dynamic import).

</details>

<details>
<summary><strong>Audio correctness</strong> — multi-codec decode, resampling, Ogg rewriter</summary>

- Pure-Go multi-codec decode for the transcoder + AutoDJ: MP3, Ogg Opus, Ogg Vorbis, FLAC, FLAC-in-Ogg, WAV (8/16/24/32-bit PCM and IEEE float, mono or stereo).
- Automatic resampler when targeting Opus (locked at 48 kHz) — MP3/Vorbis/FLAC/WAV sources no longer play 8.8 % too fast.
- MP3 bitrate is actually honoured (the bundled `shine` encoder's internal bitrate index is updated).
- Per-listener Ogg page rewriter regenerates the bitstream serial and rebases granule positions, so late joiners on long-running Ogg streams don't see a multi-minute granule jump that strict decoders filled with silence (the old "robotic voice" bug).
- The Icecast SOURCE handler captures BOS/Tags pages so late-joining listeners receive a playable start.

</details>

<details>
<summary><strong>Security & operations</strong> — OIDC hardening, session expiry, shutdown, trusted proxies</summary>

- OIDC: state bound to the originating browser, nonce set and ID-token-verified, `email_verified` required (GitHub `/user/emails` is consulted; only primary + verified addresses log in).
- Sessions have absolute 7-day and sliding 24-hour expiry with a periodic reaper. Login rotates the cookie (no fixation). Deleted users have their live sessions purged immediately.
- Login is constant-time — bcrypt always runs, even for unknown usernames.
- `TrustedProxies` config + `X-Forwarded-For` handling so scan-detection and bans work behind nginx / Caddy / Traefik without auto-whitelisting loopback.
- Auto-updater verifies SHA-256 from `checksums.txt` before overwriting the running binary.
- RTMP shutdown closes live publisher connections so `Ctrl+C` quits within seconds, even mid-stream.
- CSRF on every mutating admin form. Super-admin gates on transcoder/webhook CRUD. Webhook/relay URLs reject loopback and RFC1918 addresses (SSRF).
- `SaveConfig` is serialised across goroutines so concurrent admin writes can't shred the JSON.
- Auto-remove dormant streams after 2 min of silence (the feature existed but wasn't enabled).
- YP directory reporter emits proper `add` / `touch` / `remove` lifecycle, not just repeated `add`s.

</details>

<details>
<summary><strong>Admin UI</strong> — edit flows, DOMPurified landing, toasts</summary>

- **Edit** for Streams, Transcoders, Relays, AutoDJ. All in-place updates, no more destroy-and-recreate on a save-button click.
- Transcoder editor exposes Opus application / frame size / complexity / VBR and a sample-rate override.
- Landing markdown goes through DOMPurify before `dangerouslySetInnerHTML` (closed an admin → visitor XSS).
- Error toasts on every mutation path so HTTP 403 / 500 no longer disappear silently.
- SSE reconnect no longer duplicates event delivery.

</details>

<details>
<summary><strong>Build / packaging</strong></summary>

- Multi-stage `Dockerfile` (+ `.dockerignore`) for container deploys.
- `make build` rebuilds frontend + binary; `go generate ./server/...` pulls in hls.js + DOMPurify as lazy chunks so audio-only pages don't pay the JS cost.

</details>

---

## Quick start

### 1. Install

```bash
# Latest release binary
curl -LJO "https://github.com/DatanoiseTV/tinyice/releases/latest/download/tinyice-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
chmod +x tinyice-*
mv tinyice-* tinyice

# Or Docker — pre-built multi-arch images on GHCR (linux/amd64, linux/arm64)
# Use :beta while we're in the 2.0 beta line; :latest mirrors the newest release.
docker run --rm -p 8000:8000 -v tinyice-data:/data ghcr.io/datanoisetv/tinyice:beta
# Pin a specific release: ghcr.io/datanoisetv/tinyice:v2.0.0-beta.8

# Or from source — Go 1.25+, Node 20+
git clone https://github.com/DatanoiseTV/tinyice.git
cd tinyice
make build
```

### 2. First run

```
FIRST RUN: SECURE CREDENTIALS GENERATED
  Admin Password:  Oy9…
  Default Source Password: Rm3…
  Live Mount Password:     8fX…
```

Save these, then open **http://localhost:8000**.

### 3. Stream

| Source | How |
|---|---|
| **BUTT / Mixxx / LadioCast** | Icecast 2 · server `host:8000` · mount `/live` · password = *Live Mount Password* |
| **OBS** | See [below](#stream-video-from-obs) |
| **FFmpeg** | `ffmpeg -re -i input.mp3 -f mp3 -content_type audio/mpeg icecast://source:<pw>@host:8000/live` |
| **SRT** | `srt://host:9000?streamid=#!::r=live,m=publish,key=<pw>` from OBS, ffmpeg, or a DVB mux |
| **Browser** | Go to **Admin → Go Live** for WebRTC mic/line broadcasting |
| **Files** | Configure an AutoDJ (Admin → AutoDJ) pointed at a directory of audio files |

---

## Stream video from OBS

TinyIce accepts H.264 + AAC (or H.264 + MP3) over RTMP and produces HLS
audio + video at `/<mount>/playlist.m3u8`.

1. **Enable RTMP** in `tinyice.json`:
   ```json
   "ingest": { "rtmp_enabled": true, "rtmp_port": "1935" }
   ```

2. **Create a mount** in Admin → Streams → Add Mount. The password is your OBS Stream Key.

3. **OBS → Settings → Stream** (Service: Custom):
   - **Server**: `rtmp://<host>/<mount>` — e.g. `rtmp://radio.example.com/live`
   - **Stream Key**: the mount's source password
   > The classic single-URL form `rtmp://<host>/` + Stream Key `<mount>?key=<password>` also works.

4. **OBS → Settings → Output**: Video Encoder `x264` (or a hardware H.264 encoder), Audio Encoder `AAC` (default) or `MP3`, 2 s keyframe interval.

5. Click **Start Streaming**. Server log shows `RTMP: Publishing started mount=/<name>` and `Parsed AVC config`.

6. **Watch it** one of three ways:
   - **Browser player**: `https://<host>/player/<mount>` — automatically renders a 16 : 9 `<video>` layout.
   - **Direct HLS**: `https://<host>/<mount>/playlist.m3u8` — VLC, mpv, ffplay, Safari, iOS.
   - **Raw debug**: `http://<host>/<mount>/video` — H.264 Annex-B for `mpv`.

---

## Configuration

TinyIce stores configuration in a single JSON file (`tinyice.json`). The
setup wizard writes a minimal working version on first run.

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
    "ingest": {
        "rtmp_enabled": true,
        "rtmp_port": "1935",
        "srt_enabled": true,
        "srt_port": "9000"
    },
    "trusted_proxies": ["127.0.0.1", "10.0.0.0/8"],
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

Ports 80/443 need to be reachable for ACME challenges. On Linux without root:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./tinyice
```

### Trusted proxies

If TinyIce sits behind nginx / Caddy / Traefik / Cloudflare tunnel, add the
proxy's address(es) to `trusted_proxies` so `X-Forwarded-For` is honoured for
scan-detection / bans. When the list is **non-empty**, loopback stops being
auto-whitelisted — you'll see real client IPs instead of `127.0.0.1`.

### Advanced per-mount settings

Admin → Streams → Edit lets you set per-mount:

- Source **password** (takes precedence over the default source password)
- **Visibility** in public listings
- **Enabled / disabled** (disabled mounts refuse new SOURCE connections)
- **Burst size** override (default 128 KB — controls the "instant start" at the cost of a little extra latency)

### Branding

Admin → Settings → Branding customises the public landing page:

- **Site name** & **tagline**
- **Accent colour** (visual picker + hex)
- **Logo** (PNG/JPG/SVG, served at `/branding/logo`)
- **Landing markdown** (full GFM via `marked`, sanitised with DOMPurify)

---

## HTTP API

All management operations have a JSON API under `/api/*`. Auth via session
cookie (web UI) or bearer token (scripts / CI / integrations).

**Interactive docs**: `/api/docs` (Swagger UI) · **OpenAPI spec**: `/api/openapi.yaml`

```bash
# Create a token in Admin → API Tokens, then:
TOKEN="ti_your_token_here"

# List streams (each entry has has_video=true if the mount has a /video sub-mount)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/streams

# Create a mount
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"mount": "/radio", "password": "secret"}' \
    http://localhost:8000/api/streams

# Toggle visibility in-place
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"mount":"/radio","visible":true}' http://localhost:8000/api/streams

# Server stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/stats
```

Every AutoDJ / transcoder / relay action in the admin UI has a JSON API
equivalent. See `/api/docs` for the full list.

---

## Admin UI

- **Dashboard**: live bandwidth (in + out), listeners, streams, health.
- **Streams**: create, edit (password / visibility / enabled / burst), kick source or listeners, remove.
- **AutoDJ**: full CRUD, inline edit, external `song_command` hook.
- **Studio**: 3-column live control — library browser, playlist editor, transport, visualiser, mount switcher.
- **Go Live**: browser WebRTC broadcasting with device picker, spectrum analyser, level meters + headroom in dB.
- **Transcoders**: MP3 and Opus targets with per-instance Opus application / frame size / complexity / VBR knobs.
- **Relays**: pull streams from upstream Icecast servers with in-stream ICY metadata parsing.
- **Users**: roles (super-admin, admin, DJ), passkey enrolment, OIDC linking, bearer-token management.
- **Security**: IP ban / whitelist with CIDR, audit log tab with filters.
- **Pending Users**: approve or deny users who signed up via OIDC.
- **Settings**: HTTPS, directory listing, branding, SMTP, auto-update.

---

## Observability

- **Prometheus** `/metrics` — total + per-mount listener counts, bytes in/out, memory, goroutines, GC stats, uptime. Example Grafana dashboard in [`monitoring/grafana-dashboard.json`](monitoring/grafana-dashboard.json) and a scrape config in [`monitoring/prometheus.yml`](monitoring/prometheus.yml).
- **Structured logs** — `-json-logs` for ELK/Loki ingestion; `-auth-log-file` splits auth events into a separate audit trail.
- **Health monitor** — auto-removes streams that go silent for 2 min; exposed per-stream in `/api/streams`.
- **SSE events** on `/events` — live metadata / listener / stream events for custom dashboards.

---

## Command line

```
./tinyice [options]
```

| Flag | Default | Description |
|---|---|---|
| `-host` | `0.0.0.0` | Network interface to bind |
| `-port` | `8000` | HTTP/Icecast port |
| `-https-port` | `443` | HTTPS port |
| `-use-https` | `false` | Enable HTTPS |
| `-auto-https` | `false` | Automatic SSL via Let's Encrypt |
| `-domains` | | Comma-separated domains for the ACME cert |
| `-config` | `tinyice.json` | Config file path |
| `-log-file` | | Log output file (stdout if unset) |
| `-auth-log-file` | | Separate auth audit log |
| `-log-level` | `info` | `debug` · `info` · `warn` · `error` |
| `-json-logs` | `false` | Structured JSON logging |
| `-daemon` | `false` | Run in background |
| `-pid-file` | | PID file path |
| `-autoupdate` | `false` | Check + apply signed updates every hour |

Subcommands: `./tinyice dump-config`, `./tinyice set <key> <value>`, `./tinyice get <key>`, `./tinyice reload`.

---

## Embedding the player

```html
<iframe
    src="https://your-server.com/embed/live"
    width="100%" height="80" frameborder="0"
    allow="autoplay"
></iframe>
```

The embed detects video mounts and renders a `<video>` instead of the compact audio bar when appropriate.

---

## Developing

Requires **Go 1.25+** and **Node.js 20+**.

```bash
make build       # frontend + Go binary
make generate    # frontend only (go generate ./server/...)
make quick       # Go-only (reuse existing dist/)
make dev         # Vite frontend dev server (hot reload)
make clean       # remove build artifacts
```

Frontend is **Preact + @preact/signals + Vite**, in `server/frontend/src/`. All dist assets are embedded into the Go binary via `go:embed`, so the released binary is self-contained.

See [`DEVELOPERS.md`](DEVELOPERS.md) for the architectural overview, [`ARCHITECTURE.md`](ARCHITECTURE.md) for the internals, and [`PERFORMANCE.md`](PERFORMANCE.md) for hardware sizing.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

---

<sub>Built by [DatanoiseTV](https://github.com/DatanoiseTV) · [file a bug](https://github.com/DatanoiseTV/tinyice/issues)</sub>
