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
    <td width="50%" align="center">
      <a href="assets/screenshots/landing.png"><img src="assets/screenshots/landing.png" width="100%" alt="Landing page" /></a>
      <sub>Landing</sub>
    </td>
    <td width="50%" align="center">
      <a href="assets/screenshots/admin-dashboard.png"><img src="assets/screenshots/admin-dashboard.png" width="100%" alt="Admin dashboard" /></a>
      <sub>Admin dashboard</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <a href="assets/screenshots/admin-autodj.png"><img src="assets/screenshots/admin-autodj.png" width="100%" alt="AutoDJ" /></a>
      <sub>AutoDJ</sub>
    </td>
    <td width="50%" align="center">
      <a href="assets/screenshots/developers.png"><img src="assets/screenshots/developers.png" width="100%" alt="Developer portal" /></a>
      <sub>Developer portal</sub>
    </td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="https://github.com/user-attachments/assets/243914ac-edb5-472c-aba7-699af987da9f" width="75%" alt="Video Stream player" />
      <br /><sub>Video stream player</sub>
    </td>
  </tr>
</table>

---

## At a glance

| | |
|---|---|
| **Ingest** | Icecast2 SOURCE/PUT · RTMP (H.264 + AAC/MP3) · SRT MPEG-TS · WebRTC browser broadcasting · Icecast relay pull |
| **Output** | Icecast passthrough · HLS audio · **HLS audio + video** · **WHEP / WebRTC playback** · **OBS simulcast (master playlist)** · embeddable player |
| **Codecs** | MP3 · Ogg Opus · Ogg Vorbis · FLAC / FLAC-in-Ogg · WAV (8/16/24/32-bit & float) · H.264 · AAC-LC |
| **Transcoder** | Pure-Go multi-codec decode → MP3 or Opus with automatic resampling. No FFmpeg dependency. |
| **AutoDJ** | Multi-instance, keyframe-accurate pacing, shuffle/loop/queue, MPD protocol per instance, external `song_command` hook |
| **Auth** | Username + bcrypt password · Passkeys (WebAuthn) · OIDC/OAuth2 · Bearer API tokens · per-mount source passwords |
| **Player** | 16:9 video layout · live poster thumbnails · stream stats overlay (codec/res/fps/GOP/bitrate, dropped frames, buffer, latency) · DVR seek (last 60 s) |
| **Ops** | Prometheus metrics · structured logging · ACME auto-HTTPS (Let's Encrypt) · zero-downtime hot-swap · Docker image (GHCR multi-arch) |
| **Deploy** | One static Go binary (≈25 MB) with all assets embedded · `make build` also produces multi-stage Docker image |

---

## What's new in v2.1.0

Templated webhooks with presets, AutoDJ track-start hooks, lower-latency
HLS, an honest viewer count — and the in-process self-updater is gone
(distros own the binary; manual install of a new release is one line).

<details open>
<summary><strong>Webhooks v2 &amp; track-start hooks</strong> — templated bodies, presets, <code>now_playing</code>, AutoDJ <code>on_play_command</code></summary>

- New **`now_playing`** event fires once per track on every AutoDJ mount, alongside the existing `source_connect` / `source_disconnect` / `metadata_update` / `security_lockout` events.
- **Templated webhook bodies** with Go `text/template` syntax. Empty template falls back to the legacy JSON envelope so existing receivers keep working unchanged.
- **Per-webhook HTTP method, Content-Type, custom headers**, and a free-form body template. For `GET` / `HEAD` the rendered body is appended as a query string — that's how the TuneIn AIR `Playing.ashx` preset works from a single template.
- **Always-available variables**: `{{.Event}}`, `{{.Timestamp}}`, `{{.UnixTimestamp}}`, `{{.Date}}`, `{{.Time}}`, `{{.Hostname}}`, `{{.BaseURL}}`, `{{.Version}}`. When the event payload carries a mount, `{{.MountURL}}` and `{{.PlayerURL}}` are derived from `base_url`. Helper funcs: `urlencode`, `json`, `lower`, `upper`.
- **Presets** for Discord, Slack, Mattermost, Microsoft Teams, Telegram, ntfy.sh, Pushover, TuneIn AIR `Playing.ashx`, generic JSON envelope, and webhook.site (for debugging templates).
- **Admin UI**: dedicated `/admin/webhooks` page with add / edit / delete, per-row Test button (fires a sample payload), preset dropdown, click-to-insert placeholder helper.
- **AutoDJ `on_play_command`**: shell hook executed at track-start with `TINYICE_ARTIST` / `TINYICE_TITLE` / `TINYICE_ALBUM` / `TINYICE_FILE` / `TINYICE_MOUNT` env vars, for integrations that prefer a script over an HTTP endpoint.

See [Webhooks](#webhooks) for the full reference.

</details>

<details open>
<summary><strong>Player &amp; UX</strong> — stats overlay, posters, DVR, viewer count, listening time</summary>

- New **stream stats overlay** (STATS button in the player's bottom strip): transport (HLS/WebRTC/Icecast), audio codec &amp; bitrate, video codec/resolution/FPS/GOP/bitrate, plus client-side buffer seconds, dropped frames + drop %, and HLS live-edge latency.
- Live **poster thumbnails** on landing &amp; explore cards: the player snapshots the `<video>` element a few seconds into playback and POSTs a JPEG to the server, which caches it per mount and serves it at `/<mount>/poster.jpg`.
- **Viewer counting** for browser playback: HLS playlist polls and WHEP offers feed a 30 s sliding-window IP tracker. Video mounts no longer show "0 listeners" while people are actively watching, and the player renders "viewers" for video / "listeners" for audio.
- **Listening time** indicator next to the listener/viewer count; resets on pause.
- 60 s **DVR window**: every video stream is seekable backwards a minute by default — no extra config, hls.js shows a scrubbable timeline.

</details>

<details open>
<summary><strong>Lower latency &amp; ABR</strong> — 1 s segments, master playlist, WHEP egress</summary>

- HLS default segment 4 s → **1 s** with keyframe-aligned flushes; segments still cleanly start on IDR even when the encoder's GOP is longer.
- **OBS simulcast / master playlist** at `/<primary>/master.m3u8`: declare a `variant_groups` map in config, point each OBS output at its own RTMP mount (e.g. `/live`, `/live_720`, `/live_480`), and the server emits a multivariant playlist with `BANDWIDTH` and `RESOLUTION` derived from live ingest metrics.
- **WHEP** (`POST /<mount>/whep`, `application/sdp` in/out) for sub-second WebRTC viewer playback. Gated behind `?webrtc=1` while we shake out B-frame handling; HLS stays the default.
- Viewer-side **video metrics** sampled in the ingest path (pure-Go H.264 SPS parser, 1 s rolling window for fps/bitrate, average GOP). Surfaced under each mount in the admin Streams table.

</details>

<details>
<summary><strong>Stability fixes since v2.0.0-beta.6</strong></summary>

- **Audio buffers**: listener default burst 128 → 512 KiB, transcoder input burst 32 → 256 KiB, listener read chunk 4 → 64 KiB. Tracking 2048 Ogg page offsets (was 128) so a generous burst isn't silently truncated to a few seconds — fixes the "underrun every 4–5 s on reconnect".
- **Bandwidth meter**: the dashboard's "Inbound" / "Outbound" stats were showing cumulative byte totals as MB/s; now compute a per-tick rate.
- **Ban false-positives**: a player hammering an offline mount no longer trips the scan-attempt lockout. Distinct-path threshold (25) replaces raw hit count, and configured / known-extension prefetch paths are skipped entirely.
- **Docker on GHCR**: `ghcr.io/datanoisetv/tinyice:beta` (newest beta), `:latest` (newest stable), `:vX.Y.Z`, `:X.Y`, `:X` — all multi-arch (linux/amd64, linux/arm64) — published on every release tag.

</details>

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

4. **OBS → Settings → Output**: Video Encoder `x264` (or a hardware H.264 encoder), Audio Encoder `AAC` (default) or `MP3`, **1 s keyframe interval** (matches the default segment size for lowest latency; 2 s is fine too).

5. Click **Start Streaming**. Server log shows `RTMP: Publishing started mount=/<name>` and `Parsed AVC config`.

6. **Watch it** one of four ways:
   - **Browser player**: `https://<host>/player/<mount>` — auto 16:9 `<video>` layout, click the **STATS** button for codec / resolution / fps / GOP / bitrate / dropped frames / buffer / latency. The bottom strip also shows live viewer count and listening time.
   - **Direct HLS**: `https://<host>/<mount>/playlist.m3u8` — VLC, mpv, ffplay, Safari, iOS.
   - **WebRTC (sub-second latency, opt-in)**: append `?webrtc=1` to the player URL. Requires the OBS encoder to publish without B-frames (Profile = `baseline`, or `bf=0` in x264 params).
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
- **Burst size** override (default 512 KB — controls the "instant start" at the cost of a little extra latency)

### OBS simulcast (ABR ladder)

Run multiple OBS outputs to different mounts (one per rendition) and group
them into a single multivariant playlist:

```json
{
    "variant_groups": {
        "/live": ["/live", "/live_720", "/live_480"]
    }
}
```

`/live/master.m3u8` then advertises all three with `BANDWIDTH` and
`RESOLUTION` derived from each member's live ingest metrics. The built-in
player auto-detects the master playlist and lets hls.js do ABR; falls back
to `/live/playlist.m3u8` when no group is configured.

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

## Webhooks

Outbound HTTP notifications for stream and AutoDJ events. Manage from
**Admin → Webhooks** or via the JSON API at `/api/webhooks` (super-admin
only). URLs are validated against the same SSRF guard as relays —
loopback, private and link-local addresses are rejected.

### Events

| Event | Fired when |
|---|---|
| `now_playing` | A new track starts on an AutoDJ mount. Carries `mount`, `name`, `artist`, `title`, `album`, `file`, `format`, `bitrate`, `duration_seconds`. |
| `source_connect` | An external source (broadcaster) connects to a mount. |
| `source_disconnect` | An external source disconnects from a mount. |
| `metadata_update` | Mount metadata (title / artist / song) changes. |
| `security_lockout` | An IP is locked out for repeated auth failures. |

### Body templates

Webhooks have an optional `body_template` rendered with Go's
`text/template` syntax. Leaving it empty sends the legacy JSON envelope
(`{event, timestamp, hostname, data}`). Filling it in lets you match
whatever shape the receiver wants.

**Always-available variables** (every event, every template):

| Variable | Example |
|---|---|
| `{{.Event}}` | `now_playing` |
| `{{.Timestamp}}` | `2026-05-04T19:30:00Z` |
| `{{.UnixTimestamp}}` | `1809974400` |
| `{{.Date}}` · `{{.Time}}` | `2026-05-04` · `19:30:00` |
| `{{.Hostname}}` · `{{.BaseURL}}` · `{{.Version}}` | from config |

When the payload carries a `mount`, the dispatcher derives `{{.MountURL}}`
(public listen URL) and `{{.PlayerURL}}` (embedded player) from
`base_url`. Use `{{if .MountURL}}…{{end}}` to no-op gracefully when
`base_url` isn't set.

**Helper funcs**: `urlencode`, `json`, `lower`, `upper`. Snake-case payload
keys also expose a CamelCase alias — `{{.DurationSeconds}}` and
`{{.duration_seconds}}` both work.

For `GET` / `HEAD` webhooks the rendered body is appended to the URL as
a query string instead of being sent as a request body — that's how the
TuneIn AIR preset hits `Playing.ashx` from a single template.

### Presets

The editor's **Load preset** dropdown ships templates for: Discord,
Slack, Mattermost, Microsoft Teams (MessageCard), Telegram bot
`sendMessage`, ntfy.sh, Pushover, TuneIn AIR `Playing.ashx`, generic
JSON, and webhook.site (echo for debugging). Loading a preset fills
method, headers and body — the URL field is left alone if you've
already typed one.

### Example: Discord "now playing"

```json
{
  "name": "Discord — #now-playing",
  "url": "https://discord.com/api/webhooks/<channel-id>/<token>",
  "method": "POST",
  "events": ["now_playing"],
  "body_template": "{\"username\":\"TinyIce\",\"content\":\":musical_note: **{{.Mount}}** — {{.Artist}} – {{.Title}}{{if .MountURL}} — [Listen]({{.MountURL}}){{end}}\"}",
  "enabled": true
}
```

### Track-start without HTTP: `on_play_command`

If you'd rather run a local script than an HTTP webhook, AutoDJ exposes
an `on_play_command` per instance. The command runs asynchronously at
each track start with the metadata as env vars (`TINYICE_ARTIST`,
`TINYICE_TITLE`, `TINYICE_ALBUM`, `TINYICE_FILE`, `TINYICE_MOUNT`):

```bash
#!/bin/bash
curl -s "https://air.radiotime.com/Playing.ashx?partnerId=$P&partnerKey=$K&id=$ID&title=${TINYICE_TITLE}&artist=${TINYICE_ARTIST}"
```

---

## Admin UI

- **Dashboard**: live bandwidth (in + out), listeners, streams, health.
- **Streams**: create, edit (password / visibility / enabled / burst), kick source or listeners, remove.
- **AutoDJ**: full CRUD, inline edit, external `song_command` (next-track selector) and `on_play_command` (track-start notifier) hooks.
- **Studio**: 3-column live control — library browser, playlist editor, transport, visualiser, mount switcher.
- **Go Live**: browser WebRTC broadcasting with device picker, spectrum analyser, level meters + headroom in dB.
- **Transcoders**: MP3 and Opus targets with per-instance Opus application / frame size / complexity / VBR knobs.
- **Relays**: pull streams from upstream Icecast servers with in-stream ICY metadata parsing.
- **Users**: roles (super-admin, admin, DJ), passkey enrolment, OIDC linking, bearer-token management.
- **Webhooks**: outbound HTTP notifications for stream + AutoDJ events; templated bodies, custom headers/method, preset library (Discord, Slack, Teams, Telegram, ntfy, Pushover, TuneIn AIR, …), per-row Test button.
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
