# TinyIce Streaming Hardening & Multi-Protocol Design

## Overview

Comprehensive overhaul of TinyIce's streaming engine to make it production-grade, multi-protocol, multi-tenant, and video-ready. The work decomposes into 6 phases, each building on the previous.

---

## Phase 1: Harden Existing Streaming

### 1.1 Buffer & Synchronization Fixes

**Problem:** The circular buffer and Ogg page sync have edge cases that can cause audio corruption or listener disconnects under load.

**Changes to `relay/buffer.go`:**
- Add wrap-around read support: `ReadAt` currently stops at buffer boundary instead of wrapping. A listener read that spans the wrap point gets truncated, causing audio glitches. Fix: when `pos+n > Size`, read the tail segment then read the remainder from offset 0.
- Add `Available()` method returning `Head - (Head - Size)` clamped — useful for health checks.
- Add `Reset()` for clean stream restarts without reallocating.

**Changes to `relay/stream.go`:**
- Guard against `Broadcast()` being called on a closed stream (currently no check — writing to closed listener channels would panic if `Close()` and `Broadcast()` race).
- Add a `closed` atomic bool, checked in `Broadcast()` and `Subscribe()`.
- Fix `Subscribe()` for edge case: when `PageOffsets` is empty and `LastPageOffset` is 0, the current code falls through to `start = s.Buffer.Head`, which means the listener gets no burst at all. Fix: fall back to `s.Buffer.Head - int64(burstSize)` clamped to `validStart` — same as the non-Ogg burst calculation.
- `Subscribe()` must return an error (or second bool) when the stream is closed, to reject new subscriptions after `Close()` has been called.
- Add `BytesIn`/`BytesOut` rate calculation (rolling 10-second window) for health monitoring.

**Changes to `relay/ogg.go`:**
- `FindNextPageBoundary`: validate that the found "OggS" is actually a valid Ogg page header by checking the version byte (must be 0) and that the page has a sane segment table. This prevents false sync on binary data that happens to contain "OggS".

### 1.2 Error Recovery & Reconnection

**Changes to `relay/client.go` (RelayManager):**
- Add exponential backoff with jitter on reconnection (currently fixed 5s). Cap at 60s.
- Add configurable `MaxRetries` (0 = infinite, default).
- Track connection state: `Connecting`, `Connected`, `Reconnecting`, `Failed`.
- Add per-relay health stats: `LastConnected`, `LastError`, `ReconnectCount`, `Uptime`.
- Use a proper HTTP client with timeouts instead of `http.DefaultClient` (no timeouts = hangs forever on DNS/TLS issues).

**Changes to `relay/streamer.go` (AutoDJ):**
- The `runStreamerLoop` busy-polls with `time.Sleep(100ms)` when stopped. Replace with `sync.Cond` or a channel-based approach to eliminate CPU waste.
- Add file validation before streaming (check file exists, is readable, has valid header) to avoid the 1-second error sleep loop on corrupt files.
- Handle `decoder` errors more granularly: distinguish between "corrupt file" (skip) vs "I/O error" (retry) vs "context cancelled" (stop).

**Changes to `relay/webrtc.go`:**
- `HandleSourceOffer` doesn't track the PeerConnection — no way to disconnect a WebRTC source. Add a `sources` map keyed by mount, with `DisconnectSource(mount)` method.
- `streamToTrack`: the 512KB sync search limit is arbitrary. Make it configurable and add a timeout (if no OggS found in 5 seconds, give up).
- Add ICE restart support for network changes.
- Add DTLS fingerprint verification logging for security auditing.

### 1.3 Connection Health Monitoring

**New file: `relay/health.go`:**
- `StreamHealthMonitor` goroutine per stream: checks `LastDataReceived` age, listener count trends, buffer utilization, byte rate.
- Expose health status: `Healthy`, `Degraded` (no data for >5s), `Dead` (no data for >30s).
- Auto-remove dead streams after configurable timeout.
- Emit webhook events for health state transitions.
- Track per-listener stats: bytes sent, drops, latency estimate.

**Changes to `server/handlers_stream.go` (`serveStreamData`):**
- Add slow-listener detection and graceful disconnect. Currently a slow listener just gets `BytesDropped` incremented but keeps consuming resources. In the `ReadAt` loop (the inner `for` in `serveStreamData`), track consecutive skip count. After N consecutive skips (configurable, default 5), disconnect with a log warning.
- Add listener connection duration tracking for analytics.

### 1.4 Graceful Degradation

**Changes to `server/handlers_stream.go`:**
- `handleListener`: the fallback mount logic re-checks every 10 seconds via `recoveryTicker` (line 221), but there's a race — if the primary comes back and immediately goes down again, listeners ping-pong. Add hysteresis: track when primary was first seen alive; only switch back after it has been continuously alive for 30 seconds. When switching mounts, the listener must re-subscribe from the new stream's current head (no burst carryover between different streams).
- Add `X-Stream-Status` response header for load balancers to probe.
- Send silence/comfort noise instead of hanging when buffer underruns.

---

## Phase 2: Protocol-Agnostic Pipeline Architecture

### 2.1 Core Abstractions

**New file: `relay/pipeline.go`:**

```go
// MediaType represents the kind of media in a track
type MediaType int
const (
    MediaAudio MediaType = iota
    MediaVideo
)

// Track represents a single media track (audio or video).
// Wraps the existing Stream type for buffer/listener management,
// adding codec metadata and media type classification.
type Track struct {
    Type      MediaType
    Codec     string       // "opus", "mp3", "aac", "h264", "vp8"
    Stream    *Stream      // Reuses existing buffer + listener infrastructure
    Metadata  TrackMetadata
}

// TrackMetadata holds codec-specific information
type TrackMetadata struct {
    SampleRate  int
    Channels    int
    Bitrate     int
    Width       int    // video only
    Height      int    // video only
    FPS         float64 // video only
    CodecExtra  []byte // codec-specific init data (SPS/PPS for H.264, OpusHead, etc.)
}

// IngestSource represents any source of media data
type IngestSource interface {
    Protocol() string          // "icecast", "webrtc", "rtmp", "srt"
    Mount() string
    Tracks() []*Track
    Start(ctx context.Context) error
    Stop()
    Health() SourceHealth
}

// OutputAdapter represents any output format
type OutputAdapter interface {
    Protocol() string          // "icecast", "hls", "dash", "webrtc"
    SupportsMediaType(MediaType) bool
    Start(ctx context.Context, tracks []*Track) error
    Stop()
}

// HTTPOutputAdapter extends OutputAdapter for HTTP-based outputs
type HTTPOutputAdapter interface {
    OutputAdapter
    ContentType() string
    ServeListener(w http.ResponseWriter, r *http.Request) error
}

// PeerOutputAdapter extends OutputAdapter for peer-to-peer outputs (WebRTC)
type PeerOutputAdapter interface {
    OutputAdapter
    HandleOffer(offer webrtc.SessionDescription) (*webrtc.SessionDescription, error)
}

// Pipeline connects sources to outputs through a stream
type Pipeline struct {
    Mount      string
    TenantID   string          // empty = default tenant
    Source     IngestSource
    Outputs    []OutputAdapter
    Tracks     []*Track
    Health     PipelineHealth
    mu         sync.RWMutex
}
```

### 2.2 Refactor Existing Code Into Adapters

**`relay/ingest_icecast.go`** — wraps current `handleSource` logic as an `IngestSource`.

**`relay/ingest_webrtc.go`** — wraps current `WebRTCManager.HandleSourceOffer` as an `IngestSource`.

**`relay/ingest_autodj.go`** — wraps current `Streamer` as an `IngestSource`.

**`relay/ingest_relay.go`** — wraps current `RelayManager` pull logic as an `IngestSource`.

**`relay/output_icecast.go`** — wraps current `serveStreamData` as an `OutputAdapter` (progressive HTTP streaming).

**`relay/output_webrtc.go`** — wraps current `streamToTrack` as an `OutputAdapter`.

The existing `Stream` struct becomes the internal implementation of a single-track audio `Pipeline`. All existing behavior is preserved — the adapters delegate to the same buffer/broadcast/subscribe mechanisms.

### 2.3 Pipeline Manager

**New file: `relay/pipeline_manager.go`:**
- Replaces the current `Relay` as the top-level coordinator.
- Manages pipeline lifecycle: create, start, stop, health-check.
- Routes incoming connections to the correct pipeline by mount + tenant.
- Maintains backward compatibility: `GetOrCreateStream(mount)` still works, internally creating a single-track audio pipeline.

---

## Phase 3: HLS/DASH Output

### 3.1 HLS Output Adapter

**New file: `relay/output_hls.go`:**
- Implements `OutputAdapter` for HLS.
- Segments audio (and later video) into `.ts` or `.m4s` fragments.
- Generates `.m3u8` playlists (live window of last N segments).
- Uses an in-memory ring buffer of segments (no filesystem I/O for performance).
- Configurable segment duration (default 4s for audio, 2s for low-latency).
- Supports LL-HLS with partial segments and `#EXT-X-PRELOAD-HINT`.

**New file: `relay/output_dash.go`:**
- Implements `OutputAdapter` for DASH.
- Generates MPD manifests.
- Shares the same segment ring buffer as HLS where possible.

**Changes to `server/server.go`:**
- Add routes: `GET /{mount}/playlist.m3u8`, `GET /{mount}/segment-{n}.ts`, `GET /{mount}/manifest.mpd`, `GET /{mount}/chunk-{n}.m4s`.

### 3.2 Segment Muxing

**New file: `relay/mux_mpegts.go`:**
- Pure-Go MPEG-TS muxer for HLS segments.
- Audio: AAC in ADTS frames wrapped in TS packets (broadly supported by all players). MP3 in TS packets (also well supported).
- Opus is NOT muxed into MPEG-TS (non-standard, poor player support). Opus streams use fMP4/CMAF containers instead.
- For video: H.264/HEVC NALUs in PES packets with proper PTS/DTS.

**New file: `relay/mux_fmp4.go`:**
- Fragmented MP4 muxer for DASH and CMAF (shared format between HLS fMP4 and DASH).
- Uses `github.com/Eyevinn/mp4ff` (pure Go) for MP4 box construction.
- Handles `init.mp4` generation (moov box with codec config) and `moof+mdat` fragments.
- This is the container used for Opus in HLS (since Opus+MPEG-TS is non-standard).

---

## Phase 4: RTMP/SRT Ingest

### 4.1 RTMP Ingest

**New file: `relay/ingest_rtmp.go`:**
- Implements `IngestSource` for RTMP.
- Uses `github.com/yutopp/go-rtmp` (pure Go, production-tested RTMP library) for the protocol layer.
- Listens on configurable port (default 1935), supports RTMPS (TLS) via existing cert config.
- Demuxes FLV packets into audio track (AAC/MP3) and video track (H.264).
- AAC audio is decoded and re-encoded to Opus/MP3 via the transcoder pipeline.
- H.264 video NALUs are passed through to the video track buffer.
- Authentication: stream key format `{tenant_id}/{mount}?key={source_password}`. Failed auth triggers existing lockout mechanism.
- Rate limit: max 10 handshake attempts per IP per minute.

### 4.2 SRT Ingest

**New file: `relay/ingest_srt.go`:**
- Implements `IngestSource` for SRT.
- Uses `github.com/datarhei/gosrt` for the SRT protocol layer.
- Accepts MPEG-TS over SRT (the standard SRT payload format).
- Demuxes TS packets into audio and video tracks.
- Stream ID parsing for mount/authentication routing.

**Changes to `config/config.go`:**
```go
type IngestConfig struct {
    RTMPEnabled bool   `json:"rtmp_enabled"`
    RTMPPort    string `json:"rtmp_port"`    // default "1935"
    SRTEnabled  bool   `json:"srt_enabled"`
    SRTPort     string `json:"srt_port"`     // default "9000"
    SRTLatency  int    `json:"srt_latency"`  // ms, default 120
}
```

---

## Phase 5: Video Readiness

### 5.1 Multi-Track Buffer Architecture

**Changes to `relay/buffer.go`:**
- Add `KeyframeIndex`: a secondary index tracking absolute offsets of keyframes (IDR frames for H.264). This enables:
  - New video listeners starting at the nearest keyframe.
  - HLS/DASH segment boundaries aligned to keyframes.
- Increase default buffer size for video tracks (8MB vs 512KB for audio).

**Changes to `relay/pipeline.go`:**
- `Pipeline` supports multiple `Track` instances (one audio + one video).
- Synchronization: tracks share a common `PresentationClock` based on PTS/DTS timestamps.
- A/V sync: output adapters receive frames from both tracks and mux them together using presentation timestamps.

### 5.2 Video Codec Support

**New file: `relay/codec_h264.go`:**
- H.264 NALU parser: identifies keyframes (IDR), SPS, PPS.
- Extracts codec configuration for init segments.
- Keyframe detection for buffer indexing and segment alignment.

**New file: `relay/codec_aac.go`:**
- AAC ADTS parser for RTMP ingest (RTMP typically carries raw AAC).
- ADTS frame boundary detection for proper segmentation.

### 5.3 Video-Capable Output

- HLS/DASH adapters already handle video tracks via the muxers from Phase 3.
- WebRTC output gets H.264/VP8 track support (via pion/webrtc — already supports video).
- Progressive HTTP (Icecast) remains audio-only — this is by design.

---

## Phase 6: Multi-Tenancy

### 6.1 Tenant Model

**New file: `relay/tenant.go`:**
```go
type Tenant struct {
    ID          string
    Name        string
    Plan        string            // "free", "starter", "pro", "enterprise"
    Limits      TenantLimits
    Config      *TenantConfig     // Overrides global config per tenant
    Streams     map[string]*Pipeline
    Stats       TenantStats
    APIKeys     []APIKey
    CreatedAt   time.Time
    mu          sync.RWMutex
}

type TenantLimits struct {
    MaxStreams        int   // 0 = unlimited
    MaxListeners      int   // Per stream
    MaxTotalListeners int   // Across all streams
    MaxBitrateKbps    int   // Max source bitrate
    MaxStorageMB      int   // For AutoDJ files
    AllowTranscoding  bool
    AllowRelay        bool
    AllowWebRTC       bool
    AllowRTMP         bool
    AllowSRT          bool
    AllowHLS          bool
    AllowVideo        bool
    BandwidthLimitMB  int64 // Monthly, 0 = unlimited
}

type TenantConfig struct {
    CustomDomain    string
    BrandingConfig  BrandingConfig
    WebhookConfigs  []*WebhookConfig
    SourcePasswords map[string]string // mount -> password hash
}

type TenantStats struct {
    BytesInTotal     int64
    BytesOutTotal    int64
    CurrentListeners int
    PeakListeners    int
    StreamMinutes    int64 // For billing
}
```

### 6.2 Tenant Isolation

**Changes to `relay/relay.go` / `relay/pipeline_manager.go`:**
- All stream operations are scoped by tenant ID.
- Mount points become `/{tenant_id}/{mount}` internally, but exposed as `/{mount}` with tenant resolved from:
  1. Custom domain mapping (preferred for SaaS)
  2. `X-Tenant-ID` header (for API access)
  3. URL prefix `/{tenant_id}/{mount}` (for shared-domain deployments)
  4. Default tenant (backward compat — single-tenant mode)

**Changes to `server/server.go`:**
- Add tenant resolution middleware.
- Rate limiting per tenant.
- Bandwidth metering per tenant (for billing integration).

**Changes to `config/config.go`:**
```go
type MultiTenantConfig struct {
    Enabled       bool              `json:"multi_tenant"`
    DefaultTenant string            `json:"default_tenant"`
    TenantStore   string            `json:"tenant_store"` // "config", "database", "api"
    Tenants       map[string]*Tenant `json:"tenants"`      // For "config" store
}
```

### 6.3 Billing-Ready Hooks

- Tenant stats are persisted to the database on a configurable interval (default 60s).
- Webhook events include tenant ID.
- Expose `/api/tenants/{id}/usage` endpoint for billing system integration.
- Track: stream minutes, listener minutes, bandwidth consumed, peak concurrent listeners.

---

## Implementation Order & Dependencies

```
Phase 1 (Hardening) ─── no dependencies, can start immediately
    │
Phase 2 (Pipeline Abstraction) ─── depends on Phase 1 being stable
    │
    ├── Phase 3 (HLS/DASH) ─── depends on Phase 2 OutputAdapter interface
    │
    ├── Phase 4 (RTMP/SRT) ─── depends on Phase 2 IngestSource interface
    │
    └── Phase 5 (Video) ─── depends on Phase 2 Track abstraction + Phase 3 muxers
         │
Phase 6 (Multi-Tenancy) ─── depends on Phase 2 Pipeline manager (can start partially in parallel)
```

## Key Design Decisions

1. **Pure Go for new code, pragmatic CGO for codecs** — The existing codebase already uses CGO via `opus-go` (wraps libopus). New protocol code (RTMP, MPEG-TS, fMP4, H.264 parsing) will be pure Go. Codec encoding/decoding (Opus, AAC) may use CGO wrappers where no production-quality pure-Go alternative exists. The "single binary" goal is maintained via static linking.

2. **Backward compatible** — single-tenant mode is the default. Existing configs work without changes. The pipeline abstraction wraps existing code rather than replacing it.

3. **Lazy initialization** — RTMP/SRT servers only start if enabled in config. Video track buffers only allocate when a video source connects.

4. **Tenant isolation via composition** — each tenant gets its own `Pipeline` instances, stats, and config. No global mutable state shared between tenants (except the underlying OS resources).

5. **Memory-first, disk-optional** — HLS segments live in ring buffers. No temp files unless persistence is explicitly configured. Memory budget: ~512KB per audio stream, ~8MB per video stream, ~2MB per HLS segment ring (configurable). For 100-tenant SaaS with video, budget ~2GB minimum.

6. **Use existing libraries where mature** — RTMP: use `github.com/yutopp/go-rtmp` (pure Go, production-tested). SRT: use `github.com/datarhei/gosrt` (CGO, accepted exception). fMP4: use `github.com/Eyevinn/mp4ff` (pure Go). MPEG-TS: custom implementation (simple enough for our needs, existing libs are heavyweight).

---

## CGO Dependencies

| Dependency | Purpose | CGO? | Justification |
|-----------|---------|------|---------------|
| `kazzmir/opus-go` | Opus encoding/decoding | Yes | No production-quality pure-Go Opus encoder exists |
| `datarhei/gosrt` | SRT protocol | Yes | SRT is inherently complex (ARQ, encryption, congestion control) |
| `yutopp/go-rtmp` | RTMP protocol | No | Pure Go |
| `Eyevinn/mp4ff` | fMP4 muxing | No | Pure Go |
| `pion/webrtc` | WebRTC | No | Pure Go |

Static linking with `CGO_ENABLED=1` and `-tags netgo` maintains single-binary distribution.

---

## Testing Strategy

### Phase 1
- **Unit tests** for `CircularBuffer` wrap-around reads (property-based: random offsets, sizes, verify data integrity)
- **Unit tests** for `FindNextPageBoundary` with crafted Ogg page headers (valid, invalid version, split across wrap boundary)
- **Race detection tests** for `Stream.Broadcast`/`Close`/`Subscribe` concurrency (`go test -race`)
- **Integration test** for relay pull reconnection (mock HTTP server that drops connections)

### Phase 2
- **Interface compliance tests** for each adapter (ensure all IngestSource/OutputAdapter implementations satisfy the interface contract)
- **Pipeline integration tests** — source → pipeline → output round-trip with data verification
- **Backward compatibility tests** — existing Icecast source clients (liquidsoap, butt, MIXXX) still connect and stream

### Phase 3-4
- **Fuzz tests** for RTMP handshake parser, FLV demuxer, MPEG-TS muxer
- **Conformance tests** for HLS output (validate m3u8 with Apple's mediastreamvalidator or equivalent)
- **Load tests** for concurrent listener scaling (1000+ listeners per stream)

### Phase 5-6
- **A/V sync tests** — verify PTS alignment between audio and video tracks
- **Tenant isolation tests** — verify one tenant cannot access another's streams or stats
- **Memory budget tests** — verify actual memory usage matches estimates under load

---

## Security Considerations

### New Ingest Protocols
- **RTMP authentication**: Stream key = `{tenant_id}/{mount}?key={source_password}`. Keys are bcrypt-hashed in config. Failed attempts trigger the existing auth lockout mechanism.
- **RTMP hardening**: Rate limit handshake attempts (10/min per IP). Validate all AMF values before processing. Max message size 10MB to prevent memory exhaustion.
- **RTMPS**: Support TLS on the RTMP port (reuse existing cert config). Configurable: allow plaintext, require TLS, or both.
- **SRT encryption**: Support AES-128 and AES-256 passphrase-based encryption (built into the SRT protocol). Configurable per stream key.
- **SRT hardening**: Validate stream ID format. Reject connections with unknown stream IDs before completing handshake.
- **Input validation**: All protocol parsers must handle malformed input without panicking. Fuzz testing is mandatory for parsers.

### Multi-Tenancy Security
- **Tenant isolation**: Tenants cannot enumerate or access other tenants' streams, stats, or configuration.
- **API key scoping**: Each API key is scoped to a single tenant. Keys use crypto/rand for generation, bcrypt for storage.
- **Rate limiting**: Per-tenant rate limits on API and source connections. Configurable per plan tier.

---

## Migration Path

### Phase 1 → Phase 2 Transition
- `PipelineManager` wraps `Relay` — it delegates to the existing `Relay` internally. No breaking changes.
- All existing `Server` methods continue to work via `PipelineManager.GetOrCreateStream()` which returns the same `*Stream` type.
- Feature flag: `pipeline_engine: true/false` in config (default false initially, flipped to true after validation).

### Single-Tenant → Multi-Tenant Migration
- Multi-tenancy is opt-in (`multi_tenant: true` in config).
- When disabled, all operations use the "default" tenant implicitly — zero behavior change.
- When enabled, existing streams are automatically assigned to the default tenant.
- Database schema: extend existing GORM models with `TenantID` column (nullable, default = "default"). Migration is additive — no destructive changes.

### Rollback Strategy
- Each phase is a separate set of commits on the `streaming-hardening` branch.
- If a phase introduces regressions, it can be reverted independently.
- The feature flag for pipeline engine allows instant rollback to the `Relay`-based code path.

---

## Persistence for Multi-Tenancy

### Tenant Store Options
1. **Config file** (default for small deployments): Tenants defined in `tinyice.json` alongside existing config.
2. **Database** (recommended for SaaS): Extend existing GORM/SQLite schema with `tenants`, `tenant_stats`, `api_keys` tables. The existing `history.db` becomes `tinyice.db` with all tables.
3. **External API** (enterprise): Fetch tenant config from an external service (e.g., billing system). Cached locally with configurable TTL.

### Database Schema (for option 2)
```sql
CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT,
    plan TEXT DEFAULT 'free',
    limits_json TEXT,  -- JSON blob of TenantLimits
    config_json TEXT,  -- JSON blob of TenantConfig
    created_at DATETIME
);

CREATE TABLE tenant_stats (
    tenant_id TEXT REFERENCES tenants(id),
    recorded_at DATETIME,
    bytes_in INT,
    bytes_out INT,
    peak_listeners INT,
    stream_minutes INT
);

CREATE TABLE api_keys (
    key_hash TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    name TEXT,
    created_at DATETIME,
    expires_at DATETIME
);
```

---

## Memory Budget Estimates

| Component | Per-Stream | Notes |
|-----------|-----------|-------|
| Audio CircularBuffer | 512 KB | Current default |
| Video CircularBuffer | 8 MB | Only allocated when video source connects |
| HLS Segment Ring (audio) | ~2 MB | 30 segments x ~64KB each |
| HLS Segment Ring (video) | ~16 MB | 30 segments x ~512KB each |
| Per-listener state | ~4 KB | Signal channel, offset, metadata |
| Ogg page tracking | ~1 KB | 128 int64 offsets |

**Deployment scenarios:**
- 10 audio-only streams, 100 listeners: ~15 MB
- 100 audio streams (SaaS), 1000 listeners: ~100 MB
- 10 A/V streams, 500 listeners: ~250 MB
- 100 A/V streams (SaaS), 5000 listeners: ~2.5 GB

Memory pressure strategy: when RSS exceeds configurable threshold (default 80% of available), stop accepting new source connections, log warning. At 90%, disconnect lowest-priority tenants (free tier first).

---

## Files Created/Modified Summary

### New Files
- `relay/health.go` — Stream health monitoring
- `relay/pipeline.go` — Core pipeline abstractions (Track, IngestSource, OutputAdapter, Pipeline)
- `relay/pipeline_manager.go` — Pipeline lifecycle management
- `relay/ingest_icecast.go` — Icecast source adapter
- `relay/ingest_webrtc.go` — WebRTC source adapter
- `relay/ingest_autodj.go` — AutoDJ adapter
- `relay/ingest_relay.go` — Relay pull adapter
- `relay/ingest_rtmp.go` — RTMP ingest
- `relay/rtmp_protocol.go` — RTMP protocol implementation
- `relay/ingest_srt.go` — SRT ingest
- `relay/output_icecast.go` — Progressive HTTP output adapter
- `relay/output_webrtc.go` — WebRTC output adapter
- `relay/output_hls.go` — HLS output adapter
- `relay/output_dash.go` — DASH output adapter
- `relay/mux_mpegts.go` — MPEG-TS muxer
- `relay/mux_fmp4.go` — Fragmented MP4 muxer
- `relay/codec_h264.go` — H.264 NALU parser
- `relay/codec_aac.go` — AAC ADTS parser
- `relay/tenant.go` — Multi-tenancy model

### Modified Files
- `relay/buffer.go` — Wrap-around reads, keyframe index, Reset()
- `relay/stream.go` — Close guard, health stats, rate tracking
- `relay/ogg.go` — Validate OggS page headers
- `relay/relay.go` — Tenant-scoped operations
- `relay/client.go` — Exponential backoff, proper HTTP client, health tracking
- `relay/streamer.go` — Channel-based state, file validation, better error handling
- `relay/webrtc.go` — Source tracking, disconnect support, ICE restart
- `relay/interfaces.go` — New interfaces for pipeline architecture
- `server/server.go` — New routes, tenant middleware, RTMP/SRT server startup
- `server/handlers_stream.go` — Fallback hysteresis, silence on underrun, slow listener disconnect
- `config/config.go` — RTMP/SRT/HLS config, multi-tenant config
