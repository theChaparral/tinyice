# Developer Guide ❄️

Welcome to the TinyIce codebase! This document provides an architectural overview and technical deep-dive to help you understand how TinyIce works and how to contribute effectively.

## Tech Stack

- **Language**: Go 1.21+
- **Database**: SQLite (via `modernc.org/sqlite` pure-Go driver) for persistent song history.
- **Frontend**: Vanilla JavaScript + HTML5 Templates (embedded via `embed.FS`).
- **Real-time**: Server-Sent Events (SSE) for dashboard metrics.
- **Security**: Argon2/Bcrypt for password hashing, TLS via ACME (autocert).

## Core Architecture

TinyIce is built around a central **Pub/Sub** engine located in the `relay/` package. Unlike traditional servers that use individual channels per listener, TinyIce utilizes a **Shared Circular Buffer** architecture. 

### Codebase Map
...
- `relay/`:
    - `relay.go`: The heart of the server. Manages `Stream` objects and the `CircularBuffer`.
...

## The Streaming Flow

1.  **Source Connection**: A streamer (BUTT, OBS) sends a `SOURCE` or `PUT` request.
2.  **Hijacking**: The server hijacks the TCP connection (`http.Hijacker`) to provide a raw, low-latency pipe for binary data.
3.  **Broadcasting**: Data chunks are written to a stream-specific `CircularBuffer`.
4.  **Zero-Allocation Distribution**: Listeners subscribe by maintaining an offset into the shared buffer. A signal channel triggers a read loop that pumps data directly from the shared memory to the network socket. This significantly reduces memory allocations and garbage collection pressure under high load.

## Key Technical Decisions

### 1. Pure Go SQLite
We use `github.com/glebarez/go-sqlite` because it is a CGO-free port of SQLite. This allows us to maintain "Zero-Config" portability, meaning you can cross-compile TinyIce for Linux, Windows, or FreeBSD from any OS without needing a GCC toolchain.

### 2. Intelligent Routing
TinyIce uses a custom `Mux` logic to handle dual-protocols. It automatically redirects web browsers to HTTPS (if configured) while allowing legacy hardware encoders (which often don't support TLS) to remain on plain HTTP.

### 3. SSE for Metrics
Instead of polling a JSON API every second, the dashboard uses a single long-lived **Server-Sent Events** connection. This reduces CPU usage and allows for the 500ms "superfast" dashboard response time.

## Development Workflow

### Prerequisites
- Go 1.21 or later.
- `make` (optional).

### Running in Development
```bash
# Clean start (deletes previous config/history)
rm -f tinyice.json history.db && go run main.go
```

### Adding New Features
1.  **Backend**: Add logic to `relay/` or `config/` first.
2.  **API**: Expose the logic via a new handler in `server/server.go`.
3.  **UI**: Add a new tab or element in `server/templates/admin.html` and update the SSE `onmessage` handler if real-time data is needed.

## Performance Tuning

When testing high-load scenarios:
- Monitor **Goroutine counts**: Each listener uses exactly one goroutine.
- Check **Memory usage**: Go channels use ~400KB per listener. 10,000 listeners will require ~4GB of RAM.
- Use the **Low Latency Mode**: Toggle this in the Admin panel to disable `X-Accel-Buffering` and other HTTP-level caching.

## Contributing

1.  Keep it **CGO-free**.
2.  Ensure templates remain **self-contained** (no external CDNs).
3.  Update `DEVELOPERS.md` if you change core architectural patterns.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
