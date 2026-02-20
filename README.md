# TinyIce

![TinyIce Logo](https://raw.githubusercontent.com/DatanoiseTV/tinyice/main/assets/logo.png?v=2)

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

### UI Screenshots
<img width="3023" height="1507" alt="Admin Dashboard" src="https://github.com/user-attachments/assets/e789d5df-d530-4ff3-a4a2-d551ea0ffc11" />
<img width="3024" height="1508" alt="Station Management" src="https://github.com/user-attachments/assets/8da73f4a-27d8-4d7d-993c-9040a89a0c0d" />
<img width="3023" height="1507" alt="Real-time Metrics" src="https://github.com/user-attachments/assets/75010d65-f0ce-4ee0-8a92-7d04df54406a" />
<img width="3023" height="1507" alt="Insights and Trends" src="https://github.com/user-attachments/assets/4fc8cb37-620c-4e24-ae07-300aff4a2fa9" />
<img width="3024" height="1852" alt="Web Player" src="https://github.com/user-attachments/assets/d3278890-4f5f-4536-aa88-5fd19518ca3d" />

---

## Core Features

- **Massive Scalability**: Built with a shared circular buffer architecture designed for 100,000+ concurrent listeners with near-zero memory allocations.
- **Pure Go Transcoding**: Built-in, CGO-free transcoding support for MP3 and Opus.
- **Zero-Downtime Updates**: Support for `SO_REUSEPORT` allows starting a new version while the old one is still running.
- **Automatic SSL**: Built-in support for ACME (Let's Encrypt) for zero-configuration HTTPS.
- **Smart Fallback**: Automatically switch listeners to a backup stream if the primary source drops and recover seamlessly when it returns.
- **Outbound ICY Metadata**: Injects song titles directly into the audio stream for compatibility with all traditional players (VLC, Winamp, etc.).
- **Multi-Tenant Management**: Create multiple admin users with scoped access to specific mount points.
- **Real-time Insights**: SSE-powered dashboards and historical 24-hour listener trend charts.
- **Instant Start**: 64KB audio burst upon connection to eliminate buffering delays.

---

## Getting Started

### 1. Build
Requires Go 1.21 or later.
```bash
go build -o tinyice
```

### 2. Run
```bash
./tinyice
```
On the first run, TinyIce will generate `tinyice.json` with unique random credentials. Ensure you save these from the terminal output.

### 3. Stream
Point your encoder (e.g., BUTT, OBS, Mixxx) to:
- **Server Type**: Icecast 2
- **Address**: your-server-ip
- **Port**: 8000
- **Mount**: /live

---

## Command Line Usage

By default, TinyIce looks for `tinyice.json` in the current directory and binds to port 8000.

```bash
./tinyice [options]
```

### Options
- `-host`: Network interface to bind to (default: "0.0.0.0").
- `-port`: Port for HTTP/Icecast (default: "8000").
- `-https-port`: Port for HTTPS (default: "443").
- `-config`: Path to the configuration file (default: "tinyice.json").
- `-log-file`: Path to a file for log output.
- `-auth-log-file`: Path to a separate file for authentication audit logs (useful for Fail2Ban).
- `-log-level`: Set verbosity (`debug`, `info`, `warn`, `error`).
- `-daemon`: Run the process in the background.

---

## Operational Guides

### Running on Standard Ports (80/443) without Root
Let's Encrypt requires ports 80 and 443 for domain verification. On Linux, you can grant TinyIce permission to bind to these ports as a non-root user:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./tinyice
./tinyice -port 80 -https-port 443
```

### Fail2Ban Integration
Standardized logs make it easy to protect your server. Run with `-auth-log-file tinyice-auth.log`.

**Example Filter (`/etc/fail2ban/filter.d/tinyice.conf`):**
```ini
[Definition]
failregex = ^.*level=warning.*Authentication failed for user '.*' from <HOST>:.*$
```

**Example Jail (`/etc/fail2ban/jail.local`):**
```ini
[tinyice]
enabled = true
filter = tinyice
logpath = /path/to/tinyice-auth.log
maxretry = 5
```

### Embedding the Player
You can embed a station player into any website using an iframe:

```html
<iframe src="https://your-server.com/embed/<stream_name>" width="100%" height="80" frameborder="0" scrolling="no"></iframe>
```

---

## Ecosystem & Applications

- **Ableton Link Audio**: Check out [abletonlink-go](https://github.com/DatanoiseTV/abletonlink-go/tree/main/examples/icecast_stream) for an example of how to stream multichannel audio via Ableton's new beta protocol directly to TinyIce.
- **Edge Relaying**: Use TinyIce as a global edge node to offload bandwidth from a central studio.

---

## Performance
TinyIce is designed for high-density streaming. Per-listener overhead is minimized to approximately 15KB - 30KB of RAM. See [PERFORMANCE.md](PERFORMANCE.md) for detailed hardware and traffic estimates.

## Contributing
Contributions are welcome. Please see [DEVELOPERS.md](DEVELOPERS.md) for architectural details and coding standards.

## License
Distributed under the Apache License 2.0. See `LICENSE` for more information.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
