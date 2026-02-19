# TinyIce ❄️

![TinyIce Logo](https://raw.githubusercontent.com/DatanoiseTV/tinyice/main/assets/logo.png?v=2)

**Run it, and you've got a ready Icecast server in seconds.**

> **Notice**: This is a side project. Use it at your own risk. While it implements security best practices, it has not undergone an independent audit.

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

<img width="3023" height="1507" alt="image" src="https://github.com/user-attachments/assets/e789d5df-d530-4ff3-a4a2-d551ea0ffc11" />
<img width="3024" height="1508" alt="image" src="https://github.com/user-attachments/assets/8da73f4a-27d8-4d7d-993c-9040a89a0c0d" />
<img width="3023" height="1507" alt="image" src="https://github.com/user-attachments/assets/75010d65-f0ce-4ee0-8a92-7d04df54406a" />
<img width="3024" height="1852" alt="image" src="https://github.com/user-attachments/assets/d3278890-4f5f-4536-aa88-5fd19518ca3d" />


[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Why TinyIce?

Traditional streaming servers can be complex to configure and resource-heavy. TinyIce aims to solve this by providing:

-   **Massive Scalability**: Built with a **Shared Circular Buffer** architecture that allows a single stream to be broadcast to hundreds of thousands of listeners with near-zero memory allocations.
-   **Instant Deployment**: A single binary with all assets (templates, icons) embedded.
-   **Zero-Config Security**: Unique secure credentials automatically generated on first run.
-   **Multi-Tenant Ready**: Create multiple admin users who can only manage their own mount points.
-   **Edge-Ready Relaying**: Pull streams from other servers with automatic reconnection and in-stream ICY metadata parsing.
-   **Secure & Hardened**: Salted **bcrypt** password hashing, CSRF protection, and HTTP resource hardening.
-   **Auto-HTTPS**: Built-in support for **ACME (Let's Encrypt)** for zero-configuration SSL certificates. Supports custom ACME CAs (e.g., Step-CA) for homelab environments.
-   **Real-time Insights**: SSE-powered dashboards with smooth, hardware-accelerated traffic charts.
-   **Playback History**: Persistent song history stored in a lightweight SQLite database.
-   **Observability**: Built-in **Prometheus** metrics endpoint and structured logging.

## Features

-   **Zero-Downtime Updates**: Support for `SO_REUSEPORT` allows starting a new version of TinyIce while the old one is still running, ensuring no service interruption.
-   **Stream Health Monitoring**: Real-time detection of downstream packet loss and buffer skips, displayed as a health percentage in the dashboard.
-   **Instant Start**: Listeners receive a 64KB audio burst upon connection, eliminating the "buffering" delay common in traditional servers.
-   **High-Performance Distribution**: Shared circular buffer architecture designed for 100,000+ concurrent listeners per stream.
-   **Icecast2 Compatible**: Works with standard source clients (BUTT, OBS, Mixxx, LadioCast) and players (VLC, web browsers).
-   **Approval Workflow**: New streams are hidden by default until approved by an administrator.
-   **Stream Relaying**: Act as an edge node by pulling streams from remote servers.
-   **Web-Based Audio Player**: Every station gets a dedicated, modern player page with real-time metadata and a reactive audio visualizer.
-   **Dual-Protocol Architecture**: Handles HTTPS for listeners while allowing legacy encoders to stream over plain HTTP.
-   **Smart Fallback & Auto-Recovery**: Automatically switch listeners to a backup stream if the primary source drops, and seamlessly transition them back once the primary is restored.
-   **Playback Tracking**: View the last 100 songs played per station in the admin dashboard.
-   **Playlist Support**: Support for `.m3u8`, `.m3u`, and `.pls` playlists for easy integration with external players (VLC, Winamp, mobile apps).
-   **Public Directory Listing**: Built-in support for Icecast YP protocol (e.g., `dir.xiph.org`).
-   **Dynamic Management**: Add, update, disable, or remove mount points, users, and relays on the fly.
-   **IP Banning**: Instantly block malicious IPs or entire network ranges using **CIDR support** (e.g., `1.2.3.0/24`).
-   **Detailed Audit Logging**: Comprehensive logging of admin logins and encoder authentication results for better security monitoring.
-   **Advanced Monitoring**: Built-in debug mode (`?debug`) to track system RAM and goroutine counts in real-time.
-   **Legacy API**: Support for `/status-json.xsl` for compatibility with existing Icecast tools.
-   **Now Playing Metadata**: Real-time display of song titles pushed from broadcast software or pulled from relays.

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
On the **first run**, TinyIce will generate `tinyice.json` with unique random passwords. **Save them from the terminal!**

### 3. Stream
Point your encoder (e.g., BUTT) to:
-   **Server Type**: Icecast 2
-   **Address**: your-server-ip
-   **Port**: 8000
-   **Password**: [The generated source password]
-   **Mount**: /live

## Configuration

TinyIce uses a JSON configuration file (`tinyice.json`). Below are the available options:

```json
{
    "bind_host": "0.0.0.0",
    "port": "8000",
    "base_url": "https://radio.example.com",
    "page_title": "TinyIce",
    "page_subtitle": "Live Streaming Server powered by Go",
    "use_https": true,
    "auto_https": true,
    "https_port": "443",
    "acme_email": "admin@example.com",
    "acme_directory_url": "",
    "domains": ["radio.example.com"],
    "max_listeners": 100,
    "directory_listing": true,
    "directory_server": "http://dir.xiph.org/cgi-bin/yp-cgi",
    "low_latency_mode": false,
    "banned_ips": []
}
```

### Custom ACME (Homelab)
To use TinyIce with a custom ACME CA (like Step-CA or Smallstep) in a homelab environment, set the `acme_directory_url` in your config:

```json
{
    "auto_https": true,
    "acme_directory_url": "https://ca.internal/acme/acme/directory",
    "acme_email": "admin@homelab.local",
    "domains": ["radio.homelab.local"]
}
```

## Command Line Usage

```bash
./tinyice -host 0.0.0.0 -port 8000 -daemon -log-file tinyice.log
```

-   `-host`: Network interface to bind to (default: "0.0.0.0").
-   `-config`: Path to the configuration file.
-   `-log-file`: Path to a file for log output.
-   `-auth-log-file`: Path to a separate file for authentication audit logs.
-   `-log-level`: `debug`, `info`, `warn`, `error`.
-   `-json-logs`: Enable structured JSON logging.
-   `-daemon`: Run in the background.
-   `-pid-file`: Path to write the process ID.

## Common Use Cases

TinyIce is built to handle everything from a single home stream to large-scale distribution. Here is where it fits best:

*   **Global Edge Distribution**: Use TinyIce as a lightweight "edge" node to offload bandwidth from your main studio. It can handle thousands of listeners on a tiny VPS with near-zero overhead.
*   **Multi-DJ Community Radio**: Host multiple independent stations on one server. Give every DJ their own login and mount point so they can manage their own stats and history without seeing anyone else's data.
*   **Ready-to-Use Listener Pages**: No need to build your own website. Every mount point comes with a beautiful, built-in player page featuring real-time "Now Playing" titles and a live visualizer.
*   **Private Home Streaming**: The single-binary setup makes it a breeze to run on a Raspberry Pi or a home server. Stream your local music collection to your phone or smart speakers securely using the built-in HTTPS support.
*   **Custom Audio Apps**: If you're building a modern web player or a mobile app, TinyIce's real-time SSE metadata and JSON API mean your "Now Playing" widgets update instantly without any heavy polling.

## Performance

See [PERFORMANCE.md](PERFORMANCE.md) for detailed hardware and traffic estimates.

## Contributing

Contributions are welcome! Please see [DEVELOPERS.md](DEVELOPERS.md) for an architectural overview, tech stack details, and onboarding guide.

## License

Distributed under the Apache License 2.0. See `LICENSE` for more information.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
