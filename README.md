# TinyIce ❄️

**Run it, and you've got a ready Icecast server in seconds.**

> **Notice**: This is a side project. Use it at your own risk. While it implements security best practices, it has not undergone an independent audit.

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

<img width="3024" height="1508" alt="image" src="https://github.com/user-attachments/assets/aca35b42-d93c-4ccc-86a1-365121cae74e" />
<img width="3024" height="1508" alt="image" src="https://github.com/user-attachments/assets/8637a012-0fad-4018-98a5-5abb5d357fde" />
<img width="3024" height="1508" alt="image" src="https://github.com/user-attachments/assets/4d5f339c-f1dd-49cb-a196-7dc6dad48331" />
<img width="3024" height="1852" alt="image" src="https://github.com/user-attachments/assets/d3278890-4f5f-4536-aa88-5fd19518ca3d" />


[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Why TinyIce?

Traditional streaming servers can be complex to configure and resource-heavy. TinyIce aims to solve this by providing:

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

-   **Icecast2 Compatible**: Works with standard source clients (BUTT, OBS, Mixxx, LadioCast) and players (VLC, web browsers).
-   **Approval Workflow**: New streams are hidden by default until approved by an administrator.
-   **Stream Relaying**: Act as an edge node by pulling streams from remote servers.
-   **Dual-Protocol Architecture**: Handles HTTPS for listeners while allowing legacy encoders to stream over plain HTTP.
-   **Playback Tracking**: View the last 100 songs played per station in the admin dashboard.
-   **Public Directory Listing**: Built-in support for Icecast YP protocol (e.g., `dir.xiph.org`).
-   **Dynamic Management**: Add, update, disable, or remove mount points, users, and relays on the fly.
-   **IP Banning**: Instantly block malicious IPs from streaming or listening.
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
    "page_title": "TinyIce",
    "page_subtitle": "Live streaming network powered by Go",
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
-   `-log-level`: `debug`, `info`, `warn`, `error`.
-   `-json-logs`: Enable structured JSON logging.
-   `-daemon`: Run in the background.
-   `-pid-file`: Path to write the process ID.

## Performance

See [PERFORMANCE.md](PERFORMANCE.md) for detailed hardware and traffic estimates.

## Contributing

Contributions are welcome! Please see [DEVELOPERS.md](DEVELOPERS.md) for an architectural overview, tech stack details, and onboarding guide.

## License

Distributed under the Apache License 2.0. See `LICENSE` for more information.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
