# TinyIce ❄️

**Run it, and you've got a ready Icecast server in seconds.**

> **Notice**: This is a side project. Use it at your own risk. While it implements security best practices, it has not undergone an independent audit.

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

![TinyIce Admin Dashboard](assets/scr1.png)
![TinyIce Public View](assets/scr2.png)

[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why TinyIce?

Traditional streaming servers can be complex to configure and resource-heavy. TinyIce aims to solve this by providing:

-   **Instant Deployment**: A single binary with all assets (templates, icons) embedded.
-   **Zero-Config Security**: Unique secure credentials automatically generated on first run.
-   **Multi-Tenant Ready**: Create multiple admin users who can only manage their own mount points.
-   **Edge-Ready Relaying**: Pull streams from other servers with automatic reconnection and metadata parsing.
-   **Secure & Hardened**: Salted **bcrypt** password hashing, CSRF protection, and HTTP resource hardening.
-   **Auto-HTTPS**: Built-in support for **ACME (Let's Encrypt)** for zero-configuration SSL certificates.
-   **Real-time Insights**: SSE-powered dashboards with smooth, hardware-accelerated traffic charts.

## Features

-   **Icecast2 Compatible**: Works with standard source clients (BUTT, OBS, Mixxx, LadioCast) and players (VLC, web browsers).
-   **Stream Relaying**: Act as an edge node by pulling streams from remote Icecast/Shoutcast servers. Supports in-stream ICY metadata parsing.
-   **Dual-Protocol Architecture**: Handles HTTPS for listeners while allowing legacy encoders to stream over plain HTTP.
-   **Public Directory Listing**: Built-in support for Icecast YP protocol (e.g., `dir.xiph.org`).
-   **Dynamic Management**: Add, update, disable, or remove mount points, users, and relays on the fly.
-   **IP Banning**: Instantly block malicious IPs from streaming or listening.
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

## Configuration

```json
{
    "bind_host": "0.0.0.0",
    "port": "8000",
    "page_title": "My Stream Portal",
    "use_https": true,
    "auto_https": true,
    "acme_email": "admin@example.com",
    "domains": ["radio.example.com"],
    "directory_listing": true,
    "relays": [
        {
            "url": "https://ice3.somafm.com/live-128-mp3",
            "mount": "/soma",
            "burst_size": 20
        }
    ],
    "banned_ips": ["1.2.3.4"],
    "max_listeners": 100
}
```

## License

Distributed under the MIT License. See `LICENSE` for more information.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
