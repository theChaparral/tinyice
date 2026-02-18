# TinyIce

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

[![Go Report Card](https://goreportcard.com/badge/github.com/DatanoiseTV/tinyice)](https://goreportcard.com/report/github.com/DatanoiseTV/tinyice)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why TinyIce?

Traditional streaming servers can be complex to configure and resource-heavy. TinyIce aims to solve this by providing:

-   **Zero Dependencies**: A single binary with all assets including templates and icons embedded at compile time.
-   **No Default Passwords**: Unique secure credentials are automatically generated on the first run, and all passwords are stored using SHA-256 hashing.
-   **Modern UI**: Real-time dashboards powered by Server-Sent Events (SSE) with smooth, hardware-accelerated traffic charts.
-   **Super Low Latency**: A dedicated mode that disables server-side buffering for near-real-time broadcasting.
-   **Operational Insights**: Per-stream bandwidth monitoring, listener counts, and "Now Playing" metadata extraction.

## Features

-   **Icecast2 Compatible**: Fully supports standard source clients such as BUTT, OBS, Mixxx, and LadioCast, as well as players like VLC and modern web browsers.
-   **Dynamic Mount Management**: Add, update, disable, or remove mount points through the admin panel without requiring a server restart.
-   **Real-time Analytics**: Visual traffic charts for Inbound and Outbound data flow along with global server statistics.
-   **Administrative Controls**: Capability to kick specific streamers or disconnect all listeners with a single action.
-   **Now Playing Metadata**: Support for industry-standard metadata updates via HTTP query parameters.
-   **Embedded Web UI**: Dark-themed, mobile-responsive interface for public status and system administration.

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
On the **first run**, TinyIce will:
1.  Generate a secure `tinyice.json` configuration file.
2.  Create unique random passwords for the admin user and the default source.
3.  Display these credentials in your terminal for immediate use.

### 3. Stream
Configure your encoder (e.g., BUTT) to point to:
-   **Server Type**: Icecast 2
-   **Address**: your-server-ip
-   **Port**: 8000
-   **Password**: [The generated source password]
-   **Mount**: /live (or any path you have provisioned)

### 4. Manage
Visit `http://localhost:8000/admin` to manage your stations and view live traffic analytics.

## Configuration

The `tinyice.json` file allows for extensive customization:

```json
{
    "port": "8000",
    "default_source_password": "hashed_password",
    "mounts": {
        "/radio1": "hashed_password"
    },
    "admin_user": "admin",
    "admin_password": "hashed_password",
    "hostname": "localhost",
    "low_latency_mode": false,
    "max_listeners": 100
}
```

## Advanced Usage

### Super Low Latency Mode
Enable this feature in the Admin Panel to disable the "burst-on-connect" buffer. This reduces playback delay from several seconds to less than one second, making it ideal for live interactions and interviews.

### Metadata Updates
TinyIce supports standard Icecast metadata updates:
`GET /admin/metadata?mount=/live&mode=updinfo&song=Artist+-+Title`

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgements

-   Powered by [Go](https://golang.org)
-   Inspired by the [Icecast](https://icecast.org) project.

---
Developed by [DatanoiseTV](https://github.com/DatanoiseTV)
