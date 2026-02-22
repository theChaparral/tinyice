# TinyIce ❄️

![TinyIce Logo](https://raw.githubusercontent.com/DatanoiseTV/tinyice/main/assets/logo.png?v=2)

**Run it, and you've got a ready Icecast server in seconds.**

> **Notice**: This is a side project. Use it at your own risk. While it implements security best practices, it has not undergone an independent audit.

TinyIce is a lightweight, high-performance, and secure Icecast2-compatible streaming server written in Go. It is designed to be self-contained, easy to deploy, and provides a modern web interface for both administrators and listeners.

<img width="3023" height="1507" alt="image" src="https://github.com/user-attachments/assets/e789d5df-d530-4ff3-a4a2-d551ea0ffc11" />
<img width="3024" height="1508" alt="image" src="https://github.com/user-attachments/assets/8da73f4a-27d8-4d7d-993c-9040a89a0c0d" />
<img width="3023" height="1507" alt="image" src="https://github.com/user-attachments/assets/75010d65-f0ce-4ee0-8a92-7d04df54406a" />
<img width="3023" height="1507" alt="image" src="https://github.com/user-attachments/assets/4fc8cb37-620c-4e24-ae07-300aff4a2fa9" />
<img width="3027" height="1545" alt="image" src="https://github.com/user-attachments/assets/968c21ed-547e-4f19-a030-93d05a845a2b" />
<img width="3027" height="1418" alt="image" src="https://github.com/user-attachments/assets/d531cf1c-1072-4cbc-adc5-c4e7be54e4a6" />
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
-   **Precision AutoDJ Automation**: High-fidelity 24/7 broadcasting from local music libraries. Features frame-accurate pacing, recursive folder management, smart shuffle, and manual queue prioritization.
-   **Per-Instance MPD Integration**: Every AutoDJ can expose its own dedicated Music Player Daemon (MPD) server, allowing professional remote control via any standard client with optional password protection.
-   **Hardened Security Perimeter**: Integrated TCP-level IP banning that drops malicious connections before they reach the application layer, combined with intelligent connection-scanning detection.
-   **Real-Time SSE Dashboard**: A modern, zero-latency administrative interface with AJAX-powered transport controls and live hardware-accelerated traffic visualization.
-   **High-Performance Relay & Transcoding**: Act as a transparent edge node or a high-quality transcoder (MP3/Opus) with zero external dependencies.
-   **Outbound ICY Metadata**: Injects song titles directly into the audio stream, ensuring "Now Playing" info appears on all traditional radio players (VLC, Winamp, etc.).
-   **Built-in Transcoding**: High-performance, pure Go transcoding (MP3/Opus) to provide multiple quality options or formats for a single source.
-   **Web-Based Audio Player**: Every station gets a dedicated, modern player page with real-time metadata and a reactive audio visualizer.
-   **Embeddable Player**: Minimalist iframe-based player for easy integration into external websites.
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

### 1. Install (Pre-built Binary)

You can download the latest pre-built binary for your system directly from GitHub releases.

**a. Identify your System:**
  - **OS:** `linux`, `darwin` (macOS), `freebsd`
  - **Architecture:** `amd64`, `arm64`

**b. Find the Latest Release URL:**
  You can find the latest release information and download URLs using the GitHub API:
  ```bash
  curl -s https://api.github.com/repos/DatanoiseTV/tinyice/releases/latest | grep "browser_download_url"
  ```
  Look for a URL matching `tinyice-<your-os>-<your-arch>`.

**c. Download the Binary and Checksums:**

  Determine your system's `OS` and `ARCH` based on the available pre-built binaries:
  *   **OS options:** `linux`, `darwin` (macOS), `freebsd`
  *   **ARCH options:** `amd64`, `arm64`

  Then, download the binary and its checksum file using `curl` or `wget`. Replace `<YOUR_OS>` and `<YOUR_ARCH>` with your specific values (e.g., `tinyice-linux-amd64`).

  ```bash
  # Download the binary
  curl -LJO "https://github.com/DatanoiseTV/tinyice/releases/latest/download/tinyice-<YOUR_OS>-<YOUR_ARCH>"
  # Download the checksums file
  curl -LJO "https://github.com/DatanoiseTV/tinyice/releases/latest/download/checksums.txt"
  ```
  *Alternatively, using `wget`:*
  ```bash
  # Download the binary
  wget "https://github.com/DatanoiseTV/tinyice/releases/latest/download/tinyice-<YOUR_OS>-<YOUR_ARCH>"
  # Download the checksums file
  wget "https://github.com/DatanoiseTV/tinyice/releases/latest/download/checksums.txt"
  ```

**d. Verify the Binary (Important!):**
  Ensure the downloaded binary is authentic and untampered by verifying its SHA256 checksum.

  *   For **Linux** and **FreeBSD**, use `sha256sum`:
      ```bash
      sha256sum tinyice-<YOUR_OS>-<YOUR_ARCH>
      ```
  *   For **macOS**, use `shasum -a 256`:
      ```bash
      shasum -a 256 tinyice-<YOUR_OS>-<YOUR_ARCH>
      ```
  Compare the output with the corresponding entry in the `checksums.txt` file. If they don't match, **DO NOT RUN THE BINARY**.

**e. Make Executable and Install (Optional):**
  Move the binary to a location in your system's `PATH` and make it executable.

  *First, rename the downloaded binary to just `tinyice` for convenience:*
  ```bash
  mv tinyice-<YOUR_OS>-<YOUR_ARCH> tinyice
  ```

  *Then choose your installation method:*

  *For user-specific installation (recommended for most users, no sudo required):*
  ```bash
  mkdir -p ~/.local/bin
  mv tinyice ~/.local/bin/tinyice
  chmod +x ~/.local/bin/tinyice
  # Ensure ~/.local/bin is in your PATH. Add the following to your shell's config (e.g., ~/.bashrc, ~/.zshrc):
  # export PATH="$HOME/.local/bin:$PATH"
  ```
  *For system-wide installation (requires sudo):*
  ```bash
  sudo mv tinyice /usr/local/bin/tinyice
  sudo chmod +x /usr/local/bin/tinyice
  ```

### 2. Build from Source (Optional)

Requires Go 1.21 or later.
```bash
go build -o tinyice
```
After building, you can proceed to the "3. First Run & Password Generation" step.

### 3. First Run & Password Generation

On its **first run**, TinyIce will automatically generate a configuration file (`tinyice.json`) and unique, secure credentials (Admin, Source, Live Mount passwords).

**It is CRITICAL that you save these passwords from your terminal output!**

```bash
# If installed user-specific, assuming ~/.local/bin is in your PATH
tinyice

# If installed system-wide
tinyice

# If running from the current directory after 'go build'
./tinyice
```
TinyIce will print messages like:
```
  FIRST RUN: SECURE CREDENTIALS GENERATED
  Admin Password:  your_admin_password_here
  Default Source Password: your_source_password_here
  Live Mount Password:   your_livemount_password_here
Note: To reset all credentials, run: rm tinyice.json && ./tinyice
```
**Make sure to copy and securely store these generated passwords.** The `tinyice.json` file will be created in the current working directory from where you run `tinyice`, or in the directory specified by the `-config` flag.

### 4. Stream

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
    "banned_ips": [],
    "autodjs": [
        {
            "name": "24/7 Chill",
            "mount": "/chill",
            "music_dir": "/music/chill",
            "format": "mp3",
            "bitrate": 128,
            "enabled": true,
            "loop": true,
            "inject_metadata": true,
            "mpd_enabled": true,
            "mpd_port": "6600"
        }
    ]
}
```

### Auto-HTTPS (Let's Encrypt)
To use built-in SSL support, ensure the following:
1.  **Ports**: Your server must be listening on (or have traffic forwarded to) **port 80 and 443**. Let's Encrypt requires these ports to verify your ownership of the domain.
2.  **Domains**: Add your full domain name to the `domains` list in `tinyice.json`.
3.  **Permissions**: Binding to ports 80/443 usually requires root/sudo permissions.

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

### Running on Port 80/443 without Root (Linux)
To satisfy Let's Encrypt challenges, TinyIce must be reachable on ports 80 and 443. On Linux, binding to ports below 1024 usually requires root. You can allow TinyIce to bind to these ports as a regular user by granting it the `CAP_NET_BIND_SERVICE` capability:

```bash
# Grant permission to the binary
sudo setcap 'cap_net_bind_service=+ep' ./tinyice

# Now you can run it as a normal user on port 80/443
./tinyice -port 80 -https-port 443
```



### Transcoding (Multi-Format Support)
TinyIce includes a built-in, CGO-free transcoder that allows you to take one input stream and output it in multiple formats or bitrates (e.g., 128kbps MP3 for desktop and 64kbps Opus for mobile).

- **Pure Go**: No external tools like FFmpeg or LAME required.
- **Low Overhead**: Highly optimized for minimal CPU impact.
- **Dynamic**: Manage transcoders on the fly via the Admin Dashboard.

> **Note**: Currently supporting MP3 (128kbps fixed) and Opus.

### Broadcast-Grade AutoDJ
TinyIce includes a sophisticated internal automation engine designed for reliable, 24/7 autonomous broadcasting.

- **Multi-Instance Orchestration**: Instantiate and manage multiple independent AutoDJs on different mount points from a single server.
- **Deep Recursive Library**: Advanced file browser with the ability to add entire directory trees or specific tracks recursively.
- **Protocol Compatibility**: Full MPD protocol support per instance, including password authentication and support for standard transport commands.
- **Precision Pacing**: Frame-accurate bitstream pacing ensures that file-based streams behave exactly like live broadcasts with zero drift.
- **Pro Transport Controls**: Non-destructive "Skip Next", "Smart Shuffle", and "Priority Queue" management via a latency-free AJAX UI.
- **Dynamic Meta-Injection**: Automatic ID3 tag extraction and real-time ICY metadata injection for a professional listener experience.
- **On-the-Fly Transcoding**: Stream your library in high-fidelity Opus or standard MP3 with customizable bitrates.



> **Note**: Once the certificate is successfully obtained and stored in the `certs/` directory, you can revert TinyIce to custom ports (like 8000/8443) if needed.
 However, you will need to switch back to ports 80/443 for automatic renewals (typically every 60-90 days).

## Monitoring & Observability

<img width="3004" height="1828" alt="image" src="https://github.com/user-attachments/assets/277ad0db-b8af-4025-9c05-780aa9e28762" />

TinyIce provides built-in support for real-time monitoring via Prometheus.

- **Metrics Endpoint**: `/metrics` (Requires Basic Auth)
- **Included Metrics**: 
  - **Listeners**: Total and per-mount counts.
  - **Throughput**: Bytes in/out and dropped packets (health ratio).
  - **System**: Memory usage, goroutine counts, GC statistics, and server uptime.

### Grafana Dashboard & Prometheus Config
Example monitoring configurations are available in the repository:
- [monitoring/grafana-dashboard.json](monitoring/grafana-dashboard.json)
- [monitoring/prometheus.yml](monitoring/prometheus.yml)

To use them:
1.  Add the contents of `prometheus.yml` to your Prometheus configuration (update targets and auth).
2.  Import the Grafana JSON file into your Grafana instance.
3.  Select your Prometheus data source.

## Command Line Usage

By default, TinyIce will look for `tinyice.json` in the current directory and bind to all interfaces:

```bash
./tinyice
```

### Advanced Options

```bash
./tinyice -host 0.0.0.0 -port 8000 -https-port 443 -daemon -log-file tinyice.log
```

-   `-host`: Network interface to bind to (default: "0.0.0.0").
-   `-port`: Port for HTTP/Icecast (default: "8000").
-   `-https-port`: Port for HTTPS (default: "443").
-   `-use-https`: Enable HTTPS server.
-   `-auto-https`: Enable automatic SSL via Let's Encrypt.
-   `-domains`: Comma-separated list of domains for SSL (e.g. "radio.com,stream.com").
-   `-config`: Path to the configuration file (default: "tinyice.json").
-   `-log-file`: Path to a file for log output.
-   `-auth-log-file`: Path to a separate file for authentication audit logs.
-   `-log-level`: `debug`, `info`, `warn`, `error`.
-   `-json-logs`: Enable structured JSON logging.
-   `-daemon`: Run in the background.
-   `-pid-file`: Path to write the process ID.

## Embedding the Player

You can easily embed any of your stations into your own website using an `<iframe>`. 

### Standard Embed Code
```html
<iframe 
    src="https://your-server.com/embed/<stream_name>" 
    width="100%" 
    height="80" 
    frameborder="0" 
    scrolling="no">
</iframe>
```

### Things to keep in mind:
1.  **HTTPS**: If your website uses HTTPS, your TinyIce server **must** also use HTTPS, or the browser will block the player (Mixed Content error).
2.  **Autoplay**: Modern browsers often prevent audio from playing automatically. The embed player requires a user to click the "Play" button to start the stream.
3.  **Responsiveness**: The player is designed to be responsive and will adjust its layout to fit the width of its container.

## Ecosystem & Applications

TinyIce is designed to be a flexible hub for many types of audio applications. 

*   **Live Performance Streaming**: Check out [abletonlink-go](https://github.com/DatanoiseTV/abletonlink-go/tree/main/examples/icecast_stream) for an example of how to stream **Ableton Link Audio** (multichannel audio streaming via Ableton's new beta protocol) directly to a TinyIce server.

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
