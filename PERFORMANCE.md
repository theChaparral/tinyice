# Performance and Scalability Estimates

TinyIce is written in Go, utilizing a high-concurrency Pub/Sub model. Unlike traditional C-based servers, TinyIce leverages Go's scheduler and channels to handle thousands of concurrent connections with minimal overhead.

This document provides realistic estimates for various hardware configurations.

## Theoretical Limits

The primary bottleneck for any streaming server is almost always **Network Bandwidth**, not CPU or Memory.

*   **128 kbps stream**: ~8 listeners per 1 Mbps of bandwidth.
*   **1 Gbps Uplink**: ~7,000 to 8,000 concurrent listeners (theoretical max).
*   **Memory per Listener**: TinyIce uses approximately 200KB - 500KB of RAM per listener (primarily for the buffered data channels).

## Hardware Estimates

Values below assume a standard **128 kbps MP3/AAC stream**.

### 1. Raspberry Pi 4 (or similar ARM SBC)
*   **CPU**: 4-core ARM
*   **RAM**: 4 GB
*   **Network**: 1 Gbps (shared bus)
*   **Estimated Max Listeners**: 1,000 - 1,500
*   **Estimated Max Sources**: 20 - 50
*   **Note**: Great for small community stations or internal relays.

### 2. Entry-Level VPS (DigitalOcean/Hetzner/AWS)
*   **CPU**: 1 vCPU (Shared)
*   **RAM**: 2 GB
*   **Network**: 1 Gbps - 2 Gbps burst
*   **Estimated Max Listeners**: 2,000 - 3,000
*   **Estimated Max Sources**: 50+
*   **Note**: The most common production setup. Performance is highly stable.

### 3. Mid-Range Dedicated Server
*   **CPU**: 4 - 8 Cores (Modern Intel/AMD)
*   **RAM**: 16 GB
*   **Network**: 1 Gbps Dedicated
*   **Estimated Max Listeners**: 5,000 - 7,000
*   **Estimated Max Sources**: 200+
*   **Note**: Capable of saturating a 1 Gbps line entirely.

### 4. High-End Infrastructure
*   **CPU**: 16+ Cores
*   **RAM**: 32 GB+
*   **Network**: 10 Gbps Uplink
*   **Estimated Max Listeners**: 20,000+
*   **Note**: At this scale, OS-level tuning (file descriptors, TCP stack) becomes more important than the application logic.

## Resource Usage Patterns

### CPU
*   **Streaming**: Very low. Moving bytes from a source channel to listener channels is an O(n) operation that is extremely efficient in Go.
*   **Authentication**: Moderate. TinyIce uses **bcrypt** for password hashing. Connecting a new source or logging into the admin panel incurs a temporary CPU spike by design (to prevent brute-force attacks).
*   **SSL/TLS**: Moderate. Using HTTPS (ACME/Manual) adds encryption overhead. For >5,000 listeners, consider offloading SSL to a load balancer if CPU becomes a bottleneck.

### Memory
*   **Static Cost**: ~20MB (Binary and basic buffers).
*   **Per Source**: ~1MB (Includes burst-on-connect buffer).
*   **Per Listener**: ~400KB (Channel buffer).

## Optimizing for High Load

1.  **Increase File Descriptors**: Ensure your OS allows enough open files (`ulimit -n 65535`).
2.  **Low Latency Mode**: Enabling Low Latency mode reduces memory usage per mount because the `burstBuffer` is disabled.
3.  **JSON Logging**: Disable `-json-logs` and set `-log-level warn` if you are hitting IO bottlenecks on the disk.
4.  **Network Proximity**: Deploy TinyIce as close to your listeners as possible to reduce jitter.

## Bottlenecks to Watch

*   **Browser Buffering**: Modern browsers may buffer up to 2MB of audio before starting playback. This is not a server bottleneck, but a client-side behavior.
*   **Context Switches**: While Go handles concurrency well, having 10,000+ listeners on a single-core machine will eventually lead to CPU contention due to scheduling.
