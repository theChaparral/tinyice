#!/bin/sh
# Create the dedicated tinyice system user the systemd unit runs as.
# Idempotent: noop if the user already exists from a previous install.

set -e

if ! getent passwd tinyice >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd \
            --system \
            --home-dir /var/lib/tinyice \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --user-group \
            --comment "TinyIce streaming server" \
            tinyice
    elif command -v adduser >/dev/null 2>&1; then
        # busybox / alpine fallback
        addgroup -S tinyice 2>/dev/null || true
        adduser -S -D -H -h /var/lib/tinyice -s /sbin/nologin -G tinyice tinyice
    fi
fi
