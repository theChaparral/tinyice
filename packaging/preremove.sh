#!/bin/sh
# Stop the service before files are pulled out from under it. Leave
# disable/daemon-reload to postremove so the unit file is still on
# disk while we stop.

set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if systemctl is-active --quiet tinyice 2>/dev/null; then
        systemctl stop tinyice || true
    fi
fi
