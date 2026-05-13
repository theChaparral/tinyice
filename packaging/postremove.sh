#!/bin/sh
# Final cleanup. Unmask first so subsequent disable can act on the
# real unit, then disable + reload. Leave /var/lib/tinyice on disk —
# it holds the operator's history DB and any captured stream
# metadata, and dpkg/rpm don't distinguish remove from purge for
# nFPM-produced packages.

set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl unmask tinyice.service 2>/dev/null || true
    systemctl disable tinyice.service 2>/dev/null || true
    systemctl daemon-reload || true
fi
