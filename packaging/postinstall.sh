#!/bin/sh
# Wire up the systemd unit but DO NOT start it. The user has to:
#  1. configure /etc/tinyice/tinyice.json (or let TinyIce auto-write
#     it on first start),
#  2. explicitly unmask the unit, then
#  3. enable and start it.
#
# We mask the unit on install so a stray `systemctl start tinyice`
# can't bring up an unconfigured daemon by accident. masking also
# protects against package-manager hooks (e.g. presets) that try to
# enable every newly-installed unit on certain distros.

set -e

chown -R tinyice:tinyice /var/lib/tinyice /etc/tinyice 2>/dev/null || true

# Give the binary CAP_NET_BIND_SERVICE so a non-root tinyice can bind
# to ports 80/443. Best-effort — skipped on systems where setcap is
# absent (e.g. minimal containers).
if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' /usr/bin/tinyice || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl mask tinyice.service >/dev/null 2>&1 || true

    cat <<'MSG'

TinyIce installed. The systemd unit is MASKED until you decide to
start it; this prevents an unconfigured daemon from coming up on
reboot or via a distro auto-enable hook.

First-time setup:

  1. (Optional) edit /etc/tinyice/tinyice.json. If you skip this
     step, TinyIce will auto-write a default config with a generated
     admin password on first start.

  2. Unmask, enable, and start the service:

       sudo systemctl unmask tinyice
       sudo systemctl enable --now tinyice

  3. Read the generated admin password from the journal (only
     printed the first time):

       sudo journalctl -u tinyice -n 50 --no-pager

  4. Open http://<host>:8000 (default port).

State + history DB lives under /var/lib/tinyice; config at
/etc/tinyice/tinyice.json. The binary has CAP_NET_BIND_SERVICE so
it can bind to ports 80/443 without root if you change the port.

MSG
fi
