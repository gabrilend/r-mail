#!/bin/sh
# view-logs.sh — display rmail daemon logs in real-time
#
# Usage: ./scripts/view-logs.sh [log-file]
#
# Default log source is /tmp/rmail.log (RAM-backed, no disk wear).
# install.sh's runit/systemd/openrc branches write service files that
# redirect to this path.
#
# If the log file doesn't exist, fall back to `journalctl -u
# rmail.service -f` when systemd is active — that covers NixOS installs
# whose configuration.nix defines a custom rmail service logging to
# journald instead of to a file.  See the 2026-04-17 follow-up in
# issues/completed/205-redirect-service-logs-to-tmp.md.

LOG_FILE="/tmp/rmail.log"

# Allow override via argument.
[ -n "$1" ] && LOG_FILE="$1"

# Fast path: log file exists, tail it.  -F follows even across
# rotations and service restarts.
if [ -f "$LOG_FILE" ]; then
    exec tail -F "$LOG_FILE"
fi

# No log file.  If rmail is running under systemd with journald as the
# sink, that's the right place to look.  `is-active --quiet` sets exit
# status without producing any output.
if command -v systemctl >/dev/null 2>&1 && \
   systemctl is-active --quiet rmail.service 2>/dev/null; then
    echo "rmail.service is running under systemd; $LOG_FILE does not exist."
    echo "Following journald output instead.  Ctrl-C to stop."
    echo ""
    exec journalctl -u rmail.service -f
fi

# Neither a log file nor an active systemd service.  Keep the original
# wait-for-file behaviour so a slow-starting runit/openrc install still
# works: user starts the service, then runs this script, then sees
# output as soon as the first line is written.
echo "Log file not found: $LOG_FILE"
echo "The rmail service may not be running yet."
echo ""
echo "Waiting for log file to appear..."
while [ ! -f "$LOG_FILE" ]; do
    sleep 1
done
echo "Log file created, following..."
exec tail -F "$LOG_FILE"
