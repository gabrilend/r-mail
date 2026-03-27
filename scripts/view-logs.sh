#!/bin/sh
# view-logs.sh — display rmail daemon logs in real-time
#
# Usage: ./scripts/view-logs.sh
#
# Logs are stored in RAM (/tmp/rmail.log) to avoid disk wear.
# They don't persist across reboots.

DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_FILE="/tmp/rmail.log"

# allow override via argument
[ -n "$1" ] && LOG_FILE="$1"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    echo "The rmail service may not be running yet."
    echo ""
    echo "Waiting for log file to appear..."
    while [ ! -f "$LOG_FILE" ]; do
        sleep 1
    done
    echo "Log file created, following..."
fi

# use tail -F (capital F) to follow even if file is recreated
# this handles log rotation or service restarts
exec tail -F "$LOG_FILE"
