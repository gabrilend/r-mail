#!/bin/sh
# Called by rmail when a message is received.
# Add to rmail.lua config: ON_RECEIVE = "/path/to/scripts/on-message.sh"

NOTIFY_FILE="${HOME}/mail/.state/new-mail"
echo "message $(basename "$1")" >> "$NOTIFY_FILE"
