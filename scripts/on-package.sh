#!/bin/sh
# Called by rmail when an attachment is received.
# Add to rmail.lua config: ON_PACKAGE = "/path/to/scripts/on-package.sh"

NOTIFY_FILE="${HOME}/mail/.state/new-mail"
echo "package $(basename "$1")" >> "$NOTIFY_FILE"
