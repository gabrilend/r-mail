#!/bin/sh
# Source this from your shell rc file to get new mail notifications.
# Add to ~/.bashrc or ~/.zshrc:
#   . /path/to/scripts/check-mail.sh

NOTIFY_FILE="${HOME}/mail/.state/new-mail"

if [ -s "$NOTIFY_FILE" ]; then
    echo "you have new mail:"
    while IFS= read -r line; do
        echo "  $line"
    done < "$NOTIFY_FILE"
    > "$NOTIFY_FILE"
fi
