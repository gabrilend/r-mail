#!/bin/sh
# rdeny — deny a package consent request
# Usage: rdeny <consent-file>
#
# Removes the "accept" line from a consent-to-download-form file, leaving
# only "deny" for the daemon to pick up on the next sync cycle.

if [ $# -ne 1 ]; then
    printf 'Usage: rdeny <consent-file>\n' >&2
    exit 1
fi

file="$1"

if [ ! -f "$file" ]; then
    printf 'rdeny: file not found: %s\n' "$file" >&2
    exit 1
fi

tmp=$(mktemp)
grep -v '^accept$' "$file" > "$tmp"
mv "$tmp" "$file"
