#!/bin/sh
# raccept — accept a package consent request
# Usage: raccept <consent-file>
#
# Removes the "deny" line from a consent-to-download-form file, leaving
# only "accept" for the daemon to pick up on the next sync cycle.

if [ $# -ne 1 ]; then
    printf 'Usage: raccept <consent-file>\n' >&2
    exit 1
fi

file="$1"

if [ ! -f "$file" ]; then
    printf 'raccept: file not found: %s\n' "$file" >&2
    exit 1
fi

tmp=$(mktemp)
grep -v '^deny$' "$file" > "$tmp"
mv "$tmp" "$file"
