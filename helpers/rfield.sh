#!/bin/sh
# rfield — read an arbitrary field from the rmail contacts file
# Usage: rfield <name> <field>
# Example: rfield alice phone

if [ $# -ne 2 ]; then
    printf 'Usage: rfield <name> <field>\n' >&2
    printf 'Example: rfield alice phone\n' >&2
    exit 1
fi

name="$1"
field="$2"

# Determine contacts file path.
# Read mail = ... from ~/.config/rmail/config, fall back to ~/mail.
config="${HOME}/.config/rmail/config"
mail_dir=""

if [ -f "$config" ]; then
    mail_dir=$(grep -m1 '^[[:space:]]*mail[[:space:]]*=' "$config" \
        | sed 's/^[[:space:]]*mail[[:space:]]*=[[:space:]]*//' \
        | sed 's/[[:space:]]*$//' \
        | sed "s|^~|${HOME}|")
fi

if [ -z "$mail_dir" ]; then
    mail_dir="${HOME}/mail"
fi

contacts="${mail_dir}/contacts"

if [ ! -f "$contacts" ]; then
    printf 'rfield: contacts file not found: %s\n' "$contacts" >&2
    exit 1
fi

# Search for the line matching ^<name>.<field>\s*=\s*
line=$(grep -m1 "^${name}\\.${field}[[:space:]]*=" "$contacts")

if [ -z "$line" ]; then
    printf 'rfield: field not found: %s.%s\n' "$name" "$field" >&2
    exit 1
fi

# Extract the value: everything after the first '='
value=$(printf '%s' "$line" | sed 's/^[^=]*=[[:space:]]*//')

# Strip leading and trailing whitespace
value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')

# Strip surrounding double quotes
case "$value" in
    '"'*'"')
        value=$(printf '%s' "$value" | sed 's/^"//' | sed 's/"$//')
        ;;
    "'"*"'")
        value=$(printf '%s' "$value" | sed "s/^'//" | sed "s/'$//")
        ;;
esac

printf '%s\n' "$value"
