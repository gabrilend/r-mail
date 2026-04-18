#!/bin/sh
# rfield — read an arbitrary field from an rmail contacts file
# Usage: rfield <contacts-file> <name> <field>
# Example: rfield ~/mail/contacts alice phone

if [ $# -ne 3 ]; then
    printf 'Usage: rfield <contacts-file> <name> <field>\n' >&2
    printf 'Example: rfield ~/mail/contacts alice phone\n' >&2
    exit 1
fi

contacts="$1"
name="$2"
field="$3"

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

# Strip surrounding double or single quotes
case "$value" in
    '"'*'"')
        value=$(printf '%s' "$value" | sed 's/^"//' | sed 's/"$//')
        ;;
    "'"*"'")
        value=$(printf '%s' "$value" | sed "s/^'//" | sed "s/'$//")
        ;;
esac

printf '%s\n' "$value"
