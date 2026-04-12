#!/bin/sh
# rto — insert to: lines into an outbox file
# Usage: rto <file> <recipient> [<recipient> ...]
#
# New to: lines are placed after the existing header block (contiguous
# to:/attach: lines at the top of the file), preserving attachment
# targeting semantics.

if [ $# -lt 2 ]; then
    printf 'Usage: rto <file> <recipient> [<recipient> ...]\n' >&2
    exit 1
fi

file="$1"
shift

# Build the new to: lines
new_lines=""
for name in "$@"; do
    new_lines="${new_lines}to: ${name}
"
done

# If file doesn't exist or is empty, just write the to: lines
if [ ! -f "$file" ] || [ ! -s "$file" ]; then
    printf '%s' "$new_lines" > "$file"
    exit 0
fi

# Find the end of the header block (contiguous to:/attach: lines)
header_end=0
while IFS= read -r line; do
    case "$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')" in
        to:*|attach:*) header_end=$((header_end + 1)) ;;
        *) break ;;
    esac
done < "$file"

if [ "$header_end" -eq 0 ]; then
    # No existing headers — prepend
    tmp=$(mktemp)
    printf '%s' "$new_lines" > "$tmp"
    cat "$file" >> "$tmp"
    mv "$tmp" "$file"
else
    # Insert after header block
    tmp=$(mktemp)
    head -n "$header_end" "$file" > "$tmp"
    printf '%s' "$new_lines" >> "$tmp"
    tail -n +"$((header_end + 1))" "$file" >> "$tmp"
    mv "$tmp" "$file"
fi
