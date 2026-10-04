#!/bin/sh
# run-demo.sh — ask which phase to show, and run that phase's demo
#
# The project's issues are sorted into nine phases (docs/table-of-contents.md).
# Each has a demo in issues/completed/demos/ that starts throwaway mailboxes
# in RAM, makes them do that phase's work, prints what came out and how long
# it took, and runs the phase's tests.  This asks for a phase number and
# runs its demo.
#
# Usage:
#   ./run-demo.sh          # asks
#   ./run-demo.sh 3        # phase 3 at once
#   ./run-demo.sh 3 /path  # phase 3 of another checkout

DIR="$(cd "$(dirname "$0")" && pwd)"
DEMOS="$DIR/issues/completed/demos"
[ -n "$2" ] && DIR="$2"

phases=$(ls "$DEMOS" | sed -n 's/^phase-\([0-9]*\)-demo\.sh$/\1/p' | sort -n)
last=$(echo "$phases" | tail -1)

choice="$1"
if [ -z "$choice" ]; then
    echo "rmail phase demos:"
    for p in $phases; do
        printf "  %s  %s\n" "$p" "$(sed -n '2s/^# phase-[0-9]*-demo\.sh — //p' "$DEMOS/phase-$p-demo.sh")"
    done
    printf "which phase (1-%s)? " "$last"
    read -r choice
fi

case "$choice" in
    ''|*[!0-9]*) echo "not a phase number: $choice" >&2; exit 2 ;;
esac
if [ ! -x "$DEMOS/phase-$choice-demo.sh" ]; then
    echo "no demo for phase $choice (there are 1-$last)" >&2
    exit 2
fi
exec "$DEMOS/phase-$choice-demo.sh" "$DIR"
