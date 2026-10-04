#!/bin/sh
# phase-6-demo.sh — installation, services and drives, measured: this machine's init system and mailboxes, a portable mailbox built in RAM, the documents
#
# Phase 6 is getting rmail onto machines and keeping it running: the
# installer, one service per mailbox, portable drives, the documents.
# This reports what the installer would find on this machine, builds a
# portable mailbox drive into a RAM folder and shows what is on it and how
# big, counts the guides, then runs phase 6's tests.
#
# Usage: issues/completed/demos/phase-6-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=6
PHASE_NAME="installation, services, drives and the documents"
. "$SCRIPT_DIR/lib/demo.sh"
start

heading "What the installer would find here"
init="unknown"
[ -f /etc/NIXOS ] && init="nixos"
[ "$init" = unknown ] && [ -f /proc/1/comm ] && case "$(cat /proc/1/comm)" in
    systemd) init=systemd ;; runit) init=runit ;; openrc-init) init=openrc ;; esac
show "init system: $init  (NixOS first, then process 1, then the tools present)"
n=0
for f in ~/.config/systemd/user/*.service /etc/systemd/system/*.service /etc/sv/*/run /etc/init.d/*; do
    [ -f "$f" ] && grep -q "run-rmail.sh\|rmail.lua" "$f" 2>/dev/null || continue
    n=$((n + 1))
    show "a mailbox service: $f -> $(grep -o '[^ ]*/config' "$f" | head -1)"
done
show "$n mailbox service(s) installed; each serves one mailbox, named after it"
running=$(ps -eo args | grep -c "[r]mail.lua .*/config")
show "$running daemon(s) running on this machine right now"

heading "A portable mailbox, built into RAM"
t0=$(now_ms)
mkdir -p "$DEMO_WORK/drive"
if "$DIR/scripts/make-mailbox-drive.sh" --name traveller --port 51999 --dest "$DEMO_WORK/drive" > "$DEMO_WORK/drive.out" 2>&1; then
    t1=$(now_ms)
    show "built in $((t1 - t0)) ms; what is on the drive:"
    (cd "$DEMO_WORK/drive" && find . -maxdepth 2 -not -path "*/source-code/*" | sort | sed 's/^\.\///' | grep -v '^\.$') | sed 's/^/      /'
    show "the program it carries: $(du -sh "$DEMO_WORK/drive/mailbox-0/source-code" 2>/dev/null | cut -f1) ($(find "$DEMO_WORK/drive/mailbox-0/source-code" -type f | wc -l) files: daemon, libraries, interpreter)"
    show "the whole drive: $(du -sh "$DEMO_WORK/drive" | cut -f1)"
else
    show "the drive could not be built here: $(tail -2 "$DEMO_WORK/drive.out" | tr '\n' ' ')"
fi

heading "The documents"
words=0; count=0
for f in "$DIR"/docs/.templates/*.md; do
    count=$((count + 1)); words=$((words + $(wc -w < "$f")))
done
show "$count guides, $words words, generated per machine from docs/.templates/ (real paths filled in)"
show "README: $(wc -w < "$DIR/README.md") words; table of contents: docs/table-of-contents.md"

stop_all

heading "Phase 6's tests"
run_tests test-license-harvest.sh
echo ""
