#!/bin/sh
# test-log-location.sh — check where a mailbox daemon keeps its own log file
#
# Besides writing every log line to whoever started it (a terminal, or the
# service's log), the daemon keeps a second copy in a plain file.  That file
# records every exchange with every contact, by name and time, so since
# 2026-09-23 it lives in RAM, in the daemon's shared folder
# /tmp/rmail-progress/, named after the mailbox path, and is gone after a
# reboot.  It used to sit in the mailbox's .state/ folder on disk.
#
# This script starts the real daemon on throwaway mailboxes in RAM, stops it
# as soon as it is listening, and checks which file got the log:
#
#   default      no log_file setting: RAM folder, named after the mailbox
#   explicit     log_file set to a path: that path, and nothing in RAM
#   none         log_file = "": no file copy anywhere
#
# Every mailbox is empty and every port is in the high 59xxx range that no
# install uses.  The three run at once.
#
# Usage:
#   scripts/test-log-location.sh          # use the enclosing checkout
#   scripts/test-log-location.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/log-location"

# The daemon's shared RAM folder, and the prefix every log file this run
# causes there will carry (the mailbox path with slashes turned to dashes).
RAM_DIR="/tmp/rmail-progress"
RAM_PREFIX="$RAM_DIR/log-tmp-rmail-tests-log-location-"

# Longest a daemon is left running.  A passing case stops as soon as the
# daemon says it is listening, which happens within a second or two.
DEADLINE_SECONDS=30

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail log-location test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f "$RAM_PREFIX"*

# make_mailbox <dir> <name> <port> [extra-config-line]
make_mailbox() {
    _dir="$1"; _name="$2"; _port="$3"; _extra="${4:-}"
    mkdir -p "$_dir/inbox" "$_dir/outbox" "$_dir/.state"
    : > "$_dir/contacts"
    {
        printf 'name = %s\n' "$_name"
        printf 'port = %s\n' "$_port"
        [ -n "$_extra" ] && printf '%s\n' "$_extra"
    } > "$_dir/config"
}

# run_case <name> <port> — start, wait until listening, stop.
run_case() {
    _name="$1"; _port="$2"
    _out="$WORK/$_name.stdout"
    : > "$_out"
    "$LAUNCHER" "$WORK/$_name/config" > "$_out" 2>&1 &
    _pid=$!
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "listening on :$_port" "$_out" && break
        sleep 1
        _waited=$((_waited + 1))
    done
    kill "$_pid"
    wait "$_pid" 2>/dev/null
}

make_mailbox "$WORK/default"  logdefault  59391
make_mailbox "$WORK/explicit" logexplicit 59392 "log_file = \"$WORK/explicit-chosen.log\""
make_mailbox "$WORK/none"     lognone     59393 'log_file = ""'

echo "running three mailboxes at once (up to ${DEADLINE_SECONDS}s)"
run_case default  59391 &
run_case explicit 59392 &
run_case none     59393 &
wait

echo ""
echo "no log_file setting"
if grep -q "rmail starting: name=logdefault" "${RAM_PREFIX}default" 2>/dev/null; then
    ok "the log is in RAM, named after the mailbox"
else
    note_fail "no log at ${RAM_PREFIX}default"
    info "RAM folder holds: $(ls "$RAM_DIR" 2>&1)"
fi
if [ ! -e "$WORK/default/.state/rmail.log" ]; then
    ok "and nothing was written to the mailbox's .state/ folder"
else
    note_fail "a log was still written to .state/rmail.log"
fi

echo ""
echo "log_file set to a path"
if grep -q "rmail starting: name=logexplicit" "$WORK/explicit-chosen.log" 2>/dev/null; then
    ok "the log is at the chosen path"
else
    note_fail "no log at the chosen path"
fi
if [ ! -e "${RAM_PREFIX}explicit" ]; then
    ok "and not in RAM as well"
else
    note_fail "a copy also went to the RAM folder"
fi

echo ""
echo "log_file = \"\""
if [ ! -e "${RAM_PREFIX}none" ] && [ ! -e "$WORK/none/.state/rmail.log" ]; then
    ok "no file copy anywhere"
else
    note_fail "a file copy was written anyway"
fi
if grep -q "rmail starting: name=lognone" "$WORK/none.stdout"; then
    ok "the lines still reach whoever started the daemon"
else
    note_fail "nothing reached standard error"
fi

# The RAM folder is shared with the real mailboxes; leave nothing in it.
rm -f "$RAM_PREFIX"*

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
