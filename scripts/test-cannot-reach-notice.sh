#!/bin/sh
# test-cannot-reach-notice.sh — check that a contact the daemon cannot reach is reported in the outbox, and the report withdrawn once they are reached
#
# Issue #102, step 7, the outbound case: a contact who has mail waiting and
# has not been reached for `cannot_reach_notice_after` seconds (a day by
# default) gets a notice, `outbox/CANNOT-REACH-<name>`, written by the
# daemon for the person who owns the mailbox.  It is not mail: it names
# nobody to send to, and it stays as written.  The next time the contact
# is reached the daemon removes it.
#
# Cases, against one throwaway mailbox named "sender" whose contact
# "alice" is at a port nothing listens on, with one note waiting for her:
#   default          one failed attempt writes no notice (a day has not
#                    passed)
#   after the limit  with cannot_reach_notice_after = 0 the failed attempt
#                    writes the notice in the outbox (not the inbox),
#                    naming alice; the note stays waiting; the notice is
#                    not touched by the outbox's own passes and is said
#                    once in the log
#   reached          alice comes up (a stand-in recipient) and calls; the
#                    daemon delivers the note and removes the notice
#
# Usage:
#   scripts/test-cannot-reach-notice.sh          # use the enclosing checkout
#   scripts/test-cannot-reach-notice.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/cannot-reach-notice"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-cannot-reach-notice-*"
PORT=59518
ALICE_PORT=59519
ALICE_TOKEN="cannot-reach-notice-alice-token-not-a-secret"
BOX="$WORK/box"
NOTICE="$BOX/outbox/CANNOT-REACH-alice"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_for <seconds> <shell test>: 0 once the test holds, 1 at the deadline
wait_for() {
    w_left=$1; shift
    while [ "$w_left" -gt 0 ]; do
        if eval "$@"; then return 0; fi
        sleep 1; w_left=$((w_left - 1))
    done
    eval "$@"
}

start_daemon() {
    "$LAUNCHER" "$BOX/config" >> "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
}
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}
failed_attempts() { grep -c "unreachable contacts this cycle: .*alice" "$WORK/daemon.log"; }

echo ""
echo "rmail cannot-reach-notice test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/attachments" "$WORK/alice"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\n' "$PORT" > "$BOX/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" > "$BOX/contacts"
printf 'to: alice\n\nhello\n' > "$BOX/outbox/a-note"

echo ""
echo "default: a day has not passed"
start_daemon
if wait_for 60 '[ "$(failed_attempts)" -ge 1 ]'; then
    ok "the daemon tried alice and failed"
else
    note_fail "the daemon never tried alice"
fi
sleep 2
if [ -e "$NOTICE" ]; then
    note_fail "one failed attempt wrote a notice before a day had passed"
else
    ok "one failed attempt writes no notice"
fi
stop_daemon

echo ""
echo "after the limit: cannot_reach_notice_after = 0"
printf 'cannot_reach_notice_after = 0\n' >> "$BOX/config"
start_daemon
if wait_for 60 '[ -e "$NOTICE" ]'; then
    ok "the failed attempt wrote outbox/CANNOT-REACH-alice"
else
    note_fail "no notice in the outbox after a failed attempt"
fi
[ -e "$BOX/inbox/CANNOT-REACH-alice" ] && note_fail "the notice went to the inbox too"
if grep -q "mail waiting for alice" "$NOTICE" 2>/dev/null && grep -q "not sent to anyone" "$NOTICE"; then
    ok "it names alice and says it is not sent"
else
    note_fail "the notice does not name alice or say it is not sent"
fi
if grep -q "^to:" "$NOTICE" 2>/dev/null; then
    note_fail "the notice has a to: line"
fi
cp "$NOTICE" "$WORK/notice-first" 2>/dev/null
# a few more passes over the outbox (the notice's own arrival is a file
# change); alice is backed off, so nothing rewrites it meanwhile
printf 'to: alice\n\nanother\n' > "$BOX/outbox/b-note"
sleep 6
if cmp -s "$NOTICE" "$WORK/notice-first"; then
    ok "the outbox's passes leave the notice as written"
else
    note_fail "the notice changed or went while alice was not tried"
fi
if grep -q "^to: alice" "$BOX/outbox/a-note" 2>/dev/null; then
    ok "the note to alice is still waiting"
else
    note_fail "the note to alice is gone"
fi
said=$(grep -c "could not reach alice for" "$WORK/daemon.log")
if [ "$said" -eq 1 ]; then
    ok "the log says it once"
else
    note_fail "the log says it $said times"
fi
if grep "CANNOT-REACH" "$WORK/daemon.log" | grep -vq "could not reach alice for"; then
    note_fail "the daemon treated the notice as mail:"
    grep "CANNOT-REACH" "$WORK/daemon.log" | grep -v "could not reach alice for" | head -3 | while IFS= read -r l; do info "$l"; done
fi

echo ""
echo "reached: alice comes up and calls"
"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
ALICE_PID=$!
sleep 1
# her call makes her due at once (the daemon's backoff is per contact and
# an inbound call resets it), so the next pass dials her
"$LUA" - "$DIR" "$PORT" "$ALICE_TOKEN" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local alice = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local status = alice:request("POST", "/deliver", alice.json.encode({type = "message", subject = "back",
    body = "I am back\n", message_id = "alice-back-1"}))
print("alice's call answered " .. tostring(status))
LUA
info "$(cat "$WORK/lua.out")"
if wait_for 60 '[ -e "$WORK/alice/inbox/a-note" ] && [ ! -e "$NOTICE" ]'; then
    ok "alice got the note and the notice is gone"
else
    [ -e "$WORK/alice/inbox/a-note" ] || note_fail "alice never got the note"
    [ -e "$NOTICE" ] && note_fail "the notice is still in the outbox after alice was reached"
fi
grep -q "reached alice again: removed the outbox notice" "$WORK/daemon.log" \
    && ok "the log says the notice was removed" \
    || note_fail "no log line for the removal"

stop_daemon
touch "$WORK/alice/stop"
sleep 1
kill "$ALICE_PID" 2>/dev/null
wait "$ALICE_PID" 2>/dev/null
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "daemon log: $WORK/daemon.log"
exit 1
