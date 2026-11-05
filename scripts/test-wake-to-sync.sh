#!/bin/sh
# test-wake-to-sync.sh — check that a daemon whose machine slept checks its address and announces itself on waking
#
# Issue #419.  A machine that suspends is unreachable while it sleeps, so
# its contacts back off, and resume is when its address is likely to have
# moved.  The running daemon now notices the sleep -- its wait in the
# main loop came back far later by the wall clock than it asked for --
# and on waking checks its address, owes every contact an announcement,
# and makes every contact due at once, so the announcements go on the
# next pass instead of when each contact's timer would have come round.
#
# The machine's sleep is played by stopping the daemon (SIGSTOP) for 12
# seconds and letting it go on (SIGCONT): the wall clock runs on while it
# is stopped, as it does while a machine is suspended.  wake_gap is 3 so
# the test need not stop it for a minute.  One mailbox "sender", whose
# public address is written into .state by hand (198.51.100.7, a
# documentation address), and a stand-in contact "alice"
# (scripts/lib/fake-recipient.lua) that answers at once.  The cases:
#
#   idle         awake and idle for longer than wake_gap: no wake is
#                claimed (the loop's own waits are not mistaken for sleep)
#   backed off   alice is down when the daemon starts, so its start-up
#                announcement fails and alice is backed off to a minute or
#                more; alice comes up and the machine sleeps: on waking
#                the log says so, the address is checked, and alice has
#                the announcement within a few seconds, long before her
#                timer would have come round; the owed file is gone
#   delivered    alice up and nothing owed, the machine sleeps again: on
#                waking a fresh announcement is owed and delivered
#
# Usage:
#   scripts/test-wake-to-sync.sh          # use the enclosing checkout
#   scripts/test-wake-to-sync.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/wake-to-sync"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-wake-to-sync-*"
PORT=59525
ALICE_PORT=59526
TOKEN="wake-to-sync-test-token-not-a-real-secret"
BOX="$WORK/sender"
ALICE="$WORK/alice"
OWED="$BOX/outbox/.address-announcement-alice"
ASLEEP=12

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_for <seconds> <shell test>: 0 once it holds, 1 at the deadline
wait_for() {
    n=0
    while [ "$n" -lt $(($1 * 10)) ]; do
        eval "$2" && return 0
        sleep 0.1
        n=$((n + 1))
    done
    eval "$2"
}

# addresses: how many announcements alice has had
addresses() { n=$(grep -c '"kind":"address"' "$ALICE/events" 2>/dev/null); echo "${n:-0}"; }
# wakes: how many times the daemon said it woke
wakes() { n=$(grep -c "woke after about" "$WORK/daemon.log" 2>/dev/null); echo "${n:-0}"; }
# checks: how many address checks the daemon has logged
checks() { n=$(grep -c "address check" "$WORK/daemon.log" 2>/dev/null); echo "${n:-0}"; }

start_alice() {
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$TOKEN" "$ALICE" \
        > "$WORK/alice.log" 2>&1 &
    ALICE_PID=$!
}

# sleep_machine: the daemon is stopped for $ASLEEP seconds, then goes on
sleep_machine() {
    kill -STOP "$DAEMON_PID"
    sleep "$ASLEEP"
    kill -CONT "$DAEMON_PID"
}

echo ""
echo "rmail wake-to-sync test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/attachments" "$ALICE"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\nattachment_pending_dir = %s\nwake_gap = 3\n' \
    "$PORT" "$WORK/pending" > "$BOX/config"
printf 'alice.ip    = "127.0.0.1"\nalice.port  = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$TOKEN" > "$BOX/contacts"
printf '198.51.100.7\n' > "$BOX/.state/public_ip"

DAEMON_PID=""
ALICE_PID=""
stop_all() {
    [ -n "$DAEMON_PID" ] && kill -CONT "$DAEMON_PID" 2>/dev/null && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$ALICE_PID" ] && touch "$ALICE/stop" && kill "$ALICE_PID" 2>/dev/null
    wait 2>/dev/null
}
trap stop_all EXIT

"$LAUNCHER" "$BOX/config" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

echo ""
echo "idle"
if wait_for 30 'grep -q "backing off alice" "$WORK/daemon.log"'; then
    : # alice was down: the start-up announcement failed and she is backed off
else
    note_fail "the start-up announcement to alice (down) never failed: $(tail -3 "$WORK/daemon.log" | tr '\n' ' ')"
fi
FAILED_AT=$(date +%s)
sleep 8
[ "$(wakes)" = "0" ] && ok "8 seconds awake and idle: no wake claimed" \
    || note_fail "a wake was claimed while the daemon was awake: $(grep "woke after" "$WORK/daemon.log" | head -1)"
[ -e "$OWED" ] && ok "the start-up announcement waits in the outbox, alice backed off" \
    || note_fail "no owed announcement for alice after the failure"

echo ""
echo "backed off"
start_alice
wait_for 5 '[ -e "$ALICE/events" ] || [ -d "$ALICE/inbox" ]' > /dev/null
CHECKS_BEFORE=$(checks)
sleep_machine
WOKE_AT=$(date +%s)
if wait_for 4 '[ "$(addresses)" -ge 1 ]'; then
    ok "on waking alice had the announcement at once ($(($(date +%s) - WOKE_AT))s after waking, $(($(date +%s) - FAILED_AT))s after the failure)"
else
    note_fail "alice had no announcement within 4s of waking (her timer was not made due)"
fi
grep -q "woke after about [0-9]*s asleep" "$WORK/daemon.log" \
    && ok "the log says the daemon woke, and how long it was asleep" \
    || note_fail "no log line for the wake"
grep -q "after waking: announcing 198.51.100.7:$PORT to 1 contact(s)" "$WORK/daemon.log" \
    && ok "the log says the announcement was owed on waking" \
    || note_fail "no log line for announcing after waking"
wait_for 3 '[ "$(checks)" -gt "$CHECKS_BEFORE" ]' \
    && ok "the address was checked on waking" || note_fail "no address check on waking"
wait_for 3 '[ ! -e "$OWED" ]' && ok "the owed file is gone once delivered" \
    || note_fail "the owed file stayed after delivery"

echo ""
echo "delivered"
sleep 2
BEFORE=$(addresses)
WAKES_BEFORE=$(wakes)
sleep_machine
if wait_for 5 '[ "$(addresses)" -gt "$BEFORE" ]'; then
    ok "nothing owed, the machine slept again: a fresh announcement on waking"
else
    note_fail "no fresh announcement after the second sleep (alice has $(addresses))"
fi
[ "$(wakes)" -gt "$WAKES_BEFORE" ] && ok "the second wake is logged too" \
    || note_fail "the second wake was not noticed"
wait_for 3 '[ ! -e "$OWED" ]' || note_fail "the second owed file stayed"

stop_all
DAEMON_PID=""
ALICE_PID=""
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "daemon log: $WORK/daemon.log"
exit 1
