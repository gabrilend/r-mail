#!/bin/sh
# test-serve-while-syncing.sh — two real daemons that each have something to send the other at the same moment both deliver within one cycle (#120)
#
# A sync cycle waits on its own requests.  When it ran inline, a daemon
# answered nobody while it waited: two daemons dialing each other at once
# each waited out the other's 8-second limit and backed off, and from
# 2026-10-04 each answered the other "busy" and tried again a few seconds
# later.  That is why the two-mailbox tests use a stand-in recipient.
# Since 2026-11-05 the cycle is a coroutine of the main loop and requests
# are served while it waits.
#
# Two throwaway mailboxes, "west" and "east", each the other's contact on
# this machine.  Each also has a stand-in contact, "slow"
# (scripts/lib/fake-recipient.lua), that holds its first answer for 6
# seconds, so each daemon's first cycle is certainly still waiting when
# the other's message reaches it.  Each round both daemons start with a
# message already in the outbox for the other and one for "slow"; at
# start-up every contact is due, so both dial each other at once:
#
#   each round   both messages arrive before either stand-in has
#                answered, so inside each daemon's first cycle
#   afterwards   neither log has a connect timeout, a backing-off line, a
#                "busy" answer or retry, or a state file changed under a
#                request
#
# Usage:
#   scripts/test-serve-while-syncing.sh          # use the enclosing checkout
#   scripts/test-serve-while-syncing.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/serve-while-syncing"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-serve-while-syncing-*"
WEST_PORT=59560
EAST_PORT=59561
WEST_SLOW_PORT=59562
EAST_SLOW_PORT=59563
TOKEN="serve-while-syncing-token-not-a-real-secret"
SLOW_TOKEN="serve-while-syncing-slow-token-not-a-secret"
ROUNDS=3
HOLD=6

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail serve-while-syncing test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then note_fail "no launcher at $LAUNCHER"; exit 1; fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES

# make_mailbox <dir> <name> <port> <other name> <other port> <slow port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
    printf '%s.ip    = "127.0.0.1"\n%s.port  = %s\n%s.token = "%s"\n\n' "$4" "$4" "$5" "$4" "$TOKEN" > "$1/contacts"
    printf 'slow.ip    = "127.0.0.1"\nslow.port  = %s\nslow.token = "%s"\n' "$6" "$SLOW_TOKEN" >> "$1/contacts"
}
make_mailbox "$WORK/west" west "$WEST_PORT" east "$EAST_PORT" "$WEST_SLOW_PORT"
make_mailbox "$WORK/east" east "$EAST_PORT" west "$WEST_PORT" "$EAST_SLOW_PORT"

# not_answered <side>: that side's stand-in has not answered yet (its hold
# file goes once it has), so that side's first cycle, which sends to it,
# is still waiting.  Whether it had begun holding is checked afterwards:
# the two daemons can finish with each other before the stand-in has even
# read its request.
not_answered() {
    [ -f "$WORK/$1-slow/hold" ]
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
    for side in west east; do
        rm -rf "$WORK/$side-slow"
        mkdir -p "$WORK/$side-slow"
        printf '%s\n' "$HOLD" > "$WORK/$side-slow/hold"
    done
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$WEST_SLOW_PORT" "$SLOW_TOKEN" "$WORK/west-slow" \
        >> "$WORK/west-slow.log" 2>&1 &
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$EAST_SLOW_PORT" "$SLOW_TOKEN" "$WORK/east-slow" \
        >> "$WORK/east-slow.log" 2>&1 &
    printf 'to: east\n\nround %s, from west\n' "$round" > "$WORK/west/outbox/round-$round"
    printf 'to: slow\n\nround %s, from west\n' "$round" > "$WORK/west/outbox/slow-$round"
    printf 'to: west\n\nround %s, from east\n' "$round" > "$WORK/east/outbox/round-$round"
    printf 'to: slow\n\nround %s, from east\n' "$round" > "$WORK/east/outbox/slow-$round"
    echo "--- round $round" >> "$WORK/west.log"
    echo "--- round $round" >> "$WORK/east.log"
    "$LAUNCHER" "$WORK/west/config" >> "$WORK/west.log" 2>&1 &
    WEST_PID=$!
    "$LAUNCHER" "$WORK/east/config" >> "$WORK/east.log" 2>&1 &
    EAST_PID=$!

    # wait (up to 30 s) for both messages, noting whether both stand-ins
    # were still holding when the second one arrived
    tenths=0
    arrived=no
    while [ "$tenths" -lt 300 ]; do
        holding=no
        if not_answered west && not_answered east; then holding=yes; fi
        if [ -f "$WORK/east/inbox/round-$round" ] && [ -f "$WORK/west/inbox/round-$round" ]; then
            arrived=yes
            break
        fi
        sleep 0.1
        tenths=$((tenths + 1))
    done
    took="$(printf '%d.%d' $((tenths / 10)) $((tenths % 10)))"
    if [ "$arrived" = yes ] && [ "$holding" = yes ]; then
        ok "round $round: both messages arrived (${took}s after start) while both daemons' first cycles still waited"
    elif [ "$arrived" = yes ]; then
        note_fail "round $round: both messages arrived after ${took}s, but only after a stand-in had answered (a first cycle had ended)"
    else
        note_fail "round $round: after ${took}s east has $(ls "$WORK/east/inbox" | tr '\n' ' ')and west has $(ls "$WORK/west/inbox" | tr '\n' ' ')"
    fi

    # let the stand-ins answer and the messages to them go, then stop
    wait_slow=0
    while [ "$wait_slow" -lt 300 ]; do
        if ls "$WORK/west-slow/inbox" 2>/dev/null | grep -q . \
            && ls "$WORK/east-slow/inbox" 2>/dev/null | grep -q .; then break; fi
        sleep 0.1
        wait_slow=$((wait_slow + 1))
    done
    if ls "$WORK/west-slow/inbox" 2>/dev/null | grep -q . && ls "$WORK/east-slow/inbox" 2>/dev/null | grep -q . \
        && [ -f "$WORK/west-slow/holding" ] && [ -f "$WORK/east-slow/holding" ]; then
        ok "round $round: both stand-ins held their answers, then got their messages"
    else
        note_fail "round $round: a stand-in never held its answer or never got its message"
    fi
    kill "$WEST_PID" "$EAST_PID"
    wait "$WEST_PID" "$EAST_PID" 2>/dev/null
    # a stand-in looks for its stop file every half second
    touch "$WORK/west-slow/stop" "$WORK/east-slow/stop"
    sleep 1
    round=$((round + 1))
done

for side in west east; do
    if grep -q "timeout connecting" "$WORK/$side.log"; then
        note_fail "$side waited out a connect timeout"
    else
        ok "$side never waited out a connect timeout"
    fi
    if grep -q "backing off\|answered busy\|at the same moment\|changed by another request or sync step" "$WORK/$side.log"; then
        note_fail "$side backed off, answered or was answered busy, or had a state file changed under it"
    else
        ok "$side never backed off, answered or was answered busy, or had a state file changed under it"
    fi
done

rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "logs: $WORK/west.log $WORK/east.log"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
