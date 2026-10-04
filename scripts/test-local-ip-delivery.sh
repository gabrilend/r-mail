#!/bin/sh
# test-local-ip-delivery.sh — check that two mailboxes behind one router
# reach each other at the home-network address in a contact's local-ip line
#
# Two mailboxes in one house share a public address.  Sending to that public
# address from inside the house needs the router to turn the packet round
# ("hairpin NAT"), which many routers will not do.  So a contact can carry a
# `local-ip` line, its address on the home network, and rmail tries that
# first whenever it is on our own network (#409).
#
# Until 2026-10-04 a separate step also swapped a request to our own public
# address for the contact's local address, and LAN discovery broadcast to
# find addresses.  Both are gone (#418).  This checks the local-ip line
# alone gets a message through, and that it is the address used.
#
# Two throwaway mailboxes in RAM on this machine, each holding the other
# under this machine's public address with a local-ip line of this
# machine's home address.  Alpha sends Bravo one message.
#
# Needs a working network: the public address is looked up at startup, and
# the home address comes from the routing table.
#
# Usage:
#   scripts/test-local-ip-delivery.sh          # use the enclosing checkout
#   scripts/test-local-ip-delivery.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
WORK="/tmp/rmail/tests/local-ip-delivery"
ALPHA_PORT=59393
BRAVO_PORT=59394
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail local-ip delivery test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

ROUTE=$(ip route get 1.1.1.1)
LAN_IP=$(echo "$ROUTE" | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -z "$LAN_IP" ]; then
    note_fail "this machine has no route to the internet, so no home address to use"
    exit 1
fi

rm -rf "$WORK"
RAM_LOGS="/tmp/rmail-progress/log-tmp-rmail-tests-local-ip-delivery-"
rm -f "$RAM_LOGS"*

# {{{ make_mailbox <dir> <own-name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state"
    : > "$1/contacts"
    printf 'name = %s\nport = %s\n' "$2" "$3" > "$1/config"
}
# }}}

# {{{ wait_for <file-or-log> <pattern>
# With a pattern: wait until the file contains it.  Without: until it exists.
wait_for() {
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        if [ -n "$2" ]; then grep -q "$2" "$1" && return 0
        else [ -e "$1" ] && return 0
        fi
        sleep 1
        _waited=$((_waited + 1))
    done
    return 1
}
# }}}

# The public address, learned from a probe mailbox's startup lookup.
make_mailbox "$WORK/probe" probe 59392
"$LAUNCHER" "$WORK/probe/config" > "$WORK/probe.log" 2>&1 &
PROBE_PID=$!
wait_for "$WORK/probe.log" "public IP recorded"
kill "$PROBE_PID"
wait "$PROBE_PID" 2>/dev/null
PUBLIC_IP=$(cat "$WORK/probe/.state/public_ip" 2>/dev/null)
if [ -z "$PUBLIC_IP" ]; then
    note_fail "could not learn this machine's public address (no network?)"
    exit 1
fi
info "public address: $PUBLIC_IP   home address: $LAN_IP"

TOKEN="local-ip-delivery-test-token-not-a-real-secret"
make_mailbox "$WORK/alpha" alpha "$ALPHA_PORT"
make_mailbox "$WORK/bravo" bravo "$BRAVO_PORT"
printf 'bravo.ip       = %s\nbravo.local-ip = %s\nbravo.port     = %s\nbravo.token    = "%s"\n' \
    "$PUBLIC_IP" "$LAN_IP" "$BRAVO_PORT" "$TOKEN" > "$WORK/alpha/contacts"
printf 'alpha.ip       = %s\nalpha.local-ip = %s\nalpha.port     = %s\nalpha.token    = "%s"\n' \
    "$PUBLIC_IP" "$LAN_IP" "$ALPHA_PORT" "$TOKEN" > "$WORK/bravo/contacts"

"$LAUNCHER" "$WORK/bravo/config" > "$WORK/bravo.log" 2>&1 &
BRAVO_PID=$!
"$LAUNCHER" "$WORK/alpha/config" > "$WORK/alpha.log" 2>&1 &
ALPHA_PID=$!
wait_for "$WORK/alpha.log" "LAN IP recorded"
printf 'to: bravo\n\nacross the house\n' > "$WORK/alpha/outbox/hello"

echo "a message between two mailboxes in one house"
if wait_for "$WORK/bravo/inbox/hello"; then
    ok "bravo got alpha's message"
else
    note_fail "bravo never got alpha's message"
    info "$(tail -5 "$WORK/alpha.log")"
fi
if grep -q "timeout connecting to $PUBLIC_IP:$BRAVO_PORT" "$WORK/alpha.log"; then
    note_fail "alpha tried the public address first"
else
    ok "alpha did not wait on the public address"
fi
if grep -qi "discovery\|multicast\|same-network\|using LAN IP" "$WORK/alpha.log" "$WORK/bravo.log"; then
    note_fail "a removed step (discovery or the address swap) still ran"
else
    ok "no discovery and no address swap: the local-ip line did it alone"
fi

kill "$ALPHA_PID" "$BRAVO_PID"
wait "$ALPHA_PID" 2>/dev/null
wait "$BRAVO_PID" 2>/dev/null
rm -f "$RAM_LOGS"*

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n"
    exit 0
fi
printf "  \033[31m%d case(s) failed\033[0m\n" "$FAILURES"
exit 1
