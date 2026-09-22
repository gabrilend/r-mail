#!/bin/sh
# test-lan-discovery-names.sh — check that two mailboxes on one network find
# each other even when they call each other by different names
#
# Every name in a contacts file is chosen locally: I can call you "bravo"
# while you call yourself "b-home".  When two mailboxes sit behind the same
# router they look for each other with an encrypted "are you here?" packet,
# and the receiver tells who sent it by which contact's password opens it.
# The address it learns has to be filed under that contact's local name,
# because that is the name every later lookup uses.  It used to be filed
# under a name written inside the packet — the sender's name for itself —
# so whenever the two names differed, the search found the other mailbox and
# then forgot it (#393).  The packet no longer carries a name at all.
#
# This script starts two throwaway mailboxes in RAM, each naming the other
# differently from how the other names itself, and checks each log says the
# address was filed under the local contact name.  Only multicast on this
# machine is involved; nothing reaches a real peer.  It needs a working
# network, because a mailbox only searches for contacts that share its
# public address, and that address is looked up over DNS at startup.
#
# Usage:
#   scripts/test-lan-discovery-names.sh          # use the enclosing checkout
#   scripts/test-lan-discovery-names.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
WORK="/tmp/rmail/tests/lan-discovery-names"
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail LAN-discovery naming test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

rm -rf "$WORK"
mkdir -p "$WORK"

# {{{ make_mailbox <dir> <own-name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state"
    : > "$1/contacts"
    printf 'name = %s\nport = %s\n' "$2" "$3" > "$1/config"
}
# }}}

# {{{ wait_for <log> <pattern>
wait_for() {
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$2" "$1" && return 0
        sleep 1
        _waited=$((_waited + 1))
    done
    return 1
}
# }}}

# A mailbox searches only for contacts stored under its own public address,
# so learn that address first from a probe mailbox's startup lookup.
make_mailbox "$WORK/probe" probe 59390
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
info "public address: $PUBLIC_IP"

TOKEN="lan-discovery-test-token-not-a-real-secret"
make_mailbox "$WORK/alpha" alpha-calls-itself 59391
make_mailbox "$WORK/bravo" bravo-calls-itself 59392
printf 'bravo-to-alpha.ip    = %s\nbravo-to-alpha.port  = 59392\nbravo-to-alpha.token = "%s"\n' \
    "$PUBLIC_IP" "$TOKEN" > "$WORK/alpha/contacts"
printf 'alpha-to-bravo.ip    = %s\nalpha-to-bravo.port  = 59391\nalpha-to-bravo.token = "%s"\n' \
    "$PUBLIC_IP" "$TOKEN" > "$WORK/bravo/contacts"

"$LAUNCHER" "$WORK/alpha/config" > "$WORK/alpha.log" 2>&1 &
ALPHA_PID=$!
"$LAUNCHER" "$WORK/bravo/config" > "$WORK/bravo.log" 2>&1 &
BRAVO_PID=$!

echo "each side files the other under its own name for it"
if wait_for "$WORK/alpha.log" "LAN discovery: bravo-to-alpha is at"; then
    ok "alpha filed the address under 'bravo-to-alpha'"
else
    note_fail "alpha did not file bravo's address under its contact name"
    info "$(grep 'LAN discovery' "$WORK/alpha.log" | tail -3)"
fi
if wait_for "$WORK/bravo.log" "LAN discovery: alpha-to-bravo is at"; then
    ok "bravo filed the address under 'alpha-to-bravo'"
else
    note_fail "bravo did not file alpha's address under its contact name"
    info "$(grep 'LAN discovery' "$WORK/bravo.log" | tail -3)"
fi

# Each mailbox's own name lives only in its own config.  If it turned up in
# the other side's log, it travelled in a packet.
if grep -q "bravo-calls-itself" "$WORK/alpha.log" || grep -q "alpha-calls-itself" "$WORK/bravo.log"; then
    note_fail "a mailbox's own name reached the other side"
else
    ok "neither mailbox's own name reached the other side"
fi

kill "$ALPHA_PID" "$BRAVO_PID"
wait "$ALPHA_PID" 2>/dev/null
wait "$BRAVO_PID" 2>/dev/null

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n"
    exit 0
fi
printf "  \033[31m%d case(s) failed\033[0m\n" "$FAILURES"
exit 1
