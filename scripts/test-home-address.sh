#!/bin/sh
# test-home-address.sh — check what a mailbox records as its own home-network
# address, and that old-style contact address lines are rewritten
#
# A mailbox keeps its own address on the home network (its "LAN IP") so it
# knows which contacts share its network and can be reached across it
# directly.  Until 2026-10-04 that lookup had a second guess that returned
# 127.0.0.1 -- the loopback address, which every machine has and which is
# never the home network -- whenever the network was not up yet, as at
# boot.  Both of the owner's mailboxes held 127.0.0.1, so neither tried the
# other's home address.  The same day LAN discovery (a broadcast "are you
# here?" to every device on the network) was removed (#418), and old
# `name.lan_ip` contact lines are now rewritten as `name.local-ip` lines.
#
# This script starts one throwaway mailbox in RAM and checks:
#
#   stale loopback   a mailbox that starts with 127.0.0.1 on record
#                    replaces it with this machine's real home address (the
#                    one the routing table gives), says "recorded" rather
#                    than "changed", and writes no "your address changed"
#                    notice into the inbox
#   lan_ip lines     a contact with only a lan_ip line gets a local-ip line;
#                    one whose lan_ip repeats its local-ip loses the copy;
#                    one whose lan_ip differs gets local-ip[1]
#   no discovery     the mailbox listens on TCP only, and logs no discovery
#                    or multicast lines
#
# It needs a working network: the mailbox looks its public address up at
# startup, and this machine's home address comes from the routing table.
#
# Usage:
#   scripts/test-home-address.sh          # use the enclosing checkout
#   scripts/test-home-address.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
WORK="/tmp/rmail/tests/home-address"
BOX="$WORK/box"
PORT=59395
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail home-address test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

# The answer the mailbox should arrive at: the routing table's source
# address for reaching the internet.
ROUTE=$(ip route get 1.1.1.1)
EXPECTED=$(echo "$ROUTE" | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -z "$EXPECTED" ]; then
    note_fail "this machine has no route to the internet, so there is no home address to expect"
    info "$ROUTE"
    exit 1
fi
info "this machine's home address (from the routing table): $EXPECTED"

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state"
printf 'name = home-address-test\nport = %s\n' "$PORT" > "$BOX/config"
echo "127.0.0.1" > "$BOX/.state/lan_ip"
TOKEN="home-address-test-token-not-a-real-secret"
cat > "$BOX/contacts" <<EOF
only-old.ip           = 203.0.113.10
only-old.port         = 59001
only-old.token        = "$TOKEN-1"
only-old.lan_ip       = 192.168.50.10

repeated.ip           = 203.0.113.11
repeated.port         = 59002
repeated.token        = "$TOKEN-2"
repeated.local-ip     = 192.168.50.11
repeated.lan_ip       = 192.168.50.11

different.ip          = 203.0.113.12
different.port        = 59003
different.token       = "$TOKEN-3"
different.local-ip    = 192.168.50.12
different.lan_ip      = 192.168.50.13
EOF

# Its RAM log is named after the mailbox path; cleared before and after.
RAM_LOGS="/tmp/rmail-progress/log-tmp-rmail-tests-home-address-"
rm -f "$RAM_LOGS"*

"$LAUNCHER" "$BOX/config" > "$WORK/box.log" 2>&1 &
BOX_PID=$!

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

echo "a stale loopback address on record"
if wait_for "$WORK/box.log" "LAN IP recorded\|LAN IP changed\|LAN IP: no route"; then
    recorded=$(cat "$BOX/.state/lan_ip")
    if [ "$recorded" = "$EXPECTED" ]; then
        ok "replaced by this machine's home address, $recorded"
    else
        note_fail "recorded '$recorded', expected $EXPECTED"
    fi
    if grep -q "LAN IP recorded: $EXPECTED" "$WORK/box.log"; then
        ok "logged as recorded, not as the machine having moved"
    else
        note_fail "not logged as a fresh record"
        info "$(grep 'LAN IP' "$WORK/box.log")"
    fi
    if [ -e "$BOX/inbox/lan-ip-changed" ]; then
        note_fail "a 'your address changed' notice was written for a loopback record"
    else
        ok "no 'your address changed' notice"
    fi
else
    note_fail "the mailbox never checked its home address"
fi

echo "old lan_ip contact lines"
# align_contacts runs at startup, before the address checks above finish.
if grep -q "^only-old\.local-ip *= 192\.168\.50\.10$" "$BOX/contacts" \
   && ! grep -q "^only-old\.lan_ip" "$BOX/contacts"; then
    ok "a lone lan_ip line became local-ip"
else
    note_fail "a lone lan_ip line was not rewritten"
fi
if [ "$(grep -c "192\.168\.50\.11" "$BOX/contacts")" = 1 ] && ! grep -q "^repeated\.lan_ip" "$BOX/contacts"; then
    ok "a lan_ip repeating the local-ip was dropped"
else
    note_fail "a repeated lan_ip line was not dropped"
fi
if grep -q "^different\.local-ip\[1\] *= 192\.168\.50\.13$" "$BOX/contacts" \
   && grep -q "^different\.local-ip *= 192\.168\.50\.12$" "$BOX/contacts"; then
    ok "a different lan_ip became local-ip[1], the first one kept"
else
    note_fail "a different lan_ip did not become local-ip[1]"
fi
if [ "$(grep -c "rewritten as\|already a local-ip line" "$WORK/box.log")" = 3 ]; then
    ok "each of the three was logged"
else
    note_fail "the conversions were not each logged"
fi

echo "no discovery"
if grep -q "listening on :$PORT (TCP" "$WORK/box.log" && ! grep -q "UDP" "$WORK/box.log"; then
    ok "listens on TCP only"
else
    note_fail "still listening on UDP"
    info "$(grep 'listening' "$WORK/box.log")"
fi
if grep -qi "discovery\|multicast" "$WORK/box.log"; then
    note_fail "discovery or multicast still appears in the log"
else
    ok "no discovery or multicast in the log"
fi

kill "$BOX_PID"
wait "$BOX_PID" 2>/dev/null
rm -f "$RAM_LOGS"*

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n"
    exit 0
fi
printf "  \033[31m%d case(s) failed\033[0m\n" "$FAILURES"
exit 1
