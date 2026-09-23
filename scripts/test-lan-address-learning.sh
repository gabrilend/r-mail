#!/bin/sh
# test-lan-address-learning.sh — check which home-network addresses a mailbox learns from incoming connections
#
# When a contact who lives in the same house (same public address as us)
# connects to our mailbox, the daemon notes the address the connection came
# from, so later messages to that contact can go straight across the home
# network instead of out to the internet and back.  That is only right when
# the connection came straight across our own network.  In September 2026 a
# contact's connections arrived through a router (two routers in a row, the
# outer one relaying), the daemon noted the router's address as the
# contact's, and every later message to them was refused by the router.
#
# This script starts real daemons in RAM, one receiver and two senders, and
# has each sender deliver one message to the receiver by a different route:
#
#   direct    arrives from 192.168.1.x, the receiver's own network: never
#             taken for a relay
#   relayed   arrives from 192.168.122.1, a private address on another
#             network (this machine's virtual-machine bridge stands in for
#             an outer router): logged once and not learned
#
# It reads the receiver's log to see which it learned.  The machine must
# have an address on 192.168.1.x and the address 192.168.122.1 (true of
# the machine this was written on); the script stops if either is missing.
# The daemons look their public address up at startup, so this needs a
# working network and takes some seconds.
#
# Usage:
#   scripts/test-lan-address-learning.sh          # use the enclosing checkout
#   scripts/test-lan-address-learning.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/lan-address-learning"

# The daemons' shared RAM folder; this run's files there carry this prefix.
RAM_PREFIX="/tmp/rmail-progress/log-tmp-rmail-tests-lan-address-learning-"

RECEIVER_PORT=59460
DIRECT_PORT=59461
RELAYED_PORT=59462

# Longest any daemon runs.  Only reached when a case fails.
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail LAN-address learning test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

# The two routes the cases depend on.  A missing one is a machine this test
# cannot run on, not a pass.
HOME_LAN_IP=$(ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep '^192\.168\.1\.' | head -1)
if [ -z "$HOME_LAN_IP" ]; then
    note_fail "this machine has no 192.168.1.x address; cannot run the direct case"
    exit 1
fi
if ! ip -4 -o addr show | grep -q ' 192\.168\.122\.1/'; then
    note_fail "this machine has no 192.168.122.1 address; cannot run the relayed case"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f "$RAM_PREFIX"*

# The receiver files a contact as "in our house" when the contact's address
# is our own public address, so the senders are written down under it.
PUBLIC_IP=$(cat /home/ritz/mail/.state/public_ip)

# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state"
    : > "$1/contacts"
    printf 'name = %s\nport = %s\n' "$2" "$3" > "$1/config"
}

make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"
make_mailbox "$WORK/direct"   direct   "$DIRECT_PORT"
make_mailbox "$WORK/relayed"  relayed  "$RELAYED_PORT"

# The receiver knows both senders as housemates.
cat > "$WORK/receiver/contacts" <<EOF
direct.ip    = $PUBLIC_IP
direct.port  = $DIRECT_PORT
direct.token = "test-token-direct"

relayed.ip    = $PUBLIC_IP
relayed.port  = $RELAYED_PORT
relayed.token = "test-token-relayed"
EOF

# Each sender reaches the receiver by a different local address, which is
# what decides the address its connection arrives from.
printf 'receiver.ip    = %s\nreceiver.port  = %s\nreceiver.token = "test-token-direct"\n' \
    "$HOME_LAN_IP" "$RECEIVER_PORT" > "$WORK/direct/contacts"
printf 'receiver.ip    = 192.168.122.1\nreceiver.port  = %s\nreceiver.token = "test-token-relayed"\n' \
    "$RECEIVER_PORT" > "$WORK/relayed/contacts"

printf 'to: receiver\n\nsent straight across the home network\n' > "$WORK/direct/outbox/hello-direct"
printf 'to: receiver\n\nsent by way of another network\n'        > "$WORK/relayed/outbox/hello-relayed"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/direct/config" > "$WORK/direct.log" 2>&1 &
DIRECT_PID=$!
"$LAUNCHER" "$WORK/relayed/config" > "$WORK/relayed.log" 2>&1 &
RELAYED_PID=$!

# Done when both messages have arrived; the learning happens on the first
# request of each connection, before the delivery is logged.
echo "running three mailboxes (up to ${DEADLINE_SECONDS}s)"
waited=0
while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
    if grep -q "from direct -> hello-direct" "$WORK/receiver.log" \
       && grep -q "from relayed -> hello-relayed" "$WORK/receiver.log"; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done
# Now the behaviour that matters: the receiver writes back to the relayed
# sender.  Written only after both deliveries, so that whatever the
# receiver learned from their connection is already in place.  A receiver
# that learned the relay's address sends by it and says "same-network:
# using LAN IP 192.168.122.1 for relayed"; a correct one tries the public
# address, which on a test port answers no one and ends in the unreachable
# summary.
printf 'to: relayed\n\na reply\n' > "$WORK/receiver/outbox/reply-to-relayed"
waited=0
while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
    if grep -q "using LAN IP 192.168.122.1 for relayed" "$WORK/receiver.log" \
       || grep -q "unreachable contacts this cycle: .*relayed" "$WORK/receiver.log" \
       || grep -q "sent: reply-to-relayed" "$WORK/receiver.log"; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done

kill "$RECEIVER_PID" "$DIRECT_PID" "$RELAYED_PID"
wait "$RECEIVER_PID" "$DIRECT_PID" "$RELAYED_PID" 2>/dev/null

echo ""
echo "delivery"
if grep -q "from direct -> hello-direct" "$WORK/receiver.log" \
   && grep -q "from relayed -> hello-relayed" "$WORK/receiver.log"; then
    ok "both messages arrived"
else
    note_fail "not both messages arrived; the cases below mean nothing"
    info "$(grep 'delivered' "$WORK/receiver.log")"
fi

# Whether the direct sender's address is learned from its connection, or
# first from discovery or its own address announcement, is a race between
# daemons that all share this machine's one address -- so the direct case
# checks only what cannot race: a connection from our own network is never
# taken for a relay.
echo ""
echo "a connection straight across our network"
if grep -q "LAN address: direct connected from" "$WORK/receiver.log"; then
    note_fail "a connection from our own network was taken for a relay"
    info "$(grep 'LAN address' "$WORK/receiver.log")"
else
    ok "it is not taken for a relay"
fi

echo ""
echo "a connection from a private address on another network"
if grep -q "LAN address: relayed connected from 192.168.122.1, which is not on our network" "$WORK/receiver.log"; then
    ok "it is named in the log as a relay"
else
    note_fail "no relay line for the relayed sender"
    info "$(grep 'LAN address' "$WORK/receiver.log")"
fi
if grep -q "LAN address: relayed is at" "$WORK/receiver.log"; then
    note_fail "the relaying address was learned as the contact's own"
else
    ok "and it is not learned"
fi
if [ "$(grep -c 'LAN address: relayed connected from' "$WORK/receiver.log")" -le 1 ]; then
    ok "and the relay is logged at most once"
else
    note_fail "the relay line repeats"
fi
if grep -q "using LAN IP 192.168.122.1 for relayed" "$WORK/receiver.log"; then
    note_fail "a reply to the relayed sender was sent to the relay's address"
elif grep -q "unreachable contacts this cycle: .*relayed\|sent: reply-to-relayed" "$WORK/receiver.log"; then
    ok "and a reply to them is not sent to the relay's address"
else
    note_fail "the receiver never tried to send the reply, so this was not tested"
fi

rm -f "$RAM_PREFIX"*

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
