#!/bin/sh
# phase-4-demo.sh — addresses and networking, measured: what this machine knows of itself, an announcement merged, an announcement that changes nothing
#
# Phase 4 is reaching people whose addresses change: knowing our own,
# telling contacts, and keeping every address a contact has told us.
# This starts a real mailbox, shows the addresses it found for itself,
# has a stand-in contact announce a set of addresses to it, shows the
# contacts file before and after, shows that the same announcement again
# writes nothing, then runs phase 4's tests.
#
# Usage: issues/completed/demos/phase-4-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=4
PHASE_NAME="addresses and networking"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE
TOKEN="demo-phase-4-carol"
demo_box home "$PORT"
printf '// carol: we only had her old address\ncarol.ip    = "127.0.0.1"\ncarol.port  = 51000\ncarol.token = "%s"\n' "$TOKEN" > "$BOX_home/contacts"

heading "What this machine knows of itself"
t0=$(now_ms)
start_daemon home
wait_for 40 '[ -f "$BOX_home/.state/public_ip" ]'
wait_for 20 '[ -f "$BOX_home/.state/public_ip" ]'
t1=$(now_ms)
for f in public_ip lan_ip public_ipv6; do
    [ -f "$BOX_home/.state/$f" ] && show "$(printf '%-12s %s' "$f" "$(cat "$BOX_home/.state/$f")")"
done
show "found $((t1 - t0)) ms after start (public address from DNS-based services, confirmed by a second one when it changes)"

heading "carol announces where she is"
show "before:"
sed 's/^/      | /' "$BOX_home/contacts"
"$LUA" - "$DIR" "$PORT" "$TOKEN" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local carol = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local st = carol:post_json("/update-address", {ip = "203.0.113.7", port = 51000,
    ips = {{addr = "203.0.113.7", port = 51000}, {addr = "2001:db8::7", port = 51000}}})
print("    she sent: public 203.0.113.7 and IPv6 2001:db8::7 -> answered " .. tostring(st))
LUA
sleep 1
show "after (her pinned address stays first; the rest follow, tried in turn):"
sed 's/^/      | /' "$BOX_home/contacts"
ls -a "$BOX_home/inbox" | grep -q "^.address-update-carol$" && show "a hidden note, inbox/.address-update-carol, says to confirm it by reaching her there"

heading "The same announcement again"
before=$(stat -c %Y.%s "$BOX_home/contacts")
sleep 1
"$LUA" - "$DIR" "$PORT" "$TOKEN" <<'LUA' > /dev/null
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3]):post_json("/update-address", {ip = "203.0.113.7", port = 51000,
    ips = {{addr = "2001:db8::7", port = 51000}, {addr = "203.0.113.7", port = 51000}}})
LUA
sleep 1
after=$(stat -c %Y.%s "$BOX_home/contacts")
if [ "$before" = "$after" ]; then
    show "the contacts file was not written: nothing new, in a different order, is not news"
    show "(writing it would wake the watcher, announce back, and two idle daemons would talk forever)"
else
    show "the contacts file was written again"
fi

stop_all

heading "Phase 4's tests"
run_tests test-lan-address-learning.sh test-lan-discovery-names.sh
show "(LAN discovery's naming test also failed before 2026-10-04 on this machine; see the phase 4 notes)"
echo ""
