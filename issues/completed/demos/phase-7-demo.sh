#!/bin/sh
# phase-7-demo.sh — helpers and the door for the owner's own devices, measured: each helper on a sample mailbox, one sync exchange as a phone or thin client makes it
#
# Phase 7 is the tools around a mailbox: shell helpers that edit its files,
# and the door the home daemon opens for the owner's own devices (the
# phone, the desktop thin client).  This runs every helper on a sample
# outbox and consent form, then plays a device: one sync exchange with a
# real mailbox, showing what it is told to fetch and how long it took,
# then runs phase 7's tests.
#
# Usage: issues/completed/demos/phase-7-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=7
PHASE_NAME="helpers, the owner's own devices, desktop tools"
. "$SCRIPT_DIR/lib/demo.sh"
start

H="$DIR/helpers"
heading "The helpers, on a sample mailbox"
demo_box home "$DEMO_PORT_BASE"
printf 'to: alice\n\nminutes of the meeting\n' > "$BOX_home/outbox/minutes"
"$H/rto.sh" "$BOX_home/outbox/minutes" bob > /dev/null
"$H/rattach.sh" "$BOX_home/outbox/minutes" "$DIR/README.md" > /dev/null
show "rto.sh + rattach.sh turned the outbox file into:"
sed 's/^/      | /' "$BOX_home/outbox/minutes"
printf 'carol wants to send you an attachment.\n\naccept\ndeny\n' > "$DEMO_WORK/form-a"
cp "$DEMO_WORK/form-a" "$DEMO_WORK/form-b"
"$H/raccept.sh" "$DEMO_WORK/form-a" > /dev/null; "$H/rdeny.sh" "$DEMO_WORK/form-b" > /dev/null
show "raccept.sh leaves: $(tail -1 "$DEMO_WORK/form-a")      rdeny.sh leaves: $(tail -1 "$DEMO_WORK/form-b")"
printf 'alice.ip = "203.0.113.1"\nalice.phone = "555-0100"\n' > "$DEMO_WORK/contacts"
show "rfield.sh contacts alice phone -> $("$H/rfield.sh" "$DEMO_WORK/contacts" alice phone)"
show "checksum.sh README.md          -> $("$H/checksum.sh" "$DIR/README.md" | cut -c1-32)..."
show "filename.sh /home/x/inbox/hi   -> $("$H/filename.sh" /home/x/inbox/hi)"

heading "A device syncing with its home mailbox"
PORT=$((DEMO_PORT_BASE + 1)); PHONE="demo-phase-7-phone"
demo_box house "$PORT"
printf 'phone.token = "%s"\nphone.own = true\n\nalice.token = "a"\n' "$PHONE" > "$BOX_house/contacts"
printf 'see you at noon\n' > "$BOX_house/inbox/lunch"
printf '{"lunch":{"from":"alice","message_id":"m-1"}}' > "$BOX_house/.state/inbox.json"
printf 'to: alice\n\ndraft reply\n' > "$BOX_house/outbox/reply"
start_daemon house
wait_for 30 'grep -q "listening on" "$DEMO_WORK/house.log" 2>/dev/null'
# let its start-up cycle (address lookups, announcements) finish first:
# a request during a cycle waits for it
wait_for 30 '[ -f "$BOX_house/.state/public_ip" ]'; sleep 3
"$LUA" - "$DIR" "$PORT" "$PHONE" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local phone = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local t0 = phone.socket.gettime()
local st, answer = phone:post_json("/api/sync", {inbox = {}, outbox = {}, deleted_inbox = {}, deleted_outbox = {}})
local ms = (phone.socket.gettime() - t0) * 1000
print(string.format("    a device with nothing asked what it lacks: answered %s in %.1f ms", tostring(st), ms))
for _, e in ipairs(answer.fetch_inbox or {}) do print("      fetch inbox:  " .. e.filename .. "  (from " .. e.from .. ")") end
for _, f in ipairs(answer.fetch_outbox or {}) do print("      fetch outbox: " .. f) end
print("      contacts sent along: " .. (answer.contacts and (select(2, answer.contacts:gsub("\n", "")) .. " lines") or "none"))
local st2 = phone:request("GET", "/api/file/inbox/lunch")
print("      then GET /api/file/inbox/lunch -> " .. tostring(st2))
local stranger = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), "a")
print("    alice, a contact but not an own device, asking the same: " .. tostring((stranger:post_json("/api/sync", {}))))
LUA

stop_all

heading "Phase 7's tests"
run_tests test-phone-upload-checks.sh test-received-links.sh test-phone-contacts-save.sh
echo ""
