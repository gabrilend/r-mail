#!/bin/sh
# phase-5-demo.sh — contacts and identity, measured: the file as a person writes it, the form the phone holds, a phone save that keeps every comment
#
# Phase 5 is the contacts file: written by hand, read by the daemon, held
# by the phone in a plain sorted form, and saved back from the phone
# without losing the person's comments.  This shows a contacts file and
# its canonical form side by side, saves an edit from a stand-in phone,
# shows exactly which lines changed, then runs phase 5's tests.
#
# Usage: issues/completed/demos/phase-5-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=5
PHASE_NAME="contacts, identity and saved state"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE
PHONE_TOKEN="demo-phase-5-phone"
demo_box home "$PORT"
cat > "$BOX_home/contacts" <<CONTACTS
// my contacts

// the phone in my pocket
phone.token = "$PHONE_TOKEN"
phone.own   = true

# zed first: I write to him most
zed.ip    = "203.0.113.9"
zed.port  = 51001
zed.token = "zed-secret"

// alice, home computer and laptop
alice.ip    = "203.0.113.1"
alice.ip[1] = "198.51.100.1"
alice.port  = 51002
alice.token = "alice-secret"
CONTACTS
cp "$BOX_home/contacts" "$DEMO_WORK/contacts.before"
start_daemon home
wait_for 30 'grep -q "listening on" "$DEMO_WORK/home.log" 2>/dev/null'

heading "The file, and the form the phone holds"
"$LUA" - "$DIR" "$PORT" "$PHONE_TOKEN" > "$DEMO_WORK/canonical" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local _, text = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3]):request("GET", "/api/contacts")
io.write(text)
LUA
paste -d'\0' "$BOX_home/contacts" /dev/null | awk '{printf "    %-44s\n", $0}' > "$DEMO_WORK/left"
awk '{printf "%s\n", $0}' "$DEMO_WORK/canonical" > "$DEMO_WORK/right"
show "$(printf '%-44s %s' 'contacts (as written)' 'canonical (the phone, the hash)')"
paste "$DEMO_WORK/left" "$DEMO_WORK/right" | sed 's/\t/ /' | sed 's/^    //' | sed 's/^/    /'
show "$(grep -c '' "$BOX_home/contacts") lines with comments and order -> $(grep -c . "$DEMO_WORK/canonical") lines, sorted, one fact each"

heading "The phone changes zed's address and adds bob"
"$LUA" - "$DIR" "$PORT" "$PHONE_TOKEN" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local phone = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local _, text = phone:request("GET", "/api/contacts")
text = text:gsub('zed%.ip = "203%.0%.113%.9"', 'zed.ip = "203.0.113.99"')
text = text .. 'bob.ip = "192.0.2.5"\nbob.port = 51003\nbob.token = "bob-secret"\n'
print("    saved: answered " .. tostring((phone:request("POST", "/api/contacts", text))))
LUA
sleep 1
show "the lines that changed in the file (everything else, comments included, as it was):"
diff "$DEMO_WORK/contacts.before" "$BOX_home/contacts" | grep '^[<>]' | sed 's/^/      /'
show "comments before: $(grep -c '^\s*\(//\|#\)' "$DEMO_WORK/contacts.before"), after: $(grep -c '^\s*\(//\|#\)' "$BOX_home/contacts")"

stop_all

heading "Phase 5's tests"
run_tests test-phone-contacts-save.sh
echo ""
