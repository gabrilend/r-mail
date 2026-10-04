#!/bin/sh
# phase-3-demo.sh — attachments and consent, measured: a consent form, a file in pieces, one yes and one no, the answers kept
#
# Phase 3 is attachments: nothing moves before the recipient says yes; then
# the file travels in checked pieces, packed once, and every recipient's
# answer is kept.  This shows the consent form a real mailbox writes, sends
# one file from a real mailbox to two stand-in recipients (one says yes,
# one says no), measures the transfer, prints the sender's record of their
# answers, then runs phase 3's tests.
#
# Usage: issues/completed/demos/phase-3-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=3
PHASE_NAME="attachments and consent"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE
ALICE_PORT=$((PORT + 1)); BOB_PORT=$((PORT + 2)); RX_PORT=$((PORT + 3))
ALICE_TOKEN="demo-phase-3-alice"; BOB_TOKEN="demo-phase-3-bob"

# {{{ say — a recipient's own word to the sender
say() {
    "$LUA" - "$DIR" "$PORT" "$1" "$2" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
print((fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3]):request("POST", "/deliver", arg[4])))
LUA
}
# }}}
# {{{ request_id — the attachment id a stand-in was offered
request_id() {
    "$LUA" - "$DIR" "$DEMO_WORK/$1/events" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do local e = json.decode(line) if e and e.kind == "request" then print(e.id) break end end
LUA
}
# }}}

heading "The consent form a mailbox writes"
demo_box receiver "$RX_PORT"
printf 'sender.token = "demo-phase-3-sender"\n' > "$BOX_receiver/contacts"
start_daemon receiver
wait_for 30 'grep -q "listening on" "$DEMO_WORK/receiver.log" 2>/dev/null'
"$LUA" - "$DIR" "$RX_PORT" <<'LUA' > /dev/null
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local s = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), "demo-phase-3-sender")
s:post_json("/deliver", {type = "attachment_request", attachment_id = "abcdef01-2345-4678-9abc-def012345678",
    filename = "holiday-photos.zip", expected_size = 48000000, message_id = "demo"})
LUA
for f in "$BOX_receiver/inbox/"*-consent-to-download-form; do
    show "inbox/$(basename "$f"):"
    sed 's/^/      | /' "$f"
done

heading "One file to two people"
demo_box home "$PORT"
printf 'attachment_chunk_size = 65536\n' >> "$BOX_home/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n\nbob.ip = "127.0.0.1"\nbob.port = %s\nbob.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" "$BOB_PORT" "$BOB_TOKEN" > "$BOX_home/contacts"
mkdir -p "$DEMO_WORK/files"
head -c 3000000 /dev/urandom > "$DEMO_WORK/files/recording.bin"
printf 'to: alice\nto: bob\nattach: %s\n\nthe recording from Saturday\n' "$DEMO_WORK/files/recording.bin" > "$BOX_home/outbox/recording"
start_recipient alice "$ALICE_PORT" "$ALICE_TOKEN"
start_recipient bob "$BOB_PORT" "$BOB_TOKEN"
start_daemon home
wait_for 120 '[ -n "$(request_id alice)" ] && [ -n "$(request_id bob)" ]'
A=$(request_id alice); Bb=$(request_id bob)
show "both were offered it: a 3,000,000-byte file, packed once"
t0=$(now_ms)
say "$ALICE_TOKEN" "{\"type\":\"attachment_response\",\"attachment_id\":\"$A\",\"consent\":true}" > /dev/null
say "$BOB_TOKEN" "{\"type\":\"attachment_response\",\"attachment_id\":\"$Bb\",\"consent\":false}" > /dev/null
show "alice said yes; bob said no"
wait_for 120 '[ -f "$DEMO_WORK/alice/received/$A.zip" ]'
t1=$(now_ms)
pieces=$(ls "$DEMO_WORK/alice/pieces/$A" | wc -l)
bytes=$(wc -c < "$DEMO_WORK/alice/received/$A.zip")
ms=$((t1 - t0))
show "alice holds the whole zip: $bytes bytes in $pieces pieces of 64 KiB, $ms ms after her yes"
show "$(awk -v b="$bytes" -v m="$ms" 'BEGIN { if (m > 0) printf "%.1f MB/s, each piece checked by its SHA-256 on arrival", b / m / 1000 }')"
wait_for 30 '! ls "$BOX_home/attachments/.pending/"rmail-*.zip >/dev/null 2>&1'
show "the sender's packed copy is gone: everyone has answered"

heading "What the sender keeps about each recipient"
"$LUA" - "$DIR" "$BOX_home/.state/outbox.json" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[2]); local state = require("dkjson").decode(f:read("*a")); f:close()
for _, who in ipairs({"alice", "bob"}) do
    local r = state.recording.recipients[who]
    for path, answer in pairs(r.attachments or {}) do
        print(string.format("    %-6s %-10s %s", who, answer, path:match("[^/]+$")))
    end
end
LUA
show "(complete and declined are never offered again; withdrawn is, if the line comes back)"

stop_all

heading "Phase 3's tests"
run_tests test-attachment-answers.sh test-attachment-withdraw-and-resume.sh test-attachment-round-trip.sh \
          test-attachment-ids-and-consent.sh test-consent-form-name.sh test-chunk-rules.sh \
          test-torn-pack.sh test-unpacked-size.sh test-received-links.sh test-stale-transfer-records.sh \
          test-zip-library.sh test-phone-upload-checks.sh
echo ""
