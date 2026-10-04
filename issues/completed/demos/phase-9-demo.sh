#!/bin/sh
# phase-9-demo.sh — what someone watching the network learns today: message sizes show through the sealed frames
#
# Phase 9 is privacy against people who watch the network, and carrying
# rmail over other networks.  None of it is built yet, so this demo
# measures the problem it exists to solve: a real mailbox sends messages
# of very different lengths to a stand-in recipient that records the size
# of every sealed frame as it arrives — exactly what an onlooker sees.
# The table shows the length of what was written showing straight through
# the encryption.  Then it lists the phase's planned issues.
#
# Usage: issues/completed/demos/phase-9-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=9
PHASE_NAME="privacy against watchers; new transports"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE; ALICE_PORT=$((PORT + 1)); TOKEN="demo-phase-9-alice"
demo_box home "$PORT"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' "$ALICE_PORT" "$TOKEN" > "$BOX_home/contacts"
start_recipient alice "$ALICE_PORT" "$TOKEN"
start_daemon home
wait_for 30 'grep -q "listening on" "$DEMO_WORK/home.log" 2>/dev/null'
sleep 10

heading "Sizes on the wire"
for n in 2 20 200 2000 20000; do
    head -c "$n" /dev/zero | tr '\0' 'x' > "$DEMO_WORK/body"
    { printf 'to: alice\n\n'; cat "$DEMO_WORK/body"; } > "$BOX_home/outbox/.m$n"
    mv "$BOX_home/outbox/.m$n" "$BOX_home/outbox/m$n"
done
wait_for 120 '[ -f "$DEMO_WORK/alice/inbox/m20000" ] && [ -f "$DEMO_WORK/alice/inbox/m2" ]'
"$LUA" - "$DIR" "$DEMO_WORK/alice/events" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local rows = {}
for line in io.lines(arg[2]) do
    local e = json.decode(line)
    if e and e.kind == "message" then rows[#rows + 1] = e end
end
table.sort(rows, function(a, b) return a.body_bytes < b.body_bytes end)
print("      written   sealed frame   frame - written")
for _, e in ipairs(rows) do
    print(string.format("    %8d   %12d   %15d", e.body_bytes, e.frame, e.frame - e.body_bytes))
end
print("    the frame is the message plus a near-constant wrapping: its length is")
print("    there for anyone on the path to read, along with who and when")
LUA

stop_all

heading "What phase 9 plans"
for f in "$DIR"/issues/9*.md; do
    [ -f "$f" ] || continue
    show "$(sed -n 's/^# #\?[0-9]* *[—-]* *//p' "$f" | head -1)"
done
show "(nothing here is built yet; there are no tests to run)"
echo ""
