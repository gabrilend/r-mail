#!/bin/sh
# test-busy-while-sending.sh — check that a daemon waiting on its own requests answers a contact it is dialing at once, and holds everyone else
#
# A sync cycle waits on its requests on the main thread.  Until 2026-10-04
# a daemon answered nobody meanwhile, so two daemons that each had
# something to send the other both waited out their 8-second limit, both
# backed off, and then -- each handling the other's late request, which
# makes the other due at once -- dialed each other at the same instant
# again, every few seconds, for as long as both had mail (#120).
#
# Now, while a batch waits, a caller it is dialing gets an immediate sealed
# "503 busy" (retry soon, no backoff), and any other caller is held and
# handled the moment the cycle ends.
#
# One real mailbox.  Its contact alice is a stand-in recipient
# (scripts/lib/fake-recipient.lua) told to hold its answer for 6 seconds;
# bob is a contact the daemon has no message for.  While the daemon waits
# on alice:
#
#   alice calls      answered "busy" at once, sealed with alice's key
#   bob calls        held: answered properly, after the cycle -- not
#                    refused, not "busy"
#   afterwards       alice still gets the message; the daemon did not
#                    back off from her
#
# Usage:
#   scripts/test-busy-while-sending.sh          # use the enclosing checkout
#   scripts/test-busy-while-sending.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/busy-while-sending"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-busy-while-sending-*"
PORT=59505
ALICE_PORT=59506
ALICE_TOKEN="busy-while-sending-alice-token-not-a-secret"
BOB_TOKEN="busy-while-sending-bob-token-not-a-secret"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail busy-while-sending test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
mkdir -p "$WORK/box/inbox" "$WORK/box/outbox" "$WORK/box/.state" "$WORK/box/attachments" "$WORK/alice"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\n' "$PORT" > "$WORK/box/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n\nbob.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" "$BOB_TOKEN" > "$WORK/box/contacts"

# alice holds her first answer for 6 seconds
printf '6\n' > "$WORK/alice/hold"
"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
"$LAUNCHER" "$WORK/box/config" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
printf 'to: alice\n\nhello\n' > "$WORK/box/outbox/a-note"

"$LUA" - "$DIR" "$PORT" "$ALICE_TOKEN" "$BOB_TOKEN" "$WORK" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local alice = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local bob   = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[4])
local WORK  = arg[5]
local socket = alice.socket

-- {{{ local function exists
local function exists(path)
    local f = io.open(path)
    if f then f:close() return true end
    return false
end
-- }}}

if not alice:wait_for(60, function() return exists(WORK .. "/alice/holding") end) then
    print("-- the daemon never dialed alice")
    os.exit(0)
end
print("ok the daemon is waiting on alice")

-- bob, from another process, at the same moment
local bob_out = WORK .. "/bob.out"
os.execute("( " .. arg[1] .. "/deps/lua/bin/lua -e 'package.path=\"" .. arg[1] ..
    "/scripts/lib/?.lua;\"..package.path local fc=require(\"fake-contact\") local b=fc.new(\"" ..
    arg[1] .. "\",\"127.0.0.1\"," .. arg[2] .. ",\"" .. arg[4] ..
    "\") local t0=b.socket.gettime() local s,body=b:request(\"GET\",\"/\") print(s, b.socket.gettime()-t0, body)' > " ..
    bob_out .. " 2>&1 ) &")

local t0 = socket.gettime()
local status, body = alice:request("POST", "/deliver", '{"type":"chunk_failed"}')
local took = socket.gettime() - t0
if status == 503 and body:find('"busy"') and took < 3 then
    print(string.format("ok alice, whom it is dialing, was answered busy at once (%.1fs)", took))
else
    print(string.format("-- alice was answered %s after %.1fs: %s", tostring(status), took, body))
end

alice:wait_for(20, function()
    local f = io.open(bob_out) if not f then return false end
    local s = f:read("*a") f:close() return s:match("^%d+") ~= nil
end)
local f = io.open(bob_out); local line = f and f:read("*a") or ""; if f then f:close() end
local bs, btook = line:match("^(%d+)%s+([%d%.]+)")
if bs == "200" and tonumber(btook) and tonumber(btook) >= 2 then
    print(string.format("ok bob was held, then answered properly after the cycle (%.1fs)", tonumber(btook)))
else
    print("-- bob was not held and answered: " .. line)
end
LUA
while IFS= read -r line; do
    case "$line" in
        "ok "*) ok "${line#ok }" ;;
        "-- "*) note_fail "${line#-- }" ;;
        *)      info "$line" ;;
    esac
done < "$WORK/lua.out"

waited=0
while [ "$waited" -lt 60 ] && [ ! -f "$WORK/alice/inbox/a-note" ]; do sleep 1; waited=$((waited + 1)); done
[ -f "$WORK/alice/inbox/a-note" ] && ok "alice got the message" || note_fail "alice never got the message"
if grep -q "backing off alice" "$WORK/daemon.log"; then
    note_fail "the daemon backed off from alice"
else
    ok "the daemon did not back off from alice"
fi
if grep -q "alice called while we were sending to them; answered busy" "$WORK/daemon.log"; then
    ok "the daemon's log says why alice was answered busy"
else
    note_fail "no log line for the busy answer"
fi

kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null
touch "$WORK/alice/stop"
wait
rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "daemon log: $WORK/daemon.log"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
