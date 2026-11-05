#!/bin/sh
# test-busy-while-sending.sh — check that a daemon waiting on its own requests serves everyone meanwhile, and that a request touching a file the waiting step holds waits for that step only
#
# A sync cycle waits on its requests.  Until 2026-10-04 a daemon answered
# nobody meanwhile, so two daemons that each had something to send the
# other both waited out their 8-second limit, both backed off, and then
# -- each handling the other's late request, which makes the other due at
# once -- dialed each other at the same instant again, every few seconds,
# for as long as both had mail (#120).  From 2026-10-04 a caller it was
# dialing got a sealed "503 busy" and everyone else was held until the
# cycle ended.
#
# Since 2026-11-05 (#120) the cycle is a coroutine of the main loop and
# requests are served while it waits.  A request that reads or writes a
# state file the waiting step keeps across its wait (outbox.json and
# chunks-outgoing.json, for the outbox step) waits for that step, and no
# longer: its change can then not be lost.
#
# One real mailbox.  Its contact alice is a stand-in recipient
# (scripts/lib/fake-recipient.lua) told to hold its answer for 6 seconds;
# bob is a contact the daemon has no message for.  While the daemon waits
# on alice:
#
#   alice calls      answered properly at once (not "busy")
#   alice calls      the same, from a web page: her sealed request inside
#     again          a POST, answered inside a web reply at once
#   bob calls        answered at once
#   bob calls again  the same from a web page
#   bob answers an   that reads chunks-outgoing.json, which the outbox step
#     attachment     holds: answered (404, no such transfer) only after the
#     offer          step is done, never before alice answers
#   afterwards       alice still gets the message; the daemon did not
#                    back off from her and answered nobody "busy"
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
local held_since = socket.gettime()
print("ok the daemon is waiting on alice")

-- {{{ local function in_background
-- Runs one request as bob from another process, so it can wait while this
-- one goes on: `path` and `body` of a POST to /deliver.  Its status, how
-- long it took, when it ended and the answer's body land in `out`.
local function in_background(out, body)
    local script = out .. ".lua"
    local h = io.open(script, "w")
    h:write([[
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local b = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local t0 = b.socket.gettime()
local s, answer = b:request("POST", "/deliver", arg[4])
print(s, b.socket.gettime() - t0, b.socket.gettime(), answer)
]])
    h:close()
    os.execute(string.format("( %s/deps/lua/bin/lua %s %s %s %s '%s' > %s 2>&1 ) &",
        arg[1], script, arg[1], arg[2], arg[4], body, out))
end
-- }}}

-- bob answers an attachment offer the daemon never made: the handler reads
-- chunks-outgoing.json, which the outbox step holds while it waits on alice
local lease_out = WORK .. "/bob-lease.out"
in_background(lease_out, '{"type":"attachment_response","attachment_id":"nosuchoffer","consent":true}')

-- {{{ local function timed
local function timed(what, call)
    local t0 = socket.gettime()
    local a, b2, c = call()
    return socket.gettime() - t0, a, b2, c
end
-- }}}

local took, status, body = timed("alice", function() return alice:request("POST", "/deliver", '{"type":"chunk_failed"}') end)
if status == 200 and not body:find('"busy"') and took < 2 then
    print(string.format("ok alice, whom it is dialing, was answered properly at once (%.1fs)", took))
else
    print(string.format("-- alice was answered %s after %.1fs: %s", tostring(status), took, tostring(body)))
end

local web, inner, wbody
took, web, inner, wbody = timed("alice web", function() return alice:web_post("POST", "/deliver", '{"type":"chunk_failed"}') end)
if web == 200 and inner == 200 and wbody and not wbody:find('"busy"') and took < 2 then
    print(string.format("ok alice, calling from a web page, was answered properly inside a web reply (%.1fs)", took))
else
    print(string.format("-- alice from a web page was answered %s / %s after %.1fs: %s",
        tostring(web), tostring(inner), took, tostring(wbody)))
end

local bob = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[4])
took, status, body = timed("bob", function() return bob:request("GET", "/") end)
if status == 200 and took < 2 then
    print(string.format("ok bob was answered at once while the daemon waited (%.1fs)", took))
else
    print(string.format("-- bob was answered %s after %.1fs: %s", tostring(status), took, tostring(body)))
end

took, web, inner = timed("bob web", function() return bob:web_post("GET", "/") end)
if web == 200 and inner == 200 and took < 2 then
    print(string.format("ok bob from a web page was answered at once inside a web reply (%.1fs)", took))
else
    print(string.format("-- bob from a web page was answered %s / %s after %.1fs", tostring(web), tostring(inner), took))
end

-- the request that read a held file: answered only once alice was
alice:wait_for(30, function()
    local f = io.open(lease_out) if not f then return false end
    local s = f:read("*a") f:close() return s:match("^%d+") ~= nil
end)
local f = io.open(lease_out); local line = f and f:read("*a") or ""; if f then f:close() end
local ls, ltook, lat = line:match("^(%d+)%s+([%d%.]+)%s+([%d%.]+)")
if ls == "404" and tonumber(lat) and tonumber(lat) - held_since >= 5 then
    print(string.format("ok bob's answer to an offer, which reads a file the outbox step holds, waited for that step (%.1fs)",
        tonumber(ltook)))
else
    print("-- bob's answer to an offer was not held for the outbox step: " .. line)
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
if grep -q "answered busy" "$WORK/daemon.log"; then
    note_fail "the daemon answered someone busy"
else
    ok "nobody was answered busy"
fi
if grep -q "changed by another request or sync step" "$WORK/daemon.log"; then
    note_fail "a state file was changed under a request or sync step"
else
    ok "no state file was changed under anyone"
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
