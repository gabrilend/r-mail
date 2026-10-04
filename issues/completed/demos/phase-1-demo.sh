#!/bin/sh
# phase-1-demo.sh — the daemon's core, measured: start-up, a sealed frame, finding the sender, the timers, a busy answer
#
# Phase 1 is the daemon itself: one daemon per mailbox, a loop that waits
# on sockets and file watchers, every request sealed with the sender's key,
# a sync cycle with a timer per contact.  This starts a throwaway mailbox
# in RAM and measures those parts as they run, then runs phase 1's tests.
#
# Usage: issues/completed/demos/phase-1-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=1
PHASE_NAME="the daemon's core"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE
TOKEN="demo-phase-1-alice-token"
demo_box home "$PORT"
printf 'alice.token = "%s"\n' "$TOKEN" > "$BOX_home/contacts"

heading "Starting a mailbox"
t0=$(now_ms)
start_daemon home
wait_for 30 'grep -q "listening on" "$DEMO_WORK/home.log" 2>/dev/null'
t1=$(now_ms)
show "listening $((t1 - t0)) ms after launch; the start-up lines it wrote:"
grep -E "rmail starting|json decoder|watcher active|listening on" "$DEMO_WORK/home.log" | sed 's/^/      /'

heading "One request, sealed"
"$LUA" - "$DIR" "$PORT" "$TOKEN" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. arg[1] .. "/libs/?.lua;" .. package.path
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local crypto = require("rmail_crypto")
local fc = require("fake-contact")
local alice = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local text = "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
local key = crypto.sha256(arg[3])
local nonce = crypto.random_bytes(12)
local sealed = crypto.aes_gcm_encrypt(key, nonce, text)
local frame = #nonce + #sealed
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
print(string.format("    the request:     %q (%d bytes)", text, #text))
print(string.format("    on the wire:     4-byte length + 12-byte nonce + %d sealed + 16-byte tag = %d bytes", #text, 4 + frame))
print("    the frame starts " .. hex(nonce):sub(1, 24) .. " " .. hex(sealed):sub(1, 24) .. "...")
local status, body = alice:request("GET", "/")
print(string.format("    the daemon answered %s, sealed with the same key: %s", tostring(status), body))
-- finding the sender: a wrong key fails its tag; how long N wrong keys take
local socket = require("socket")
print("    nothing in a frame names its sender; the daemon tries each contact's key:")
for _, n in ipairs({1, 10, 100, 1000}) do
    local keys = {}
    for i = 1, n do keys[i] = crypto.sha256("someone-else-" .. i) end
    local t0 = socket.gettime()
    for i = 1, n do crypto.aes_gcm_decrypt(keys[i], nonce, sealed) end
    local ms = (socket.gettime() - t0) * 1000
    print(string.format("      %5d wrong keys tried in %7.2f ms  (%.1f µs each)", n, ms, ms * 1000 / n))
end
LUA

heading "A timer per contact"
show "after a cycle that reached them: due again in 30 s (± 30 s jitter)"
show "after one that did not, the wait grows by 6 minutes, to a ceiling of 2 hours:"
"$LUA" - <<'LUA'
local floor, step, ceiling = 30, 360, 7200
local t, i, line = floor, 0, {}
repeat
    i = i + 1
    line[#line + 1] = string.format("%d:%ds", i, t)
    t = math.min(ceiling, t + step)
until t == ceiling
line[#line + 1] = string.format("%d+:%ds", i + 1, ceiling)
print("      failures:wait  " .. table.concat(line, "  "))
print(string.format("      at the ceiling an unreachable contact costs %d attempts a day (a fixed 30 s would be %d)",
    math.floor(86400 / ceiling), 86400 / floor))
LUA

stop_all

heading "Phase 1's tests"
run_tests test-mailbox-selection.sh test-log-location.sh test-json-decoders.sh \
          test-plaintext-health-check.sh test-busy-while-sending.sh test-edit-delivery.sh
echo ""
