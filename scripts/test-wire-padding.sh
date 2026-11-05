#!/bin/sh
# test-wire-padding.sh — check that frames are padded inside the seal, to power-of-two sizes, only between daemons that read padding (#901)
#
# A frame's length is on the wire for anyone to see.  A padded plaintext is
# [4-byte length][the real one][random bytes], sealed whole, to the next
# power of two (64 bytes at least, 16 KiB more at most).  Older daemons,
# the phone and the thin client cannot read that, so it is agreed: every
# request carries `Rmail-Pad: 1`, answers are padded only when asked, and
# requests only to a contact that has shown it reads padding.
#
# The daemon under test, "receiver", has two contacts: "mallory", played
# by scripts/lib/fake-contact.lua, who calls it, and "alice", played by
# scripts/lib/fake-recipient.lua, whom it sends to.  Both speak the padded
# framing from their own code, written from the issue, not the daemon's.
#
# Cases:
#   an older caller      a request with no padding and no Rmail-Pad line
#                        is answered unpadded, and mallory is not noted
#   a newer caller       the line alone gets a padded answer, and mallory
#                        is noted in .state/wire-padding.json; a padded
#                        request is read (the message lands, byte for
#                        byte) and answered padded; an old-format request
#                        is still read
#   an older recipient   what is sent to alice carries the line, unpadded
#   a newer recipient    alice answers padded, is noted, and what follows
#                        is padded: every frame a power of two plus the
#                        32 bytes of length, nonce and tag; two messages of
#                        different lengths in one bucket are the same size
#                        on the wire; a big one gets 16 KiB and no more;
#                        alice gets every body byte for byte
#   after a restart      the note survives, and the first request is padded
#   busy                 alice calls while the daemon waits on her answer:
#                        the "busy" answer is padded as well
#   back to older        alice goes back to an older daemon: the padded
#                        request is answered 404 unpadded, alice is
#                        forgotten (log and state), and the message is sent
#                        again unpadded and arrives
#
# Usage:
#   scripts/test-wire-padding.sh          # use the enclosing checkout
#   scripts/test-wire-padding.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/wire-padding"
PORT=59570
TEST_NAME="wire-padding"
. "$SCRIPT_DIR/lib/test-receiver.sh"

ALICE_PORT=59571
ALICE_TOKEN="wire-padding-alice-token-not-a-secret"
export ALICE_PORT ALICE_TOKEN
printf '\nalice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" >> "$BOX/contacts"
mkdir -p "$WORK/alice"
"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
ALICE_PID=$!

start_receiver

# The Lua half's shared start: the helpers every phase uses.
PRELUDE='
package.path = arg[1] .. "/scripts/lib/?.lua;" .. arg[1] .. "/libs/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local json = mallory.json
local alice_dir = work .. "/alice"
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail ~= nil and (": " .. tostring(detail)) or "")) end
end
local function read(path) local f = io.open(path, "rb"); if not f then return nil end; local s = f:read("*a"); f:close(); return s end
local function write(path, s) local f = assert(io.open(path, "wb")); f:write(s); f:close() end
local function log() return read(work .. "/daemon.log") or "" end
local function noted(name) local t = json.decode(read(box .. "/.state/wire-padding.json") or "") ; return type(t) == "table" and t[name] ~= nil end
local function events()
    local list = {}
    for line in (read(alice_dir .. "/events") or ""):gmatch("[^\n]+") do list[#list + 1] = json.decode(line) end
    return list
end
local function message_event(subject)
    for _, e in ipairs(events()) do if e.kind == "message" and e.subject == subject then return e end end
end
local function pow2(n) local p = 64; while p < n do p = p * 2 end; return p == n end
-- a note for alice in the outbox, with a body of `size` bytes; returns its body
local function send(subject, size)
    local body = string.rep("x", size - 1) .. "\n"
    write(box .. "/outbox/" .. subject, "to: alice\n\n" .. body)
    return body
end
local function arrived(subject, seconds)
    return mallory:wait_for(seconds or 60, function() return message_event(subject) ~= nil end)
end
'

# (through a file, not a pipe: a function at the end of a pipe runs in a
# subshell, and the failures it counted would be lost with it)
run_phase() {
    { printf '%s\n' "$PRELUDE"; cat; } > "$WORK/phase.lua"
    run_lua_cases < "$WORK/phase.lua"
}

run_phase <<'LUA'
print("section an older caller")
local status = mallory:request("GET", "/")
check(status == 200 and mallory.last.padded == false, "a request with no padding and no line is answered unpadded")
check(not noted("mallory"), "and mallory is not noted as reading padding")

print("section a newer caller")
status = mallory:request("GET", "/", nil, {ask = true})
check(status == 200 and mallory.last.padded, "the Rmail-Pad line alone gets a padded answer")
check(pow2(mallory.last.got - 32), "the answer is a power of two plus 32 bytes on the wire", mallory.last.got)
check(noted("mallory"), "mallory is noted in .state/wire-padding.json")
check(log():find("mallory reads padded frames", 1, true), "and the log says so")
local body = "a short one, padded\n"
status = mallory:request("POST", "/deliver", json.encode({type = "message", subject = "padded-in",
    message_id = "wire-padding-1", body = body}), {ask = true, pad = true})
check(status == 200 and mallory.last.padded, "a padded request is read and answered padded", status)
check(pow2(mallory.last.sent - 32), "the request was a power of two on the wire too", mallory.last.sent)
check(mallory:wait_for(10, function() return read(box .. "/inbox/padded-in") == body end),
    "the message lands, byte for byte", read(box .. "/inbox/padded-in"))
status = mallory:request("GET", "/")
check(status == 200 and not mallory.last.padded, "an old-format request is still read, and answered in kind")

print("section an older recipient")
send("first", 10)
check(arrived("first"), "the note reaches alice")
local e = message_event("first") or {}
check(e.asked == true and e.padded == false, "with the Rmail-Pad line, unpadded", json.encode(e))
check(not noted("alice"), "and alice is not noted")

print("section a newer recipient")
write(alice_dir .. "/pads", "")
send("second", 10)
check(arrived("second"), "the next note reaches her")
check(mallory:wait_for(10, function() return noted("alice") end), "her padded answer gets her noted")
local sizes = {short = 10, also_short = 25, middling = 700, longer = 5000}
local bodies = {}
for subject, size in pairs(sizes) do bodies[subject] = send(subject, size) end
local all = true
for subject in pairs(sizes) do all = arrived(subject) and all end
check(all, "four more notes reach her")
local padded_all, buckets, exact = true, true, true
for subject in pairs(sizes) do
    local ev = message_event(subject) or {}
    if not ev.padded then padded_all = false; print("   unpadded: " .. subject) end
    if not pow2((ev.frame or 0) - 32) then buckets = false; print("   " .. subject .. ": " .. tostring(ev.frame)) end
    if read(alice_dir .. "/inbox/" .. subject) ~= bodies[subject] then exact = false; print("   differs: " .. subject) end
end
check(padded_all, "every one of them padded")
check(buckets, "each frame a power of two plus 32 bytes")
check(exact, "every body arrives byte for byte")
local a, b = message_event("short") or {}, message_event("also_short") or {}
check(a.frame and a.frame == b.frame, "10 and 25 bytes of body are the same size on the wire",
    tostring(a.frame) .. " " .. tostring(b.frame))
local big_body = send("big", 40000)
check(arrived("big"), "a 40000-byte note reaches her")
local big = message_event("big") or {}
-- padded to 4 + n + 16384, n being the whole sealed request: a little more
-- than the body, nowhere near the 65536 bucket
local added = (big.frame or 0) - 32 - 16384
check(big.padded and added > 40000 and added < 41000, "it gets 16 KiB of padding, no more", big.frame)
check(read(alice_dir .. "/inbox/big") == big_body, "byte for byte")
LUA

stop_receiver
start_receiver

run_phase <<'LUA'
print("section after a restart")
send("after-restart", 10)
check(arrived("after-restart"), "a note after the restart reaches alice")
check((message_event("after-restart") or {}).padded, "padded from the first request: the note survived")

print("section busy")
-- alice holds her answer; while the daemon waits on it, alice calls
write(alice_dir .. "/hold", "6\n")
send("while-busy", 10)
check(mallory:wait_for(60, function() return read(alice_dir .. "/holding") ~= nil end), "alice is holding her answer")
local alice = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), os.getenv("ALICE_TOKEN"))
local status = alice:request("GET", "/", nil, {ask = true})
check(status == 503 and alice.last.padded and pow2(alice.last.got - 32),
    "the busy answer to her call is padded too", tostring(status) .. " " .. tostring(alice.last.got))
check(arrived("while-busy"), "and the note still reaches her")

print("section back to older")
os.remove(alice_dir .. "/pads")
local body = send("going-back", 300)
check(arrived("going-back"), "a note still reaches alice")
local saw_unreadable = false
for _, e in ipairs(events()) do if e.kind == "unreadable" then saw_unreadable = true end end
check(saw_unreadable, "her older daemon could not read the padded request")
check(log():find("alice answered a padded request unpadded", 1, true), "the daemon says it saw that")
check(not noted("alice"), "alice is forgotten")
local ev = message_event("going-back") or {}
check(ev.padded == false and ev.asked == true, "the note went again unpadded, with the line", json.encode(ev))
check(read(alice_dir .. "/inbox/going-back") == body, "byte for byte")
LUA

stop_receiver
touch "$WORK/alice/stop"
wait "$ALICE_PID" 2>/dev/null
finish
