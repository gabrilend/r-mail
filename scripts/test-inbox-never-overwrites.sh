#!/bin/sh
# test-inbox-never-overwrites.sh — check that a message arriving never replaces a file already in the inbox
#
# A message is saved in the inbox under its subject.  When that name is
# taken, the receiver picks another name: "-from-<sender>" for a different
# sender, a short code from the message's id for the same sender, then
# "-2", "-3" and on.  The owner's rule (2026-10-13): "the filesystem should
# win" — whatever is already on disk stays, and the newcomer moves aside.
#
# Until 2026-10-13 three paths wrote over a file instead:
#   a file rmail has no record of   one the owner made by hand: neither
#                                   renaming rule fired, because both
#                                   start from rmail's record of who sent
#                                   the file already there
#   a second "-from-<sender>"       the sender-tagged name was used without
#                                   checking whether it was free, so a
#                                   contact's second message with a subject
#                                   someone else had used replaced its first
#   the 99th numbered name          the numbering gave up after 99 and
#                                   wrote over the last; a contact choosing
#                                   its own message ids could force this
#
# Cases, against one throwaway mailbox named "receiver" with contacts
# "mallory" and "bob":
#   hand-made file    kept byte for byte; the message lands beside it
#   sender tag        bob's two "hi" messages, after mallory's "hi", are
#                     three separate files
#   numbering         101 messages from mallory whose ids share their first
#                     six characters are 101 separate files, and the first
#                     is unchanged
#
# Usage:
#   scripts/test-inbox-never-overwrites.sh          # use the enclosing checkout
#   scripts/test-inbox-never-overwrites.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/inbox-never-overwrites"
PORT=59517
TEST_NAME="inbox-never-overwrites"
. "$SCRIPT_DIR/lib/test-receiver.sh"

BOB_TOKEN="inbox-never-overwrites-bob-token-not-a-secret"
printf '\nbob.token = "%s"\n' "$BOB_TOKEN" >> "$BOX/contacts"

# The owner's own file, made by hand: rmail has no record of it.
printf 'my own notes, written by hand\n' > "$BOX/inbox/note"

start_receiver

"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$BOB_TOKEN" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, box, work = fc.for_test(arg)
local bob = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[6])
local json = mallory.json

-- {{{ local function check
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. detail) or "")) end
end
-- }}}

-- {{{ local function send
-- One plain message; returns the status the receiver answered with.
local function send(contact, subject, message_id, body)
    return (contact:request("POST", "/deliver", json.encode({type = "message",
        subject = subject, message_id = message_id, body = body})))
end
-- }}}

-- {{{ local function inbox_bodies
-- Every inbox file's body, as a set: body -> how many files hold it.
local function inbox_bodies()
    local seen = {}
    local p = io.popen('ls -A "' .. box .. '/inbox"')
    for f in p:lines() do
        local body = fc.read_file(box .. "/inbox/" .. f) or "?"
        seen[body] = (seen[body] or 0) + 1
    end
    p:close()
    return seen
end
-- }}}

print("section a file rmail has no record of")
local status = send(mallory, "note", "hand-made-clash", "mallory's note\n")
check(status == 200, "mallory's message named \"note\" is accepted", tostring(status))
check(fc.read_file(box .. "/inbox/note") == "my own notes, written by hand\n",
    "the hand-made file is unchanged")
check(inbox_bodies()["mallory's note\n"] == 1, "mallory's message is in the inbox under another name")

print("section the sender-tagged name")
send(mallory, "hi", "mallory-hi", "hi from mallory\n")
send(bob, "hi", "bob-hi-1", "bob's first hi\n")
send(bob, "hi", "bob-hi-2", "bob's second hi\n")
local seen = inbox_bodies()
check(seen["hi from mallory\n"] == 1, "mallory's \"hi\" is kept")
check(seen["bob's first hi\n"] == 1, "bob's first \"hi\" is kept after his second arrives")
check(seen["bob's second hi\n"] == 1, "bob's second \"hi\" is saved too")

print("section numbering does not run out")
-- every id starts "collid", the six characters the renaming takes from it
for n = 1, 101 do
    send(mallory, "flood", "collide-" .. n, "flood message " .. n .. "\n")
end
seen = inbox_bodies()
local kept = 0
for n = 1, 101 do
    if seen["flood message " .. n .. "\n"] == 1 then kept = kept + 1 end
end
check(kept == 101, "all 101 messages are separate files", kept .. " of 101 kept")
check(fc.read_file(box .. "/inbox/flood") == "flood message 1\n", "the first one is unchanged")
LUA
lua_status=$?
while IFS= read -r line; do
    case "$line" in
        "section "*) echo ""; echo "${line#section }" ;;
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/lua.out"
if [ "$lua_status" -ne 0 ]; then
    note_fail "the stand-in contact stopped with status $lua_status"
fi

stop_receiver
finish
