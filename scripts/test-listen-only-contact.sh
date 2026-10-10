#!/bin/sh
# test-listen-only-contact.sh — check that a website's contact may send a plain message and nothing else, and is never sent to
#
# A website that sends notes to an rmail mailbox is one contact in that
# mailbox, and its token is in every page, so anyone may hold it.  Marked
# `listen = true` in the contacts file (issue #420), such a contact may
# deliver a plain message and nothing else, and the mailbox never sends it
# anything.  The rule belongs to the contact, not to how a request arrives:
# the token works in a bare frame from any program as well as in a
# browser's POST, so both are tried here.
#
# Cases, against one throwaway mailbox named "receiver" with a listen-only
# contact "door" beside the usual "mallory" and phone:
#   plain messages   accepted bare and inside a web POST, with or without
#                    a time; a 64 KiB body is accepted
#   refused (403)    a delete and an edit of door's own message; a message
#                    with attachments, with auto_body, with an unknown
#                    field, or with a body over 64 KiB; an attachment
#                    request; an address change; GET /deps and the sealed
#                    GET /; each logged, and the inbox, the saved state and
#                    the contacts file are byte for byte as before
#   per contact      mallory, an ordinary contact, may still delete her
#                    own message
#   never sent to    deleting door's message from the inbox owes door no
#                    notice; an outbox file addressed to door is marked
#                    LISTEN-ONLY CONTACT and nothing is sent
#
# Usage:
#   scripts/test-listen-only-contact.sh          # use the enclosing checkout
#   scripts/test-listen-only-contact.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/listen-only-contact"
PORT=59511
TEST_NAME="listen-only-contact"
. "$SCRIPT_DIR/lib/test-receiver.sh"

DOOR_TOKEN="listen-only-contact-door-token-printed-on-a-website"
printf '\n// a website: its token is in every page\ndoor.token = "%s"\ndoor.listen = true\n' \
    "$DOOR_TOKEN" >> "$BOX/contacts"

start_receiver

"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$DOOR_TOKEN" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, box, work = fc.for_test(arg)
local door = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[6])
local json = door.json

-- {{{ local function check
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. detail) or "")) end
end
-- }}}

-- {{{ local function snapshot
-- Everything a refused request must leave alone: every inbox file with its
-- contents, every saved-state file, and the contacts file.
local function snapshot()
    local parts = {}
    for _, dir in ipairs({box .. "/inbox", box .. "/.state", box .. "/attachments"}) do
        local p = io.popen('ls -A "' .. dir .. '"')
        for f in p:lines() do
            local h = io.open(dir .. "/" .. f, "rb")
            parts[#parts + 1] = dir .. "/" .. f .. "\n" .. (h and h:read("*a") or "?")
            if h then h:close() end
        end
        p:close()
    end
    parts[#parts + 1] = fc.read_file(box .. "/contacts")
    return table.concat(parts, "\n--\n")
end
-- }}}

-- {{{ local function message
local function message(fields)
    local m = {type = "message", subject = "note", body = "hello\n", message_id = "m-" .. os.time()}
    for k, v in pairs(fields or {}) do if v == false then m[k] = nil else m[k] = v end end
    return json.encode(m)
end
-- }}}

print("section plain messages from the listen-only contact")
local status = door:request("POST", "/deliver", message({subject = "from-the-door", message_id = "door-1",
    body = "a note through a bare frame\n"}))
check(status == 200, "a plain message in a bare frame is accepted", tostring(status))
local web, inner = door:web_post("POST", "/deliver", message({subject = "from-a-page", message_id = "door-2",
    body = "a note through a browser's POST\n", mtime = 1700000000}))
check(web == 200 and inner == 200, "a plain message with a time, inside a web POST, is accepted",
    tostring(web) .. " / " .. tostring(inner))
status = door:request("POST", "/deliver", message({subject = "exactly-64-kib", message_id = "door-3",
    body = string.rep("a", 64 * 1024)}))
check(status == 200, "a body of exactly 64 KiB is accepted", tostring(status))
local landed = io.open(box .. "/inbox/from-the-door")
check(landed ~= nil, "the message is in the inbox")
if landed then landed:close() end

print("section everything else from it is refused, and changes nothing")
local before = snapshot()
local refusals = {
    {"a delete of its own message",  "POST", "/delete", json.encode({message_id = "door-1"})},
    {"an edit of its own message",   "POST", "/deliver", json.encode({type = "update",
        message_id = "door-1", body = "rewritten by a stranger\n"})},
    {"a message with attachments",   "POST", "/deliver", message({subject = "with-attachment",
        attachments = {{filename = "x.txt", data = "aGk="}}})},
    {"a message marked auto_body",   "POST", "/deliver", message({subject = "auto", auto_body = true})},
    {"a message with an unknown field", "POST", "/deliver", message({subject = "odd", colour = "red"})},
    {"a body one byte over 64 KiB",  "POST", "/deliver", message({subject = "too-long",
        body = string.rep("a", 64 * 1024 + 1)})},
    {"an attachment request",        "POST", "/deliver", json.encode({type = "attachment_request",
        attachment_id = "a1", filename = "x.zip", expected_size = 10, message_id = "door-1"})},
    {"an address change",            "POST", "/update-address", json.encode({ip = "203.0.113.9", port = 4000})},
    {"GET /deps",                    "GET",  "/deps", nil},
    {"the sealed GET /",             "GET",  "/", nil},
}
for _, r in ipairs(refusals) do
    local s, body = door:request(r[2], r[3], r[4])
    check(s == 403, r[1] .. " is refused with 403", tostring(s) .. " " .. tostring(body))
end
web, inner = door:web_post("POST", "/delete", json.encode({message_id = "door-2"}))
check(web == 200 and inner == 403, "a delete inside a web POST is refused the same way",
    tostring(web) .. " / " .. tostring(inner))
check(snapshot() == before, "the inbox, the saved state and the contacts file are byte for byte as before")

print("section the rule belongs to the contact")
status = mallory:request("POST", "/deliver", message({subject = "from-mallory", message_id = "mallory-1"}))
check(status == 200, "mallory's message is accepted", tostring(status))
status = mallory:request("POST", "/delete", json.encode({message_id = "mallory-1"}))
local gone = io.open(box .. "/inbox/from-mallory") == nil
check(status == 200 and gone, "mallory, an ordinary contact, may still delete her own message", tostring(status))

print("section nothing is ever sent to it")
-- the owner deletes door's message, and writes to door; writing to the
-- outbox wakes a sync cycle, which handles both
os.remove(box .. "/inbox/from-the-door")
local f = assert(io.open(box .. "/outbox/a-reply-to-the-door", "w"))
f:write("to: door\n\nthanks for the note\n")
f:close()
local marked = door:wait_for(40, function()
    return fc.read_file(box .. "/outbox/a-reply-to-the-door"):find("LISTEN%-ONLY CONTACT") ~= nil
end)
check(marked, "an outbox file addressed to it is marked LISTEN-ONLY CONTACT",
    fc.read_file(box .. "/outbox/a-reply-to-the-door"))
local record = json.decode(fc.read_file(box .. "/.state/inbox.json"))
check(type(record) == "table" and record["from-the-door"] == nil,
    "its deleted message is forgotten, with no notice owed")
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
[ "$lua_status" -eq 0 ] || note_fail "the stand-in contact stopped with status $lua_status"

echo ""
echo "what the daemon's log says"
refused=$(grep -c "refused a request from listen-only contact door" "$WORK/daemon.log")
if [ "$refused" -eq 11 ]; then
    ok "each of the 11 refusals is one log line"
else
    note_fail "expected 11 refusal log lines, found $refused"
fi
if grep -q "notified door\|backing off door\|unreachable contacts this cycle:.*door\|request to listen-only contact door reached the send gate" "$WORK/daemon.log"; then
    note_fail "the daemon tried to send to door: $(grep 'door' "$WORK/daemon.log" | grep -v refused | head -2)"
else
    ok "the daemon never tried to send to door"
fi
if grep -q "listen-only contact 'door' in a-reply-to-the-door" "$WORK/daemon.log"; then
    ok "the log says why the reply waits"
else
    note_fail "no log line for the reply to door"
fi

stop_receiver
finish
