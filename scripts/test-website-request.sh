#!/bin/sh
# test-website-request.sh — check that a contact who asks gets the mailbox's website, and only as often as it changes (#715a)
#
# `website = <folder>` in a mailbox's config publishes that folder to its
# contacts.  A contact asks with a message called `website`; the request
# is used up on arrival, any text in it is kept in the inbox under the
# receiving time, and the answer is an outbox message to them with the
# whole folder attached, so the usual consent form and transfer follow.
#
# Cases, against one throwaway mailbox with a stand-in contact "friend"
# (scripts/lib/fake-recipient.lua) and a listen-only contact "door":
#   asking         no `website` file is kept; the note is saved under a
#                  millisecond date name; the outbox gets
#                  website-for-friend: to: friend, the folder attached,
#                  and the offer text with its size said twice
#   the offer      reaches friend as a message and an attachment request
#   waiting        a second request while the offer waits makes no
#                  offer and is one log line; a request with no text
#                  keeps nothing, and friend is told it was deleted, so
#                  their `website` file leaves their outbox
#   accepted       friend says yes and receives the folder whole; a
#                  request then makes no offer ("already have this
#                  version")
#   changed        a file in the site changes: the next request makes a
#                  new offer under a new name, and the old offer goes
#   listen-only    door's request keeps its note and makes no offer
#   start-up       a website that is not a folder, `website_access =
#                  public` with no website (#715b) and an unknown access
#                  value each stop the daemon with the reason
#   no website     with no `website` key a message called `website` is
#                  an ordinary message
#
# Usage:
#   scripts/test-website-request.sh          # use the enclosing checkout
#   scripts/test-website-request.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/website-request"
PORT=59551
FRIEND_PORT=59552
FRIEND_TOKEN="website-request-friend-token-not-a-secret"
DOOR_TOKEN="website-request-door-token-not-a-secret"
TEST_NAME="website-request"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# the site, beside the config, named relatively as a hook path would be
mkdir -p "$BOX/site/pictures"
printf '<h1>receiver</h1>\n<p>How to reach me.</p>\n' > "$BOX/site/index.html"
head -c 300000 /dev/urandom > "$BOX/site/pictures/me.jpg"
printf 'website = site\nwebsite_access = private\n' >> "$BOX/config"
printf '\nfriend.ip = "127.0.0.1"\nfriend.port = %s\nfriend.token = "%s"\n' \
    "$FRIEND_PORT" "$FRIEND_TOKEN" >> "$BOX/contacts"
printf '\ndoor.token = "%s"\ndoor.listen = true\n' "$DOOR_TOKEN" >> "$BOX/contacts"
cp "$BOX/config" "$WORK/config.good"

"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$FRIEND_PORT" "$FRIEND_TOKEN" "$WORK/friend" \
    > "$WORK/friend.log" 2>&1 &
FRIEND_PID=$!
start_receiver

# {{{ the Lua half
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$FRIEND_TOKEN" "$DOOR_TOKEN" \
    > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local friend = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[6])
local door = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[7])
local json = friend.json
local site = box .. "/site"

local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. tostring(detail)) or "")) end
end
local function exists(path) local f = io.open(path, "rb"); if f then f:close() end; return f ~= nil end
local function read(path) local f = io.open(path, "rb"); if not f then return "" end; local s = f:read("*a"); f:close(); return s end
local function log() return read(work .. "/daemon.log") end
local function count(text, pattern) local _, n = text:gsub(pattern, ""); return n end
local function ls(dir)
    local out, p = {}, io.popen('ls -1A "' .. dir .. '" 2>/dev/null')
    for name in p:lines() do out[#out + 1] = name end
    p:close()
    return out
end
local function events(kind)
    local out = {}
    for line in read(work .. "/friend/events"):gmatch("[^\n]+") do
        local e = json.decode(line)
        if e and e.kind == kind then out[#out + 1] = e end
    end
    return out
end
local n = 0
-- a request, sent again while the daemon answers busy (it does while
-- it is sending to the same contact), as a real sender would
local function ask(who, body)
    n = n + 1
    local status
    who:wait_for(30, function()
        status = who:request("POST", "/deliver", json.encode({type = "message", subject = "website",
            message_id = "ask-" .. n, body = body}))
        return status == 200
    end)
    return status
end

print("section asking")
local inbox_before = #ls(box .. "/inbox")
check(ask(friend, "Hi! Found your address on the forum.\n") == 200, "friend's request is answered 200")
check(not exists(box .. "/inbox/website"), "no file called website is kept")
local notes = {}
for _, name in ipairs(ls(box .. "/inbox")) do
    if name:match("^%d%d%d%d%-%d%d%-%d%d%-%d%d%-%d%d%-%d%d%-%d%d%d$") then notes[#notes + 1] = name end
end
check(#notes == 1 and read(box .. "/inbox/" .. (notes[1] or "")) == "Hi! Found your address on the forum.\n",
    "the note is kept under the receiving time, to the millisecond", table.concat(notes, " "))
check(#ls(box .. "/inbox") == inbox_before + 1, "and nothing else arrives in the inbox")
local offer = read(box .. "/outbox/website-for-friend")
check(offer:find("^to: friend\nattach: " .. site:gsub("%p", "%%%0") .. "\n\n"),
    "the outbox has website-for-friend, to friend, the whole site attached", offer:sub(1, 120))
check(offer:find("This is receiver's website, ", 1, true) and count(offer, "%d+%.%d KB") == 2,
    "the offer says the site's size twice", offer)
check(offer:find("saying no costs you nothing", 1, true), "and both ways round")
check(log():find("website offered to friend (website-for-friend", 1, true), "the log says it was offered")

print("section the offer")
check(friend:wait_for(60, function() return #events("message") > 0 and #events("request") > 0 end),
    "friend gets the message and a consent request for the site")
local request = events("request")[1] or {}
check(events("message")[1] and events("message")[1].subject == "website-for-friend", "the message is website-for-friend")

print("section waiting")
check(ask(friend, "") == 200, "a second request, with no text, is answered 200")
check(not exists(box .. "/outbox/website-for-friend-2"), "it makes no second offer")
check(count(log(), "website not offered to friend: an offer to them is still waiting") == 1,
    "it is one log line, with the reason")
check(friend:wait_for(60, function()
    for _, e in ipairs(events("delete")) do if e.message_id == "ask-2" then return true end end
end), "the request with no text is answered as deleted, so it leaves friend's outbox")
local after = 0
for _, e in ipairs(events("delete")) do if e.message_id == "ask-1" then after = after + 1 end end
check(after == 0, "the request with a note stays until its note is deleted")

print("section accepted")
local status = friend:post_json("/deliver", {type = "attachment_response", attachment_id = request.id, consent = true})
check(status == 200, "friend says yes", status)
check(friend:wait_for(120, function() return #events("complete") > 0 end), "friend receives the site whole")
check(friend:wait_for(30, function() return log():find("website received whole by friend", 1, true) end),
    "the daemon records it")
local record = json.decode(read(box .. "/.state/website.json")) or {}
check(record.friend and record.friend.accepted == record.friend.fingerprint, "as the version friend holds")
check(ask(friend, "") == 200, "a request after that is answered 200")
check(log():find("website not offered to friend: they already have this version", 1, true),
    "a request now makes no offer: they already have this version")
check(not exists(box .. "/outbox/website-for-friend-2"), "and no new file")

print("section changed")
local f = assert(io.open(site .. "/index.html", "a")); f:write("<p>New: my phone number changed.</p>\n"); f:close()
os.execute("touch -d '+2 seconds' '" .. site .. "/index.html'")
check(ask(friend, "") == 200, "a request after the change is answered 200")
check(exists(box .. "/outbox/website-for-friend-2"), "a changed site makes a new offer, under a new name")
check(not exists(box .. "/outbox/website-for-friend"), "and the old offer goes")
check(friend:wait_for(60, function()
    local seen = false
    for _, e in ipairs(events("request")) do if e.id ~= request.id then seen = true end end
    return seen
end), "friend gets a new consent request")

print("section listen-only")
check(ask(door, "a note from the door\n") == 200, "door's request is answered 200")
check(not exists(box .. "/outbox/website-for-door"), "door is offered nothing")
check(log():find("website not offered to door: a listen-only contact is never sent anything", 1, true),
    "the log says why")
local kept = false
for _, name in ipairs(ls(box .. "/inbox")) do
    if read(box .. "/inbox/" .. name) == "a note from the door\n" then kept = true end
end
check(kept, "door's note is kept")
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
[ "$lua_status" -eq 0 ] || note_fail "the Lua half stopped with status $lua_status"
# }}}

stop_receiver
cp "$WORK/daemon.log" "$WORK/daemon-1.log"
touch "$WORK/friend/stop"
sleep 1
kill "$FRIEND_PID" 2>/dev/null
wait "$FRIEND_PID" 2>/dev/null

# {{{ start-up: a website that cannot be served stops the daemon
echo ""
echo "start-up"
refuses() {
    _words="$1"; _expect="$2"; shift 2
    cp "$WORK/config.good" "$BOX/config"
    grep -v '^website' "$WORK/config.good" > "$BOX/config"
    printf '%s\n' "$@" >> "$BOX/config"
    timeout 20 "$LAUNCHER" "$BOX/config" > "$WORK/start.log" 2>&1
    _status=$?
    if [ "$_status" -ne 0 ] && [ "$_status" -ne 124 ] && grep -q "$_expect" "$WORK/start.log"; then
        ok "$_words"
    else
        note_fail "$_words (status $_status): $(head -c 300 "$WORK/start.log")"
    fi
}
printf 'not a folder\n' > "$BOX/a-file"
refuses "a website that is a file stops the daemon" "which is not a folder" "website = a-file"
refuses "a website that is not there stops the daemon" "which is not a folder" "website = no-such-folder"
refuses "website_access = public with no website stops it (#715b)" "needs 'website', a folder to publish" "website_access = public"
refuses "an unknown website_access stops it" "must be private or public" "website = site" "website_access = friends"
# }}}

# {{{ no website: a message called website is a message
echo ""
echo "without a website"
grep -v '^website' "$WORK/config.good" > "$BOX/config"
start_receiver
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" > "$WORK/lua2.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box = fc.for_test(arg)
local status = mallory:request("POST", "/deliver", mallory.json.encode({type = "message", subject = "website",
    message_id = "plain-1", body = "is this your site?\n"}))
local f = io.open(box .. "/inbox/website", "rb")
local body = f and f:read("*a"); if f then f:close() end
if status == 200 and body == "is this your site?\n" then print("ok it is filed as an ordinary message")
else print("-- it is filed as an ordinary message: " .. tostring(status) .. " " .. tostring(body)) end
local h = io.popen('ls "' .. box .. '/outbox"'); local out = h:read("*a"); h:close()
if not out:find("website-for-mallory", 1, true) then print("ok nothing is offered")
else print("-- nothing is offered: " .. out) end
LUA
while IFS= read -r line; do
    case "$line" in
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/lua2.out"
stop_receiver
# }}}

finish
