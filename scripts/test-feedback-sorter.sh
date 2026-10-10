#!/bin/sh
# test-feedback-sorter.sh — check that a project's feedback mailbox files each website note under the page it is about
#
# The rmail-integration skill carries sort-feedback.lua: run as a feedback
# mailbox's on_receive hook, it moves each note from a website (a
# listen-only contact) out of the flat inbox into a folder tree shaped like
# the site, with a few lines on top saying when and from where, and sends
# notes about no page, or a page the site does not have, to _refused/ with
# the reason.  This runs it under a real daemon.
#
# Cases, one throwaway mailbox with a listen-only contact "website", the
# usual "mallory", and a list of the site's pages:
#   sorted           a note about docs/guide/install.html lands in
#                    feedback/docs/guide/install/, whole, under lines naming
#                    when it came, from whom, and its page; a page written
#                    with a leading slash is the same page; the inbox no
#                    longer holds them
#   refused          a page the site does not have, a note naming no page,
#                    and a page path that climbs ("..") each land in
#                    feedback/_refused/ with the reason; nothing is written
#                    outside the tree
#   left alone       a message from mallory, a person, stays in the inbox
#   owes nothing     after a sync cycle, rmail has forgotten the moved
#                    notes and sent the website nothing
#
# Usage:
#   scripts/test-feedback-sorter.sh          # use the enclosing checkout
#   scripts/test-feedback-sorter.sh /path    # use some other checkout
#
# Needs luajit (the sorter's interpreter).  Exit status is 0 when every
# case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/feedback-sorter"
PORT=59512
TEST_NAME="feedback-sorter"
SORTER="$DIR/.claude/skills/rmail-integration/sort-feedback.lua"
. "$SCRIPT_DIR/lib/test-receiver.sh"

WEBSITE_TOKEN="feedback-sorter-website-token-in-every-page"
printf '\nwebsite.token = "%s"\nwebsite.listen = true\n' "$WEBSITE_TOKEN" >> "$BOX/contacts"
printf 'on_receive = %s\n' "$SORTER" >> "$BOX/config"
printf 'pages = site-pages\ntree = feedback\n' > "$BOX/feedback.conf"
printf 'index.html\ndocs/guide/install.html\ndocs/055-the-documentation-site.html\n' > "$BOX/site-pages"

start_receiver

"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$WEBSITE_TOKEN" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, box, work = fc.for_test(arg)
local website = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[6])
local json = website.json

-- {{{ local function check
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. detail) or "")) end
end
-- }}}

-- {{{ local function exists
local function exists(path)
    local f = io.open(path)
    if f then f:close() return true end
    return false
end
-- }}}

-- {{{ local function send
local function send(who, subject, body)
    return who:request("POST", "/deliver", json.encode({type = "message", subject = subject,
        body = body, message_id = subject .. "-id"}))
end
-- }}}

-- {{{ local function arrives
-- Wait for the sorter (run in the background) to put `path` in place.
local function arrives(path)
    return website:wait_for(15, function() return exists(path) end)
end
-- }}}

print("section notes sorted under their pages")
send(website, "install-note-1", "page: docs/guide/install.html\ntag: unclear\n---\nstep 3 is missing\n")
local sorted = box .. "/feedback/docs/guide/install/install-note-1"
check(arrives(sorted), "a note about docs/guide/install.html is in feedback/docs/guide/install/")
local text = exists(sorted) and fc.read_file(sorted) or ""
check(text:find("^received: %d%d%d%d%-%d%d%-%d%d") and text:find("\nfrom: website\n", 1, true)
    and text:find("\npage: docs/guide/install.html\n", 1, true),
    "with lines on top naming when it came, from whom, and its page", text:sub(1, 160))
check(text:find("step 3 is missing\n", 1, true) and text:find("tag: unclear", 1, true),
    "and the note whole below them")
check(not exists(box .. "/inbox/install-note-1"), "the inbox no longer holds it")
send(website, "index-note", "page: /index.html\n\nlovely front page\n")
check(arrives(box .. "/feedback/index/index-note"), "a page written with a leading slash is the same page")

print("section notes refused, with the reason")
local refusals = {
    {"no-such-page", "page: docs/secret.html\n\nhello\n", "the site has no page"},
    {"no-page-line", "just some words\n", "names no page"},
    {"climbing",     "page: ../../outside.html\n\nhello\n", "climbs"},
}
for _, r in ipairs(refusals) do
    send(website, r[1], r[2])
    local where = box .. "/feedback/_refused/" .. r[1]
    local landed = arrives(where)
    local body = landed and fc.read_file(where) or ""
    check(landed and body:find("refused: [^\n]*" .. r[3]),
        r[1] .. ": in _refused/, saying \"" .. r[3] .. "\"", body:sub(1, 200))
end
check(not exists(box .. "/outside.html") and not exists(work .. "/outside.html")
    and not exists(box .. "/feedback/outside"), "nothing was written outside the tree")

print("section a person's message is left alone")
send(mallory, "from-mallory", "page: docs/guide/install.html\n\nI am a person\n")
website:wait_for(3, function() return false end)
check(exists(box .. "/inbox/from-mallory"), "mallory's message stays in the inbox")

print("section the moved notes are forgotten, and the website is owed nothing")
-- an outbox file wakes a sync cycle; to the website it is marked, which
-- shows the cycle ran
local f = assert(io.open(box .. "/outbox/wake-a-cycle", "w"))
f:write("to: website\n\nhi\n")
f:close()
website:wait_for(40, function()
    return fc.read_file(box .. "/outbox/wake-a-cycle"):find("LISTEN%-ONLY CONTACT") ~= nil
end)
local record = json.decode(fc.read_file(box .. "/.state/inbox.json"))
check(type(record) == "table" and record["install-note-1"] == nil and record["no-page-line"] == nil
    and record["from-mallory"] ~= nil,
    "rmail no longer records the moved notes, and still records mallory's")
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
echo "the logs"
if grep -q "notified website\|backing off website\|unreachable contacts this cycle:.*website" "$WORK/daemon.log"; then
    note_fail "the daemon tried to send to the website"
else
    ok "the daemon never tried to send to the website"
fi
sorted_lines=$(grep -c " sorted " "$BOX/feedback/sort.log" 2>/dev/null)
refused_lines=$(grep -c " refused " "$BOX/feedback/sort.log" 2>/dev/null)
if [ "$sorted_lines" = "2" ] && [ "$refused_lines" = "3" ]; then
    ok "the sorter's log has 2 sorted and 3 refused lines"
else
    note_fail "the sorter's log has $sorted_lines sorted and $refused_lines refused lines"
fi

stop_receiver
finish
