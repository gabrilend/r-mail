#!/bin/sh
# test-website-received.sh — check that a contact's website is kept one per contact, the old copy in RAM, with information pages (#715a)
#
# The other half of scripts/test-website-request.sh: here the daemon under
# test is the one that asked, and a stand-in contact, "mallory", sends it
# her website the way her daemon would -- a message called
# `website-for-receiver`, then its folder as an attachment, accepted on
# the consent form.
#
# Cases, against one throwaway mailbox:
#   kept           the site lands in attachments/websites/mallory/, the
#                  author's files byte for byte, nothing left under its
#                  own name in attachments/
#   information    beside each file that is not part of a page (a video,
#                  a program, a zip, a file with no extension) an
#                  <name>.info.html: name, size, kind, date, the SHA-256
#                  the reader can compare, an "open this file" link, and
#                  the ad-shaped boxes, each a Wikipedia article; no
#                  script; a name with spaces and & is escaped and its
#                  link encoded.  Pages, styles and pictures get none, and
#                  the author's own pages are not changed
#   replaced       mallory's next website takes its place; the one before
#                  is moved into the RAM folder, whole, and the log says
#                  where
#   not a website  a single file with a website-for message, and a
#                  folder sent with an ordinary message, stay where
#                  attachments go, with no information pages
#
# Usage:
#   scripts/test-website-received.sh          # use the enclosing checkout
#   scripts/test-website-received.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/website-received"
PORT=59561
TEST_NAME="website-received"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# the RAM folder the daemon moves an old copy into, and this run's part of it
RAM_OLD="/tmp/rmail-progress/old-websites"
RAM_TAG="$(printf '%s' "$BOX" | sed 's|^/||; s|/|-|g')-mallory-"
rm -rf "$RAM_OLD/$RAM_TAG"*

# mallory's site, twice: the first version, and the one that replaces it
SITE1="$WORK/mallory/v1/site"
SITE2="$WORK/mallory/v2/site"
mkdir -p "$SITE1/pictures" "$SITE1/files" "$SITE2"
printf '<h1>mallory</h1>\n<a href="files/video.mp4.info.html">my video</a>\n' > "$SITE1/index.html"
printf 'body { color: red; }\n' > "$SITE1/style.css"
head -c 20000 /dev/urandom > "$SITE1/pictures/me.jpg"
head -c 50000 /dev/urandom > "$SITE1/files/video.mp4"
head -c 3000 /dev/urandom > "$SITE1/files/setup.exe"
head -c 1000 /dev/urandom > "$SITE1/files/Notes & Plans v2.zip"
printf 'no extension\n' > "$SITE1/files/README"
printf '<h1>mallory, second version</h1>\n' > "$SITE2/index.html"
printf 'mallory, mallory@example.org\n' > "$WORK/mallory/card.txt"
mkdir -p "$WORK/mallory/photos"
head -c 4000 /dev/urandom > "$WORK/mallory/photos/beach.mp4"

start_receiver

"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$RAM_OLD" "$RAM_TAG" \
    > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. arg[1] .. "/libs/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local zip = require("zip-writer")
local crypto, json = mallory.crypto, mallory.json
local ram_old, ram_tag = arg[6], arg[7]
local sites = box .. "/attachments/websites"

local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. tostring(detail)) or "")) end
end
local function read(path) local f = io.open(path, "rb"); if not f then return nil end; local s = f:read("*a"); f:close(); return s end
local function exists(path) return read(path) ~= nil end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function log() return read(work .. "/daemon.log") or "" end

-- {{{ local function send_folder
-- A message from mallory, then `folder` attached to it, accepted on the
-- owner's behalf and sent whole.
local function send_folder(subject, att_id, folder)
    local status = mallory:request("POST", "/deliver", json.encode({type = "message", subject = subject,
        message_id = "test-" .. att_id, body = "for you\n"}))
    check(status == 200, subject .. ": the message is delivered", status)
    local packed = work .. "/" .. att_id .. ".zip"
    local made = zip.pack(folder, packed)
    local bytes = read(packed)
    local answer_status = mallory:send_whole(box, att_id, folder:match("([^/]+)$"), bytes, made.size)
    check(answer_status == 200, subject .. ": the folder arrives whole", answer_status)
end
-- }}}

print("section kept, one per contact")
send_folder("website-for-receiver", "5e7e0001", work .. "/mallory/v1/site")
local here = sites .. "/mallory"
check(mallory:wait_for(10, function() return exists(here .. "/index.html") end),
    "the site is at attachments/websites/mallory/")
local same = true
for _, rel in ipairs({"index.html", "style.css", "pictures/me.jpg", "files/video.mp4", "files/setup.exe",
                      "files/Notes & Plans v2.zip", "files/README"}) do
    if read(here .. "/" .. rel) ~= read(work .. "/mallory/v1/site/" .. rel) then same = false; print("   differs: " .. rel) end
end
check(same, "every file of it, byte for byte, the author's pages unchanged")
check(not exists(box .. "/attachments/site/index.html"), "nothing is left under its own name in attachments/")

print("section information pages")
local info = read(here .. "/files/video.mp4.info.html") or ""
check(info ~= "", "a video gets one: files/video.mp4.info.html")
local video = read(here .. "/files/video.mp4")
check(info:find("<h1>video.mp4</h1>", 1, true) and info:find("(50000 bytes)", 1, true)
    and info:find("a video", 1, true), "it says the name, the size and the kind")
check(info:find(hex(crypto.sha256(video)), 1, true), "and the SHA-256 the reader can compare")
check(info:find('href="video.mp4">Open this file</a>', 1, true), "an open this file link, beside it")
local articles = 0
for _ in info:gmatch('href="https://en%.wikipedia%.org/wiki/[^"]+"') do articles = articles + 1 end
check(articles == 8 and info:find("CLICK ME, I&#39;M AN AD", 1, true), "eight ad-shaped boxes, each a Wikipedia article",
    articles)
check(info:find("wiki/Malvertising", 1, true) and info:find("wiki/Checksum", 1, true)
    and info:find("wiki/Trojan_horse_(computing)", 1, true), "the articles the owner approved")
check(not info:lower():find("<script", 1, true), "no script")
check(exists(here .. "/files/setup.exe.info.html") and (read(here .. "/files/setup.exe.info.html") or ""):find("a Windows program", 1, true),
    "a program gets one, naming its kind")
check(exists(here .. "/files/README.info.html"), "a file with no extension gets one")
local odd = read(here .. "/files/Notes & Plans v2.zip.info.html") or ""
check(odd:find("<h1>Notes &amp; Plans v2.zip</h1>", 1, true) and odd:find('href="Notes%20%26%20Plans%20v2.zip"', 1, true),
    "a name with spaces and & is escaped, and its link encoded")
check(not exists(here .. "/index.html.info.html") and not exists(here .. "/style.css.info.html")
    and not exists(here .. "/pictures/me.jpg.info.html"), "pages, styles and pictures get none")
check(log():find("website from mallory saved at " .. here .. " (4 information pages)", 1, true),
    "the log says where it is and how many pages were written")

print("section replaced")
send_folder("website-for-receiver", "5e7e0002", work .. "/mallory/v2/site")
check(mallory:wait_for(10, function() return (read(here .. "/index.html") or ""):find("second version", 1, true) end),
    "mallory's next website takes the place of the first")
check(not exists(here .. "/files/video.mp4"), "with nothing of the first left in it")
local h = io.popen('ls -d "' .. ram_old .. '/' .. ram_tag .. '"* 2>/dev/null')
local moved = h:read("*l"); h:close()
check(moved ~= nil, "the first copy is in the RAM folder", ram_old)
check(moved and read(moved .. "/files/video.mp4") == video and exists(moved .. "/files/video.mp4.info.html"),
    "whole, information pages and all")
check(moved and log():find("website from mallory: the previous copy moved to " .. moved, 1, true),
    "the log says where it went")

print("section not a website")
send_folder("website-for-receiver", "ca7d0001", work .. "/mallory/card.txt")
check(mallory:wait_for(10, function() return exists(box .. "/attachments/card.txt") end),
    "a single file with a website-for message stays in attachments/: a website is a folder")
check((read(here .. "/index.html") or ""):find("second version", 1, true) and not exists(sites .. "/mallory/card.txt"),
    "and mallory's website is left as it was")
send_folder("holiday", "94070501", work .. "/mallory/photos")
check(mallory:wait_for(10, function() return exists(box .. "/attachments/photos/beach.mp4") end),
    "a folder with an ordinary message stays in attachments/")
check(not exists(box .. "/attachments/photos/beach.mp4.info.html") and not exists(sites .. "/mallory/beach.mp4"),
    "with no information pages, and not taken for a website")
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

stop_receiver
rm -rf "$RAM_OLD/$RAM_TAG"*
finish
