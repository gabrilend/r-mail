#!/bin/sh
# test-phone-upload-checks.sh — check that a file sent up from the phone is verified before it is filed
#
# The owner's phone sends a file to its home mailbox by zipping it,
# cutting the zip into pieces, telling the mailbox the checksum of every
# piece (a "resume" request), and then sending the pieces the mailbox
# does not have yet.  Until 2026-09-29 (issue #311c) the mailbox used the
# piece checksums only to throw away stale pieces already on disk; a piece
# arriving afterwards was stored unchecked, there was no checksum of the
# whole, a zip of several files was joined end to end into one, and a
# failed unzip still filed whatever half-file it left behind.
#
# Now every piece is checked as it arrives, the whole zip is checked
# against a whole-file checksum, the zip must hold exactly one regular
# file, and unzip's own verdict is read.
#
# Cases, sent by a stand-in phone (a contact marked own, through
# scripts/lib/fake-contact.lua) to one throwaway mailbox:
#
#   required checksums  a resume without piece checksums, and one without
#                       the whole-file checksum: refused
#   honest upload       a wrong piece is refused and not stored; the right
#                       pieces are taken and the file is filed byte for byte
#   two files           a zip holding two files: refused, nothing filed
#   a folder            a zip holding only a folder: refused
#   broken zip          a zip whose content is damaged (its outer checksum
#                       matches, so only the zip reader can tell): refused
#                       as damaged, and no half-file is filed
#   not a zip           a plain file: refused -- everything that crosses
#                       the network travels zipped (owner, 2026-09-29)
#
# Usage:
#   scripts/test-phone-upload-checks.sh          # use the enclosing checkout
#   scripts/test-phone-upload-checks.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/phone-upload-checks"
PORT=59483
TEST_NAME="phone-upload-checks"
. "$SCRIPT_DIR/lib/test-receiver.sh"

mkdir -p "$WORK/one" "$WORK/two/d" "$WORK/folder/only"
head -c 9000 /dev/urandom > "$WORK/one/photo.jpg"
(cd "$WORK/one" && zip -q "$WORK/one.zip" photo.jpg)
printf 'first\n' > "$WORK/two/a.txt"
printf 'second\n' > "$WORK/two/b.txt"
(cd "$WORK/two" && zip -q "$WORK/two.zip" a.txt b.txt)
(cd "$WORK/folder" && zip -q "$WORK/folder.zip" only)
# A zip whose stored data is damaged: text compresses (20,000 bytes of one
# repeated line become about a hundred), so the damage at byte 80 -- past
# the 30-byte header, the name and its extra fields -- lands inside the
# compressed stream.  (At byte 200 it landed in the table of contents.)
yes 'a line of text that compresses well' | head -c 20000 > "$WORK/one/letter.txt"
(cd "$WORK/one" && zip -q "$WORK/broken.zip" letter.txt)
printf 'XXXX' | dd of="$WORK/broken.zip" bs=1 seek=80 conv=notrunc status=none

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)
local json = phone.json
local PIECE = 4096

-- {{{ local function pieces_of
local function pieces_of(bytes)
    local list = {}
    for i = 1, #bytes, PIECE do list[#list + 1] = bytes:sub(i, i + PIECE - 1) end
    return list
end
-- }}}
-- {{{ local function resume
-- The phone's resume request for these pieces; `drop` names a field to
-- leave out.  Returns status, answer.
local function resume(filename, pieces, whole, drop)
    local sums = {}
    for i, p in ipairs(pieces) do sums[tostring(i - 1)] = phone:sha256_hex(p) end
    local msg = {filename = filename, num_chunks = #pieces,
                 chunk_checksums = sums, total_checksum = phone:sha256_hex(whole)}
    if drop then msg[drop] = nil end
    return phone:post_json("/api/upload/resume", msg)
end
-- }}}
-- {{{ local function put
local function put(id, n, bytes)
    local status, body = phone:request("PUT", "/api/upload/" .. id .. "/chunk/" .. n, bytes)
    return status, json.decode(body) or {raw = body}
end
-- }}}
-- {{{ local function send_all
-- Resume, then send every piece; returns the last piece's status, answer.
local function send_all(filename, bytes)
    local pieces = pieces_of(bytes)
    local s, a = resume(filename, pieces, bytes)
    if s ~= 200 then return s, a end
    local id = a.upload_id
    for i, p in ipairs(pieces) do
        s, a = put(id, i - 1, p)
        -- a piece before the last must be taken; the last one's answer is the verdict
        if i < #pieces and s ~= 200 then return s, a end
    end
    return s, a
end
-- }}}

local one = fc.read_file(WORK .. "/one.zip")

print("section required checksums")
local s, a = resume("photo.jpg", pieces_of(one), one, "chunk_checksums")
print(s == 400 and "ok a resume without piece checksums is refused" or ("-- it answered " .. s))
s, a = resume("photo.jpg", pieces_of(one), one, "total_checksum")
print(s == 400 and "ok a resume without the whole-file checksum is refused" or ("-- it answered " .. s))

print("section honest upload")
local pieces = pieces_of(one)
s, a = resume("photo.jpg", pieces, one)
local id = a.upload_id
print(s == 200 and id and "ok the resume is taken" or ("-- resume answered " .. s .. " " .. json.encode(a)))
local wrong = string.rep("x", #pieces[1])
s, a = put(id, 0, wrong)
print(s == 400 and "ok a piece that does not match its checksum is refused" or ("-- it answered " .. s))
local stored = io.open(BOX .. "/attachments/.uploads/" .. id .. "/chunk-0", "rb")
if stored then stored:close() end
print(stored and "-- and it was stored anyway" or "ok and it was not stored")
local last
for i, p in ipairs(pieces) do s, last = put(id, i - 1, p) end
print(s == 200 and last.server_path and "ok the right pieces are taken and the file filed" or
      ("-- the last piece answered " .. s .. " " .. json.encode(last)))

print("section two files")
local id_s, ans = send_all("pair.txt", fc.read_file(WORK .. "/two.zip"))
print(id_s == 500 and tostring(ans.error):find("2 entries") and "ok a zip of two files is refused" or
      ("-- it answered " .. tostring(id_s) .. " " .. json.encode(ans)))

print("section a folder")
id_s, ans = send_all("only", fc.read_file(WORK .. "/folder.zip"))
print(id_s == 500 and tostring(ans.error):find("not a regular file") and "ok a zip of a folder is refused" or
      ("-- it answered " .. tostring(id_s) .. " " .. json.encode(ans)))

print("section broken zip")
id_s, ans = send_all("letter.txt", fc.read_file(WORK .. "/broken.zip"))
print(id_s == 500 and tostring(ans.error):find("refused damaged", 1, true) and "ok a damaged zip is refused" or
      ("-- it answered " .. tostring(id_s) .. " " .. json.encode(ans)))

print("section not a zip")
id_s, ans = send_all("plain.jpg", fc.read_file(WORK .. "/one/photo.jpg"))
print(id_s == 500 and tostring(ans.error):find("not a zip") and "ok an upload that is not a zip is refused" or
      ("-- it answered " .. tostring(id_s) .. " " .. json.encode(ans)))
LUA
stop_receiver

ATT="$BOX/attachments"
echo ""
echo "what was filed"
if cmp -s "$ATT/photo.jpg" "$WORK/one/photo.jpg"; then
    ok "the honest upload arrived byte for byte"
else
    note_fail "the honest upload did not arrive whole"
fi
for name in pair.txt only letter.txt plain.jpg; do
    if [ -e "$ATT/$name" ]; then
        note_fail "the refused upload $name was filed"
    else
        ok "the refused upload $name was not filed"
    fi
done
LEFT=$(ls -A "$ATT/.uploads")
if [ -z "$LEFT" ]; then
    ok "no upload is left half-done"
else
    note_fail "uploads left behind: $LEFT"
fi

finish
