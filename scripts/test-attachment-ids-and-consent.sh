#!/bin/sh
# test-attachment-ids-and-consent.sh — check that a contact cannot name folders or skip the owner's yes
#
# A contact chooses the id of each attachment it offers, and the receiving
# mailbox names a folder after it -- and removes that folder with rm -rf
# when the transfer is cancelled.  Until 2026-09-29 (issue #404e) the id
# was not looked at, so an id like ../../home/you pointed that removal at
# the owner's home folder.  And pieces of an attachment were taken before
# the owner had answered its consent form, so a contact could send the
# whole thing unasked and have it filed.
#
# Now an id must look like the ids rmail makes (hex digits and dashes),
# and no piece is taken until the owner has said yes.
#
# Cases, sent by a stand-in contact (scripts/lib/fake-contact.lua) to one
# throwaway mailbox:
#
#   climbing id     a request whose id climbs out of the pending folder
#                   towards a folder holding a file: refused, and so is a
#                   piece for it; the folder and its file survive
#   before consent  a piece sent while the consent form is unanswered:
#                   refused and not stored; after the owner accepts, the
#                   same piece is taken and the file arrives
#
# Usage:
#   scripts/test-attachment-ids-and-consent.sh          # use the enclosing checkout
#   scripts/test-attachment-ids-and-consent.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/attachment-ids-and-consent"
PORT=59484
TEST_NAME="attachment-ids-and-consent"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# The folder a climbing id aims at: <pending>/.pending/../../victim
mkdir -p "$WORK/victim" "$WORK/src"
printf 'the owner keeps this\n' > "$WORK/victim/keep.txt"
head -c 6000 /dev/urandom > "$WORK/src/gift.bin"
(cd "$WORK/src" && zip -q "$WORK/gift.zip" gift.bin)
head -c 50000 /dev/urandom > "$WORK/src/big.bin"
(cd "$WORK/src" && zip -q "$WORK/big.zip" big.bin)

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)

print("section climbing id")
local CLIMB = "../../victim"
local s, a = mallory:post_json("/deliver", {type = "attachment_request",
    attachment_id = CLIMB, filename = "x.bin", expected_size = 10, message_id = "m-climb"})
print(s == 400 and "ok the request is refused" or ("-- the request answered " .. s))
-- An oversize piece is what used to trigger the removal.
local big = fc.read_file(WORK .. "/big.zip")
s, a = mallory:send_chunk(CLIMB, big, 0, #big)
print(s == 400 and "ok a piece for it is refused" or ("-- the piece answered " .. s .. " " .. mallory.json.encode(a)))

print("section before consent")
local ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
local gift = fc.read_file(WORK .. "/gift.zip")
s, a = mallory:post_json("/deliver", {type = "attachment_request",
    attachment_id = ID, filename = "gift.bin", expected_size = 6000, message_id = "m-gift"})
print(s == 200 and "ok the request is taken and a form written" or ("-- the request answered " .. s))
s, a = mallory:send_chunk(ID, gift, 0, #gift)
print(s == 403 and "ok a piece before the owner answers is refused" or
      ("-- the early piece answered " .. s .. " " .. mallory.json.encode(a)))
local f = io.open(WORK .. "/pending/.pending/" .. ID .. "/chunk-0", "rb")
if f then f:close() end
print(f and "-- and it was stored anyway" or "ok and it was not stored")
-- Now answer the form the way the owner would (ask_and_accept's request is
-- a repeat, which the receiver takes as "already asked").
if not mallory:ask_and_accept(BOX, ID, "gift.bin", 6000, 30) then
    print("-- consent never recorded"); os.exit(1)
end
s, a = mallory:send_chunk(ID, gift, 0, #gift)
print(s == 200 and a.ok == true and "ok after the owner accepts, the piece is taken" or
      ("-- after consent it answered " .. s .. " " .. mallory.json.encode(a)))
LUA
stop_receiver

echo ""
echo "what is on disk"
if [ -f "$WORK/victim/keep.txt" ]; then
    ok "the folder the climbing id aimed at, and its file, survive"
else
    note_fail "the folder the climbing id aimed at was removed"
fi
if cmp -s "$BOX/attachments/gift.bin" "$WORK/src/gift.bin"; then
    ok "the accepted attachment arrived whole"
else
    note_fail "the accepted attachment did not arrive"
fi

finish
