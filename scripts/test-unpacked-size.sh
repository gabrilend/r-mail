#!/bin/sh
# test-unpacked-size.sh — check that an attachment cannot unpack to more than its sender declared
#
# Before a contact sends an attachment, the owner is shown its declared
# size and says yes or no.  The file then arrives packed in a zip.  The
# packed bytes have been counted against the declared size since issue
# #310, but a zip is a box of compressed streams, and a megabyte of zeros
# packs into about a kilobyte: a small zip, well within the packed limit,
# could unpack into gigabytes and fill the disk (a "zip bomb").
#
# Since 2026-09-29 the unpacked size is measured before anything is
# extracted, by really decompressing into a counter that stops one byte
# past the limit, and the same limit applies: declared size × 1.1 + 4 KiB.
#
# Cases, sent by a stand-in contact (scripts/lib/fake-contact.lua) to one
# throwaway mailbox:
#
#   zip bomb        declares 4000 bytes, packs to about 1 KiB, unpacks to
#                   1 MiB: refused, nothing filed, record says why
#   honest          declares 4000 bytes and is 4000 bytes: arrives
#   declared zero   declares 0 bytes and sends 5000: refused (0 used to
#                   switch the limit off)
#   no size         a request with no declared size, or half a byte:
#                   refused outright (it used to be read as 0)
#
# Usage:
#   scripts/test-unpacked-size.sh          # use the enclosing checkout
#   scripts/test-unpacked-size.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/unpacked-size"
PORT=59481
TEST_NAME="unpacked-size"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# ---- The zips -----------------------------------------------------------
mkdir -p "$WORK/bomb" "$WORK/honest" "$WORK/big"
head -c 1048576 /dev/zero > "$WORK/bomb/zeros.bin"
(cd "$WORK/bomb" && zip -q -9 "$WORK/bomb.zip" zeros.bin)
head -c 4000 /dev/urandom > "$WORK/honest/honest.bin"
(cd "$WORK/honest" && zip -q "$WORK/honest.zip" honest.bin)
head -c 5000 /dev/urandom > "$WORK/big/big.bin"
(cd "$WORK/big" && zip -q "$WORK/big.zip" big.bin)
info "the bomb zip is $(wc -c < "$WORK/bomb.zip") bytes packed, 1048576 unpacked"

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)

print("section zip bomb")
local id = "33333333-3333-4333-8333-333333333333"
local s, a = mallory:send_whole(BOX, id, "zeros.bin", fc.read_file(WORK .. "/bomb.zip"), 4000)
print(s == 200 and a.cancelled == true and "ok the transfer was refused" or
      ("-- not refused: " .. tostring(s) .. " " .. mallory.json.encode(a or {})))
local rec = mallory:consent_record(BOX, id)
print(rec and rec.rejection_reason == "oversize-unpacked" and "ok its record says oversize-unpacked" or
      ("-- its record says " .. tostring(rec and rec.rejection_reason)))

print("section honest")
id = "44444444-4444-4444-8444-444444444444"
s, a = mallory:send_whole(BOX, id, "honest.bin", fc.read_file(WORK .. "/honest.zip"), 4000)
print(s == 200 and a.ok == true and "ok the transfer was taken" or
      ("-- not taken: " .. tostring(s) .. " " .. mallory.json.encode(a or {})))

print("section declared zero")
id = "55555555-5555-4555-8555-555555555555"
s, a = mallory:send_whole(BOX, id, "big.bin", fc.read_file(WORK .. "/big.zip"), 0)
print(s == 200 and a.cancelled == true and "ok 5000 bytes against a declared 0 were refused" or
      ("-- not refused: " .. tostring(s) .. " " .. mallory.json.encode(a or {})))

print("section no size")
s, a = mallory:post_json("/deliver", {type = "attachment_request",
    attachment_id = "66666666-6666-4666-8666-666666666666", filename = "x", message_id = "m"})
print(s == 400 and "ok a request with no size is refused" or ("-- it answered " .. s))
s, a = mallory:post_json("/deliver", {type = "attachment_request",
    attachment_id = "77777777-7777-4777-8777-777777777777", filename = "x",
    expected_size = 10.5, message_id = "m"})
print(s == 400 and "ok a size of 10.5 bytes is refused" or ("-- it answered " .. s))
LUA
stop_receiver

ATT="$BOX/attachments"
echo ""
echo "what was filed"
if [ -e "$ATT/zeros.bin" ]; then
    note_fail "the zip bomb's content was filed ($(wc -c < "$ATT/zeros.bin") bytes)"
else
    ok "nothing of the zip bomb was filed"
fi
if [ -e "$WORK/pending/.pending/33333333-3333-4333-8333-333333333333" ]; then
    note_fail "the zip bomb's pending folder was left behind"
else
    ok "the zip bomb's pending folder was removed"
fi
if cmp -s "$ATT/honest.bin" "$WORK/honest/honest.bin"; then
    ok "the honest file arrived whole"
else
    note_fail "the honest file did not arrive whole"
fi
if [ -e "$ATT/big.bin" ]; then
    note_fail "the file declared as 0 bytes was filed"
else
    ok "the file declared as 0 bytes was not filed"
fi

finish
