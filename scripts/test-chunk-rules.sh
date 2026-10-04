#!/bin/sh
# test-chunk-rules.sh — check that every claim in an attachment piece is checked before it is used
#
# A contact's attachment arrives as numbered pieces ("chunks") of one zip.
# Each piece says which one it is, how many there are, and carries a
# checksum of itself and of the whole zip.  Until 2026-09-29 (issue #311b)
# the receiver believed each piece on its own: a piece with no checksum
# skipped the check, the count could change from piece to piece, and a
# piece numbered -3 or 2.5 was written to disk under that name.
#
# Now both checksums are required, piece numbers must be whole and in
# range, and the transfer's shape -- how many pieces, the whole zip's
# checksum, the length of a piece -- is fixed when piece 0 arrives.  A
# later piece that disagrees is not stored; the answer asks for piece 0
# again, which is also how a sender that packed its file anew starts over.
#
# Cases, sent by a stand-in contact (scripts/lib/fake-contact.lua) to one
# throwaway mailbox, against a zip cut into three 8 KiB pieces:
#
#   required fields   no piece checksum, no whole checksum, piece -1,
#                     piece 2.5, piece 3 of 3: each refused with 400
#   pinning           piece 1 before piece 0: not stored, piece 0 asked
#                     for; piece 0: pinned; piece 1 claiming 4 pieces: not
#                     stored, piece 0 asked for; a short middle piece: 400;
#                     a damaged piece: dropped and still owed
#   out of order      the last piece, then the middle one: the file
#                     arrives whole
#   impossible shape  50,000 pieces of 8 KiB for a 20 KB file: cancelled
#                     as oversize; more pieces than the cap: refused
#   tiny pieces       the same zip in 100-byte pieces (about 200 of them):
#                     each answer lists at most a batch of 64 owed pieces
#                     and how many are held, and the file arrives whole.
#                     There is no smallest piece -- the owner wants
#                     messages under 1 KB carried as attachments -- so the
#                     count is capped instead (2026-09-29, #311b)
#
# Usage:
#   scripts/test-chunk-rules.sh          # use the enclosing checkout
#   scripts/test-chunk-rules.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/chunk-rules"
PORT=59482
TEST_NAME="chunk-rules"
. "$SCRIPT_DIR/lib/test-receiver.sh"

mkdir -p "$WORK/src"
head -c 20000 /dev/urandom > "$WORK/src/pieces.bin"
(cd "$WORK/src" && zip -q "$WORK/pieces.zip" pieces.bin)
info "the zip is $(wc -c < "$WORK/pieces.zip") bytes: three pieces of up to 8192"

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)
local json = mallory.json
local zip = fc.read_file(WORK .. "/pieces.zip")
local SIZE = 8192
local ID = "88888888-8888-4888-8888-888888888888"
local PENDING = WORK .. "/pending/.pending/" .. ID

-- {{{ local function expect
local function expect(what, want_status, status, answer, check)
    local good = status == want_status and (check == nil or check(answer))
    print((good and "ok " or "-- ") .. what ..
          (good and "" or (" (answered " .. tostring(status) .. " " .. json.encode(answer) .. ")")))
end
-- }}}
-- {{{ local function missing_is
local function missing_is(list)
    return function(a)
        return type(a.missing) == "table" and json.encode(a.missing) == json.encode(list)
    end
end
-- }}}
-- {{{ local function on_disk
local function on_disk(n)
    local f = io.open(PENDING .. "/chunk-" .. n, "rb")
    if f then f:close(); return true end
    return false
end
-- }}}

if not mallory:ask_and_accept(BOX, ID, "pieces.bin", 20000, 30) then
    print("-- consent never recorded"); os.exit(1)
end

print("section required fields")
local s, a = mallory:send_chunk(ID, zip, 0, SIZE, {chunk_checksum = false})
expect("a piece with no checksum of its own is refused", 400, s, a)
s, a = mallory:send_chunk(ID, zip, 0, SIZE, {total_checksum = false})
expect("a piece with no checksum of the whole is refused", 400, s, a)
s, a = mallory:send_chunk(ID, zip, 0, SIZE, {chunk_index = -1})
expect("piece -1 is refused", 400, s, a)
s, a = mallory:send_chunk(ID, zip, 0, SIZE, {chunk_index = 2.5})
expect("piece 2.5 is refused", 400, s, a)
s, a = mallory:send_chunk(ID, zip, 0, SIZE, {chunk_index = 3})
expect("piece 3 of 3 is refused", 400, s, a)

print("section pinning")
s, a = mallory:send_chunk(ID, zip, 1, SIZE)
expect("piece 1 before piece 0 asks for piece 0", 200, s, a, missing_is({0}))
print(on_disk(1) and "-- and piece 1 was stored anyway" or "ok and piece 1 was not stored")
s, a = mallory:send_chunk(ID, zip, 0, SIZE)
expect("piece 0 pins the transfer and 1, 2 are owed", 200, s, a, missing_is({1, 2}))
s, a = mallory:send_chunk(ID, zip, 1, SIZE, {total_chunks = 4})
expect("piece 1 claiming 4 pieces asks for piece 0", 200, s, a, missing_is({0}))
print(on_disk(1) and "-- and it was stored anyway" or "ok and it was not stored")
local short = zip:sub(SIZE + 1, SIZE + 100)
s, a = mallory:send_chunk(ID, zip, 1, SIZE, {data = mallory.mime.b64(short),
                                            chunk_checksum = mallory:sha256_hex(short)})
expect("a 100-byte middle piece is refused", 400, s, a)
s, a = mallory:send_chunk(ID, zip, 1, SIZE, {chunk_checksum = string.rep("0", 64)})
expect("a damaged piece is dropped and still owed", 200, s, a, missing_is({1, 2}))

print("section out of order")
s, a = mallory:send_chunk(ID, zip, 2, SIZE)
expect("the last piece is taken", 200, s, a, missing_is({1}))
s, a = mallory:send_chunk(ID, zip, 1, SIZE)
expect("the middle piece completes the transfer", 200, s, a, missing_is({}))

print("section impossible shape")
local ID2 = "99999999-9999-4999-8999-999999999999"
if not mallory:ask_and_accept(BOX, ID2, "huge.bin", 20000, 30) then
    print("-- consent never recorded"); os.exit(1)
end
s, a = mallory:send_chunk(ID2, zip, 0, SIZE, {total_chunks = 50000})
expect("50,000 pieces of 8 KiB for 20 KB is cancelled", 200, s, a, function(x) return x.cancelled == true end)
local rec = mallory:consent_record(BOX, ID2)
print(rec and rec.rejection_reason == "oversize" and "ok its record says oversize" or
      ("-- its record says " .. tostring(rec and rec.rejection_reason)))
local ID4 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
if not mallory:ask_and_accept(BOX, ID4, "counted.bin", 20000, 30) then
    print("-- consent never recorded"); os.exit(1)
end
s, a = mallory:send_chunk(ID4, zip, 0, 1, {total_chunks = 100001})
expect("more pieces than the cap is refused", 400, s, a)

print("section tiny pieces")
local ID3 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
if not mallory:ask_and_accept(BOX, ID3, "tiny.bin", 20000, 30) then
    print("-- consent never recorded"); os.exit(1)
end
local TINY = 100
local count = math.ceil(#zip / TINY)
s, a = mallory:send_chunk(ID3, zip, 0, TINY)
local first = {}
for i = 1, 64 do first[i] = i end
expect("piece 0 of " .. count .. " is taken, and the answer lists pieces 1 to 64", 200, s, a,
       missing_is(first))
expect("the answer says one piece is held", 200, s, a, function(x) return x.held == 1 end)
local largest, last_a = 0, a
for i = 1, count - 1 do
    s, last_a = mallory:send_chunk(ID3, zip, i, TINY)
    if s ~= 200 then print("-- piece " .. i .. " answered " .. tostring(s)); break end
    largest = math.max(largest, #last_a.missing)
end
print(largest <= 64 and "ok no answer listed more than 64 owed pieces" or
      ("-- an answer listed " .. largest .. " owed pieces"))
expect("the last tiny piece completes the transfer", 200, s, last_a, missing_is({}))
LUA
stop_receiver

echo ""
echo "what was filed"
if cmp -s "$BOX/attachments/pieces.bin" "$WORK/src/pieces.bin"; then
    ok "the file sent out of order arrived whole"
else
    note_fail "the file sent out of order did not arrive whole"
fi
if [ -e "$BOX/attachments/huge.bin" ] || [ -e "$BOX/attachments/counted.bin" ]; then
    note_fail "a refused transfer filed something"
else
    ok "the refused transfers filed nothing"
fi

finish
