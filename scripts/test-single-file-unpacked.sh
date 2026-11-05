#!/bin/sh
# test-single-file-unpacked.sh — check that a single large file is sent from where it lies, with no packed copy, and that a change to it loses the offer
#
# Issue #317.  Before a file is offered it used to be packed into a copy in
# the pending folder, which for the ritzmenardi.com shrine's large zip
# meant needing its size twice over in disk.  A single file at or above
# `attachment_copy_below` bytes is now laid out instead: a small
# `rmail-<id>.virtual` file holds the zip's header and directory, and each
# piece is read from the file itself.  What travels is byte for byte the
# zip the packer would have made.
#
# One real sending mailbox; its recipient alice is a stand-in
# (scripts/lib/fake-recipient.lua), and the test answers her consent forms
# through scripts/lib/fake-contact.lua.  Pieces are 64 KiB here, and the
# big file's size puts the zip's directory across a piece boundary.
#
#   laid out         big.bin (above the threshold) is offered with no
#                    packed copy: one small .virtual file in the pending
#                    folder, no zip; small.bin (below it) is packed as
#                    before; the log says which
#   identical        alice accepts big.bin: what she receives is exactly
#                    the zip zip-writer.lua makes of the same file, and
#                    the checksum offered is that zip's
#   replaced         a file replaced, before she accepts, by another of the
#                    same size and time (only its inode differs): the
#                    offer is lost, with the outbox note, and nothing is
#                    sent
#   changed mid-way  a file written to while its first piece is in flight:
#                    no further piece is sent and the offer is lost
#   kept             the files themselves are never removed
#
# Usage:
#   scripts/test-single-file-unpacked.sh          # use the enclosing checkout
#   scripts/test-single-file-unpacked.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/single-file-unpacked"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-single-file-unpacked-*"
SENDER_PORT=59522
ALICE_PORT=59523
ALICE_TOKEN="single-file-unpacked-alice-token-not-a-secret"
BOX="$WORK/sender"
PENDING="$BOX/attachments/.pending"
FILES="$WORK/files"
DEADLINE_SECONDS=90

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_until <shell test>: 0 once it holds, 1 at the deadline; sets $waited
wait_until() {
    waited=0
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        eval "$1" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# event_field <kind> <filename> <field>: that field of the first such
# event in alice's record (a request carries filename; id names it)
id_of() {
    "$LUA" - "$DIR" "$WORK/alice/events" "$1" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do
    local e = json.decode(line)
    if e and e.kind == "request" and e.filename == arg[3] then print(e.id) break end
end
f:close()
LUA
}

# answer <attachment id>: alice accepts that offer
accept() {
    "$LUA" - "$DIR" "$SENDER_PORT" "$ALICE_TOKEN" "$1" <<'LUA' > /dev/null
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local me = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
me:request("POST", "/deliver", me.json.encode({type = "attachment_response",
    attachment_id = arg[4], consent = true}))
LUA
}

# checksum_offered <attachment id>: the total checksum the transfer record holds
checksum_offered() {
    "$LUA" - "$DIR" "$BOX/.state/chunks-outgoing.json" "$1" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[2]) if not f then print("none") return end
local s = require("dkjson").decode(f:read("*a")) f:close()
print(s and s[arg[3]] and s[arg[3]].total_checksum or "none")
LUA
}

virtuals() { ls "$PENDING"/rmail-*.virtual 2>/dev/null | grep -c .; }
zips()     { ls "$PENDING"/rmail-*.zip 2>/dev/null | grep -c .; }

echo ""
echo "rmail single-file-unpacked test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/attachments" "$FILES" "$WORK/alice"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\nattachment_chunk_size = 65536\nattachment_copy_below = 100000\n' \
    "$SENDER_PORT" > "$BOX/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" > "$BOX/contacts"

# header 46 bytes + 196522 = 196568; the 84-byte directory and end record
# then straddle the piece boundary at 196608
head -c 196522 /dev/urandom > "$FILES/big.bin"
head -c 5000 /dev/urandom > "$FILES/small.bin"
head -c 150000 /dev/urandom > "$FILES/swapped.bin"
head -c 200000 /dev/urandom > "$FILES/mid.bin"
cp "$FILES/big.bin" "$WORK/big.orig"

# the zip the packer makes of big.bin, made now, before anything runs
"$LUA" - "$DIR" "$FILES/big.bin" "$WORK/expected.zip" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
require("zip-writer").pack(arg[2], arg[3])
LUA

printf 'to: alice\nattach: %s\nattach: %s\n\ntwo files\n' "$FILES/big.bin" "$FILES/small.bin" > "$BOX/outbox/first"
printf 'to: alice\nattach: %s\n\nto be swapped\n' "$FILES/swapped.bin" > "$BOX/outbox/second"
printf 'to: alice\nattach: %s\n\nto be written to\n' "$FILES/mid.bin" > "$BOX/outbox/third"

"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
ALICE_PID=$!
"$LAUNCHER" "$BOX/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

echo ""
echo "laid out"
if wait_until '[ -n "$(id_of big.bin)" ] && [ -n "$(id_of small.bin)" ] && [ -n "$(id_of swapped.bin)" ] && [ -n "$(id_of mid.bin)" ]'; then
    ok "alice was asked about all four files (after ${waited}s)"
else
    note_fail "alice was not asked about every file: $(cat "$WORK/alice/events" 2>/dev/null | wc -l) events"
fi
if [ "$(virtuals)" -eq 3 ] && [ "$(zips)" -eq 1 ]; then
    ok "three .virtual layouts and one packed zip (small.bin) in the pending folder"
else
    note_fail "$(virtuals) layouts and $(zips) zips in the pending folder: $(ls "$PENDING" 2>/dev/null | tr '\n' ' ')"
fi
largest=$(ls -l "$PENDING" 2>/dev/null | awk '/\.virtual$/ {print $5}' | sort -n | tail -n 1)
if [ -n "$largest" ] && [ "$largest" -lt 2048 ]; then
    ok "each layout is small ($largest bytes at most)"
else
    note_fail "a layout is $largest bytes"
fi
grep -q "sending $FILES/big.bin from where it lies" "$WORK/sender.log" \
    && ok "the log says big.bin is sent from where it lies" || note_fail "no log line for big.bin"
grep -q "sending $FILES/small.bin from where it lies" "$WORK/sender.log" \
    && note_fail "small.bin, below the threshold, was not packed"

echo ""
echo "identical"
BIG_ID=$(id_of big.bin)
EXPECTED_SUM=$(sha256sum "$WORK/expected.zip" | cut -d' ' -f1)
offered=$(checksum_offered "$BIG_ID")
[ "$offered" = "$EXPECTED_SUM" ] && ok "the checksum offered is that of the packer's zip" \
    || note_fail "the checksum offered is $offered, the packer's zip is $EXPECTED_SUM"
accept "$BIG_ID"
if wait_until '[ -f "$WORK/alice/received/$BIG_ID.zip" ]'; then
    if cmp -s "$WORK/alice/received/$BIG_ID.zip" "$WORK/expected.zip"; then
        ok "alice received exactly the packer's zip, in $(ls "$WORK/alice/pieces/$BIG_ID" | wc -l) pieces"
    else
        note_fail "what alice received differs from the packer's zip"
    fi
else
    note_fail "alice never received big.bin"
fi

echo ""
echo "replaced"
SWAP_ID=$(id_of swapped.bin)
head -c 150000 /dev/urandom > "$WORK/swapped.new"
touch -r "$FILES/swapped.bin" "$WORK/swapped.new"
mv "$WORK/swapped.new" "$FILES/swapped.bin"
accept "$SWAP_ID"
if wait_until 'grep -q "ATTACHMENT LOST: $FILES/swapped.bin" "$BOX/outbox/second"'; then
    ok "a same-size, same-time replacement loses the offer, with the outbox note"
else
    note_fail "the replaced file's offer was not lost"
fi
[ -d "$WORK/alice/pieces/$SWAP_ID" ] && note_fail "a piece of the replaced file was sent"
grep -q "$FILES/swapped.bin has changed since it was offered" "$WORK/sender.log" \
    && ok "the log says it changed" || note_fail "no log line for the replacement"

echo ""
echo "changed mid-way"
MID_ID=$(id_of mid.bin)
# the replaced file's withdrawal reaches alice first, so the hold below
# catches mid.bin's first piece and nothing else
wait_until 'grep -q "\"kind\":\"cancel\"" "$WORK/alice/events"' || info "alice was never told the replaced file was withdrawn"
sleep 2
printf '4\n' > "$WORK/alice/hold"
rm -f "$WORK/alice/holding"
accept "$MID_ID"
if wait_until '[ -f "$WORK/alice/holding" ]'; then
    printf 'X' | dd of="$FILES/mid.bin" bs=1 seek=100 conv=notrunc 2>/dev/null
    if wait_until 'grep -q "ATTACHMENT LOST: $FILES/mid.bin" "$BOX/outbox/third"'; then
        ok "written to while a piece was in flight: the offer is lost"
    else
        note_fail "the offer of the file written to mid-way was not lost"
    fi
    held=$(ls "$WORK/alice/pieces/$MID_ID" 2>/dev/null | wc -l)
    if [ "$held" -le 1 ] && [ ! -f "$WORK/alice/received/$MID_ID.zip" ]; then
        ok "no piece after the change was sent ($held held)"
    else
        note_fail "$held pieces were sent of the file written to mid-way"
    fi
else
    note_fail "the first piece of mid.bin never reached alice"
fi

echo ""
echo "kept"
if cmp -s "$FILES/big.bin" "$WORK/big.orig" && [ -f "$FILES/small.bin" ] \
   && [ -f "$FILES/swapped.bin" ] && [ -f "$FILES/mid.bin" ]; then
    ok "the files sent from where they lie are all still there, big.bin unchanged"
else
    note_fail "a file sent from where it lies was removed or changed"
fi
if [ "$(virtuals)" -le 1 ]; then
    ok "the layouts of the lost offers are gone"
else
    note_fail "$(virtuals) layouts remain: $(ls "$PENDING" | tr '\n' ' ')"
fi

kill "$SENDER_PID" 2>/dev/null
wait "$SENDER_PID" 2>/dev/null
touch "$WORK/alice/stop"
sleep 1
kill "$ALICE_PID" 2>/dev/null
wait "$ALICE_PID" 2>/dev/null
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "sender log: $WORK/sender.log"
exit 1
