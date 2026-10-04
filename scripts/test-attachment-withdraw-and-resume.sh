#!/bin/sh
# test-attachment-withdraw-and-resume.sh — check what a receiving mailbox does when a file is withdrawn, and that arriving pieces wait on disk across a restart
#
# Two things the receiving side does since 2026-10-04:
#
#   - a sender can withdraw an attachment it offered (issues #312, #313):
#     one "this attachment is cancelled" message, naming the attachment.
#     The receiver throws away the pieces and the consent form, leaves a
#     note saying the file was withdrawn, and touches nothing else;
#   - pieces of an arriving attachment wait on disk, in a hidden folder
#     inside the mailbox, not in /tmp (#311f).  A transfer survives a
#     restart and finishes from where it stopped, with no new consent.  At
#     start-up, pieces and packed copies no record holds are swept away.
#
# One throwaway mailbox, served by the real daemon, with no pending
# folder named in its config (so the default is what is tested); a
# stand-in contact (scripts/lib/fake-contact.lua) sends to it:
#
#   withdrawn       a request makes a consent form; the contact withdraws
#                   it: the form and record go, a note says why; the same
#                   withdrawal again is answered 404; a contact cannot
#                   withdraw someone else's offer
#   on disk         an accepted transfer's first pieces sit under the
#                   mailbox's attachments/.pending/.pending/<id>/
#   a restart       the daemon is stopped and started; the pieces are
#                   still there, leftovers no record holds are swept, and
#                   the last piece completes the file with no starting over
#
# Usage:
#   scripts/test-attachment-withdraw-and-resume.sh          # use the enclosing checkout
#   scripts/test-attachment-withdraw-and-resume.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/attachment-withdraw-and-resume"
PORT=59503
TEST_NAME="attachment-withdraw-and-resume"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# The harness names a pending folder; this test is about the default.
grep -v '^attachment_pending_dir' "$BOX/config" > "$BOX/config.new"
mv "$BOX/config.new" "$BOX/config"

# A zip of three 8 KiB pieces, and leftovers for the start-up sweep to find.
mkdir -p "$WORK/src"
head -c 20000 /dev/urandom > "$WORK/src/resumed.bin"
(cd "$WORK/src" && zip -q "$WORK/resumed.zip" resumed.bin)

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)
local json = mallory.json
local PENDING = BOX .. "/attachments/.pending/.pending/"

-- {{{ local function exists
local function exists(path)
    local f = io.open(path, "rb")
    if f then f:close() return true end
    return false
end
-- }}}

-- {{{ local function check
local function check(what, good, detail)
    print((good and "ok " or "-- ") .. what .. ((not good and detail) and (" (" .. detail .. ")") or ""))
end
-- }}}

print("section a withdrawn attachment")
local W = "77777777-7777-4777-8777-777777777777"
local st = mallory:post_json("/deliver", {type = "attachment_request", attachment_id = W,
    filename = "draft.txt", expected_size = 100, message_id = "test-msg"})
local rec = mallory:consent_record(BOX, W)
check("the request made a consent form", st == 200 and rec ~= nil and exists(BOX .. "/inbox/" .. rec.inbox_file))
st = phone:post_json("/deliver", {type = "attachment_cancel", attachment_id = W})
check("another contact cannot withdraw it", st == 404, "answered " .. tostring(st))
st = mallory:post_json("/deliver", {type = "attachment_cancel", attachment_id = W})
check("the sender withdrew it", st == 200, "answered " .. tostring(st))
check("the form is gone", rec and not exists(BOX .. "/inbox/" .. rec.inbox_file))
check("and its record", mallory:consent_record(BOX, W) == nil)
check("a note says it was withdrawn", exists(BOX .. "/inbox/withdrawn-draft.txt"))
st = mallory:post_json("/deliver", {type = "attachment_cancel", attachment_id = W})
check("withdrawing it again is answered 404", st == 404, "answered " .. tostring(st))

print("section pieces on disk")
local R = "66666666-6666-4666-8666-666666666666"
local zip = fc.read_file(WORK .. "/resumed.zip")
local accepted = mallory:ask_and_accept(BOX, R, "resumed.bin", 20000, 30)
check("the transfer was accepted", accepted)
mallory:send_chunk(R, zip, 0, 8192)
mallory:send_chunk(R, zip, 1, 8192)
check("its first pieces wait inside the mailbox", exists(PENDING .. R .. "/chunk-0") and exists(PENDING .. R .. "/chunk-1"))
-- Leftovers no record holds, for the sweep at the next start-up.
os.execute("mkdir -p '" .. PENDING .. "88888888-dead-4888-8888-888888888888'")
local f = assert(io.open(PENDING .. "88888888-dead-4888-8888-888888888888/chunk-0", "w")) f:write("x") f:close()
f = assert(io.open(BOX .. "/attachments/.pending/rmail-orphan.zip", "w")) f:write("x") f:close()
LUA

echo ""
echo "a restart"
stop_receiver
start_receiver

run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)
local PENDING = BOX .. "/attachments/.pending/.pending/"
local R = "66666666-6666-4666-8666-666666666666"

-- {{{ local function exists
local function exists(path)
    local f = io.open(path, "rb")
    if f then f:close() return true end
    return false
end
-- }}}

-- {{{ local function check
local function check(what, good, detail)
    print((good and "ok " or "-- ") .. what .. ((not good and detail) and (" (" .. detail .. ")") or ""))
end
-- }}}

check("the pieces outlived the restart", exists(PENDING .. R .. "/chunk-0") and exists(PENDING .. R .. "/chunk-1"))
check("pieces no record holds were swept", not exists(PENDING .. "88888888-dead-4888-8888-888888888888/chunk-0"))
check("a packed copy no record holds was swept", not exists(BOX .. "/attachments/.pending/rmail-orphan.zip"))
local zip = fc.read_file(WORK .. "/resumed.zip")
local st, answer = mallory:send_chunk(R, zip, 2, 8192)
local arrived = mallory:wait_for(20, function()
    return exists(BOX .. "/attachments/resumed.bin")
end)
check("the last piece completed the file", arrived, "answered " .. tostring(st))
if arrived then
    check("byte for byte", fc.read_file(BOX .. "/attachments/resumed.bin") == fc.read_file(WORK .. "/src/resumed.bin"))
end
LUA

if grep -q "starting over" "$WORK/daemon.log"; then
    note_fail "the transfer started over after the restart"
else
    ok "the transfer did not start over"
fi
if grep -q "pending folder: removed" "$WORK/daemon.log"; then
    ok "the sweep says what it removed"
else
    note_fail "the sweep logged nothing"
fi

stop_receiver
finish
