#!/bin/sh
# test-attachment-answers.sh — check that a sender keeps each recipient's answer about an attached file, and that every recipient gets the same file
#
# One message can go to several people with a file attached.  Until
# 2026-10-04 the sending daemon kept one record for the file, not one per
# person (issues #406, #407, #408):
#
#   - when the first recipient finished, the attach: line was removed, so
#     someone reached later got the text and never the file;
#   - the packed copy was deleted when the last current transfer ended,
#     and a later recipient got a fresh packing of whatever was there then;
#   - a "no" was not remembered: the file was offered again and again;
#   - a recipient cancelling the file was read as them deleting the whole
#     message, and the author could lose their outbox file.
#
# Now each recipient has an answer per attached path (complete, declined,
# cancelled, withdrawn), the packed copy is kept until every recipient has
# answered, and a cancel names the attachment, not the message.
#
# One real sending mailbox; its recipients alice and bob are stand-ins
# (scripts/lib/fake-recipient.lua) that answer at once and never dial back,
# and the test speaks for them through scripts/lib/fake-contact.lua.  (Two
# real daemons on one machine stall each other -- the open "blocking sync
# cycle stalls inbound" issue -- so they cannot be relied on here.)
#
#   a late recipient    bob is offline while alice gets the file; the file
#                       is then changed on disk; bob, reached later, gets
#                       the bytes alice got.  The attach: line stays; the
#                       packed copy is kept until bob answers, then removed.
#   a refusal           alice says no to a second file; 70 seconds later
#                       she has not been asked again.
#   withdraw, restore   a third file waits on alice's answer; the author
#                       removes its attach: line; alice is told it is
#                       withdrawn.  The line is put back: she is asked again.
#   a cancel            alice cancels that new offer.  The outbox file and
#                       its to: lines are untouched, the file is not offered
#                       again, and an edit of the message still reaches her.
#
# The receiving side of a withdrawal, and pieces waiting on disk across a
# restart, are in scripts/test-attachment-withdraw-and-resume.sh.
#
# Usage:
#   scripts/test-attachment-answers.sh          # use the enclosing checkout
#   scripts/test-attachment-answers.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.  It takes a few
# minutes: the daemon works on 30-second timers.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/attachment-answers"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-attachment-answers-*"

SENDER_PORT=59500
ALICE_PORT=59501
BOB_PORT=59502
ALICE_TOKEN="attachment-answers-alice-token-not-a-secret"
BOB_TOKEN="attachment-answers-bob-token-not-a-secret"

DEADLINE_SECONDS=150

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ wait_until
# wait_until <shell test> — 0 once it holds, 1 at the deadline; sets $waited
wait_until() {
    waited=0
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        eval "$1" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}
# }}}

# {{{ start_recipient
# start_recipient <name> <port> <token> — a stand-in, in the background
start_recipient() {
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$2" "$3" "$WORK/$1" \
        > "$WORK/$1.log" 2>&1 &
}
# }}}

# {{{ ids_of
# ids_of <recipient> <kind> <attachment name> — the attachment ids of that
# recipient's events of that kind (requests: for that file), one per line
# (The Lua comes on standard input: given -e, Lua takes the first plain
# argument for a script's name and every argument shifts by one.)
ids_of() {
    "$LUA" - "$DIR" "$WORK/$1/events" "$2" "$3" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do
    local e = json.decode(line)
    if e and e.kind == arg[3] then
        if e.kind ~= "request" or e.filename == arg[4] then print(e.id) end
    end
end
f:close()
LUA
}
# }}}

# {{{ count_of
# count_of <recipient> <kind> <attachment name>
count_of() { ids_of "$@" | grep -c .; }
# }}}

# {{{ say
# say <token> <JSON> — the recipient with that key posts this to the
# sender's /deliver; prints the answer's status.  Any request from a
# contact also makes the sender try that contact at once.
say() {
    "$LUA" - "$DIR" "$SENDER_PORT" "$1" "$2" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local me = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local status = me:request("POST", "/deliver", arg[4])
print(status)
LUA
}
# }}}

# {{{ answer_of
# answer_of <outbox file> <recipient> <attached path> — the sender's record
answer_of() {
    "$LUA" - "$DIR" "$WORK/sender/.state/outbox.json" "$1" "$2" "$3" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[2]) if not f then print("none") return end
local state = require("dkjson").decode(f:read("*a")) f:close()
local r = state[arg[3]] and state[arg[3]].recipients and state[arg[3]].recipients[arg[4]]
print(r and r.attachments and r.attachments[arg[5]] or "none")
LUA
}
# }}}

# {{{ unpacked_matches
# unpacked_matches <zip> <original file> — the zip, unpacked with the
# daemon's own zip reader, holds exactly the original's bytes
unpacked_matches() {
    rm -rf "$WORK/unpack"; mkdir -p "$WORK/unpack"
    "$LUA" - "$DIR" "$1" "$WORK/unpack" <<'LUA' || return 1
package.path = arg[1] .. "/libs/?.lua;" .. package.path
require("zip-reader").extract(arg[2], arg[3], {size = 1e9, exact = false, now = os.time()})
LUA
    cmp -s "$WORK/unpack/photo.bin" "$2"
}
# }}}

echo ""
echo "rmail attachment answers test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
mkdir -p "$WORK/sender/inbox" "$WORK/sender/outbox" "$WORK/sender/.state" "$WORK/sender/attachments" "$WORK/files"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\nattachment_chunk_size = 16384\n' "$SENDER_PORT" > "$WORK/sender/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n\nbob.ip = "127.0.0.1"\nbob.port = %s\nbob.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" "$BOB_PORT" "$BOB_TOKEN" > "$WORK/sender/contacts"

PHOTO="$WORK/files/photo.bin"
head -c 200000 /dev/urandom > "$PHOTO"
cp "$PHOTO" "$WORK/photo.original"
printf 'to: alice\nto: bob\nattach: %s\n\nthe photo\n' "$PHOTO" > "$WORK/sender/outbox/a-photo"

start_recipient alice "$ALICE_PORT" "$ALICE_TOKEN"
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

# ---------------------------------------------------------------------------
echo ""
echo "a late recipient gets the same file"

if wait_until '[ "$(count_of alice request photo.bin)" -ge 1 ]'; then
    A1=$(ids_of alice request photo.bin | head -1)
    say "$ALICE_TOKEN" "{\"type\":\"attachment_response\",\"attachment_id\":\"$A1\",\"consent\":true}" > /dev/null
    ok "alice was asked, and said yes (after ${waited}s)"
else
    note_fail "alice was never asked"
fi
if wait_until '[ -f "$WORK/alice/received/$A1.zip" ]' && unpacked_matches "$WORK/alice/received/$A1.zip" "$WORK/photo.original"; then
    ok "alice has the file (after ${waited}s)"
else
    note_fail "alice never got the file"
fi
if grep -q "^attach: $PHOTO" "$WORK/sender/outbox/a-photo"; then
    ok "the attach: line is still in the outbox file"
else
    note_fail "the attach: line was removed: $(cat "$WORK/sender/outbox/a-photo")"
fi
if ls "$WORK/sender/attachments/.pending/"rmail-*.zip >/dev/null 2>&1; then
    ok "the packed copy is kept, on disk in the mailbox: bob has not answered"
else
    note_fail "no packed copy in $WORK/sender/attachments/.pending"
fi

# The file changes after it was offered.  Bob must not get this.
head -c 200000 /dev/urandom > "$PHOTO"
start_recipient bob "$BOB_PORT" "$BOB_TOKEN"
# Bob comes back and says something, so the sender tries him at once.
sleep 1
say "$BOB_TOKEN" '{"type":"chunk_failed"}' > /dev/null
if wait_until '[ "$(count_of bob request photo.bin)" -ge 1 ]'; then
    B1=$(ids_of bob request photo.bin | head -1)
    say "$BOB_TOKEN" "{\"type\":\"attachment_response\",\"attachment_id\":\"$B1\",\"consent\":true}" > /dev/null
    ok "bob, reached later, was asked, and said yes (after ${waited}s)"
else
    note_fail "bob was never asked"
fi
if wait_until '[ -f "$WORK/bob/received/$B1.zip" ]'; then
    if unpacked_matches "$WORK/bob/received/$B1.zip" "$WORK/photo.original"; then
        ok "bob has the bytes alice got, not the changed file (after ${waited}s)"
    else
        note_fail "bob got different bytes from alice's"
    fi
else
    note_fail "bob never got the file"
fi
if wait_until '! ls "$WORK/sender/attachments/.pending/"rmail-*.zip >/dev/null 2>&1'; then
    ok "the packed copy was removed once both had answered"
else
    note_fail "the packed copy is still there"
fi
a=$(answer_of a-photo alice "$PHOTO"); b=$(answer_of a-photo bob "$PHOTO")
[ "$a" = complete ] && [ "$b" = complete ] && ok "both answers are recorded as complete" || \
    note_fail "answers: alice $a, bob $b"

# ---------------------------------------------------------------------------
echo ""
echo "a refusal is remembered"
NOTES="$WORK/files/notes.bin"
head -c 3000 /dev/urandom > "$NOTES"
printf 'to: alice\nattach: %s\n\nsome notes\n' "$NOTES" > "$WORK/sender/outbox/b-notes"
if wait_until '[ "$(count_of alice request notes.bin)" -ge 1 ]'; then
    N1=$(ids_of alice request notes.bin | head -1)
    say "$ALICE_TOKEN" "{\"type\":\"attachment_response\",\"attachment_id\":\"$N1\",\"consent\":false}" > /dev/null
    ok "alice was asked, and said no (after ${waited}s)"
else
    note_fail "alice was never asked"
fi
if wait_until '[ "$(answer_of b-notes alice "$NOTES")" = declined ]'; then
    ok "the sender recorded it as declined"
else
    note_fail "the sender's answer is $(answer_of b-notes alice "$NOTES")"
fi
sleep 70
if [ "$(count_of alice request notes.bin)" -eq 1 ]; then
    ok "70 seconds later she has not been asked again"
else
    note_fail "she was asked $(count_of alice request notes.bin) times"
fi

# ---------------------------------------------------------------------------
echo ""
echo "withdrawn, then offered again"
DRAFT="$WORK/files/draft.bin"
head -c 3000 /dev/urandom > "$DRAFT"
printf 'to: alice\nattach: %s\n\na draft\n' "$DRAFT" > "$WORK/sender/outbox/c-draft"
if wait_until '[ "$(count_of alice request draft.bin)" -ge 1 ]'; then
    C1=$(ids_of alice request draft.bin | head -1)
    ok "alice was asked (after ${waited}s); she does not answer"
else
    note_fail "alice was never asked"
fi
printf 'to: alice\n\na draft\n' > "$WORK/sender/outbox/c-draft"
if wait_until 'ids_of alice cancel | grep -qx "$C1"'; then
    ok "the author removed the line: alice was told it is withdrawn (after ${waited}s)"
else
    note_fail "alice was never told"
fi
[ "$(answer_of c-draft alice "$DRAFT")" = withdrawn ] && ok "the sender recorded it as withdrawn" || \
    note_fail "the sender's answer is $(answer_of c-draft alice "$DRAFT")"
printf 'to: alice\nattach: %s\n\na draft\n' "$DRAFT" > "$WORK/sender/outbox/c-draft"
if wait_until '[ "$(count_of alice request draft.bin)" -ge 2 ]'; then
    C2=$(ids_of alice request draft.bin | tail -1)
    [ "$C2" != "$C1" ] && ok "the line is back: alice is asked again, as a new offer (after ${waited}s)" || \
        note_fail "the second offer reused the withdrawn id"
else
    note_fail "alice was not asked again"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a cancel stops the file, not the message"
before_outbox="$(cat "$WORK/sender/outbox/c-draft")"
st=$(say "$ALICE_TOKEN" "{\"type\":\"attachment_cancel\",\"attachment_id\":\"$C2\"}")
[ "$st" = 200 ] && ok "the sender took alice's cancel" || note_fail "the cancel was answered $st"
if [ "$(cat "$WORK/sender/outbox/c-draft")" = "$before_outbox" ]; then
    ok "the outbox file, to: line and attach: line included, is untouched"
else
    note_fail "the outbox file changed: $(cat "$WORK/sender/outbox/c-draft")"
fi
[ "$(answer_of c-draft alice "$DRAFT")" = cancelled ] && ok "the sender recorded it as cancelled" || \
    note_fail "the sender's answer is $(answer_of c-draft alice "$DRAFT")"
st=$(say "$ALICE_TOKEN" "{\"type\":\"attachment_cancel\",\"attachment_id\":\"$C2\"}")
[ "$st" = 404 ] && ok "a second cancel of it is answered 404" || note_fail "a second cancel was answered $st"
printf 'to: alice\nattach: %s\n\na draft, edited\n' "$DRAFT" > "$WORK/sender/outbox/c-draft"
if wait_until 'grep -q "a draft, edited" "$WORK/alice/inbox/c-draft"'; then
    ok "an edit of the message still reaches alice (after ${waited}s)"
else
    note_fail "the edit never reached alice"
fi
sleep 40
[ "$(count_of alice request draft.bin)" -eq 2 ] && ok "the cancelled file is not offered again" || \
    note_fail "the cancelled file was offered again"

kill "$SENDER_PID"; wait "$SENDER_PID"
touch "$WORK/alice/stop" "$WORK/bob/stop"
wait

echo ""
echo "the daemon itself"
if grep -q "request error\|sync error" "$WORK/sender.log"; then
    note_fail "the daemon threw: $(grep -h "request error\|sync error" "$WORK/sender.log" | head -1)"
else
    ok "no request or sync cycle threw"
fi

rm -f $RAM_FILES
[ "$FAILURES" -ne 0 ] && info "sender log: $WORK/sender.log"
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
