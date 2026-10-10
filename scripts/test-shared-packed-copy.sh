#!/bin/sh
# test-shared-packed-copy.sh — check that a file attached to several messages is packed once, and kept until no message needs it
#
# Before a file is offered it is packed into a copy on disk, so every
# recipient gets the same bytes however long the transfer takes.  Until
# 2026-10-09 that copy belonged to one message: a second message attaching
# the same file packed it again, so the ritzmenardi.com shrine's 9 GB zip,
# sent in several messages, needed several 9 GB copies (issue #316).  Now a
# message shares another message's copy when the file is unchanged since it
# was packed, and a copy is deleted only when no message names it.
#
# One real sending mailbox; its recipient alice is a stand-in
# (scripts/lib/fake-recipient.lua) that answers at once and never dials
# back, and the test answers her consent forms through
# scripts/lib/fake-contact.lua.
#
#   shared           two messages attach the same file: one copy on disk,
#                    named by both messages' records, and the log says it
#                    was shared
#   kept, removed    alice declines the first message's offer: the copy
#                    stays (the second still needs it); she declines the
#                    second's: the copy goes
#   changed file     a file changed between two messages' offers gives two
#                    copies, the first message keeping the bytes it offered
#   message deleted  of two messages sharing a copy, the author deletes one:
#                    the copy stays for the other
#
# Usage:
#   scripts/test-shared-packed-copy.sh          # use the enclosing checkout
#   scripts/test-shared-packed-copy.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/shared-packed-copy"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-shared-packed-copy-*"

SENDER_PORT=59513
ALICE_PORT=59514
ALICE_TOKEN="shared-packed-copy-alice-token-not-a-secret"
PENDING="$WORK/sender/attachments/.pending"

DEADLINE_SECONDS=90

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

# {{{ ids_of
# ids_of <attachment name> — the attachment ids alice was asked about for
# that file, in arrival order, one per line
ids_of() {
    "$LUA" - "$DIR" "$WORK/alice/events" "$1" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do
    local e = json.decode(line)
    if e and e.kind == "request" and e.filename == arg[3] then print(e.id) end
end
f:close()
LUA
}
# }}}

# {{{ count_of
count_of() { ids_of "$1" | grep -c .; }
# }}}

# {{{ zips
# zips — how many packed copies are on disk
zips() { ls "$PENDING"/rmail-*.zip 2>/dev/null | grep -c .; }
# }}}

# {{{ zip_of
# zip_of <outbox file> <attached path> — the copy that message's record names
zip_of() {
    "$LUA" - "$DIR" "$WORK/sender/.state/outbox.json" "$1" "$2" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[2]) if not f then print("none") return end
local state = require("dkjson").decode(f:read("*a")) f:close()
local m = state[arg[3]]
print(m and m.packed and m.packed[arg[4]] and m.packed[arg[4]].zip or "none")
LUA
}
# }}}

# {{{ decline
# decline <attachment id> — alice says no to that offer
decline() {
    "$LUA" - "$DIR" "$SENDER_PORT" "$ALICE_TOKEN" "$1" <<'LUA' > /dev/null
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local me = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
me:request("POST", "/deliver", me.json.encode({type = "attachment_response",
    attachment_id = arg[4], consent = false}))
LUA
}
# }}}

echo ""
echo "rmail shared packed copy test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
mkdir -p "$WORK/sender/inbox" "$WORK/sender/outbox" "$WORK/sender/.state" "$WORK/sender/attachments" "$WORK/files"
rm -f $RAM_FILES
printf 'name = sender\nport = %s\n' "$SENDER_PORT" > "$WORK/sender/config"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" > "$WORK/sender/contacts"

BIG="$WORK/files/big.bin"
head -c 300000 /dev/urandom > "$BIG"
printf 'to: alice\nattach: %s\n\nthe big file, first message\n' "$BIG" > "$WORK/sender/outbox/first"
printf 'to: alice\nattach: %s\n\nthe big file again\n' "$BIG" > "$WORK/sender/outbox/second"

"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

# ---------------------------------------------------------------------------
echo ""
echo "two messages attach the same file"
if wait_until '[ "$(count_of big.bin)" -ge 2 ]'; then
    ok "alice was asked about it twice (after ${waited}s)"
else
    note_fail "alice was asked $(count_of big.bin) time(s)"
fi
if [ "$(zips)" -eq 1 ]; then
    ok "one packed copy on disk"
else
    note_fail "$(zips) packed copies on disk"
fi
Z1=$(zip_of first "$BIG"); Z2=$(zip_of second "$BIG")
if [ "$Z1" != none ] && [ "$Z1" = "$Z2" ]; then
    ok "both messages' records name it"
else
    note_fail "the records name $Z1 and $Z2"
fi
if grep -q "sharing the packed copy of $BIG" "$WORK/sender.log"; then
    ok "the log says it was shared"
else
    note_fail "no log line for the sharing"
fi

# ---------------------------------------------------------------------------
echo ""
echo "kept while any message needs it"
FIRST_ID=$(ids_of big.bin | sed -n 1p)
SECOND_ID=$(ids_of big.bin | sed -n 2p)
decline "$FIRST_ID"
if wait_until 'grep -q "released: every recipient has answered; another message still uses it" "$WORK/sender.log"'; then
    if [ "$(zips)" -eq 1 ] && [ -f "$Z1" ]; then
        ok "one message done: the copy stays, the other still needs it"
    else
        note_fail "one message done: $(zips) copies, $Z1 present: $([ -f "$Z1" ] && echo yes || echo no)"
    fi
else
    note_fail "the first message's answer never released its entry"
fi
decline "$SECOND_ID"
if wait_until '[ "$(zips)" -eq 0 ]'; then
    ok "both done: the copy is removed (after ${waited}s)"
else
    note_fail "both done: $(zips) copies remain"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a file changed between two offers"
NOTES="$WORK/files/notes.bin"
head -c 40000 /dev/urandom > "$NOTES"
printf 'to: alice\nattach: %s\n\nnotes, as they were\n' "$NOTES" > "$WORK/sender/outbox/third"
wait_until '[ "$(count_of notes.bin)" -ge 1 ]'
sleep 1
head -c 40000 /dev/urandom > "$NOTES"
printf 'to: alice\nattach: %s\n\nnotes, as they are now\n' "$NOTES" > "$WORK/sender/outbox/fourth"
if wait_until '[ "$(count_of notes.bin)" -ge 2 ]'; then
    Z3=$(zip_of third "$NOTES"); Z4=$(zip_of fourth "$NOTES")
    if [ "$Z3" != none ] && [ "$Z4" != none ] && [ "$Z3" != "$Z4" ] && [ -f "$Z3" ] && [ -f "$Z4" ]; then
        ok "two copies: the first message keeps the bytes it offered"
    else
        note_fail "the records name $Z3 and $Z4"
    fi
else
    note_fail "the second offer of the changed file never came"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a message sharing a copy is deleted"
MAP="$WORK/files/map.bin"
head -c 40000 /dev/urandom > "$MAP"
printf 'to: alice\nattach: %s\n\nthe map\n' "$MAP" > "$WORK/sender/outbox/fifth"
printf 'to: alice\nattach: %s\n\nthe map again\n' "$MAP" > "$WORK/sender/outbox/sixth"
wait_until '[ "$(count_of map.bin)" -ge 2 ]'
Z5=$(zip_of fifth "$MAP")
rm "$WORK/sender/outbox/fifth"
if wait_until 'grep -q "for fifth released: the message is gone; another message still uses it" "$WORK/sender.log"'; then
    if [ -f "$Z5" ] && [ "$(zip_of sixth "$MAP")" = "$Z5" ]; then
        ok "the copy stays for the message still offering it"
    else
        note_fail "the copy is gone, or sixth names another"
    fi
else
    note_fail "the deleted message's entry was never released"
fi

kill "$SENDER_PID"; wait "$SENDER_PID" 2>/dev/null
touch "$WORK/alice/stop"
wait
rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "sender log: $WORK/sender.log"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
