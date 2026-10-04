#!/bin/sh
# test-edit-delivery.sh — check that an edited message reaches its recipient even when they could not be reached at the time
#
# When the author edits a message already sent, rmail sends the new
# version as an "update".  Until 2026-10-04 (issue #208) the sender noted
# the edit as handled the moment it built the update, before sending it.
# A recipient who was not due on their timer, or who was offline, missed
# the edit for good and kept the old text.
#
# Now each recipient keeps the checksum of the version it last answered
# for, and an update stays owed until that recipient answers it.
#
# Two real mailboxes on this machine, one message, three versions of it:
#
#   not due      the message arrives; it is edited at once, while the
#                sender's timer for that contact is still running (about
#                30s after a success).  The edit must arrive when it runs out.
#   offline      the receiver is stopped; the message is edited again; the
#                sender tries, fails and backs off.  The receiver comes back
#                and says something to the sender, which makes the sender
#                try that contact again.  The second edit must arrive.
#
# Usage:
#   scripts/test-edit-delivery.sh          # use the enclosing checkout
#   scripts/test-edit-delivery.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/edit-delivery"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-edit-delivery-*"

SENDER_PORT=59494
RECEIVER_PORT=59495
TOKEN="edit-delivery-test-token-not-a-secret"

# Longest each stage waits.  A contact's timer runs about 30s after a
# success, so one stage is at most a couple of cycles.
DEADLINE_SECONDS=120

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ make_mailbox
# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' \
        "$2" "$3" "$1/pending" > "$1/config"
}
# }}}

# {{{ wait_for_text
# wait_for_text <file> <text> — 0 once the file holds the text, 1 at the deadline
wait_for_text() {
    waited=0
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}
# }}}

echo ""
echo "rmail edit delivery test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES

make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"
printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
# The receiver learns the sender's address only in the offline stage, when
# it has to speak first.  Two daemons on one machine that dial each other at
# the same moment wait on each other (a known daemon problem, not what this
# test is about).
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

printf 'to: receiver\n\nfirst version\n' > "$WORK/sender/outbox/a-note"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

echo ""
echo "the message itself"
if wait_for_text "$WORK/receiver/inbox/a-note" "first version"; then
    ok "it arrived (after ${waited}s)"
else
    note_fail "it never arrived; nothing else can be tested"
    kill "$RECEIVER_PID" "$SENDER_PID"
    wait
    info "sender log: $WORK/sender.log"
    exit 1
fi

echo ""
echo "an edit made while the contact is not due"
printf 'to: receiver\n\nsecond version\n' > "$WORK/sender/outbox/a-note"
if wait_for_text "$WORK/receiver/inbox/a-note" "second version"; then
    ok "the edit arrived (after ${waited}s)"
else
    note_fail "the receiver still has: $(cat "$WORK/receiver/inbox/a-note")"
fi

echo ""
echo "an edit made while the contact is offline"
kill "$RECEIVER_PID"
wait "$RECEIVER_PID"
printf 'to: receiver\n\nthird version\n' > "$WORK/sender/outbox/a-note"
if wait_for_text "$WORK/sender.log" "unreachable contacts this cycle: receiver"; then
    ok "the sender tried and could not reach them (after ${waited}s)"
else
    note_fail "the sender never tried to reach the stopped receiver"
fi
# Back online, and speaking first: an incoming request from a contact
# makes that contact due again on the sender's side.
printf 'sender.ip    = "127.0.0.1"\nsender.port  = %s\n' "$SENDER_PORT" \
    >> "$WORK/receiver/contacts"
printf 'to: sender\n\nback online\n' > "$WORK/receiver/outbox/back-online"
"$LAUNCHER" "$WORK/receiver/config" >> "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
if wait_for_text "$WORK/receiver/inbox/a-note" "third version"; then
    ok "the edit arrived once they were back (after ${waited}s)"
else
    note_fail "the receiver still has: $(cat "$WORK/receiver/inbox/a-note")"
fi

kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID"
rm -f $RAM_FILES

echo ""
echo "the daemons themselves"
# A request handler that throws is logged as "request error" and answered
# with nothing.  One did here: the receiver knows the sender only by its
# key at first, and the sender's address announcement crashed the handler
# that records it (fixed 2026-10-04).
if grep -q "request error" "$WORK/sender.log" "$WORK/receiver.log"; then
    note_fail "a request handler threw: $(grep -h "request error" "$WORK/sender.log" "$WORK/receiver.log" | head -1)"
else
    ok "no request handler threw"
fi

if [ "$FAILURES" -ne 0 ]; then
    info "sender log:   $WORK/sender.log"
    info "receiver log: $WORK/receiver.log"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
