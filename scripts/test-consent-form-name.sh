#!/bin/sh
# test-consent-form-name.sh — check that an attachment's consent form is named after its message
#
# Nobody receives an attachment without saying yes first.  When a message
# with an attachment arrives, the receiving mailbox puts a small form in its
# inbox ("sorelu wants to send you an attachment ... accept / deny"), and
# the file is only transferred once the owner leaves "accept" in it.
#
# The form used to be named after the attachment alone.  A photo named by a
# phone camera (20260903_154820.jpg) then produced a form named by a bare
# date, with nothing saying which message it went with.  Since 2026-09-23
# the form is named after the message first and the attachment second, and
# says "Attached to: <message>" inside.  The name still ends in
# -consent-to-download-form, which is how the phone and the accept/deny
# helper scripts recognise forms.
#
# This script runs two throwaway mailboxes on this machine.  The sender
# mails the receiver two messages:
#
#   one attachment    dinosaur-hoodie-pic with 20260903_154820.jpg
#   two attachments   two-photos with a.jpg and b.jpg, which must get two
#                     separate forms
#
# and it checks the forms that appear in the receiver's inbox.  Only the
# sender dials; the receiver holds the sender's key but no address, because
# two daemons dialling each other at once stall and file duplicates (a
# known daemon problem this test is not about).
#
# Not covered: a request for a message the receiver has no record of (it
# was deleted before the request came).  The form is then named by the
# attachment alone and says so; producing that order of events on purpose
# needs control over the sender's timing this script does not have.
#
# Usage:
#   scripts/test-consent-form-name.sh          # use the enclosing checkout
#   scripts/test-consent-form-name.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/consent-form-name"

# The daemons' shared RAM folder; this run's files there carry this name.
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-consent-form-name-*"

SENDER_PORT=59470
RECEIVER_PORT=59471
TOKEN="consent-form-name-test-token-not-a-real-secret"

# Longest the run lasts.  Only reached when a case fails; the first
# delivery also waits on each daemon looking its public address up.
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail consent-form naming test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES

# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/files"
    printf 'name = %s\nport = %s\n' "$2" "$3" > "$1/config"
}

make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"

printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

printf 'a photo standing in\n' > "$WORK/sender/files/20260903_154820.jpg"
printf 'first photo\n'         > "$WORK/sender/files/a.jpg"
printf 'second photo\n'        > "$WORK/sender/files/b.jpg"

printf 'to: receiver\nattach: %s\n\nme in the dinosaur hoodie\n' \
    "$WORK/sender/files/20260903_154820.jpg" > "$WORK/sender/outbox/dinosaur-hoodie-pic"
printf 'to: receiver\nattach: %s\nattach: %s\n\ntwo of them\n' \
    "$WORK/sender/files/a.jpg" "$WORK/sender/files/b.jpg" > "$WORK/sender/outbox/two-photos"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

# Done when all three requests have reached the receiver.
echo "running two mailboxes (up to ${DEADLINE_SECONDS}s)"
waited=0
while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
    [ "$(grep -c 'attachment request from sender:' "$WORK/receiver.log")" -ge 3 ] && break
    sleep 1
    waited=$((waited + 1))
done
kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null

INBOX="$WORK/receiver/inbox"
FORM_ONE="$INBOX/dinosaur-hoodie-pic-20260903_154820.jpg-consent-to-download-form"
FORM_A="$INBOX/two-photos-a.jpg-consent-to-download-form"
FORM_B="$INBOX/two-photos-b.jpg-consent-to-download-form"

echo ""
echo "one attachment"
if [ -f "$FORM_ONE" ]; then
    ok "the form is named after the message, then the attachment"
else
    note_fail "no form named dinosaur-hoodie-pic-20260903_154820.jpg-consent-to-download-form"
    info "inbox holds: $(ls "$INBOX" | tr '\n' ' ')"
fi
if grep -q "^  Attached to:   dinosaur-hoodie-pic$" "$FORM_ONE" 2>/dev/null; then
    ok "and says which message it is attached to"
else
    note_fail "the form does not name its message"
fi
if grep -q "^  File:          20260903_154820.jpg$" "$FORM_ONE" 2>/dev/null; then
    ok "and still names the file"
else
    note_fail "the form does not name the file"
fi

echo ""
echo "two attachments on one message"
if [ -f "$FORM_A" ] && [ -f "$FORM_B" ]; then
    ok "each gets its own form, both named after the message"
else
    note_fail "the two forms are not both there"
    info "inbox holds: $(ls "$INBOX" | tr '\n' ' ')"
fi

echo ""
echo "every form"
if grep -q "not in the inbox record" "$WORK/receiver.log"; then
    note_fail "a request came for a message the receiver had no record of"
    info "$(grep 'not in the inbox record' "$WORK/receiver.log")"
else
    ok "found its message in the receiver's record"
fi

rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
