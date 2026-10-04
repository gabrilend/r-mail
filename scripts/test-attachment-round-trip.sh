#!/bin/sh
# test-attachment-round-trip.sh — check that an honest attachment still travels from one mailbox to another
#
# The other attachment tests play a hostile contact against one mailbox.
# This one is the control: two real mailboxes on this machine, a message
# with an attachment big enough to go in several pieces, the receiving
# owner saying yes, and the file arriving byte for byte.  It exists so the
# checks added in 2026-09-29 (issue #311: required checksums, a pinned
# piece count and length, the unpacked-size limit, links turned into
# notes) are proven not to stop an honest sender.
#
# What it sends, twice:
#   a 40 KB file cut into 16 KiB pieces (attachment_chunk_size), so three
#   pieces with a shorter last one -- the shape the pinning rules check;
#   the same file cut into 256-byte pieces, about 157 of them.  The
#   receiver lists at most 64 owed pieces per answer (#311b), so the sender
#   must follow the answers batch by batch; and there is no smallest piece.
#
# Usage:
#   scripts/test-attachment-round-trip.sh          # use the enclosing checkout
#   scripts/test-attachment-round-trip.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK_ROOT="/tmp/rmail/tests/attachment-round-trip"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-attachment-round-trip-*"

SENDER_PORT=59490
RECEIVER_PORT=59491
TOKEN="attachment-round-trip-test-token-not-a-secret"

# Longest each run lasts.  Consent goes back to the sender and the pieces
# follow on the sender's next cycle, so this is a few cycles long.
DEADLINE_SECONDS=150

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail attachment round-trip test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK_ROOT"

# make_mailbox <dir> <name> <port> <piece size>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/files" "$1/attachments"
    printf 'name = %s\nport = %s\nattachment_chunk_size = %s\nattachment_pending_dir = %s\n' \
        "$2" "$3" "$4" "$1/pending" > "$1/config"
}

# run_case <piece size> — one sender, one receiver, one attachment
run_case() {
    PIECE="$1"
    WORK="$WORK_ROOT/pieces-$PIECE"
    echo ""
    echo "in pieces of $PIECE bytes"
    rm -rf "$WORK"
    mkdir -p "$WORK"
    rm -f $RAM_FILES

    make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"   "$PIECE"
    make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT" "$PIECE"

    printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
        "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
    # The receiver starts without the sender's address.  Two daemons on one
    # machine that dial each other at the same moment both wait on each
    # other (a known daemon problem, not what this test is about), so the
    # receiver is only told where the sender is once it has something to
    # say: the answer to the consent form.
    printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

    head -c 40000 /dev/urandom > "$WORK/sender/files/photo.bin"
    printf 'to: receiver\nattach: %s\n\nthe photo\n' "$WORK/sender/files/photo.bin" \
        > "$WORK/sender/outbox/a-photo"

    "$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
    RECEIVER_PID=$!
    "$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
    SENDER_PID=$!

    info "running two mailboxes (up to ${DEADLINE_SECONDS}s)"
    waited=0
    accepted=no
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        # Answer the consent form the way the owner would: delete "deny".
        if [ "$accepted" = no ]; then
            for form in "$WORK/receiver/inbox/"*-consent-to-download-form; do
                [ -f "$form" ] || continue
                grep -v '^deny$' "$form" > "$form.new"
                mv "$form.new" "$form"
                printf 'sender.ip    = "127.0.0.1"\nsender.port  = %s\n' "$SENDER_PORT" \
                    >> "$WORK/receiver/contacts"
                accepted=yes
                info "consent given after ${waited}s"
            done
        fi
        grep -q 'attachment received: photo.bin' "$WORK/receiver.log" && break
        sleep 1
        waited=$((waited + 1))
    done
    kill "$RECEIVER_PID" "$SENDER_PID"
    wait "$RECEIVER_PID" "$SENDER_PID"

    if [ "$accepted" = yes ]; then
        ok "a consent form arrived and was answered"
    else
        note_fail "no consent form arrived"
    fi
    if cmp -s "$WORK/receiver/attachments/photo.bin" "$WORK/sender/files/photo.bin"; then
        ok "the file arrived byte for byte (after ${waited}s)"
    else
        note_fail "the file did not arrive whole"
        info "receiver log: $WORK/receiver.log"
        info "sender log:   $WORK/sender.log"
    fi
    if grep -q "does not match the pinned transfer\|checksum mismatch\|oversize" "$WORK/receiver.log"; then
        note_fail "the receiver complained about an honest sender"
        info "$(grep "does not match the pinned transfer\|checksum mismatch\|oversize" "$WORK/receiver.log")"
    else
        ok "the receiver raised no complaint about it"
    fi

    rm -f $RAM_FILES
}

run_case 16384
run_case 256

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
