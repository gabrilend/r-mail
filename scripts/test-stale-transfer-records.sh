#!/bin/sh
# test-stale-transfer-records.sh — check that a half-sent attachment never stalls the mailbox
#
# When somebody agrees to receive an attachment, the sending mailbox packs
# the file into a compressed copy and hands it over in pieces, one sync
# cycle at a time.  A written record of each transfer (which file, who it
# is for, where the compressed copy is, which pieces are still owed) sits in
# the mailbox's state folder between cycles, and can sit there for months
# while the other side makes up their mind.
#
# In September 2026 one such record, written in April by an older version
# that stored the compressed copy under a different field, made every sync
# cycle crash from the moment consent arrived.  Because the step that
# schedules the next contact comes after the crash, the mailbox stopped
# waiting between cycles altogether and logged the same error over a
# million times overnight, with every other message stuck behind it.
#
# This script builds throwaway mailboxes in RAM, plants one transfer record
# in each in a different state of disrepair, runs the real daemon until its
# log says what it did about it, and checks that no cycle crashed:
#
#   old-record      an April-style record with no copy location, source present
#   old-record-gone the same, with the source file deleted as well
#   source-deleted  a current record whose source was deleted mid-send
#                   (the compressed copy is still there and is all it needs)
#   both-gone       a current record whose source and copy are both gone
#
# The recipient is an address reserved for documentation (192.0.2.7) so no
# piece ever reaches anyone; what is tested is the sender's handling, not
# delivery.  All four mailboxes run at once, on ports no install uses.
#
# Usage:
#   scripts/test-stale-transfer-records.sh          # use the enclosing checkout
#   scripts/test-stale-transfer-records.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/stale-transfer-records"

# Longest a daemon is left running.  A passing case stops as soon as its log
# line appears; this is only reached when it never does.  The daemon looks
# its public IP up before its first sync, so allow for that.
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail stale-transfer-record test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# --------------------------------------------------------------------------
# make_sender <dir> <port>
#
# A mailbox with one contact, "far-away", at an address nothing answers on.
make_sender() {
    _dir="$1"; _port="$2"
    mkdir -p "$_dir/inbox" "$_dir/outbox" "$_dir/.state" "$_dir/files"
    {
        printf 'far-away.ip    = "192.0.2.7"\n'
        printf 'far-away.port  = 59999\n'
        printf 'far-away.token = "test-token-not-a-real-secret"\n'
    } > "$_dir/contacts"
    {
        printf 'name = sender\n'
        printf 'port = %s\n' "$_port"
    } > "$_dir/config"
    printf 'a picture, standing in\n' > "$_dir/files/picture.jpg"
}

# plant_record <dir> <copy-location-line>
#
# Write one transfer record, already consented to and mid-send.  The second
# argument is the line that says where the compressed copy is: either the
# current `"compressed_path": "..."` field or April's `"zip_id": "..."`.
plant_record() {
    _dir="$1"; _copy_line="$2"
    cat > "$_dir/.state/chunks-outgoing.json" <<EOF
{
  "att-under-test": {
    "filename": "picture.jpg",
    "original_path": "$_dir/files/picture.jpg",
    "status": "sending",
    "total_chunks": 1,
    "missing": [0],
    "total_checksum": "0000000000000000000000000000000000000000000000000000000000000000",
    "expected_size": 23,
    $_copy_line,
    "message_id": "msg-under-test",
    "to": "far-away",
    "outbox_file": "letter"
  }
}
EOF
}

# run_case <name> <port> <await-pattern>
#
# Start the daemon in the background and stop it once <await-pattern> shows
# up in its log, or at the deadline.  Runs in its own background job so the
# cases share the wait for DNS instead of taking turns.
run_case() {
    _name="$1"; _port="$2"; _await="$3"
    _log="$WORK/$_name.log"
    : > "$_log"
    "$LAUNCHER" "$WORK/$_name/config" > "$_log" 2>&1 &
    _pid=$!
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$_await" "$_log" && break
        sleep 1
        _waited=$((_waited + 1))
    done
    # Give the cycle that printed the line a moment to finish, so a crash
    # later in the same cycle still lands in the log before it is read.
    sleep 2
    kill "$_pid"
    wait "$_pid" 2>/dev/null
}

# --------------------------------------------------------------------------
# Build all four, then run them together.

make_sender "$WORK/old-record" 59381
plant_record "$WORK/old-record" '"zip_id": "92689484-33cd-4df7-a4a1-05af8a41be6b"'

make_sender "$WORK/old-record-gone" 59382
plant_record "$WORK/old-record-gone" '"zip_id": "92689484-33cd-4df7-a4a1-05af8a41be6b"'
rm "$WORK/old-record-gone/files/picture.jpg"

make_sender "$WORK/source-deleted" 59383
printf 'stands in for a compressed copy\n' > "$WORK/source-deleted/files/copy.zip"
plant_record "$WORK/source-deleted" "\"compressed_path\": \"$WORK/source-deleted/files/copy.zip\""
rm "$WORK/source-deleted/files/picture.jpg"

make_sender "$WORK/both-gone" 59384
plant_record "$WORK/both-gone" "\"compressed_path\": \"$WORK/both-gone/files/copy.zip\""
rm "$WORK/both-gone/files/picture.jpg"

echo "running four mailboxes at once (up to ${DEADLINE_SECONDS}s)"
# old-record waits for the end of the cycle, not the rebuild line: the
# rebuilt record is saved only after the send attempt to the unanswering
# address has timed out, and the case checks what was saved.
run_case old-record      59381 "unreachable contacts this cycle" &
run_case old-record-gone 59382 "original gone" &
run_case source-deleted  59383 "unreachable contacts this cycle" &
run_case both-gone       59384 "original gone" &
wait

# --------------------------------------------------------------------------
# no_crash <name> — the one check every case shares.
no_crash() {
    if grep -q "sync error" "$WORK/$1.log"; then
        note_fail "$1: a sync cycle crashed"
        info "$(grep -m1 'sync error' "$WORK/$1.log")"
    else
        ok "$1: no sync cycle crashed"
    fi
}

state_of() { cat "$WORK/$1/.state/chunks-outgoing.json"; }

echo ""
echo "an April-style record, source still there"
no_crash old-record
if grep -q "recorded by an older version" "$WORK/old-record.log"; then
    ok "the old record is named as such in the log"
else
    note_fail "no log line recognising the old record"
fi
if grep -q "was missing, recompressed" "$WORK/old-record.log"; then
    ok "the compressed copy was rebuilt from the source"
else
    note_fail "the compressed copy was not rebuilt"
    info "$(tail -3 "$WORK/old-record.log")"
fi
if state_of old-record | grep -q '"compressed_path"' \
   && ! state_of old-record | grep -q '"zip_id"'; then
    ok "the saved record now uses the current field, and the old one is gone"
else
    note_fail "the saved record was not brought up to date"
    info "$(state_of old-record)"
fi

echo ""
echo "an April-style record, source deleted"
no_crash old-record-gone
if grep -q "original gone for att-under-test, cancelling" "$WORK/old-record-gone.log"; then
    ok "the transfer was cancelled with a reason"
else
    note_fail "the transfer was not cancelled"
    info "$(tail -3 "$WORK/old-record-gone.log")"
fi
if ! state_of old-record-gone | grep -q "att-under-test"; then
    ok "and its record was removed"
else
    note_fail "the record is still there"
fi

echo ""
echo "source deleted mid-send, compressed copy still there"
no_crash source-deleted
if grep -q "zip missing" "$WORK/source-deleted.log"; then
    note_fail "the compressed copy was treated as missing"
else
    ok "the compressed copy was used as it was"
fi
if state_of source-deleted | grep -q "att-under-test"; then
    ok "the transfer is still queued, waiting for the recipient"
else
    note_fail "the transfer was dropped"
fi

echo ""
echo "source and compressed copy both gone"
no_crash both-gone
if grep -q "original gone for att-under-test, cancelling" "$WORK/both-gone.log"; then
    ok "the transfer was cancelled with a reason"
else
    note_fail "the transfer was not cancelled"
    info "$(tail -3 "$WORK/both-gone.log")"
fi

# --------------------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
