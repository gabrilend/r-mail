#!/bin/sh
# test-torn-pack.sh — check that a file being written while it is packed is packed again, not sent torn
#
# Before an attachment is offered to a contact, the sending mailbox packs
# the file into a zip.  zip reads the file from start to end; if something
# is still writing it, the zip holds the start of the old content and the
# end of the new -- a file that never existed.  Until 2026-09-29 (issue
# #404d) nothing noticed.
#
# Now the file's size and modification time (every file's, for a folder)
# are taken before and after packing.  Any difference throws the zip away,
# says so in the log, and leaves the attachment to be packed again on a
# later cycle.
#
# This script runs two throwaway mailboxes.  The sender's `zip` is a
# stand-in placed first on its PATH: while a marker file exists, it adds a
# line to the attachment and then runs the real zip -- a file being written
# during packing, every time.  The checks:
#
#   torn        the sender's log says the file changed while it was being
#               packed, and no request for it reaches the receiver
#   packed      once the marker is removed, a later cycle packs it and the
#               request reaches the receiver
#
# Only the sender dials: two daemons on one machine dialling each other at
# the same moment wait on each other (a separate daemon problem).
#
# Usage:
#   scripts/test-torn-pack.sh          # use the enclosing checkout
#   scripts/test-torn-pack.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/torn-pack"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-torn-pack-*"

SENDER_PORT=59492
RECEIVER_PORT=59493
TOKEN="torn-pack-test-token-not-a-secret"

# Longest each wait lasts.  A failed pack is retried on the sender's next
# cycle for that contact, which can be half a minute away.
DEADLINE_SECONDS=120

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail torn-pack test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

REAL_ZIP=$(command -v zip)
if [ -z "$REAL_ZIP" ]; then
    note_fail "no zip on this machine"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/bin"
rm -f $RAM_FILES

# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/files" "$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
}
make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"
printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

SOURCE="$WORK/sender/files/notes.txt"
MARKER="$WORK/keep-writing"
printf 'the first line\n' > "$SOURCE"
touch "$MARKER"

# The stand-in zip: writes to the source while the marker exists, then
# hands every argument to the real zip.
cat > "$WORK/bin/zip" <<EOF
#!/bin/sh
# stand-in zip for test-torn-pack.sh: simulates a file being written during packing
if [ -e "$MARKER" ]; then
    sleep 1
    printf 'a line written during packing\n' >> "$SOURCE"
fi
exec "$REAL_ZIP" "\$@"
EOF
chmod +x "$WORK/bin/zip"

printf 'to: receiver\nattach: %s\n\nmy notes\n' "$SOURCE" > "$WORK/sender/outbox/notes"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
PATH="$WORK/bin:$PATH" "$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

# wait_for_line <file> <text>: 0 when the text appears before the deadline
wait_for_line() {
    waited=0
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$2" "$1" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

echo "running two mailboxes (each wait up to ${DEADLINE_SECONDS}s)"
echo ""
echo "torn"
if wait_for_line "$WORK/sender.log" "changed while it was being packed"; then
    ok "the sender noticed the file changing while it was packed"
else
    note_fail "the sender never said the file changed while it was packed"
fi
if grep -q "attachment request from sender" "$WORK/receiver.log"; then
    note_fail "a request for the torn copy reached the receiver"
else
    ok "no request for a torn copy reached the receiver"
fi

rm -f "$MARKER"
echo ""
echo "packed"
if wait_for_line "$WORK/receiver.log" "attachment request from sender: notes.txt"; then
    ok "once the file stopped changing, it was packed and offered"
else
    note_fail "the file was never offered after it stopped changing"
fi

kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "sender log:   $WORK/sender.log"
info "receiver log: $WORK/receiver.log"
exit 1
