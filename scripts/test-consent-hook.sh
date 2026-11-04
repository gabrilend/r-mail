#!/bin/sh
# test-consent-hook.sh — check the on_consent hook, and the message path on_package gets (#216)
#
# Nobody receives an attachment without saying yes first: each one puts a
# consent form in the receiver's inbox, and nothing moves until the owner
# deletes "deny" (or "accept").  Since #216 the owner's on_consent script
# may answer the form as it arrives -- printing "accept" or "deny" -- and
# printing nothing leaves the form for the owner, as before.  And
# on_package gets a fourth argument: the inbox file of the message the
# attachment came with.
#
# This script runs two throwaway mailboxes on this machine.  The sender
# mails the receiver one message, three-files, with three attachments, and
# the receiver's on_consent hook answers each differently:
#
#   wanted.bin     accept    (40 KB, so it travels in several pieces)
#   unwanted.bin   deny
#   later.bin      nothing   (left for the owner)
#
# Both hooks write down the arguments they were given, and the script
# checks those, the files that arrived, and the forms left behind.
#
# Not covered: a request for a message the receiver has no record of, when
# $4 is empty (see test-consent-form-name.sh for why that order of events
# can't be made on purpose here).  Old three-argument hooks are covered by
# every other attachment test, whose mailboxes run without these hooks.
#
# Usage:
#   scripts/test-consent-hook.sh          # use the enclosing checkout
#   scripts/test-consent-hook.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/consent-hook"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-consent-hook-*"

SENDER_PORT=59530
RECEIVER_PORT=59531
TOKEN="consent-hook-test-token-not-a-real-secret"

# Longest the run lasts.  The answers go back to the sender and the pieces
# follow on its next cycle, so this is a few cycles long.
DEADLINE_SECONDS=150

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail consent hook test"
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
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/files" "$1/attachments" "$1/hooks"
    printf 'name = %s\nport = %s\nattachment_chunk_size = 16384\nattachment_pending_dir = %s\n' \
        "$2" "$3" "$1/pending" > "$1/config"
}

make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"

printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
# The receiver starts without the sender's address, and is told it once a
# form has arrived: two daemons on one machine that dial each other at the
# same moment wait on each other (see test-attachment-round-trip.sh).
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

# The receiver's hooks, named relative to its config as an installed
# mailbox names them.  Each writes one line per call: its arguments,
# separated by |, then how many there were.
cat > "$WORK/receiver/hooks/consent.sh" <<EOF
#!/bin/sh
form=missing
[ -f "\$3" ] && form=present
printf '%s|%s|%s|%s|%s|%s|%s\n' "\$1" "\$2" "\$3" "\$4" "\$5" "\$#" "\$form" >> "$WORK/consent-args"
case "\$2" in
    wanted.bin)   echo accept ;;
    unwanted.bin) echo deny ;;
esac
EOF
cat > "$WORK/receiver/hooks/package.sh" <<EOF
#!/bin/sh
printf '%s|%s|%s|%s|%s\n' "\$1" "\$2" "\$3" "\$4" "\$#" >> "$WORK/package-args"
EOF
chmod +x "$WORK/receiver/hooks/consent.sh" "$WORK/receiver/hooks/package.sh"
printf 'on_consent = ./hooks/consent.sh\non_package = ./hooks/package.sh\n' >> "$WORK/receiver/config"

head -c 40000 /dev/urandom > "$WORK/sender/files/wanted.bin"
printf 'not wanted\n'          > "$WORK/sender/files/unwanted.bin"
printf 'for the owner\n'       > "$WORK/sender/files/later.bin"
printf 'to: receiver\nattach: %s\nattach: %s\nattach: %s\n\nthree of them\n' \
    "$WORK/sender/files/wanted.bin" "$WORK/sender/files/unwanted.bin" \
    "$WORK/sender/files/later.bin" > "$WORK/sender/outbox/three-files"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

echo "running two mailboxes (up to ${DEADLINE_SECONDS}s)"
INBOX="$WORK/receiver/inbox"
told=no
waited=0
while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
    if [ "$told" = no ] && [ "$(grep -c 'attachment request from sender:' "$WORK/receiver.log")" -ge 3 ]; then
        printf 'sender.ip    = "127.0.0.1"\nsender.port  = %s\n' "$SENDER_PORT" >> "$WORK/receiver/contacts"
        told=yes
        info "the three forms arrived after ${waited}s"
    fi
    grep -q 'attachment received: wanted.bin' "$WORK/receiver.log" && [ -s "$WORK/package-args" ] && break
    sleep 1
    waited=$((waited + 1))
done
# a few seconds more, so a wrongly accepted file would have time to arrive
sleep 5
kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null

MESSAGE="$INBOX/three-files"
FORM_LATER="$INBOX/three-files-later.bin-consent-to-download-form"

echo ""
echo "on_consent"
if [ "$(cat "$WORK/consent-args" 2>/dev/null | wc -l)" -eq 3 ]; then
    ok "ran once for each of the three attachments"
else
    note_fail "did not run three times"
    info "$(cat "$WORK/consent-args" 2>/dev/null)"
fi
wanted_line="$(grep '^sender|wanted.bin|' "$WORK/consent-args" 2>/dev/null)"
if [ "$wanted_line" = "sender|wanted.bin|$INBOX/three-files-wanted.bin-consent-to-download-form|$MESSAGE|40000|5|present" ]; then
    ok "got the sender, the file, its form (already written), the message and the size"
else
    note_fail "its arguments were not sender, file, form, message, size"
    info "got: $wanted_line"
fi
if grep -q 'on_consent answered accept for wanted.bin from sender' "$WORK/receiver.log" \
   && grep -q 'on_consent answered deny for unwanted.bin from sender' "$WORK/receiver.log"; then
    ok "the log says which forms it answered"
else
    note_fail "the log does not say the hook answered accept and deny"
fi

echo ""
echo "accept"
if cmp -s "$WORK/receiver/attachments/wanted.bin" "$WORK/sender/files/wanted.bin"; then
    ok "the accepted file arrived byte for byte (after ${waited}s)"
else
    note_fail "the accepted file did not arrive whole"
    info "receiver log: $WORK/receiver.log"
fi

echo ""
echo "deny"
if [ ! -e "$WORK/receiver/attachments/unwanted.bin" ]; then
    ok "the denied file never arrived"
else
    note_fail "the denied file arrived"
fi

echo ""
echo "nothing printed"
if grep -q '^accept$' "$FORM_LATER" 2>/dev/null && grep -q '^deny$' "$FORM_LATER" 2>/dev/null; then
    ok "the form still waits for the owner, both lines in it"
else
    note_fail "the form for later.bin was answered or is gone"
fi
if [ ! -e "$WORK/receiver/attachments/later.bin" ]; then
    ok "and its file has not moved"
else
    note_fail "later.bin arrived without an answer"
fi

echo ""
echo "on_package"
package_line="$(head -n 1 "$WORK/package-args" 2>/dev/null)"
if [ "$package_line" = "sender|wanted.bin|$WORK/receiver/attachments/wanted.bin|$MESSAGE|4" ]; then
    ok "got the message the file came with as a fourth argument"
else
    note_fail "its arguments were not sender, file, saved path, message"
    info "got: $package_line"
fi

rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
