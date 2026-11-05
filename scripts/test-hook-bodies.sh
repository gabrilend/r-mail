#!/bin/sh
# test-hook-bodies.sh — a hook sees every body, whatever its size, and a
# hook that cannot run refuses the message (#215)
#
# Two hooks may rewrite a message's text before it is written into the
# inbox: on_receive_raw (a new message) and on_update (the author's edit).
# Linux will not start a program with any one argument over 128 KiB, and
# the body used to be passed only as an argument, so a big body never
# reached the hook and was saved unchecked.  Since #215 the body also comes
# on the hook's standard input, whatever its size ($3 still holds it up to
# 64 KiB), and a hook that cannot run, or exits non-zero, refuses the
# message: the sender keeps it and sends it again later.
#
# This script runs two throwaway mailboxes on this machine.  The receiver's
# hooks write down what they were given, then print "checked <bytes>" and
# the body they read from stdin, so the saved file shows the hook ran on
# all of it.  The sender mails:
#
#   small      a short body: $3 and stdin agree
#   middling   100 KiB: $3 empty (over 64 KiB), stdin whole
#   refused    on_receive_raw exits 3 until a flag file is removed: not
#              written meanwhile, then arrives on a later pass
#   missing    on_receive_raw runs a program that is not there (status 127)
#              until the flag is removed: refused the same way
#   to-self    a note to the sender itself, whose own on_receive_raw
#              refuses it the same way until its flag is removed
#
# and then edits "small" to a 200 KiB body, which on_update must see whole
# (the case that never reached the hook before).
#
# Usage:
#   scripts/test-hook-bodies.sh          # use the enclosing checkout
#   scripts/test-hook-bodies.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/hook-bodies"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-hook-bodies-*"

SENDER_PORT=59540
RECEIVER_PORT=59541
TOKEN="hook-bodies-test-token-not-a-real-secret"

DEADLINE_SECONDS=200

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail hook bodies test"
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
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments" "$1/hooks"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
}

make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"

# Only the sender knows the other's address: nothing needs to go back.
printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"

# A body hook: records "<hook>|<$1>|<$2>|<length of $3>|<bytes on stdin>|<$3 equals stdin>|<$#>",
# refuses while a flag file is there, else prints "checked <bytes>" and the body.
write_hook() {   # <path> <name> <flags folder>
    cat > "$1" <<EOF
#!/bin/sh
cat > "$WORK/$2.stdin.\$\$"
n=\$(wc -c < "$WORK/$2.stdin.\$\$" | tr -d ' ')
same=no
[ "\$(printf '%s' "\$3")" = "\$(cat "$WORK/$2.stdin.\$\$")" ] && same=yes
printf '%s|%s|%s|%s|%s|%s|%s\n' "$2" "\$1" "\$2" "\${#3}" "\$n" "\$same" "\$#" >> "$WORK/hook-args"
if [ -e "$3/refuse-\$2" ]; then rm -f "$WORK/$2.stdin.\$\$"; exit 3; fi
if [ -e "$3/missing-\$2" ]; then rm -f "$WORK/$2.stdin.\$\$"; exec "$WORK/no-such-program"; fi
printf 'checked %s\n' "\$n"
cat "$WORK/$2.stdin.\$\$"
rm -f "$WORK/$2.stdin.\$\$"
EOF
    chmod +x "$1"
}
mkdir -p "$WORK/flags"
write_hook "$WORK/receiver/hooks/raw.sh"    raw    "$WORK/flags"
write_hook "$WORK/receiver/hooks/update.sh" update "$WORK/flags"
write_hook "$WORK/sender/hooks/raw.sh"      self   "$WORK/flags"
printf 'on_receive_raw = ./hooks/raw.sh\non_update = ./hooks/update.sh\n' >> "$WORK/receiver/config"
printf 'on_receive_raw = ./hooks/raw.sh\n' >> "$WORK/sender/config"
touch "$WORK/flags/refuse-refused" "$WORK/flags/missing-missing" "$WORK/flags/refuse-to-self"

# bodies: printable lines, so the shell's comparisons stay simple
make_body() {   # <bytes>
    yes 'the quick brown fox jumps over the lazy dog, 0123456789 ABCDEFGHIJ' | head -c "$1"
}
printf 'to: receiver\n\nhello there\n' > "$WORK/sender/outbox/small"
{ printf 'to: receiver\n\n'; make_body 102400; } > "$WORK/sender/outbox/middling"
printf 'to: receiver\n\nnot yet\n'       > "$WORK/sender/outbox/refused"
printf 'to: receiver\n\nnot yet either\n' > "$WORK/sender/outbox/missing"
printf 'to: sender\n\na note to myself\n' > "$WORK/sender/outbox/to-self"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

R_INBOX="$WORK/receiver/inbox"
S_INBOX="$WORK/sender/inbox"
echo "running two mailboxes (up to ${DEADLINE_SECONDS}s)"
stage=first
refused_seen=no
waited=0
while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
    case "$stage" in
    first)
        # wait for the first two, and for each refusal to be logged once
        if [ -e "$R_INBOX/small" ] && [ -e "$R_INBOX/middling" ] \
           && grep -q 'on_receive_raw stopped with exit status 3: refused' "$WORK/receiver.log" \
           && grep -q 'on_receive_raw could not be run: not found: refused' "$WORK/receiver.log" \
           && grep -q 'on_receive_raw stopped with exit status 3: to-self not delivered to yourself' "$WORK/sender.log"; then
            info "first deliveries and the three refusals after ${waited}s"
            [ ! -e "$R_INBOX/refused" ] && [ ! -e "$R_INBOX/missing" ] && [ ! -e "$S_INBOX/to-self" ] && refused_seen=yes
            rm -f "$WORK/flags/"*
            { printf 'to: receiver\n\n'; make_body 204800; } > "$WORK/sender/outbox/small.new"
            mv "$WORK/sender/outbox/small.new" "$WORK/sender/outbox/small"
            stage=second
        fi ;;
    second)
        [ -e "$R_INBOX/refused" ] && [ -e "$R_INBOX/missing" ] && [ -e "$S_INBOX/to-self" ] \
            && grep -q '^update|.*|204800|' "$WORK/hook-args" 2>/dev/null \
            && grep -q '^checked 204800' "$R_INBOX/small" 2>/dev/null && break ;;
    esac
    sleep 1
    waited=$((waited + 1))
done
kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null

echo ""
echo "a small body"
line="$(grep '^raw|sender|small|' "$WORK/hook-args" | head -n 1)"
if [ "$line" = "raw|sender|small|12|12|yes|3" ]; then
    ok "\$3 and stdin hold the same body"
else
    note_fail "\$3 and stdin did not agree: $line"
fi
if [ "$(head -n 1 "$R_INBOX/small" 2>/dev/null)" = "checked 12" ] || grep -q '^checked 204800' "$R_INBOX/small" 2>/dev/null; then
    ok "the hook's output was saved"
else
    note_fail "the saved body is not the hook's output"
fi

echo ""
echo "a 100 KiB body"
line="$(grep '^raw|sender|middling|' "$WORK/hook-args" | head -n 1)"
if [ "$line" = "raw|sender|middling|0|102400|no|3" ]; then
    ok "\$3 empty (over 64 KiB), all 102400 bytes on stdin"
else
    note_fail "not \$3 empty and the body on stdin: $line"
fi
if [ "$(head -n 1 "$R_INBOX/middling" 2>/dev/null)" = "checked 102400" ] \
   && [ "$(tail -n +2 "$R_INBOX/middling" | wc -c | tr -d ' ')" = 102400 ]; then
    ok "saved as the hook printed it, the whole body after its line"
else
    note_fail "the saved body is not the hook's output of the whole body"
fi

echo ""
echo "a hook that fails"
if [ "$refused_seen" = yes ]; then
    ok "exit status 3, a program not found, and the same on the sender's own note: nothing written while refusing"
else
    note_fail "a refused message was written, or a refusal was not logged"
fi
if [ "$(head -n 1 "$R_INBOX/refused" 2>/dev/null)" = "checked 8" ] && [ "$(head -n 1 "$R_INBOX/missing" 2>/dev/null)" = "checked 15" ]; then
    ok "both arrived, through the hook, once it worked: the sender sent them again"
else
    note_fail "the refused messages did not arrive through the hook"
fi
if [ "$(head -n 1 "$S_INBOX/to-self" 2>/dev/null)" = "checked 17" ]; then
    ok "the note to self was delivered on a later pass, through the hook"
else
    note_fail "the note to self did not arrive through the hook"
fi
if [ "$(grep -c "^raw|sender|refused|" "$WORK/hook-args")" -ge 2 ]; then
    ok "the hook ran again for the message it refused ($(grep -c "^raw|sender|refused|" "$WORK/hook-args") times)"
else
    note_fail "the hook did not run again for the refused message"
fi

echo ""
echo "a 200 KiB edit"
line="$(grep '^update|sender|' "$WORK/hook-args" | tail -n 1)"
case "$line" in
    "update|sender|$R_INBOX/small|0|204800|no|3") ok "on_update ran: \$3 empty, all 204800 bytes on stdin" ;;
    *) note_fail "on_update did not see the whole edit: $line" ;;
esac
if [ "$(head -n 1 "$R_INBOX/small" 2>/dev/null)" = "checked 204800" ] \
   && [ "$(tail -n +2 "$R_INBOX/small" | wc -c | tr -d ' ')" = 204800 ]; then
    ok "the edit was saved as the hook printed it (before #215 the hook never started for it)"
else
    note_fail "the edit was not saved through the hook"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "all cases passed"
    rm -rf "$WORK"
    rm -f $RAM_FILES
    exit 0
fi
echo "$FAILURES case(s) failed; logs kept in $WORK"
exit 1
