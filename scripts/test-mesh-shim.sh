#!/bin/sh
# test-mesh-shim.sh — check the example hook that also hands mail to Reticulum's rncp (#904)
#
# scripts/hooks/examples/on_send.reticulum-rncp.sh is reference material,
# not installed: a user who runs Reticulum copies it over a mailbox's
# on_send.  For a contact with a `reticulum` field it runs
# `rncp <file> <destination>` in the background with the message's body,
# keeps a record so a retry does not send it twice, and prints nothing, so
# rmail still sends the message over IP as written.
#
# rncp here is a stand-in that writes down its arguments and the file it
# was given; nothing of Reticulum is run.
#
# Cases:
#   hook alone    a contact with no field: nothing run, nothing printed; a
#                 contact with one: rncp gets a file holding the body byte
#                 for byte (a 200 KiB body too, which comes only on stdin),
#                 named after the subject, and the field as destination;
#                 the same message again: not sent twice; an edit: sent;
#                 rncp failing: no record, so the next call tries again;
#                 no rncp: a note on stderr and nothing else; a field that
#                 is not hexadecimal: not used; the hook returns while a
#                 slow rncp is still running, and a call meanwhile starts
#                 no second copy
#   two mailboxes the example as a sender's on_send: the receiver gets the
#                 message over IP unchanged, rncp got the same body for
#                 the receiver's Reticulum hash, and a contact with no
#                 field is sent to over IP only
#   not installed install.sh copies scripts/hooks/*.sh, not the examples
#
# Usage:
#   scripts/test-mesh-shim.sh          # use the enclosing checkout
#   scripts/test-mesh-shim.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
HOOK="$DIR/scripts/hooks/examples/on_send.reticulum-rncp.sh"
LAUNCHER="$DIR/run-rmail.sh"
WORK="/tmp/rmail/tests/mesh-shim"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-mesh-shim-*"
SENDER_PORT=59576
RECEIVER_PORT=59577
TOKEN="mesh-shim-test-token-not-a-real-secret"
HASH=256320d405d6d525d1e9

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail mesh-shim test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
mkdir -p "$WORK/bin" "$WORK/box/hooks"
rm -f $RAM_FILES

# The stand-in rncp: "<n> <file name> <destination>" in calls, the file
# kept as got-<n>.  With $WORK/fail it fails; with $WORK/hold (a fifo) it
# waits until something is written there.
cat > "$WORK/bin/rncp" <<EOF
#!/bin/sh
n=\$(( \$(wc -l < "$WORK/calls" 2>/dev/null || echo 0) + 1 ))
echo "\$n \$(basename "\$1") \$2" >> "$WORK/calls"
cp "\$1" "$WORK/got-\$n"
[ -p "$WORK/hold" ] && read _ < "$WORK/hold"
[ -e "$WORK/fail" ] && { echo "no path to destination" >&2; exit 1; }
exit 0
EOF
chmod +x "$WORK/bin/rncp"
cp "$DIR/helpers/rfield.sh" "$WORK/bin/rfield.sh"
chmod +x "$WORK/bin/rfield.sh"

# the hook as a mailbox would have it: hooks/on_send.sh beside contacts
BOX="$WORK/box"
cp "$HOOK" "$BOX/hooks/on_send.sh"
printf 'alice.token = "x"\nalice.reticulum = %s\nbob.token = "y"\ncarol.reticulum = not-hex!\n' "$HASH" > "$BOX/contacts"

calls() { if [ -f "$WORK/calls" ]; then wc -l < "$WORK/calls" | tr -d ' '; else echo 0; fi; }
# wait_until <seconds> <shell test>: polls, as the hook's rncp runs behind it
wait_until() {
    _n=0
    while [ "$_n" -lt "$(( $1 * 10 ))" ]; do
        eval "$2" && return 0
        sleep 0.1
        _n=$((_n + 1))
    done
    return 1
}
run_hook() {  # <recipient> <subject> <body file>; stdout to $WORK/out, stderr to $WORK/err
    PATH="$WORK/bin:$PATH" sh "$BOX/hooks/on_send.sh" "$1" "$2" "$(head -c 100 "$3")" \
        < "$3" > "$WORK/out" 2> "$WORK/err"
}
settled() {  # [mailbox]: no hand-over still running there
    ! ls "${1:-$BOX}/hooks/.reticulum-sent/"*.sending > /dev/null 2>&1
}

echo ""
echo "hook alone"
printf 'hello bob\n' > "$WORK/b1"
run_hook bob "for bob" "$WORK/b1"; st=$?
if [ "$st" = 0 ] && [ ! -s "$WORK/out" ] && [ "$(calls)" = 0 ]; then
    ok "a contact with no reticulum field: nothing run, nothing printed"
else
    note_fail "for bob: status $st, printed [$(cat "$WORK/out")], $(calls) rncp call(s)"
fi

printf 'hello alice\nsecond line\n\n' > "$WORK/b2"
run_hook alice "a/b: hello" "$WORK/b2"; st=$?
wait_until 10 '[ "$(calls)" = 1 ] && settled'
if [ "$st" = 0 ] && [ ! -s "$WORK/out" ] && [ "$(sed -n 1p "$WORK/calls" 2>/dev/null)" = "1 a_b__hello.txt $HASH" ] \
   && cmp -s "$WORK/got-1" "$WORK/b2"; then
    ok "with a field: rncp gets the body byte for byte, named after the subject, for that hash; nothing printed"
else
    note_fail "for alice: status $st, printed [$(cat "$WORK/out")], calls [$(cat "$WORK/calls" 2>/dev/null)]"
fi
[ -e "$BOX/hooks/.reticulum-sent/$( { printf 'alice\na/b: hello\n'; cat "$WORK/b2"; } | sha256sum | cut -d' ' -f1)" ] \
    && ok "and a record is kept beside the hook" || note_fail "no record in hooks/.reticulum-sent: $(ls -a "$BOX/hooks/.reticulum-sent" 2>/dev/null | tr '\n' ' ')"

run_hook alice "a/b: hello" "$WORK/b2"
wait_until 2 '[ "$(calls)" != 1 ]'
[ "$(calls)" = 1 ] && ok "the same message again, as on a retry: not handed over twice" \
    || note_fail "the same message went $(calls) times"

printf 'hello alice, edited\n' > "$WORK/b3"
run_hook alice "a/b: hello" "$WORK/b3"
wait_until 10 '[ "$(calls)" = 2 ] && settled'
[ "$(calls)" = 2 ] && cmp -s "$WORK/got-2" "$WORK/b3" && ok "an edit has a new body, and goes again" \
    || note_fail "the edit: $(calls) calls"

yes 'a long line of a long body, 0123456789 abcdefghij' | head -c 204800 > "$WORK/b4"
run_hook alice "long" "$WORK/b4"
wait_until 10 '[ "$(calls)" = 3 ] && settled'
cmp -s "$WORK/got-3" "$WORK/b4" && ok "a 200 KiB body, given only on stdin, arrives whole" \
    || note_fail "the long body: $(wc -c < "$WORK/got-3" 2>/dev/null) bytes"

touch "$WORK/fail"
printf 'will fail\n' > "$WORK/b5"
run_hook alice "fails" "$WORK/b5"
wait_until 10 '[ "$(calls)" = 4 ] && settled'
rm -f "$WORK/fail"
run_hook alice "fails" "$WORK/b5"
wait_until 10 '[ "$(calls)" = 5 ] && settled'
if [ "$(calls)" = 5 ] && [ -e "$BOX/hooks/.reticulum-sent/$( { printf 'alice\nfails\n'; cat "$WORK/b5"; } | sha256sum | cut -d' ' -f1)" ]; then
    ok "rncp failing keeps no record, so the next call tries again, and its success is kept"
else
    note_fail "after a failure: $(calls) calls"
fi

printf 'no rncp here\n' > "$WORK/b6"
PATH="$WORK/only-rfield:/usr/bin:/bin" RFIELD="$WORK/bin/rfield.sh" sh "$BOX/hooks/on_send.sh" alice "none" "x" \
    < "$WORK/b6" > "$WORK/out" 2> "$WORK/err"; st=$?
if [ "$st" = 0 ] && [ ! -s "$WORK/out" ] && grep -q "no rncp to run" "$WORK/err" && [ "$(calls)" = 5 ]; then
    ok "no rncp: a note on stderr, status 0, nothing printed"
else
    note_fail "without rncp: status $st, printed [$(cat "$WORK/out")], said [$(cat "$WORK/err")]"
fi

printf 'for carol\n' > "$WORK/b7"
run_hook carol "carol" "$WORK/b7"
wait_until 1 '[ "$(calls)" != 5 ]'
[ "$(calls)" = 5 ] && grep -q "not a hexadecimal hash" "$WORK/err" \
    && ok "a field that is not a hexadecimal hash is not used, and said so" \
    || note_fail "carol's field: $(calls) calls, said [$(cat "$WORK/err")]"

mkfifo "$WORK/hold"
printf 'slow\n' > "$WORK/b8"
# The hook's stdout is a pipe here, as rmail reads it: the hook is done
# only when every holder of that pipe has let go.  Run behind, so a hook
# that waited for rncp is seen as not done rather than hanging the test.
rm -f "$WORK/hook-done"
( PATH="$WORK/bin:$PATH" sh "$BOX/hooks/on_send.sh" alice slow x < "$WORK/b8" 2> "$WORK/err" | cat > "$WORK/out"
  : > "$WORK/hook-done" ) &
returned=no
wait_until 3 '[ -e "$WORK/hook-done" ]' && returned=yes
wait_until 10 '[ "$(calls)" = 6 ]'
run_hook alice "slow" "$WORK/b8"
sleep 0.5
second=$(calls)
# Release the stand-in.  Opened for reading and writing, which does not
# wait for a reader, so a broken hook that never started rncp cannot hang
# the test here.
exec 3<> "$WORK/hold"
echo go >&3
exec 3>&-
rm -f "$WORK/hold"
wait_until 10 'settled'
wait
if [ "$returned" = yes ] && [ "$second" = 6 ]; then
    ok "the hook returns while a slow rncp runs, its stdout let go, and a call meanwhile starts no second copy"
else
    note_fail "with a slow rncp: the hook returned: $returned, calls meanwhile $second"
fi

echo ""
echo "two mailboxes"
make_mailbox() {  # <dir> <name> <port>
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments" "$1/hooks"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
}
make_mailbox "$WORK/sender" sender "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"
make_mailbox "$WORK/plain" plain "$((RECEIVER_PORT + 1))"
printf 'receiver.ip = "127.0.0.1"\nreceiver.port = %s\nreceiver.token = "%s"\nreceiver.reticulum = %s\n' \
    "$RECEIVER_PORT" "$TOKEN" "$HASH" > "$WORK/sender/contacts"
printf 'plain.ip = "127.0.0.1"\nplain.port = %s\nplain.token = "%s-2"\n' "$((RECEIVER_PORT + 1))" "$TOKEN" >> "$WORK/sender/contacts"
printf 'sender.token = "%s"\n' "$TOKEN" > "$WORK/receiver/contacts"
printf 'sender.token = "%s-2"\n' "$TOKEN" > "$WORK/plain/contacts"
cp "$HOOK" "$WORK/sender/hooks/on_send.sh"
printf 'on_send = ./hooks/on_send.sh\n' >> "$WORK/sender/config"
: > "$WORK/calls"; rm -f "$WORK"/got-*
printf 'to: receiver\n\nover the air as well\n' > "$WORK/sender/outbox/both-ways"
printf 'to: plain\n\nby wire alone\n' > "$WORK/sender/outbox/wire-only"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
R_PID=$!
"$LAUNCHER" "$WORK/plain/config" > "$WORK/plain.log" 2>&1 &
P_PID=$!
PATH="$WORK/bin:$PATH" "$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
S_PID=$!
wait_until 90 '[ -e "$WORK/receiver/inbox/both-ways" ] && [ -e "$WORK/plain/inbox/wire-only" ] && [ "$(calls)" -ge 1 ]'
wait_until 5 'settled "$WORK/sender"'
kill "$R_PID" "$P_PID" "$S_PID"
wait "$R_PID" "$P_PID" "$S_PID" 2>/dev/null

if grep -qx 'over the air as well' "$WORK/receiver/inbox/both-ways" 2>/dev/null; then
    ok "the receiver got the message over IP, its body as written"
else
    note_fail "the receiver's copy: $(cat "$WORK/receiver/inbox/both-ways" 2>/dev/null | head -3 | tr '\n' ' ')"
fi
if [ "$(cat "$WORK/calls" 2>/dev/null)" = "1 both-ways.txt $HASH" ] && [ "$(cat "$WORK/got-1")" = "over the air as well" ]; then
    ok "and rncp got the same body, once, for the receiver's Reticulum hash"
else
    note_fail "rncp calls: [$(cat "$WORK/calls" 2>/dev/null)] got [$(cat "$WORK/got-1" 2>/dev/null)]"
fi
grep -qx 'by wire alone' "$WORK/plain/inbox/wire-only" 2>/dev/null && ! grep -q wire-only "$WORK/calls" \
    && ok "a contact with no field is sent to over IP only" || note_fail "the plain contact: $(cat "$WORK/calls")"

echo ""
echo "not installed"
if grep -q 'for _h in "$ROOT/scripts/hooks"/\*.sh; do' "$DIR/scripts/install.sh" \
   && [ -z "$(find "$DIR/scripts/hooks" -maxdepth 1 -name '*reticulum*')" ]; then
    ok "install.sh copies scripts/hooks/*.sh, and the example is not among them"
else
    note_fail "the example may be installed into every mailbox"
fi

rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
