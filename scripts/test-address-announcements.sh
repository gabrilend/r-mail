#!/bin/sh
# test-address-announcements.sh — an announcement of our addresses is owed
# as a hidden file in the outbox, and the receiver merges the set (#409)
#
# An announcement owed to a contact is `outbox/.address-announcement-<name>`
# (it used to be an entry in .state/pending-address.json).  It goes at the
# next sync and the file is removed; deleted by hand, it is not sent; it
# passes through on_send, whose output replaces the payload only when it is
# a JSON object.  On the receiving side the set is merged: a hostname the
# receiver holds for us stays its pinned default, our public address is
# added beside it as ip[N], local addresses go to local-ip, and an
# announcement that changes nothing leaves the contacts file alone.
#
# Two throwaway mailboxes on this machine.  The sender's own public address
# is written into its .state by hand (198.51.100.7, a documentation address)
# so no lookup is needed; run it inside a network namespace with only
# loopback (as the project's test runner does) and no lookup can leave the
# machine either.  The cases:
#
#   legacy     a pending-address.json from an older rmail is moved into a
#              file at start-up, and the state file is gone
#   owed       with the receiver down, the start-up announcement waits as
#              outbox/.address-announcement-receiver, holding ip and port,
#              and the plain outbox listing stays empty
#   deleted    that file deleted by hand: the receiver, once up, gets a
#              message but never an announcement
#   hook       an owed file written again: on_send sees it (subject, payload
#              on stdin) and rewrites the public address; the receiver
#              merges the rewritten set and the file goes; the payload
#              names the sender, and since the receiver calls it the same,
#              no THEIR-NAME notice (#506)
#   merge      the receiver keeps the hostname it holds (localhost) as the
#              pinned default, gains the public address as ip[1] and the
#              local address as local-ip
#   footer     a hook that prints non-JSON (a footer): the payload goes as
#              computed, and the log says why
#   unchanged  an announcement that changes nothing leaves the receiver's
#              contacts file unwritten
#
# Between cases the receiver sends the sender a short message: hearing from
# a contact makes it due at once (#115), which is how the sender's next pass
# reaches the receiver without waiting out its retry interval.
#
# Usage:
#   scripts/test-address-announcements.sh          # the enclosing checkout
#   scripts/test-address-announcements.sh /path    # another checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/address-announcements"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-address-announcements-*"

SENDER_PORT=59560
RECEIVER_PORT=59561
TOKEN="address-announcements-test-token-not-a-real-secret"
PUBLIC="198.51.100.7"
REWRITTEN="203.0.113.9"
LAN="192.168.50.7"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_for <seconds> <shell condition>
wait_for() {
    n=0
    while [ "$n" -lt $(($1 * 10)) ]; do
        if eval "$2"; then return 0; fi
        sleep 0.1
        n=$((n + 1))
    done
    eval "$2"
}

echo ""
echo "rmail address announcements test"
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

SENDER_PID=""
RECEIVER_PID=""
stop_all() {
    [ -n "$SENDER_PID" ] && kill "$SENDER_PID" 2>/dev/null
    [ -n "$RECEIVER_PID" ] && kill "$RECEIVER_PID" 2>/dev/null
    wait 2>/dev/null
}
trap stop_all EXIT

# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments" "$1/hooks"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
}

make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"

# The sender knows the receiver's address, and has been told a local
# address for it, so its announcements carry its own local address too.
printf 'receiver.ip       = "127.0.0.1"\nreceiver.port     = %s\nreceiver.token    = "%s"\nreceiver.local-ip = "192.168.50.9"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
# The receiver holds a hostname for the sender as its pinned default.
printf 'sender.ip    = "localhost"\nsender.port  = %s\nsender.token = "%s"\n' \
    "$SENDER_PORT" "$TOKEN" > "$WORK/receiver/contacts"

# The sender's own addresses, as its lookups would have recorded them.
printf '%s\n' "$PUBLIC" > "$WORK/sender/.state/public_ip"
printf '%s\n' "$LAN" > "$WORK/sender/.state/lan_ip"

# An older rmail's queue, to be moved into a file at start-up.
printf '{"receiver": {"ip": "%s", "port": %s}}\n' "$PUBLIC" "$SENDER_PORT" > "$WORK/sender/.state/pending-address.json"

# The sender's on_send hook: records what it was given; for an announcement,
# rewrites the public address (mode "rewrite") or prints a footer (mode
# "footer"); a message body goes through unchanged.
cat > "$WORK/sender/hooks/send.sh" <<EOF
#!/bin/sh
body=\$(cat)
printf '%s|%s|%s\n' "\$1" "\$2" "\$body" >> "$WORK/hook-args"
case "\$2" in
    .address-announcement-*)
        case "\$(cat "$WORK/hook-mode" 2>/dev/null)" in
            rewrite) printf '%s' "\$body" | sed 's/$PUBLIC/$REWRITTEN/g' ;;
            footer)  printf '%s\n-- \nsent from my mailbox\n' "\$body" ;;
            *)       printf '%s' "\$body" ;;
        esac ;;
    *) printf '%s' "\$body" ;;
esac
EOF
chmod +x "$WORK/sender/hooks/send.sh"
printf 'on_send = ./hooks/send.sh\n' >> "$WORK/sender/config"

OWED="$WORK/sender/outbox/.address-announcement-receiver"
R_CONTACTS="$WORK/receiver/contacts"

start_receiver() {
    "$LAUNCHER" "$WORK/receiver/config" >> "$WORK/receiver.log" 2>&1 &
    RECEIVER_PID=$!
}

# poke <n>: the receiver sends the sender a message.  Hearing from a
# contact makes it due at once (#115), so the sender's next pass goes to
# the receiver instead of waiting out its retry interval.
poke() {
    printf 'to: sender\n\npoke %s\n' "$1" > "$WORK/receiver/outbox/poke-$1"
    wait_for 60 "[ -e '$WORK/sender/inbox/poke-$1' ]" || note_fail "poke $1 did not reach the sender"
}

# ---- the sender alone: what is owed waits as a file -------------------------

"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

echo "legacy"
if wait_for 20 'grep -q "owed announcement(s) moved from .state/pending-address.json" "$WORK/sender.log"' \
   && [ ! -e "$WORK/sender/.state/pending-address.json" ]; then
    ok "an older rmail's pending-address.json was moved into a file and removed"
else
    note_fail "pending-address.json was not moved and removed"
fi

echo ""
echo "owed"
if wait_for 20 '[ -e "$OWED" ] && grep -q "startup: announcing" "$WORK/sender.log"'; then
    ok "the start-up announcement waits as outbox/.address-announcement-receiver"
else
    note_fail "no owed file in the outbox after start-up"
fi
if grep -qx "ip = $PUBLIC" "$OWED" 2>/dev/null && grep -qx "port = $SENDER_PORT" "$OWED" 2>/dev/null; then
    ok "it holds ip = $PUBLIC and port = $SENDER_PORT"
else
    note_fail "the owed file does not hold the address and port: $(cat "$OWED" 2>/dev/null)"
fi
if [ -z "$(ls "$WORK/sender/outbox")" ]; then
    ok "a plain listing of the outbox shows nothing (a hidden file)"
else
    note_fail "the outbox listing shows: $(ls "$WORK/sender/outbox")"
fi
# a sync ran and failed to reach the receiver, and the file stayed
sleep 3
if [ -e "$OWED" ]; then
    ok "still owed while the receiver is down"
else
    note_fail "the owed file went though the receiver was down"
fi

# ---- deleted by hand --------------------------------------------------------

echo ""
echo "deleted"
rm -f "$OWED"
before="$(cat "$R_CONTACTS")"
start_receiver
sleep 1
printf 'to: receiver\n\nafter the delete\n' > "$WORK/sender/outbox/after-delete"
poke 1
if wait_for 30 '[ -e "$WORK/receiver/inbox/after-delete" ]'; then
    ok "the receiver is reachable: a message reached it"
else
    note_fail "the message did not reach the receiver"
fi
sleep 2
if ! grep -q "address set from sender\|updated address for sender" "$WORK/receiver.log" \
   && [ "$(cat "$R_CONTACTS")" = "$before" ] && ! grep -q "notified receiver of address change" "$WORK/sender.log"; then
    ok "the announcement deleted by hand was not sent"
else
    note_fail "an announcement reached the receiver after its file was deleted"
fi

# ---- through on_send, and the merge -----------------------------------------

echo ""
echo "hook"
echo rewrite > "$WORK/hook-mode"
printf 'ip = %s\nport = %s\n' "$PUBLIC" "$SENDER_PORT" > "$OWED"
poke 2
if wait_for 30 '[ ! -e "$OWED" ] && grep -q "notified receiver of address change" "$WORK/sender.log"'; then
    ok "the owed file written by hand was sent, and removed"
else
    note_fail "the owed file was not sent and removed"
fi
line="$(grep '^receiver|.address-announcement-receiver|' "$WORK/hook-args" | tail -n 1)"
case "$line" in
    *"\"ips\""*"$PUBLIC"*) ok "on_send saw it: recipient, the file's name as subject, the payload on stdin" ;;
    *) note_fail "on_send did not see the announcement: $line" ;;
esac
case "$line" in
    *'"name":"sender"'*) ok "the announcement names the mailbox it comes from (#506)" ;;
    *) note_fail "the announcement does not carry the sender's own name: $line" ;;
esac
if [ -e "$WORK/receiver/inbox/THEIR-NAME-sender" ]; then
    note_fail "a name the receiver already uses for the sender produced a notice"
fi

echo ""
echo "merge"
if wait_for 10 'grep -q "^sender.ip\[1\] *= *\"\{0,1\}$REWRITTEN" "$R_CONTACTS"'; then
    ok "the receiver merged the hook's rewritten address as ip[1]"
else
    note_fail "the rewritten address is not in the receiver's contacts: $(grep '^sender' "$R_CONTACTS" | tr '\n' ' ')"
fi
if grep -q "^sender.ip *= *\"\{0,1\}localhost" "$R_CONTACTS"; then
    ok "the hostname the receiver held stays its pinned default"
else
    note_fail "the pinned default was replaced: $(grep '^sender.ip' "$R_CONTACTS" | tr '\n' ' ')"
fi
if grep -q "^sender.local-ip *= *\"\{0,1\}$LAN" "$R_CONTACTS"; then
    ok "the sender's local address went to local-ip"
else
    note_fail "no local-ip for the sender: $(grep '^sender' "$R_CONTACTS" | tr '\n' ' ')"
fi
if grep -q "$PUBLIC" "$R_CONTACTS"; then
    note_fail "the address the hook replaced reached the receiver anyway"
else
    ok "the address the hook replaced did not reach the receiver"
fi

echo ""
echo "footer"
echo footer > "$WORK/hook-mode"
printf 'ip = %s\nport = %s\n' "$PUBLIC" "$SENDER_PORT" > "$OWED"
poke 3
if wait_for 30 '[ ! -e "$OWED" ] && grep -q "on_send printed something that is not a JSON object for the announcement to receiver" "$WORK/sender.log"'; then
    ok "a hook printing a footer: logged, and the announcement went as computed"
else
    note_fail "the footer hook's output was not refused, or the announcement did not go"
fi
if wait_for 10 'grep -q "^sender.ip\[[0-9]*\] *= *\"\{0,1\}$PUBLIC" "$R_CONTACTS"'; then
    ok "the computed address reached the receiver: $(grep -c '^sender.ip\[' "$R_CONTACTS") indexed address(es) now"
else
    note_fail "the computed address did not reach the receiver: $(grep '^sender' "$R_CONTACTS" | tr '\n' ' ')"
fi

echo ""
echo "unchanged"
echo plain > "$WORK/hook-mode"
sleep 1
stamp="$(stat -c %Y.%s "$R_CONTACTS" 2>/dev/null)$(md5sum < "$R_CONTACTS")"
sent_before="$(grep -c "notified receiver of address change" "$WORK/sender.log")"
printf 'ip = %s\nport = %s\n' "$PUBLIC" "$SENDER_PORT" > "$OWED"
poke 4
if wait_for 30 '[ "$(grep -c "notified receiver of address change" "$WORK/sender.log")" -gt "$sent_before" ]'; then
    sleep 1
    if [ "$(stat -c %Y.%s "$R_CONTACTS" 2>/dev/null)$(md5sum < "$R_CONTACTS")" = "$stamp" ]; then
        ok "the same set again: the receiver's contacts file was not written"
    else
        note_fail "the receiver rewrote its contacts file for a set that did not change"
    fi
else
    note_fail "the third announcement was not sent"
fi

stop_all
trap - EXIT

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "all cases passed"
    rm -rf "$WORK"
    rm -f $RAM_FILES
    exit 0
fi
echo "$FAILURES case(s) failed; logs kept in $WORK"
exit 1
