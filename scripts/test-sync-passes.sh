#!/bin/sh
# test-sync-passes.sh — a sync runs in passes, and no record, contact or hook can make it spin (#121, #119)
#
# A sync used to be seven steps run once with the bookkeeping at the end,
# all inside one protected call.  In September 2026 one bad attachment
# record made a step throw on every cycle: the bookkeeping never ran, no
# contact's timer moved, and the daemon logged the same error over a
# million times overnight with no mail going out.  Now a sync runs in
# passes (check, record the plan, act, check the results, record the
# outcome) until a pass plans nothing; a thrown error ends only that pass's
# steps; a contact the world refused is left out for the rest of the sync;
# and a pass that plans exactly what the one before it planned stops the
# sync.
#
# Six throwaway mailboxes in RAM, each a real daemon, one case each.  The
# recipients are stand-ins (scripts/lib/fake-recipient.lua), and the test
# speaks for them through scripts/lib/fake-contact.lua.
#
#   thrower    a planted transfer record that throws: one log entry per
#              sync with the whole traceback, the sync stops after the
#              second pass meets the same error, and the next sync comes
#              at the ordinary cadence, not back to back
#   sender     a contact that refuses (nothing listens on its port): one
#              report in the outbox naming every address tried and what
#              each got; the other contact still gets its message in the
#              same sync; the stored failures and the log are in
#              /tmp/rmail-progress/ and nothing is written to
#              .state/rmail.log; once the contact answers, the report
#              and its stored failure go
#   offerer    a consent that arrives while a sync waits: the pieces go
#              out in a later pass of that same sync
#   repeater   a recipient that says ok to a piece yet keeps asking for it:
#              the sync stops with the repeated-plan line
#   hooked     an on_send hook that writes a second outbox file during a
#              sync: delivered in the next pass of that sync (#119)
#   ticker     the scripting tutorial's periodic: an on_update hook that
#              rewrites its own outbox file every time it runs starts no
#              sync of its own, so syncs never run back to back
#
# Usage:
#   scripts/test-sync-passes.sh          # use the enclosing checkout
#   scripts/test-sync-passes.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/sync-passes"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-sync-passes-*"
TOKEN="sync-passes-token-not-a-real-secret"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ wait_until
# wait_until <seconds> <shell test> — 0 once it holds, 1 at the deadline;
# sets $waited (tenths of a second)
wait_until() {
    waited=0
    while [ "$waited" -lt "$(($1 * 10))" ]; do
        eval "$2" && return 0
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}
secs() { printf '%d.%d' $(($1 / 10)) $(($1 % 10)); }
# }}}

# {{{ make_mailbox
# make_mailbox <name> <port> [extra config line] — an empty mailbox
make_mailbox() {
    mkdir -p "$WORK/$1/inbox" "$WORK/$1/outbox" "$WORK/$1/.state" "$WORK/$1/attachments" "$WORK/$1/files"
    printf 'name = %s\nport = %s\nattachment_chunk_size = 16384\nattachment_pending_dir = %s\n%s\n' \
        "$1" "$2" "$WORK/$1/pending" "$3" > "$WORK/$1/config"
    : > "$WORK/$1/contacts"
}
# add_contact <mailbox> <contact> <port>
add_contact() {
    printf '%s.ip    = "127.0.0.1"\n%s.port  = %s\n%s.token = "%s"\n\n' "$2" "$2" "$3" "$2" "$TOKEN-$2" \
        >> "$WORK/$1/contacts"
}
# start <mailbox> — the daemon, in the background; its pid in $PID_<mailbox>
start() {
    "$LAUNCHER" "$WORK/$1/config" > "$WORK/$1.log" 2>&1 &
    eval "PID_$1=\$!"
}
stop() {
    eval "kill \$PID_$1; wait \$PID_$1 2>/dev/null"
}
# recipient <name> <port> — a stand-in, in the background
recipient() {
    mkdir -p "$WORK/$1"
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$2" "$TOKEN-$1" "$WORK/$1" \
        > "$WORK/$1.out" 2>&1 &
}
# }}}

# {{{ say
# say <as contact> <to port> <JSON> — that contact posts this to /deliver
say() {
    "$LUA" - "$DIR" "$2" "$TOKEN-$1" "$3" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local me = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
print(me:request("POST", "/deliver", arg[4]))
LUA
}
# offer_id <recipient> <file name> — the attachment id it was offered for it
offer_id() {
    "$LUA" - "$DIR" "$WORK/$1/events" "$2" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do
    local e = json.decode(line)
    if e and e.kind == "request" and e.filename == arg[3] then print(e.id) break end
end
f:close()
LUA
}
count() { grep -c "$2" "$WORK/$1.log"; }
# }}}

echo ""
echo "rmail sync-passes test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LAUNCHER" ]; then note_fail "no launcher at $LAUNCHER"; exit 1; fi
rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES

# ---------------------------------------------------------------------------
echo ""
echo "a planted record that throws"
make_mailbox thrower 59570
add_contact thrower far-away 59579
printf 'stands in for a compressed copy\n' > "$WORK/thrower/files/copy.zip"
# total_chunks is text: working out how many answers to wait for throws
cat > "$WORK/thrower/.state/chunks-outgoing.json" <<EOF
{
  "att-that-throws": {
    "filename": "picture.jpg",
    "original_path": "$WORK/thrower/files/copy.zip",
    "compressed_path": "$WORK/thrower/files/copy.zip",
    "status": "sending",
    "total_chunks": "not a number",
    "missing": [0],
    "total_checksum": "0000000000000000000000000000000000000000000000000000000000000000",
    "expected_size": 31,
    "message_id": "msg-that-throws",
    "to": "far-away",
    "outbox_file": "letter"
  }
}
EOF
start thrower
sleep 20
stop thrower
errors=$(count thrower "sync error in pass")
if [ "$errors" -ge 1 ] && [ "$errors" -le 3 ]; then
    ok "$errors sync error entries in 20 s: each sync logged it once and the next came at the ordinary cadence"
else
    note_fail "$errors sync error entries in 20 s (a spinning loop logs hundreds; none means it never threw)"
fi
if grep -A30 -m1 "sync error in pass" "$WORK/thrower.log" | grep -q "stack traceback:" \
    && grep -A30 -m1 "sync error in pass" "$WORK/thrower.log" | grep -q "send_next_chunks\|run_steps"; then
    ok "the entry carries the whole traceback, naming the callers"
else
    note_fail "no traceback naming the callers: $(grep -A6 -m1 'sync error' "$WORK/thrower.log" | tr '\n' ' ')"
fi
if grep -q "at the attachment pieces step" "$WORK/thrower.log"; then
    ok "it names the step that threw"
else
    note_fail "the step that threw is not named"
fi
if grep -q "sync stopped: pass 2 planned exactly what pass 1 planned, and met the same error" "$WORK/thrower.log"; then
    ok "the second pass met the same error and the sync stopped"
else
    note_fail "no repeated-plan stop after the same error"
fi
if [ "$(grep -c "stack traceback:" "$WORK/thrower.log")" -eq "$errors" ]; then
    ok "one traceback per sync, not one per pass"
else
    note_fail "$(grep -c "stack traceback:" "$WORK/thrower.log") tracebacks for $errors entries"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a contact that refuses, beside one that answers"
make_mailbox sender 59571
add_contact sender alice 59572
add_contact sender nobody 59573
printf 'to: alice\n\nfor alice\n' > "$WORK/sender/outbox/to-alice"
printf 'to: nobody\n\nfor nobody\n' > "$WORK/sender/outbox/to-nobody"
recipient alice 59572
start sender
REPORT="$WORK/sender/outbox/CANNOT-REACH-nobody"
FAILS="/tmp/rmail-progress/failures-tmp-rmail-tests-sync-passes-sender"
if wait_until 20 '[ -f "$WORK/alice/inbox/to-alice" ] && [ -f "$REPORT" ]'; then
    ok "alice got her message and nobody has a report (after $(secs $waited)s)"
else
    note_fail "alice's message: $(ls "$WORK/alice/inbox" 2>/dev/null); report: $(ls "$REPORT" 2>/dev/null)"
fi
sleep 1
first_done=$(grep -m1 "sync done" "$WORK/sender.log")
case "$first_done" in
    *"2 requests"*) ok "both were tried in the first sync ($first_done)" ;;
    *) note_fail "the first sync did not try both: $first_done" ;;
esac
if grep -q "127.0.0.1 port 59573: connection refused" "$REPORT" 2>/dev/null \
    && grep -q "to-nobody" "$REPORT" 2>/dev/null; then
    ok "the report names the address tried, what it got, and what is queued"
else
    note_fail "the report is: $(cat "$REPORT" 2>/dev/null)"
fi
if grep -q '"contact": *"nobody"' "$FAILS" 2>/dev/null && grep -q '"count"' "$FAILS"; then
    ok "the failure is stored in /tmp/rmail-progress/"
else
    note_fail "no stored failure at $FAILS"
fi
if [ -s /tmp/rmail-progress/log-tmp-rmail-tests-sync-passes-sender ] && [ ! -e "$WORK/sender/.state/rmail.log" ]; then
    ok "the log is in /tmp/rmail-progress/ and nothing is written to .state/rmail.log"
else
    note_fail "log in RAM: $(ls /tmp/rmail-progress/log-tmp-rmail-tests-sync-passes-sender 2>&1); .state: $(ls "$WORK/sender/.state")"
fi
if grep -q "skipping CANNOT-REACH" "$WORK/sender.log"; then
    note_fail "the report was read as a message to send"
else
    ok "the report is not read as a message to send"
fi
# nobody comes up and says something: they are tried at once
recipient nobody 59573
sleep 1
say nobody 59571 '{"type":"chunk_failed"}' > /dev/null
if wait_until 20 '[ -f "$WORK/nobody/inbox/to-nobody" ] && [ ! -f "$REPORT" ]'; then
    ok "once nobody answered, they got the message and the report went (after $(secs $waited)s)"
else
    note_fail "nobody's message: $(ls "$WORK/nobody/inbox" 2>/dev/null); report still there: $(ls "$REPORT" 2>/dev/null)"
fi
if grep -q '"nobody"' "$FAILS" 2>/dev/null; then
    note_fail "the stored failure for nobody is still there"
else
    ok "and the stored failure went"
fi
stop sender

# ---------------------------------------------------------------------------
echo ""
echo "a consent that arrives while a sync waits"
make_mailbox offerer 59574
add_contact offerer bea 59575
add_contact offerer slow 59576
head -c 20000 /dev/urandom > "$WORK/offerer/files/for-slow.bin"
head -c 40000 /dev/urandom > "$WORK/offerer/files/for-bea.bin"
printf 'to: slow\nattach: %s\n\nfor slow\n' "$WORK/offerer/files/for-slow.bin" > "$WORK/offerer/outbox/x"
printf 'to: bea\nattach: %s\n\nfor bea\n' "$WORK/offerer/files/for-bea.bin" > "$WORK/offerer/outbox/y"
recipient bea 59575
recipient slow 59576
start offerer
if wait_until 20 '[ -n "$(offer_id slow for-slow.bin)" ] && [ -n "$(offer_id bea for-bea.bin)" ]'; then
    ok "both were offered their files"
else
    note_fail "the offers never came"
fi
sleep 1
# slow will hold its answer to the first piece for 6 s; bea's yes comes
# while the offerer waits on it
printf '6\n' > "$WORK/slow/hold"
say slow 59574 "{\"type\":\"attachment_response\",\"attachment_id\":\"$(offer_id slow for-slow.bin)\",\"consent\":true}" > /dev/null
if wait_until 20 '[ -f "$WORK/slow/holding" ]'; then
    before=$(count offerer "sync done")
    say bea 59574 "{\"type\":\"attachment_response\",\"attachment_id\":\"$(offer_id bea for-bea.bin)\",\"consent\":true}" > /dev/null
    if wait_until 30 'ls "$WORK/bea/received/"*.zip >/dev/null 2>&1'; then
        sleep 2
        after=$(count offerer "sync done")
        line=$(grep "sync done" "$WORK/offerer.log" | sed -n "$((before + 1))p")
        case "$(( after - before )):$line" in
            1:*"3 passes"*) ok "bea got her file in a later pass of the sync that was waiting ($line)" ;;
            *) note_fail "bea's file took $((after - before)) syncs: $line" ;;
        esac
    else
        note_fail "bea never got her file"
    fi
else
    note_fail "slow was never asked for a piece"
fi
stop offerer

# ---------------------------------------------------------------------------
echo ""
echo "a recipient that keeps asking for the same piece"
make_mailbox repeater 59577
add_contact repeater owing 59578
printf 'stands in for a compressed copy\n' > "$WORK/repeater/files/copy.zip"
cat > "$WORK/repeater/.state/chunks-outgoing.json" <<EOF
{
  "att-owed": {
    "filename": "picture.jpg",
    "original_path": "$WORK/repeater/files/copy.zip",
    "compressed_path": "$WORK/repeater/files/copy.zip",
    "status": "sending",
    "total_chunks": 1,
    "missing": [0],
    "total_checksum": "0000000000000000000000000000000000000000000000000000000000000000",
    "expected_size": 31,
    "message_id": "msg-owed",
    "to": "owing",
    "outbox_file": "letter"
  }
}
EOF
mkdir -p "$WORK/owing"; : > "$WORK/owing/owe"
recipient owing 59578
start repeater
if wait_until 20 'grep -q "sync stopped" "$WORK/repeater.log"'; then
    line=$(grep -m1 "sync stopped" "$WORK/repeater.log")
    case "$line" in
        *"pass 2 planned exactly what pass 1 planned: attachment pieces: attachment_chunk to owing (picture.jpg) piece 0"*)
            ok "the sync stopped on the repeated plan, naming it" ;;
        *) note_fail "stopped, but said: $line" ;;
    esac
else
    note_fail "no repeated-plan stop"
fi
sleep 5
stop repeater
stops=$(count repeater "sync stopped")
if [ "$stops" -le 2 ]; then
    ok "$stops stop(s) in about 6 s: no loop"
else
    note_fail "$stops stops in about 6 s"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a hook that writes a second outbox file during a sync (#119)"
make_mailbox hooked 59580 "on_send = $WORK/hooked/on-send"
add_contact hooked cal 59581
cat > "$WORK/hooked/on-send" <<EOF
#!/bin/sh
# on_send <recipient> <subject> <body>: writes one more message, once
if [ "\$2" = first ] && [ ! -e "$WORK/hooked/outbox/second" ]; then
    printf 'to: cal\n\nwritten by the hook\n' > "$WORK/hooked/outbox/second"
fi
printf '%s' "\$3"
EOF
chmod +x "$WORK/hooked/on-send"
printf 'to: cal\n\nthe first\n' > "$WORK/hooked/outbox/first"
recipient cal 59581
start hooked
if wait_until 20 '[ -f "$WORK/cal/inbox/first" ]'; then
    if wait_until 5 '[ -f "$WORK/cal/inbox/second" ]'; then
        ok "the hook's message arrived $(secs $waited)s after the first, no timer wait"
    else
        note_fail "the hook's message did not arrive within 5 s of the first"
    fi
    sleep 1
    line=$(grep -m1 "sync done" "$WORK/hooked.log")
    case "$line" in
        *"3 passes"*) ok "in the next pass of the same sync ($line)" ;;
        *) note_fail "not in the same sync: $line" ;;
    esac
else
    note_fail "the first message never arrived"
fi
stop hooked

# ---------------------------------------------------------------------------
echo ""
echo "a hook that rewrites its own outbox file every time (the tutorial's periodic)"
make_mailbox ticker 59582 "on_update = $WORK/ticker/on-update"
cat > "$WORK/ticker/on-update" <<EOF
#!/bin/sh
# on_update <sender> <inbox path> <body>: count, and rewrite the outbox file
n=\$(printf '%s' "\$3" | sed -n 's/^ticks: //p')
printf 'ticks: %s\n' "\$n"
printf 'to: ticker\n\nticks: %s\n' "\$((n + 1))" > "$WORK/ticker/outbox/heartbeat"
EOF
chmod +x "$WORK/ticker/on-update"
printf 'to: ticker\n\nticks: 0\n' > "$WORK/ticker/outbox/heartbeat"
start ticker
wait_until 20 '[ -f "$WORK/ticker/inbox/heartbeat" ]'
# one edit by hand starts it ticking
printf 'to: ticker\n\nticks: 1\n' > "$WORK/ticker/outbox/heartbeat"
sleep 10
stop ticker
ticks=$(count ticker "self-updated")
if [ "$ticks" -ge 1 ] && [ "$ticks" -le 3 ]; then
    ok "$ticks update(s) in 10 s: the edit fired the hook, and the hook's own rewrite started no sync"
else
    note_fail "$ticks updates in 10 s (syncs back to back give hundreds; none means the hook never ran)"
fi

for d in "$WORK"/*/; do touch "$d/stop"; done
sleep 1
rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "logs: $WORK/*.log"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
