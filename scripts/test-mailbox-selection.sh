#!/bin/sh
# test-mailbox-selection.sh — check that a daemon serves the one mailbox it was told to
#
# A machine may hold several rmail mailboxes at once, each with its own
# identity, its own port and its own service.  Which mailbox a given daemon
# serves is decided by exactly one thing: the config file named on its command
# line.  The daemon used to also accept a mailbox directory and go looking for
# a matching config, and that search is what let two mailboxes on one machine
# end up sharing a single service and silently swallowing each other's mail.
#
# This script proves the selection rules still hold.  It builds throwaway
# mailboxes in RAM, starts the real daemon against each one until its log
# says what the case was waiting for, and checks which directory it reports
# serving and what it does with a message whose recipient is ambiguous.
# Nothing here touches a real mailbox or a real network peer; every mailbox
# is empty and every port is in the high 59xxx range that no install uses.
#
# The daemon does look its own public IP up over DNS during startup, before
# it reaches its first outbox sync, so the two ambiguity cases need a working
# network and take roughly ten seconds each.
#
# Usage:
#   scripts/test-mailbox-selection.sh          # use the enclosing checkout
#   scripts/test-mailbox-selection.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/mailbox-selection"

# Longest a daemon is left running before it is stopped regardless.  Only
# reached when the thing being waited for never happens, so it is a failure
# deadline, not a pace: a passing run stops as soon as the log says so.
DEADLINE_SECONDS=40

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail mailbox-selection test"
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
# make_mailbox <dir> <name> <port> [extra-config-line]
#
# Build an empty mailbox and the config that serves it.  The optional fourth
# argument is an extra config line, for the cases that need one.
# There is deliberately no mailbox path among them: a config serves the
# directory it is written into, and that is the whole of the rule.
make_mailbox() {
    _dir="$1"; _name="$2"; _port="$3"; _extra="${4:-}"
    mkdir -p "$_dir/inbox" "$_dir/outbox" "$_dir/.state"
    : > "$_dir/contacts"
    {
        printf 'name = %s\n' "$_name"
        printf 'port = %s\n' "$_port"
        [ -n "$_extra" ] && printf '%s\n' "$_extra"
    } > "$_dir/config"
}

# run_daemon <config-path> <log-path> <await-pattern>
#
# Start the daemon in the background, watch its log until <await-pattern>
# appears, then stop it.  Watching the log beats sleeping a fixed span
# because the two things this script waits for are seconds apart: the
# mailbox path is logged immediately, while the first outbox sync happens
# only after the daemon has looked its public IP up over DNS.  A run that
# never prints the pattern stops at the deadline and fails on the check
# that follows, with the log printed.
run_daemon() {
    _cfg="$1"; _log="$2"; _await="$3"
    : > "$_log"
    "$LAUNCHER" "$_cfg" > "$_log" 2>&1 &
    _pid=$!
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$_await" "$_log" && break
        sleep 1
        _waited=$((_waited + 1))
    done
    # Stopping the daemon is the normal end of every case, so the shell's
    # "Terminated" notice on reaping it is noise that makes a clean run
    # read like a crashed one.  The daemon's own output is in $_log and
    # untouched by this.
    kill "$_pid"
    wait "$_pid" 2>/dev/null
}

# start_daemon / stop_daemon — the same thing split in two, for the one case
# that needs a daemon still running while a second one is started against it.
start_daemon() {
    _cfg="$1"; _log="$2"; _await="$3"
    : > "$_log"
    "$LAUNCHER" "$_cfg" > "$_log" 2>&1 &
    HELD_PID=$!
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$_await" "$_log" && return 0
        sleep 1
        _waited=$((_waited + 1))
    done
    return 1
}

stop_daemon() {
    [ -n "$HELD_PID" ] || return 0
    kill "$HELD_PID"
    wait "$HELD_PID" 2>/dev/null
    HELD_PID=""
}

# --------------------------------------------------------------------------
# Rejections.  Each of these used to be an accepted way to start a daemon, or
# is a shape a stale service file will arrive in.  Every one must stop rather
# than guess.

echo "argument handling"

OUT="$WORK/noarg.log"
"$LAUNCHER" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "usage: rmail.lua <config-file>" "$OUT"; then
    ok "no argument is refused, and the usage names the config form"
else
    note_fail "no argument was not refused with a config-form usage line"
    info "$(head -3 "$OUT")"
fi

make_mailbox "$WORK/dirform" dirform 59351
OUT="$WORK/dirform.log"
"$LAUNCHER" "$WORK/dirform" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "is a directory" "$OUT"; then
    ok "a mailbox directory is refused instead of searched for a config"
else
    note_fail "a mailbox directory was not refused"
    info "$(head -3 "$OUT")"
fi

# The old search looked here second: a config named after the mailbox path
# with the slashes turned into dashes.  Planting one and passing the
# directory must still be refused — finding it would mean the guess is back.
SLUG=$(printf '%s' "$WORK/dirform" | sed 's|^/||; s|/|-|g')
mkdir -p "$WORK/home/.config/rmail"
cp "$WORK/dirform/config" "$WORK/home/.config/rmail/config-$SLUG"
OUT="$WORK/slug.log"
HOME="$WORK/home" "$LAUNCHER" "$WORK/dirform" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "is a directory" "$OUT"; then
    ok "a plantable slug config does not resurrect the directory form"
else
    note_fail "a slug-named config was found from a directory argument"
    info "$(head -3 "$OUT")"
fi

make_mailbox "$WORK/portless" portless 59371
sed -i '/^port = /d' "$WORK/portless/config"
OUT="$WORK/portless.log"
"$LAUNCHER" "$WORK/portless/config" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "'port' is not set" "$OUT"; then
    ok "a config with no port is refused instead of defaulting to 8025"
else
    note_fail "a config with no port was not refused"
    info "$(head -3 "$OUT")"
fi

# 8025 specifically, because that is what the old fallback picked, and on a
# machine that has been running rmail a while it is somebody's real mailbox.
if grep -q "8025" "$OUT"; then
    note_fail "the refusal mentions 8025 — the fallback may still be there"
else
    ok "and does not mention 8025 anywhere"
fi

make_mailbox "$WORK/badport" badport 59372
sed -i 's/^port = .*/port = eighty-twenty-five/' "$WORK/badport/config"
OUT="$WORK/badport.log"
"$LAUNCHER" "$WORK/badport/config" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "is not a number" "$OUT"; then
    ok "a port that is not a number is refused"
else
    note_fail "a non-numeric port was not refused"
    info "$(head -3 "$OUT")"
fi

# --------------------------------------------------------------------------
# Resolution.  Which directory the daemon actually opens.
#
# The mailbox is the config's own directory and cannot be stated any other
# way.  A `mail = ...` line used to say it; the line is gone, because once
# a config always lives in the mailbox it describes, such a line can only
# repeat where it already is or contradict it.

echo ""
echo "mailbox resolution"

make_mailbox "$WORK/plain" plaintest 59353
OUT="$WORK/plain.log"
run_daemon "$WORK/plain/config" "$OUT" "mail dir:"
if grep -q "^.* mail dir: $WORK/plain$" "$OUT"; then
    ok "the mailbox served is the directory the config sits in"
else
    note_fail "the config's own directory was not the mailbox"
    info "$(grep 'mail dir' "$OUT")"
fi

# Run from a working directory that is not the mailbox, because a service
# manager picks the working directory and it will not be this one.  This
# is also the portable drive's case: nothing anywhere records a mount
# point, so there is no mount point to go stale.
if grep -q "mail dir: \." "$OUT"; then
    note_fail "the mailbox resolved relative to the working directory"
fi

# A leftover `mail =` line from the old layout, pointing somewhere else
# entirely.  It must be ignored rather than obeyed — a config that has
# been moved or copied should serve where it is, not where it used to be.
make_mailbox "$WORK/stale" staletest 59354 "mail = /nonexistent/somewhere-else"
OUT="$WORK/stale.log"
run_daemon "$WORK/stale/config" "$OUT" "mail dir:"
if grep -q "^.* mail dir: $WORK/stale$" "$OUT"; then
    ok "a leftover 'mail =' line pointing elsewhere is ignored"
else
    note_fail "a stale 'mail =' line still steered the daemon"
    info "$(grep 'mail dir' "$OUT")"
fi

# --------------------------------------------------------------------------
# Ambiguous recipients.  The daemon decides self-delivery by comparing a
# `to:` name against its self-address word (#394; it used to be the
# mailbox's own name), and that test runs before any contacts lookup.
# When both readings exist, the contact used to lose in silence — the
# message went into our own inbox and the tracking entry was stamped as a
# self-message, so a later rename would not undo it.

echo ""
echo "recipient ambiguity"

make_mailbox "$WORK/ambig" ambigbox 59355 "self_address = kuvalu"
{
    printf 'kuvalu.ip    = "192.0.2.7"\n'
    printf 'kuvalu.port  = 59999\n'
    printf 'kuvalu.token = "test-token-not-a-real-secret"\n'
} > "$WORK/ambig/contacts"
printf 'to: kuvalu\n\nhello from the ambiguity test\n' > "$WORK/ambig/outbox/note.txt"

OUT="$WORK/ambig.log"
run_daemon "$WORK/ambig/config" "$OUT" "ambiguous recipient"

if grep -q "ambiguous recipient 'kuvalu'" "$OUT"; then
    ok "an ambiguous recipient is reported in the log"
else
    note_fail "no ambiguous-recipient line in the log"
    info "$(tail -3 "$OUT")"
fi

if grep -q "AMBIGUOUS RECIPIENT: kuvalu" "$WORK/ambig/outbox/note.txt"; then
    ok "the outbox file is marked, where the person who wrote it will look"
else
    note_fail "the outbox file carries no marker"
    info "$(cat "$WORK/ambig/outbox/note.txt" 2>&1)"
fi

if grep -q "hello from the ambiguity test" "$WORK/ambig/outbox/note.txt"; then
    ok "the message the person wrote is still there"
else
    note_fail "the message body was lost"
fi

if [ -z "$(ls -A "$WORK/ambig/inbox")" ]; then
    ok "nothing was self-delivered behind the contact's back"
else
    note_fail "the message was self-delivered anyway"
    info "inbox holds: $(ls -A "$WORK/ambig/inbox")"
fi

# The guard above must not have cost us plain self-delivery, which is a
# real feature: addressing yourself when no contact shares the word is a
# note to self and still lands in your own inbox.
make_mailbox "$WORK/selfonly" solo 59356 "self_address = me"
printf 'to: me\n\na note to myself\n' > "$WORK/selfonly/outbox/memo.txt"

OUT="$WORK/selfonly.log"
run_daemon "$WORK/selfonly/config" "$OUT" "self-delivered:"

if grep -q "self-delivered: memo.txt" "$OUT"; then
    ok "self-delivery still works when the name is not also a contact"
else
    note_fail "self-delivery broke"
    info "$(tail -3 "$OUT")"
fi

if [ -n "$(ls -A "$WORK/selfonly/inbox")" ]; then
    ok "the note to self reached the inbox"
else
    note_fail "the note to self did not reach the inbox"
fi

if grep -q '"self": *true' "$WORK/selfonly/.state/inbox.json"; then
    ok "and its inbox record carries the self mark, not just a name"
else
    note_fail "the self-delivered inbox record has no self mark"
    info "$(cat "$WORK/selfonly/.state/inbox.json")"
fi

# --------------------------------------------------------------------------
# The mailbox's name is only a label (#394).  Writing it on a `to:` line
# must not deliver anywhere; the file is marked with the word to use.

echo ""
echo "the mailbox name is a label, not an address"

make_mailbox "$WORK/label" labelbox 59359 "self_address = me"
printf 'to: labelbox\n\naddressed to the label\n' > "$WORK/label/outbox/labelled.txt"

OUT="$WORK/label.log"
run_daemon "$WORK/label/config" "$OUT" "this mailbox's label"

if grep -q "NOT AN ADDRESS: labelbox" "$WORK/label/outbox/labelled.txt" \
   && grep -q "write to: me" "$WORK/label/outbox/labelled.txt"; then
    ok "to: <name> is marked, and the marker names the self-address word"
else
    note_fail "to: <name> was not marked with the word to use"
    info "$(cat "$WORK/label/outbox/labelled.txt" 2>&1)"
fi

if [ -z "$(ls -A "$WORK/label/inbox")" ]; then
    ok "and nothing was delivered on a guess"
else
    note_fail "to: <name> was self-delivered"
fi

make_mailbox "$WORK/noself" noselfbox 59360
printf 'to: noselfbox\n\nno self address configured\n' > "$WORK/noself/outbox/n.txt"
OUT="$WORK/noself.log"
run_daemon "$WORK/noself/config" "$OUT" "this mailbox's label"
if grep -q "set self_address in the config" "$WORK/noself/outbox/n.txt"; then
    ok "with no self_address set, the marker says to set one"
else
    note_fail "the no-self_address marker is missing"
    info "$(cat "$WORK/noself/outbox/n.txt" 2>&1)"
fi

make_mailbox "$WORK/badself" badselfbox 59361 "self_address = two words"
OUT="$WORK/badself.log"
"$LAUNCHER" "$WORK/badself/config" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "'self_address'.*must be one word" "$OUT"; then
    ok "a self_address that is not one word stops the daemon"
else
    note_fail "a malformed self_address was accepted"
    info "$(head -3 "$OUT")"
fi

# --------------------------------------------------------------------------
# Mailboxes that self-delivered before #394 hold records that name the old
# self-address (the mailbox name).  They are converted once at startup; with
# no self_address to convert them to, the daemon stops and says what to add.

echo ""
echo "old self-delivery records"

make_old_self_records() {
    _dir="$1"; _name="$2"
    printf 'to: %s\n\nwritten before 394\n' "$_name" > "$_dir/outbox/old.txt"
    printf 'written before 394\n' > "$_dir/inbox/old.txt"
    printf '{"old.txt":{"from":"%s","message_id":"m-old"}}\n' "$_name" \
        > "$_dir/.state/inbox.json"
    printf '{"old.txt":{"recipients":{"%s":{"message_id":"m-old","self":true}}}}\n' "$_name" \
        > "$_dir/.state/outbox.json"
}

make_mailbox "$WORK/oldnoself" oldbox 59362
make_old_self_records "$WORK/oldnoself" oldbox
OUT="$WORK/oldnoself.log"
"$LAUNCHER" "$WORK/oldnoself/config" > "$OUT" 2>&1
if [ $? -ne 0 ] && grep -q "self_address = me" "$OUT"; then
    ok "old records with no self_address stop the daemon with the line to add"
else
    note_fail "old records without self_address did not stop the daemon"
    info "$(head -4 "$OUT")"
fi

make_mailbox "$WORK/oldconv" oldconvbox 59363 "self_address = me"
make_old_self_records "$WORK/oldconv" oldconvbox
OUT="$WORK/oldconv.log"
run_daemon "$WORK/oldconv/config" "$OUT" "idle, interval"
if grep -q "converted 1 inbox and 1 outbox" "$OUT" \
   && grep -q '"self": *true' "$WORK/oldconv/.state/inbox.json" \
   && grep -q "^to: me$" "$WORK/oldconv/outbox/old.txt"; then
    ok "old records are converted: inbox marked, outbox to: line rewritten"
else
    note_fail "old records were not converted"
    info "$(grep -i convert "$OUT")"
    info "$(cat "$WORK/oldconv/outbox/old.txt" 2>&1)"
fi
if [ -f "$WORK/oldconv/inbox/old.txt" ]; then
    ok "and the delivered copy survives the next sync"
else
    note_fail "the converted message was deleted from the inbox"
fi

# --------------------------------------------------------------------------
# The cleanup pass at the end of an outbox sync deletes any file whose
# recipient list has emptied, which normally means every recipient was
# delivered to and struck off.  A file whose `to:` line named nobody
# resolvable arrives at that pass looking exactly the same, and used to be
# deleted — seconds after the daemon had written a marker into it
# explaining the problem.  The person lost the message they had written.
# This is the older and plainer form of the same trap the ambiguity case
# above falls into, so it is checked alongside it.

echo ""
echo "unresolvable recipients are kept, not swept"

make_mailbox "$WORK/unknown" loner 59357
printf 'to: nobody-here\n\nplease do not delete me\n' > "$WORK/unknown/outbox/letter.txt"

OUT="$WORK/unknown.log"
run_daemon "$WORK/unknown/config" "$OUT" "unknown contact"

if [ -f "$WORK/unknown/outbox/letter.txt" ]; then
    ok "a message to an unknown contact survives the cleanup pass"
else
    note_fail "a message to an unknown contact was deleted"
    info "$(grep 'cleaned up' "$OUT")"
fi

if grep -q "UNKNOWN CONTACT: nobody-here" "$WORK/unknown/outbox/letter.txt"; then
    ok "and still carries the marker saying why it went nowhere"
else
    note_fail "the marker did not survive"
fi

# A message that is nothing but a `to:` line — no body, no trailing newline —
# is a legitimate shape: the filename is the subject, so a subject on its own
# says everything some messages need to.  The marker goes in below the `to:`
# line, and with no newline to go below it used to be appended to the end of
# that line instead, leaving `to: nobody-here// UNKNOWN CONTACT: …` for the
# next cycle's header scan to read as a recipient name.
make_mailbox "$WORK/nonewline" terse 59358
printf 'to: nobody-here' > "$WORK/nonewline/outbox/subject-only.txt"

OUT="$WORK/nonewline.log"
run_daemon "$WORK/nonewline/config" "$OUT" "unknown contact"

if grep -q "^to: nobody-here$" "$WORK/nonewline/outbox/subject-only.txt"; then
    ok "a to: line with no newline after it keeps the marker off its end"
else
    note_fail "the marker was glued onto the to: line"
    info "$(cat "$WORK/nonewline/outbox/subject-only.txt")"
fi

# --------------------------------------------------------------------------
# A port collision is the one thing the installer cannot reliably predict —
# it sees what is listening when it runs, and a mailbox that was stopped at
# that moment is invisible to it.  So the daemon is where the collision
# actually surfaces, and it has to surface somewhere the person will look.
# Nothing can arrive while a mailbox is not listening, which makes it
# inbound news, which means the inbox.
#
# Two daemons here rather than one daemon and a borrowed port, so the case
# holds a port it owns and never depends on what else is running.

echo ""
echo "a port that will not bind"

make_mailbox "$WORK/holder" holder 59373
make_mailbox "$WORK/blocked" blocked 59373

if start_daemon "$WORK/holder/config" "$WORK/holder.log" "listening on :59373"; then
    ok "a first daemon holds the port"

    OUT="$WORK/blocked.log"
    "$LAUNCHER" "$WORK/blocked/config" > "$OUT" 2>&1
    _blocked_status=$?
    stop_daemon

    if [ "$_blocked_status" -ne 0 ]; then
        ok "the second daemon stops rather than running portless"
    else
        note_fail "the second daemon did not stop"
    fi

    if grep -q "cannot listen on port 59373" "$OUT"; then
        ok "and says so in plain words, not a Lua assertion"
    else
        note_fail "no plain-words explanation in the log"
        info "$(tail -3 "$OUT")"
    fi

    if [ -f "$WORK/blocked/inbox/CANNOT-LISTEN" ]; then
        ok "and leaves the explanation in its own inbox"
    else
        note_fail "nothing was written to the inbox"
        info "inbox holds: $(ls -A "$WORK/blocked/inbox")"
    fi

    if grep -q "address already in use" "$WORK/blocked/inbox/CANNOT-LISTEN"; then
        ok "naming what the system actually said"
    else
        note_fail "the notice does not carry the system's own message"
    fi

    # The notice is named for the problem, not the port.  Naming it for the
    # port would strand it under the old number the moment somebody fixes
    # the collision by changing ports — a permanent complaint about a
    # solved problem.
    sed -i 's/^port = 59373$/port = 59374/' "$WORK/blocked/config"
    run_daemon "$WORK/blocked/config" "$WORK/blocked2.log" "listening on :59374"
    if [ ! -f "$WORK/blocked/inbox/CANNOT-LISTEN" ]; then
        ok "and withdraws it once the mailbox can listen again"
    else
        note_fail "the notice survived the problem being fixed"
    fi
else
    note_fail "could not start the daemon that holds the port"
    stop_daemon
fi

# --------------------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
