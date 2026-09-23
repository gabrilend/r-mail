#!/bin/sh
# test-outbox-headers.sh — check how the daemon reads the top of an outbox message
#
# A message waiting to be sent is a plain text file in the outbox folder.  Its
# first lines are a small header: one `to:` line per recipient and one
# `attach:` line per file to send along, followed by the message itself.
# Because people write these files by hand, the header has to cope with the
# ways people actually write:
#
#   wildcards     `attach: ~/photos/trip/*.jpg` should mean "every .jpg in
#                 that folder", the way it would at a shell prompt.  The
#                 daemon replaces such a line with one line per file it
#                 matched, in alphabetical order, leaving out hidden files
#                 and folders, and says in its log how many it found.  A
#                 wildcard that matches nothing, or that it cannot expand,
#                 stays in the file untouched with one warning in the log.
#   blank lines   a blank line between `to:` and `attach:` used to end the
#                 header early, so the attach line was sent as message text
#                 and no file ever went.  Blank lines are now allowed
#                 anywhere in the header and are kept as written.
#   missing files an `attach:` naming a file that is not there used to be
#                 dropped without a word.  The daemon now writes a
#                 `// MISSING ATTACHMENT:` note under that line, once, so
#                 the person who wrote the message sees it where they look,
#                 and removes the note again once the file turns up.
#   quotes        people quote paths out of shell habit:
#                 `attach: "/music/CD 1/song.mp3"`.  One layer of quotes
#                 should be taken off, as the contacts file already does.
#
# This script builds throwaway mailboxes in RAM, each with one contact at an
# address reserved for documentation (192.0.2.7) that never answers, writes
# outbox messages that exercise one of the above, runs the real daemon until
# its log shows the sync it waits for, and then reads the outbox files and
# saved state to see what the daemon did.  Only the sender's side is under
# test; nothing is ever delivered.  All mailboxes run at once, on ports
# 59400-59419, which no install uses.
#
# Usage:
#   scripts/test-outbox-headers.sh          # use the enclosing checkout
#   scripts/test-outbox-headers.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/outbox-headers"

# The daemon keeps each mailbox's log and transfers file in the machine-wide
# RAM folder /tmp/rmail-progress/, named after the mailbox path with its
# slashes turned into dashes.  That folder is shared with real mailboxes, so
# this run's files are cleared at the start (a previous run's must not be
# read as this one's) and at the end (they must not be left beside the real
# ones).
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-outbox-headers-"

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
echo "rmail outbox-header test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES*

# --------------------------------------------------------------------------
# make_sender <dir> <port>
#
# A mailbox with one contact, "far-away", at an address nothing answers on,
# a home folder of its own (so `~` in an attach: line points somewhere this
# script controls) and one plain message to far-away.  That plain message is
# always sendable, so every sync ends by logging far-away as unreachable —
# the line each case waits for, meaning "one full sync has finished".
make_sender() {
    _dir="$1"; _port="$2"
    mkdir -p "$_dir/inbox" "$_dir/outbox" "$_dir/.state" "$_dir/home"
    {
        printf 'far-away.ip    = "192.0.2.7"\n'
        printf 'far-away.port  = 59999\n'
        printf 'far-away.token = "test-token-not-a-real-secret"\n'
    } > "$_dir/contacts"
    {
        printf 'name = sender\n'
        printf 'port = %s\n' "$_port"
        # Compressed copies of attachments go here instead of /tmp, so
        # the whole run stays inside the scratch folder.
        printf 'attachment_pending_dir = %s\n' "$_dir/pending"
    } > "$_dir/config"
    printf 'to: far-away\n\njust saying hello\n' > "$_dir/outbox/plain.txt"
}

# make_pics <folder>
#
# The set of files the wildcard cases match against.  Each one is there to
# be either included or left out for a stated reason.
make_pics() {
    _p="$1"
    mkdir -p "$_p/sub.jpg" "$_p/real-folder"
    printf 'a\n' > "$_p/a.jpg"
    printf 'b\n' > "$_p/b.jpg"
    printf 'c\n' > "$_p/c with space.jpg"      # a space must survive intact
    printf 'h\n' > "$_p/.hidden.jpg"           # hidden: left out
    printf 'n\n' > "$_p/notes.txt"             # wrong extension: left out
    printf 't\n' > "$_p/target-elsewhere"
    ln -s "$_p/target-elsewhere" "$_p/link.jpg"   # link to a file: followed
    ln -s "$_p/real-folder" "$_p/dirlink.jpg"     # link to a folder: a folder
}

# plant_delivered <dir> <outbox-name>
#
# Record that the message <outbox-name> has already reached far-away, so
# the daemon treats its attach: lines as new attachments to send to an
# existing recipient — the second of the two places attachments are queued.
plant_delivered() {
    cat > "$1/.state/outbox.json" <<EOF
{
  "$2": {
    "recipients": {
      "far-away": { "message_id": "msg-under-test" }
    }
  }
}
EOF
}

# run_case <name> <port> <await-pattern> [then-hook]
#
# Start the daemon in the background with HOME pointed at the mailbox's own
# home folder, and stop it once <await-pattern> shows up in its log, or at
# the deadline.  If a fourth argument is given it names a shell function
# run after the first wait, while the daemon is still running; it does its
# own waiting.  Runs in its own background job so the cases share the wait
# for DNS instead of taking turns.
run_case() {
    _name="$1"; _port="$2"; _await="$3"; _then="${4:-}"
    _log="$WORK/$_name.log"
    : > "$_log"
    HOME="$WORK/$_name/home" "$LAUNCHER" "$WORK/$_name/config" > "$_log" 2>&1 &
    _pid=$!
    wait_for_log "$_log" "$_await"
    [ -n "$_then" ] && "$_then"
    # Give the cycle that printed the line a moment to finish, and any
    # follow-up cycle its own file writes set off a moment to run, so a
    # duplicate marker or a crash still lands before anything is read.
    sleep 3
    kill "$_pid"
    wait "$_pid" 2>/dev/null
}

wait_for_log() {
    _w=0
    while [ "$_w" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$2" "$1" && return 0
        sleep 1
        _w=$((_w + 1))
    done
    return 1
}

# --------------------------------------------------------------------------
# Wildcards that expand.

C=glob-basic
make_sender "$WORK/$C" 59400
make_pics "$WORK/$C/home/pics"
P="$WORK/$C/home/pics"
printf 'to: far-away\nattach: ~/pics/*.jpg\n\nstar body\n' > "$WORK/$C/outbox/star.txt"
printf 'to: far-away\nattach: %s/[ab].jp?\n\nclass body\n' "$P" > "$WORK/$C/outbox/class.txt"
printf 'to: far-away\nattach: %s/a.jpg\n\nliteral body\n' "$P" > "$WORK/$C/outbox/literal.txt"
cp "$WORK/$C/outbox/literal.txt" "$WORK/$C/literal.before"

# Wildcards that cannot or do not expand.  Each stays in the file as written.
C=glob-unexpanded
make_sender "$WORK/$C" 59401
make_pics "$WORK/$C/home/pics"
P="$WORK/$C/home/pics"
printf 'to: far-away\nattach: %s/*.png\nattach: %s/a.jpg\n\nnomatch body\n' "$P" "$P" \
    > "$WORK/$C/outbox/nomatch.txt"
printf 'to: far-away\nattach: pics/*.jpg\n\nrelative body\n' > "$WORK/$C/outbox/relative.txt"
printf 'to: far-away\nattach: %s/p*/a.jpg\n\ndirglob body\n' "$WORK/$C/home" \
    > "$WORK/$C/outbox/dirglob.txt"

# A wildcard matching a file already on its way: no second copy is queued.
C=in-flight
make_sender "$WORK/$C" 59402
mkdir -p "$WORK/$C/pics"
printf 'a\n' > "$WORK/$C/pics/a.jpg"
printf 'b\n' > "$WORK/$C/pics/b.jpg"
printf 'stands in for a compressed copy\n' > "$WORK/$C/copy.zip"
printf 'to: far-away\nattach: %s/pics/*.jpg\n\nbatch body\n' "$WORK/$C" > "$WORK/$C/outbox/batch.txt"
plant_delivered "$WORK/$C" batch.txt
cat > "$WORK/$C/.state/chunks-outgoing.json" <<EOF
{
  "att-already-going": {
    "filename": "a.jpg",
    "original_path": "$WORK/$C/pics/a.jpg",
    "compressed_path": "$WORK/$C/copy.zip",
    "status": "awaiting_consent",
    "request_sent": true,
    "total_chunks": 1,
    "total_checksum": "0000000000000000000000000000000000000000000000000000000000000000",
    "expected_size": 2,
    "message_id": "msg-under-test",
    "to": "far-away",
    "outbox_file": "batch.txt"
  }
}
EOF

# Blank lines inside the header.  gap.txt is the April 2026 message: a blank
# line after `to:`, then an attach: naming a file not there yet.  Only if
# the attach: line is read as a header line can it be marked missing.
C=blank-lines
make_sender "$WORK/$C" 59403
mkdir -p "$WORK/$C/files"
printf 'one\n' > "$WORK/$C/files/one.txt"
printf 'to: far-away\n\nattach: %s/files/late.jpg\n\ngap body\n' "$WORK/$C" \
    > "$WORK/$C/outbox/gap.txt"
printf 'to: far-away\n\n\nattach: %s/files/never.jpg\n\n' "$WORK/$C" \
    > "$WORK/$C/outbox/header-only.txt"
printf 'to: far-away\n\n   \nattach: %s/files/*.txt\n\nglob body\n' "$WORK/$C" \
    > "$WORK/$C/outbox/gap-glob.txt"

# Once gap.txt is marked, the file turns up.  A new outbox message sets off
# the next sync straight away instead of waiting on far-away's retry timer.
blank_lines_then() {
    wait_for_log "$WORK/blank-lines.log" "file not found: $WORK/blank-lines/files/late.jpg"
    printf 'late\n' > "$WORK/blank-lines/files/late.jpg"
    printf 'to: far-away\n\nnudge\n' > "$WORK/blank-lines/outbox/nudge.txt"
    wait_for_log "$WORK/blank-lines.log" "cleared its missing-attachment marker"
}

# A missing file on a message already delivered: marked once, never queued.
C=missing-delivered
make_sender "$WORK/$C" 59404
printf 'to: far-away\nattach: %s/gone.jpg\n\nlater body\n' "$WORK/$C" > "$WORK/$C/outbox/later.txt"
plant_delivered "$WORK/$C" later.txt

# A missing file written with `~`, as people do.
C=missing-tilde
make_sender "$WORK/$C" 59405
printf 'to: far-away\nattach: ~/nothing-here.jpg\n\ntilde body\n' > "$WORK/$C/outbox/tilde.txt"

# Quoted paths.
C=quotes
make_sender "$WORK/$C" 59406
mkdir -p "$WORK/$C/files"
printf 's\n' > "$WORK/$C/files/with space.jpg"
Q="$WORK/$C/files"
printf 'to: far-away\nattach: "%s/with space.jpg"\n\ndq body\n' "$Q" > "$WORK/$C/outbox/dq.txt"
printf "to: far-away\nattach: '%s/with space.jpg'\n\nsq body\n" "$Q" > "$WORK/$C/outbox/sq.txt"
printf 'to: far-away\nattach: "%s/*.jpg"\n\nqglob body\n' "$Q" > "$WORK/$C/outbox/qglob.txt"
printf 'to: far-away\nattach: "%s/nope.jpg"\n\nqmissing body\n' "$Q" > "$WORK/$C/outbox/qmissing.txt"

UNREACH="unreachable contacts this cycle"
echo "running seven mailboxes at once (up to ${DEADLINE_SECONDS}s, longer for the two-step case)"
run_case glob-basic        59400 "$UNREACH" &
run_case glob-unexpanded   59401 "$UNREACH" &
run_case in-flight         59402 "$UNREACH" &
run_case blank-lines       59403 "$UNREACH" blank_lines_then &
run_case missing-delivered 59404 "$UNREACH" &
run_case missing-tilde     59405 "$UNREACH" &
run_case quotes            59406 "$UNREACH" &
wait

rm -f $RAM_FILES*

# --------------------------------------------------------------------------
# Checks.

no_crash() {
    if grep -q "sync error" "$WORK/$1.log"; then
        note_fail "$1: a sync cycle crashed"
        info "$(grep -m1 'sync error' "$WORK/$1.log")"
    else
        ok "$1: no sync cycle crashed"
    fi
}

# attach_lines <file> — the attach: lines of an outbox file, in order.
attach_lines() { grep '^attach:' "$1"; }

show() { info "$(sed 's/^/  | /' "$1")"; }

echo ""
echo "wildcards that expand"
C=glob-basic; P="$WORK/$C/home/pics"; F="$WORK/$C/outbox/star.txt"
no_crash $C
EXPECT=$(printf 'attach: %s\n' "$P/a.jpg" "$P/b.jpg" "$P/c with space.jpg" "$P/link.jpg")
GOT=$(attach_lines "$F" | grep -v dirlink)
if [ "$GOT" = "$EXPECT" ]; then
    ok "~/pics/*.jpg became one line per file, sorted, space kept, link followed"
else
    note_fail "~/pics/*.jpg did not expand as expected"
    show "$F"
fi
if grep -q 'hidden\|notes.txt\|sub.jpg' "$F"; then
    note_fail "a hidden file, a non-match or a folder was included"
else
    ok "hidden files, non-matches and folders were left out"
fi
if grep -q 'dirlink.jpg' "$F"; then
    note_fail "a link to a folder was attached as though it were a file"
else
    ok "a link to a folder was left out like a folder"
fi
if grep -q '^star body$' "$F"; then
    ok "the message text is untouched"
else
    note_fail "the message text was lost"
fi
if grep -q 'attach: expanded ~/pics/\*.jpg -> [0-9]* file(s) in star.txt' "$WORK/$C.log"; then
    ok "the log says how many files the wildcard matched"
else
    note_fail "no expansion count in the log"
fi
EXPECT=$(printf 'attach: %s\n' "$P/a.jpg" "$P/b.jpg")
if [ "$(attach_lines "$WORK/$C/outbox/class.txt")" = "$EXPECT" ]; then
    ok "[ab].jp? matched a.jpg and b.jpg only"
else
    note_fail "[ab].jp? did not expand as expected"
    show "$WORK/$C/outbox/class.txt"
fi
if cmp -s "$WORK/$C/literal.before" "$WORK/$C/outbox/literal.txt"; then
    ok "a path with no wildcard leaves the file byte-for-byte as written"
else
    note_fail "a file with no wildcard was rewritten"
    show "$WORK/$C/outbox/literal.txt"
fi

echo ""
echo "wildcards that do not expand"
C=glob-unexpanded; P="$WORK/$C/home/pics"
no_crash $C
if grep -q "^attach: $P/\*.png$" "$WORK/$C/outbox/nomatch.txt" \
   && grep -q "attach: no files match $P/\*.png (nomatch.txt)" "$WORK/$C.log"; then
    ok "a wildcard matching nothing stays in the file and is named in the log"
else
    note_fail "a zero-match wildcard was not kept and logged"
    show "$WORK/$C/outbox/nomatch.txt"
fi
if [ "$(grep -c 'no files match' "$WORK/$C.log")" -eq 1 ]; then
    ok "and is warned about once, not every sync"
else
    note_fail "the zero-match warning repeated: $(grep -c 'no files match' "$WORK/$C.log") times"
fi
if grep -q "^attach: $P/a.jpg$" "$WORK/$C/outbox/nomatch.txt"; then
    ok "the message's other attach: line is still there"
else
    note_fail "the other attach: line was lost"
fi
if grep -q '^attach: pics/\*.jpg$' "$WORK/$C/outbox/relative.txt" \
   && grep -q 'glob pattern must be absolute or ~-anchored: pics/\*.jpg' "$WORK/$C.log"; then
    ok "a relative wildcard is refused in the log and left as written"
else
    note_fail "a relative wildcard was not refused"
fi
if grep -q "^attach: $WORK/$C/home/p\*/a.jpg$" "$WORK/$C/outbox/dirglob.txt" \
   && grep -q 'glob in directory component not supported' "$WORK/$C.log"; then
    ok "a wildcard in a folder name is refused in the log and left as written"
else
    note_fail "a folder-name wildcard was not refused"
fi

echo ""
echo "a wildcard over a file already being sent"
C=in-flight; S="$WORK/$C/.state/chunks-outgoing.json"
no_crash $C
# The daemon saves state without a space after the colon; the planted
# record has one.  Either form is accepted.
if [ "$(grep -c "\"original_path\": *\"$WORK/$C/pics/a.jpg\"" "$S")" -eq 1 ]; then
    ok "the file already on its way was not queued a second time"
else
    note_fail "a.jpg has $(grep -c "pics/a.jpg" "$S") transfer records"
    info "$(cat "$S")"
fi
if grep -q "\"original_path\": *\"$WORK/$C/pics/b.jpg\"" "$S"; then
    ok "the new match was queued"
else
    note_fail "b.jpg was not queued"
    info "$(cat "$S")"
fi

echo ""
echo "blank lines inside the header"
C=blank-lines; F="$WORK/$C/outbox/gap.txt"
no_crash $C
if grep -q "attach: file not found: $WORK/$C/files/late.jpg (in gap.txt)" "$WORK/$C.log"; then
    ok "an attach: line after a blank line is still read as an attachment"
else
    note_fail "the attach: line after a blank line was not read as a header"
fi
if grep -q "attach: file not found: $WORK/$C/files/never.jpg (in header-only.txt)" "$WORK/$C.log"; then
    ok "so is one in a message that is all header and no text"
else
    note_fail "a header-only message with blank lines was not read"
fi
if grep -q "cleared its missing-attachment marker" "$WORK/$C.log" \
   && ! grep -q "MISSING ATTACHMENT: $WORK/$C/files/late.jpg" "$F"; then
    ok "the note was taken away once the file turned up"
else
    note_fail "the missing-file note outlived the problem"
    show "$F"
fi
if [ "$(sed -n 2p "$F")" = "" ] && grep -q '^gap body$' "$F"; then
    ok "the blank line and the message text are kept as written"
else
    note_fail "the file was reformatted"
    show "$F"
fi
G="$WORK/$C/outbox/gap-glob.txt"
if grep -q "^attach: $WORK/$C/files/one.txt$" "$G" && [ "$(sed -n 3p "$G")" = "   " ]; then
    ok "a wildcard after blank and space-only lines expands, and they stay"
else
    note_fail "a wildcard after blank lines did not expand in place"
    show "$G"
fi

echo ""
echo "a missing file on a message already delivered"
C=missing-delivered; F="$WORK/$C/outbox/later.txt"
no_crash $C
if [ "$(sed -n 3p "$F" | cut -c1-21)" = "// MISSING ATTACHMENT" ]; then
    ok "a note is written on the line right under the attach: line"
else
    note_fail "no note under the attach: line"
    show "$F"
fi
if [ "$(grep -c 'MISSING ATTACHMENT' "$F")" -eq 1 ] \
   && [ "$(grep -c 'attach: file not found' "$WORK/$C.log")" -eq 1 ]; then
    ok "once in the file and once in the log, across repeated syncs"
else
    note_fail "the note or the log line repeated"
    show "$F"
fi
# No transfers file at all is the plainest form of "nothing queued".
if [ -f "$WORK/$C/.state/chunks-outgoing.json" ] \
   && grep -q "gone.jpg" "$WORK/$C/.state/chunks-outgoing.json"; then
    note_fail "a transfer was queued for a file that is not there"
else
    ok "nothing was queued for it"
fi

echo ""
echo "a missing file written with ~"
C=missing-tilde; F="$WORK/$C/outbox/tilde.txt"
no_crash $C
if grep -q "MISSING ATTACHMENT" "$F"; then
    ok "the note is written for a ~ path too"
else
    note_fail "no note for a missing ~ path (the message waits in silence)"
    show "$F"
fi
if grep -q "attach: file not found: .*nothing-here.jpg" "$WORK/$C.log"; then
    ok "and the log names it"
else
    note_fail "the log does not name the missing ~ path"
fi

echo ""
echo "quoted paths"
C=quotes; Q="$WORK/$C/files"
no_crash $C
for m in dq sq; do
    if grep -q "MISSING ATTACHMENT" "$WORK/$C/outbox/$m.txt"; then
        note_fail "$m.txt: a quoted path to a file that exists was called missing"
        show "$WORK/$C/outbox/$m.txt"
    else
        ok "$m.txt: a quoted path to a file that exists is found"
    fi
done
if grep -q "^attach: $Q/with space.jpg$" "$WORK/$C/outbox/qglob.txt"; then
    ok "a quoted wildcard expands"
else
    note_fail "a quoted wildcard did not expand"
    show "$WORK/$C/outbox/qglob.txt"
fi
if grep -q "^// MISSING ATTACHMENT: $Q/nope.jpg " "$WORK/$C/outbox/qmissing.txt"; then
    ok "a quoted path to a missing file is noted without its quotes"
else
    note_fail "a quoted missing path was not noted by its real name"
    show "$WORK/$C/outbox/qmissing.txt"
fi
if grep -q "^attach: \"$Q/nope.jpg\"$" "$WORK/$C/outbox/qmissing.txt"; then
    ok "the quotes the person wrote are left on their line"
else
    note_fail "the quoted attach: line was rewritten"
fi

# --------------------------------------------------------------------------

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
