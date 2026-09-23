#!/bin/sh
# test-authoring-time.sh — check that a message keeps the time it was written
#
# An rmail message is a plain file, and a plain file carries exactly one
# record of when it was written: its modification time, the date a file
# manager or `ls -lt` sorts by.  Every hop a message makes (outbox to the
# other person's inbox, phone to the home mailbox) writes a fresh file, and
# a fresh file is stamped "now".  Left alone, a week of letters collected in
# one sync would all read as arriving in the same second, and the order they
# were written in would be gone.
#
# So the sending mailbox reads the outbox file's time and sends it along
# inside the (encrypted, tamper-proof) delivery, and the receiving mailbox
# stamps the file it writes with that time instead of its own clock.  The
# phone does the same when it uploads a note: it names the note's time in a
# header, and the home mailbox stamps the outbox copy with it.
#
# This script runs two real, throwaway mailboxes on this machine, each in
# the other's contacts, talking over the loopback address.  Only the sender
# dials; the receiver holds the sender's key but no address for it (see
# make_mailbox below for why).  It plants
# messages with deliberately old times and checks every path lands them
# with those same times:
#
#   first delivery   a letter written in 2021 arrives in the other inbox
#                    dated 2021, not today
#   note to self     a message addressed to its own mailbox lands in its own
#                    inbox with the outbox file's time
#   phone upload     a note posted the way the phone posts one, naming 2019
#                    as its time, is dated 2019 in the outbox, and still 2019
#                    when it reaches the other inbox
#   phone download   fetching an inbox file the way the phone does returns
#                    the file's time alongside it
#   edit             the letter is rewritten and re-dated 2022 while its
#                    mailbox is stopped; once it starts again, the other
#                    inbox's copy is replaced and re-dated to match
#
# Attachments are not covered here: they travel as a zip archive, which
# records each file's time and restores it on unpacking, rather than
# through the mechanism above.
#
# The "phone" here is a short Lua client speaking the phone's encrypted
# protocol; it authenticates as the second mailbox, which the first lists
# as one of its own devices.  Nothing leaves this machine.
#
# Usage:
#   scripts/test-authoring-time.sh          # use the enclosing checkout
#   scripts/test-authoring-time.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/authoring-time"

# Ports reserved for this script.  Other tests use other ranges so they can
# run at the same time.
PORT_A=59420
PORT_B=59421

# The shared secret both mailboxes hold for each other.  A test value only.
TOKEN="authoring-time-test-token-not-a-real-secret"

# Longest any one wait lasts.  A passing step stops as soon as its log line
# appears; this is only reached when it never does.  The first wait also
# covers each daemon looking its public IP up over DNS at startup (~10s).
DEADLINE_SECONDS=60

# The deliberately old times planted in the messages, as the dates `touch`
# takes and the whole seconds `stat` reports back.  Each is a different
# year so a mix-up between them cannot pass by accident.
LETTER_DATE="2021-03-04 05:06:07 UTC"
EDIT_DATE="2022-06-07 08:09:10 UTC"
SELF_DATE="2020-01-02 03:04:05 UTC"
PHONE_DATE="2019-11-12 13:14:15 UTC"
LETTER_EPOCH=$(date -u -d "$LETTER_DATE" +%s)
EDIT_EPOCH=$(date -u -d "$EDIT_DATE" +%s)
SELF_EPOCH=$(date -u -d "$SELF_DATE" +%s)
PHONE_EPOCH=$(date -u -d "$PHONE_DATE" +%s)

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail authoring-time test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then
    note_fail "no launcher at $LAUNCHER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# Each daemon keeps a copy of its log in the machine-wide RAM folder, named
# after its mailbox path.  That folder is shared with the real mailboxes, so
# this run's files are cleared at the start (a previous run's must not be
# read as this one's) and at the end (they must not be left beside the
# real ones).
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-authoring-time-*"
rm -f $RAM_FILES

# --------------------------------------------------------------------------
# make_mailbox <dir> <name> <port> <contact-name> <contact-port|-> [own]
#
# A mailbox whose one contact is the other test mailbox on this machine.
# With a sixth argument the contact is marked as one of this mailbox's own
# devices, which is what lets the phone-protocol client below use its token.
#
# A contact port of "-" writes the contact with its token only, no address:
# the mailbox can read what that contact sends but never dials it.  The
# receiving mailbox is built that way on purpose.  When two daemons dial
# each other at the same moment, each one answers incoming requests only
# between its own outgoing ones, so both sit out an 8-second timeout.  The
# sender then counts a delivery that did arrive as failed and sends it
# again under a new message id, and the far inbox fills with copies
# (letter, letter-64adf3, letter-22aade, ...).  That is a daemon problem,
# not what this script is testing, so the receiver is kept from dialling.
make_mailbox() {
    _dir="$1"; _name="$2"; _port="$3"; _peer="$4"; _peer_port="$5"; _own="${6:-}"
    mkdir -p "$_dir/inbox" "$_dir/outbox" "$_dir/.state"
    {
        if [ "$_peer_port" != "-" ]; then
            printf '%s.ip    = "127.0.0.1"\n' "$_peer"
            printf '%s.port  = %s\n' "$_peer" "$_peer_port"
        fi
        printf '%s.token = "%s"\n' "$_peer" "$TOKEN"
        [ -n "$_own" ] && printf '%s.own   = "true"\n' "$_peer"
    } > "$_dir/contacts"
    {
        printf 'name = %s\n' "$_name"
        printf 'port = %s\n' "$_port"
    } > "$_dir/config"
}

# mtime_of <file> — whole seconds since 1970, or "missing".
mtime_of() {
    if [ -e "$1" ]; then stat -c %Y "$1"; else echo missing; fi
}

# wait_for <log> <pattern> — true once <pattern> is in <log>, false at the
# deadline.
wait_for() {
    _log="$1"; _pat="$2"
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "$_pat" "$_log" && return 0
        sleep 1
        _waited=$((_waited + 1))
    done
    return 1
}

# check_mtime <file> <expected-epoch> <what>
check_mtime() {
    _got=$(mtime_of "$1")
    if [ "$_got" = "$2" ]; then
        ok "$3"
    else
        note_fail "$3"
        info "expected $2 ($(date -u -d "@$2")), found $_got"
    fi
}

# stop_all — stop both daemons.  Stopping them is the normal end of the
# run, so the shell's notice on reaping them is not shown.
stop_all() {
    for _p in $PID_A $PID_B; do
        kill "$_p"
        wait "$_p" 2>/dev/null
    done
}

# The phone-protocol client.  Every request is one encrypted frame:
# a 4-byte length, a 12-byte random nonce, then the request text sealed
# with AES-256-GCM under the SHA-256 of the shared token.  The reply comes
# back framed the same way.  Printed to stdout as plain HTTP text.
cat > "$WORK/phone.lua" <<'EOF'
-- arguments: libs-dir port token method path [mtime] [body-file]
local libs, port, token, method, path, mtime, body_file = ...
package.path  = libs .. "/?.lua;" .. package.path
package.cpath = libs .. "/?.so;" .. package.cpath
local socket = require("socket")
local crypto = require("rmail_crypto")

local body = ""
if body_file then
    local f = assert(io.open(body_file, "rb")); body = f:read("*a"); f:close()
end
local req = method .. " " .. path .. " HTTP/1.1\r\n"
if mtime and mtime ~= "" then req = req .. "X-Mtime: " .. mtime .. "\r\n" end
req = req .. "Content-Length: " .. #body .. "\r\n\r\n" .. body

local function be32(n)
    return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
                       math.floor(n / 256) % 256, n % 256)
end

local key   = crypto.sha256(token)
local nonce = crypto.random_bytes(12)
local ct    = assert(crypto.aes_gcm_encrypt(key, nonce, req))
local sock  = assert(socket.connect("127.0.0.1", tonumber(port)))
-- Patient on purpose.  The daemon answers requests only between the
-- outbound connections of its sync pass, and with two test mailboxes
-- dialling each other at once, each such connection can sit out an 8s
-- timeout while the other side is busy dialling back.  A request can wait
-- through several of those before it is read.
sock:settimeout(90)
assert(sock:send(be32(#nonce + #ct) .. nonce .. ct))
local lb = assert(sock:receive(4), "no reply")
local a, b, c, d = lb:byte(1, 4)
local packet = assert(sock:receive(a * 16777216 + b * 65536 + c * 256 + d))
sock:close()
io.write(assert(crypto.aes_gcm_decrypt(key, packet:sub(1, 12), packet:sub(13)),
                "reply did not decrypt"))
EOF

# The same interpreter the launcher would pick, so the client loads the same
# socket and crypto modules the daemon does.
LUA=""
if [ -x "$DIR/deps/lua/bin/lua" ]; then
    LUA="$DIR/deps/lua/bin/lua"
else
    for _l in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
        if command -v "$_l" >/dev/null 2>&1; then LUA="$_l"; break; fi
    done
fi

phone() {
    "$LUA" "$WORK/phone.lua" "$DIR/libs" "$PORT_A" "$TOKEN" "$@"
}

# --------------------------------------------------------------------------
# Build both mailboxes and plant the messages before either starts, so the
# planted times are in place before anything reads them.

A="$WORK/alpha"
B="$WORK/bravo"
make_mailbox "$A" alpha "$PORT_A" bravo "$PORT_B" own
make_mailbox "$B" bravo "$PORT_B" alpha -

printf 'to: bravo\n\nwritten long ago\n' > "$A/outbox/letter"
touch -d "$LETTER_DATE" "$A/outbox/letter"

printf 'to: alpha\n\na note to myself\n' > "$A/outbox/memo"
touch -d "$SELF_DATE" "$A/outbox/memo"

LOG_A="$WORK/alpha.log"
LOG_B="$WORK/bravo.log"
"$LAUNCHER" "$B/config" > "$LOG_B" 2>&1 &
PID_B=$!
"$LAUNCHER" "$A/config" > "$LOG_A" 2>&1 &
PID_A=$!

echo "running two mailboxes on ports $PORT_A and $PORT_B (each wait up to ${DEADLINE_SECONDS}s)"

# --------------------------------------------------------------------------
echo ""
echo "first delivery"

if wait_for "$LOG_B" "delivered: .* from alpha -> letter"; then
    ok "the letter arrived"
    check_mtime "$B/inbox/letter" "$LETTER_EPOCH" \
        "and is dated when it was written (2021), not when it arrived"
else
    note_fail "the letter never arrived"
    info "$(tail -3 "$LOG_B")"
fi

# The sender's own file must not have been re-dated by sending it, or the
# next edit check would be comparing against the wrong thing.
check_mtime "$A/outbox/letter" "$LETTER_EPOCH" \
    "sending did not re-date the sender's own copy"

# --------------------------------------------------------------------------
echo ""
echo "note to self"

if wait_for "$LOG_A" "self-delivered: memo"; then
    ok "the note to self was delivered"
    check_mtime "$A/inbox/memo" "$SELF_EPOCH" \
        "and is dated when it was written (2020)"
else
    note_fail "the note to self was never delivered"
    info "$(tail -3 "$LOG_A")"
fi

# --------------------------------------------------------------------------
echo ""
echo "a note uploaded from the phone"

printf 'to: bravo\n\nthumbed out on a bus\n' > "$WORK/phone-note.body"
REPLY=$(phone POST /api/file/outbox/phone-note "$PHONE_EPOCH" "$WORK/phone-note.body" 2>&1)
if printf '%s' "$REPLY" | grep -q "^HTTP/1.1 200"; then
    ok "the upload was accepted"
else
    note_fail "the upload was refused"
    info "$(printf '%s' "$REPLY" | head -3)"
fi

check_mtime "$A/outbox/phone-note" "$PHONE_EPOCH" \
    "the outbox copy is dated by the phone (2019), not by the upload"

if wait_for "$LOG_B" "delivered: .* from alpha -> phone-note"; then
    ok "the uploaded note was delivered onward"
    check_mtime "$B/inbox/phone-note" "$PHONE_EPOCH" \
        "and is still dated by the phone (2019) at the far end"
else
    note_fail "the uploaded note was never delivered onward"
    info "$(tail -3 "$LOG_B")"
fi

# --------------------------------------------------------------------------
echo ""
echo "a file downloaded to the phone"

REPLY=$(phone GET /api/file/inbox/memo 2>&1)
if printf '%s' "$REPLY" | tr -d '\r' | grep -q "^X-Mtime: $SELF_EPOCH$"; then
    ok "the download names the file's own date (2020) for the phone to stamp"
else
    note_fail "the download does not carry the file's date"
    info "$(printf '%s' "$REPLY" | head -6)"
fi

# --------------------------------------------------------------------------
echo ""
echo "an edit to a delivered letter"

# The edit is made while the sending mailbox is stopped, and it is started
# again afterwards.  That is a real way to edit (a laptop closed, a drive
# unplugged), but it is chosen here because it is the one way that works
# every time today.  Edited while the daemon runs, an edit goes out only if
# the recipient happens to be due for contact at that moment.  Otherwise the
# send is held back until they are, but the record of "this body was already
# seen" moves on anyway, so when they come due there is no difference left
# to send and the edit is never delivered.  At startup every contact is due
# at once, so the held-back case cannot happen.  What this case checks is
# the date an edit carries, not that timing.
kill "$PID_A"
wait "$PID_A" 2>/dev/null

# Written and dated outside the outbox, then moved in whole: a rename keeps
# the date, so the outbox never holds a copy dated today.
printf 'to: bravo\n\nwritten long ago, and corrected later\n' > "$WORK/letter.new"
touch -d "$EDIT_DATE" "$WORK/letter.new"
mv "$WORK/letter.new" "$A/outbox/letter"

LOG_A2="$WORK/alpha-restarted.log"
"$LAUNCHER" "$A/config" > "$LOG_A2" 2>&1 &
PID_A=$!

if wait_for "$LOG_B" "updated: .* from alpha -> letter"; then
    ok "the edit reached the other inbox"
    if grep -q "corrected later" "$B/inbox/letter"; then
        ok "the other inbox holds the new text"
    else
        note_fail "the other inbox still holds the old text"
    fi
    check_mtime "$B/inbox/letter" "$EDIT_EPOCH" \
        "and is re-dated to the edit (2022)"
else
    note_fail "the edit never arrived"
    info "$(tail -3 "$LOG_A2")"
fi

# --------------------------------------------------------------------------

stop_all

if grep -q "sync error" "$LOG_A" "$LOG_A2" "$LOG_B"; then
    note_fail "a sync cycle crashed along the way"
    info "$(grep -h -m1 'sync error' "$LOG_A" "$LOG_A2" "$LOG_B")"
fi

rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
