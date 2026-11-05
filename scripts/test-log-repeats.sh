#!/bin/sh
# test-log-repeats.sh — check that a log line repeated within a short time is
# written once, with its repeats' times on one later line (#118)
#
# The daemon writes a line to its log for every web request whose method it
# does not understand ("refused a web PUT request: ...").  That gives this
# test a line it can make the real daemon repeat as often and as fast as it
# likes, with nothing but a socket on loopback.
#
#   burst        120 of the same request: the line in full once, then
#                lines of held repeats (50 at most each) whose counts add
#                up to 119 and that list one time for each repeat
#   alternating  two different lines in turn, 20 each: both are held
#                (comparing with the line just before would hold neither)
#   off          log_coalesce = false: every line written as it comes
#   slow         repeats further apart than log_coalesce: written in full
#   exit         the default setting and --once: the held repeats are
#                written before the daemon exits on its own
#
# Both copies of the log are checked: the one on stderr and the file.  Every
# mailbox is empty and every port is in the high 59xxx range that no install
# uses.  Nothing leaves the machine.
#
# Usage:
#   scripts/test-log-repeats.sh          # use the enclosing checkout
#   scripts/test-log-repeats.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/log-repeats"

# Longest wait for a daemon to start listening.
DEADLINE_SECONDS=30

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail repeated log lines test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ] || [ ! -x "$LUA" ]; then
    note_fail "no launcher or Lua under $DIR"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# Sends one request per method named, one after the other, each on its own
# connection, and reads each answer to the end.
cat > "$WORK/ask.lua" <<'EOF'
local dir, port = arg[1], tonumber(arg[2])
package.path  = dir .. "/libs/?.lua;" .. package.path
package.cpath = dir .. "/libs/?.so;" .. package.cpath
local socket = require("socket")
for i = 3, #arg do
    local c = assert(socket.connect("127.0.0.1", port))
    c:settimeout(5)
    c:send(arg[i] .. " / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
    c:receive("*a")
    c:close()
end
EOF

# make_mailbox <name> <port> [extra config line]
make_mailbox() {
    mkdir -p "$WORK/$1/inbox" "$WORK/$1/outbox" "$WORK/$1/.state"
    : > "$WORK/$1/contacts"
    {
        printf 'name = %s\nport = %s\n' "$1" "$2"
        printf 'log_file = "%s"\n' "$WORK/$1.file"
        [ -n "${3:-}" ] && printf '%s\n' "$3"
    } > "$WORK/$1/config"
}

# start <name> <port> [daemon argument] — waits until it listens; pid in $PID
start() {
    "$LAUNCHER" "$WORK/$1/config" ${3:-} > "$WORK/$1.stderr" 2>&1 &
    PID=$!
    _waited=0
    while [ "$_waited" -lt "$DEADLINE_SECONDS" ]; do
        grep -q "listening on :$2" "$WORK/$1.stderr" && return 0
        sleep 1
        _waited=$((_waited + 1))
    done
    return 1
}

# ask <port> <method>...
ask() {
    _port="$1"; shift
    "$LUA" "$WORK/ask.lua" "$DIR" "$_port" "$@"
}

# repeat_word <word> <n> — the word n times, space separated
repeat_word() {
    _i=0; _out=""
    while [ "$_i" -lt "$2" ]; do _out="$_out $1"; _i=$((_i + 1)); done
    echo "$_out"
}

# full <file> <method> — lines that give the refusal in full
full() { grep -c "[0-9] refused a web $2 request" "$1"; }

# held_check <file> <method> <want total> — the lines of held repeats for
# that method: their counts add up to the total, each lists one time per
# repeat, none lists more than 50, and every time reads as a time.
held_check() {
    awk -v m="$2" -v want="$3" '
        index($0, "refused a web " m " request") && index($0, "(repeated x") {
            line = $0
            sub(/^.*\(repeated x/, "", line)
            n = line + 0
            times = line
            sub(/^[^:]*: /, "", times)
            sub(/\).*$/, "", times)
            k = split(times, t, " ")
            if (k != n) { print "line lists " k " times for x" n; bad = 1 }
            if (n > 50) { print "line holds " n " repeats"; bad = 1 }
            if (t[1] !~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) { print "first time " t[1]; bad = 1 }
            for (i = 2; i <= k; i++) if (t[i] !~ /^\+[0-9]+$/) { print "time " t[i]; bad = 1 }
            total += n; lines++
        }
        END {
            if (total != want) { print "held repeats add up to " total ", not " want; bad = 1 }
            if (!bad) print "ok " lines
        }' "$1"
}

# expect <label> <file> <method> <want full> <want held>
expect() {
    _got_full=$(full "$2" "$3")
    _held=$(held_check "$2" "$3" "$5")
    if [ "$_got_full" = "$4" ] && [ "${_held%% *}" = "ok" ]; then
        ok "$1: $3 in full $4 time(s), $5 held repeat(s) on ${_held#ok } line(s)"
    else
        note_fail "$1: $3 in full $_got_full time(s) (want $4); $_held"
        info "the log said:"
        grep "refused a web $3" "$2" | head -8 | sed 's/^/         /'
    fi
}

echo "burst: 120 of the same line, log_coalesce = 2"
make_mailbox burst 59591 "log_coalesce = 2"
if start burst 59591; then
    ask 59591 $(repeat_word PUT 120)
    # the last held repeats are due 2s on, and the main loop looks every 3s
    sleep 7
    kill "$PID"; wait "$PID" 2>/dev/null
    expect "stderr" "$WORK/burst.stderr" PUT 1 119
    expect "file  " "$WORK/burst.file"   PUT 1 119
    if grep -q "(repeated x50, 100 so far: " "$WORK/burst.file" \
       && grep -q "(repeated x19, 119 so far: " "$WORK/burst.file"; then
        ok "later lines of the same run say how many so far"
    else
        note_fail "no running total on the later lines"
    fi
else
    kill "$PID" 2>/dev/null; note_fail "burst: the daemon did not start"
fi

echo ""
echo "alternating: two lines in turn, 20 each"
make_mailbox alternating 59592 "log_coalesce = 2"
if start alternating 59592; then
    ask 59592 $(repeat_word "PUT DELETE" 20)
    sleep 7
    kill "$PID"; wait "$PID" 2>/dev/null
    expect "file  " "$WORK/alternating.file" PUT    1 19
    expect "file  " "$WORK/alternating.file" DELETE 1 19
else
    kill "$PID" 2>/dev/null; note_fail "alternating: the daemon did not start"
fi

echo ""
echo "off: log_coalesce = false"
make_mailbox off 59593 "log_coalesce = false"
if start off 59593; then
    ask 59593 $(repeat_word PUT 30)
    sleep 1
    kill "$PID"; wait "$PID" 2>/dev/null
    expect "file  " "$WORK/off.file" PUT 30 0
else
    kill "$PID" 2>/dev/null; note_fail "off: the daemon did not start"
fi

echo ""
echo "slow: repeats 3s apart, log_coalesce = 1"
make_mailbox slow 59594 "log_coalesce = 1"
if start slow 59594; then
    ask 59594 PUT; sleep 3; ask 59594 PUT
    sleep 1
    kill "$PID"; wait "$PID" 2>/dev/null
    expect "file  " "$WORK/slow.file" PUT 2 0
else
    kill "$PID" 2>/dev/null; note_fail "slow: the daemon did not start"
fi

echo ""
echo "exit: the default setting, --once=4, 10 of the same line"
make_mailbox exit 59595
if start exit 59595 --once=4; then
    ask 59595 $(repeat_word PUT 10)
    _waited=0
    while kill -0 "$PID" 2>/dev/null && [ "$_waited" -lt 30 ]; do
        sleep 1; _waited=$((_waited + 1))
    done
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"; note_fail "exit: the daemon did not end its visit"
    fi
    wait "$PID" 2>/dev/null
    expect "stderr" "$WORK/exit.stderr" PUT 1 9
    expect "file  " "$WORK/exit.file"   PUT 1 9
    if tail -n 1 "$WORK/exit.file" | grep -q -- "--once: window of 4s closed"; then
        ok "the held repeats come before the closing line"
    else
        note_fail "the closing line is not the last"
    fi
else
    kill "$PID" 2>/dev/null; note_fail "exit: the daemon did not start"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "all repeated-log-line checks passed"
    exit 0
fi
echo "$FAILURES check(s) failed"
exit 1
