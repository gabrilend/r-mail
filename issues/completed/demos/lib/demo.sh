#!/bin/sh
# demo.sh — what every phase demo shares: headings, the phase's counts, a daemon in RAM, and running the phase's tests
#
# Sourced (not run) by issues/completed/demos/phase-N-demo.sh.  A demo
# shows a phase working: it starts throwaway mailboxes in RAM, makes them
# do the phase's things, and prints what came out and how long it took;
# then it runs the phase's tests and says how many checks passed.  Numbers
# are measured each time, never written down.
#
# The sourcing script sets DIR (the checkout), PHASE and PHASE_NAME before
# sourcing, and then has:
#   heading <words>            a section heading
#   show <words>               a line of output, indented
#   counts                     done / open for this phase, from the dashboard
#   demo_box <name> <port>     a throwaway mailbox folder in RAM: $BOX_<name>
#   start_daemon <name>        runs the real daemon on it (PID in $PID_<name>)
#   stop_all                   stops every daemon and stand-in started here
#   run_tests <script>...      runs tests, counting passed and failed checks
#   now_ms                     milliseconds, for timing

LUA="$DIR/deps/lua/bin/lua"
[ -x "$LUA" ] || LUA="$(command -v luajit || command -v lua5.4 || command -v lua)"
DEMO_WORK="/tmp/rmail/demos/phase-$PHASE"
DASHBOARD="/home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua"
DEMO_PIDS=""
DEMO_PORT_BASE=$((59600 + PHASE * 10))

B=$(printf '\033[1m'); D=$(printf '\033[2m'); G=$(printf '\033[32m'); R=$(printf '\033[31m'); N=$(printf '\033[0m')

# {{{ heading / show
heading() { printf "\n${B}%s${N}\n" "$*"; }
show()    { printf "    %s\n" "$*"; }
# }}}

# {{{ now_ms
# (Lua code comes on standard input throughout: given -e, Lua takes the
# first plain argument for a script's name and the rest shift by one.)
now_ms() {
    "$LUA" - "$DIR" <<'LUA'
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
print(math.floor(require("socket").gettime() * 1000))
LUA
}
# }}}

# {{{ counts
counts() {
    if [ -x "$DASHBOARD" ]; then
        "$DASHBOARD" "$DIR" -j > "$DEMO_WORK/dashboard.json" 2>/dev/null
        "$LUA" - "$DIR" "$PHASE" "$DEMO_WORK/dashboard.json" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[3]); local d = f and require("dkjson").decode(f:read("*a")) or {}
local p = (d.phases or {})[arg[2]] or {}
print(string.format("%d issues: %d done, %d open", p.total or 0, p.completed or 0, p.open or 0))
LUA
    else
        echo "(the progress dashboard is not on this machine)"
    fi
}
# }}}

# {{{ demo_box
# demo_box <name> <port> — config with no pending folder named (the default)
demo_box() {
    _d="$DEMO_WORK/$1"
    mkdir -p "$_d/inbox" "$_d/outbox" "$_d/.state" "$_d/attachments"
    printf 'name = %s\nport = %s\nlog_file = "%s"\n' "$1" "$2" "$DEMO_WORK/$1.log" > "$_d/config"
    : > "$_d/contacts"
    eval "BOX_$1=\"$_d\""
}
# }}}

# {{{ start_daemon
start_daemon() {
    "$DIR/run-rmail.sh" "$DEMO_WORK/$1/config" > /dev/null 2>&1 &
    eval "PID_$1=$!"
    DEMO_PIDS="$DEMO_PIDS $!"
}
# }}}

# {{{ start_recipient
# start_recipient <name> <port> <token> — a stand-in that answers at once
start_recipient() {
    "$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$2" "$3" "$DEMO_WORK/$1" > /dev/null 2>&1 &
    DEMO_PIDS="$DEMO_PIDS $!"
}
# }}}

# {{{ stop_all
stop_all() {
    for _p in $DEMO_PIDS; do kill "$_p" 2>/dev/null; done
    for _f in "$DEMO_WORK"/*/; do touch "$_f/stop" 2>/dev/null; done
    wait 2>/dev/null
    DEMO_PIDS=""
    rm -f /tmp/rmail-progress/*-tmp-rmail-demos-phase-$PHASE-*
}
# }}}

# {{{ wait_for
# wait_for <seconds> <shell test> — 0 once it holds
wait_for() {
    _n=0
    while [ "$_n" -lt "$1" ]; do
        eval "$2" && return 0
        sleep 1; _n=$((_n + 1))
    done
    return 1
}
# }}}

# {{{ run_tests
# run_tests <test script>... — each run once; counts its ok and -- lines
run_tests() {
    _pass=0; _fail=0; _scripts=0; _t0=$(date +%s)
    for _t in "$@"; do
        _scripts=$((_scripts + 1))
        _out="$DEMO_WORK/test-$(basename "$_t" .sh).out"
        "$DIR/scripts/$_t" > "$_out" 2>&1
        _p=$(grep -c '\[32mok' "$_out"); _f=$(grep -c '\[31m--' "$_out")
        _pass=$((_pass + _p)); _fail=$((_fail + _f))
        if [ "$_f" -eq 0 ]; then
            printf "    ${G}%3d checks passed${N}  %s\n" "$_p" "$_t"
        else
            printf "    ${R}%3d of %d checks failed${N}  %s  (%s)\n" "$_f" $((_p + _f)) "$_t" "$_out"
        fi
    done
    printf "    ${B}%d scripts, %d checks passed, %d failed, %ds${N}\n" "$_scripts" "$_pass" "$_fail" $(( $(date +%s) - _t0 ))
}
# }}}

# {{{ start
# Opening of every demo: the title, the phase's counts, a clean RAM folder.
start() {
    rm -rf "$DEMO_WORK"; mkdir -p "$DEMO_WORK"
    printf "\n${B}rmail — phase %s: %s${N}\n" "$PHASE" "$PHASE_NAME"
    printf "${D}%s${N}\n" "$(counts)"
    trap stop_all EXIT INT
}
# }}}
