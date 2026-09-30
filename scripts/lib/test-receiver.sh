# test-receiver.sh — shared set-up for the tests that talk to one daemon through a stand-in contact
#
# Sourced (not run) by the scripts/test-*.sh files that check how a
# mailbox treats what arrives from outside: a throwaway receiving mailbox
# in RAM, one real daemon serving it, and a Lua script playing a contact
# (and the owner's phone) against it through scripts/lib/fake-contact.lua.
#
# The sourcing script sets, before sourcing:
#   DIR        the checkout under test
#   WORK       its scratch folder (removed and rebuilt here)
#   PORT       a port no install uses
#   TEST_NAME  words for the heading
#
# and afterwards has:
#   BOX            the mailbox folder
#   MALLORY_TOKEN  the shared key of the contact "mallory"
#   PHONE_TOKEN    the shared key of "phone", the owner's own device
#   LUA            the Lua the daemon runs on
#   ok / note_fail / info    verdict printers; FAILURES counts failures
#   start_receiver           starts the daemon (DAEMON_PID)
#   run_lua_cases            runs Lua from standard input, relays its verdicts
#   stop_receiver            stops the daemon
#   finish                   prints the summary and exits 0 or 1
#
# The Lua half prints one line per verdict, which run_lua_cases relays:
#   "section <words>"  a heading      "ok <words>"  a pass
#   "-- <words>"       a failure      anything else  printed as detail

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
BOX="$WORK/box"
MALLORY_TOKEN="$TEST_NAME-contact-token-not-a-secret"
PHONE_TOKEN="$TEST_NAME-phone-token-not-a-secret"
# The daemon's shared RAM folder; this run's files there carry WORK's path.
RAM_FILES="/tmp/rmail-progress/*$(printf '%s' "$WORK" | tr '/' '-')-*"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail $TEST_NAME test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/attachments"
rm -f $RAM_FILES
printf 'name = receiver\nport = %s\nattachment_pending_dir = %s\n' "$PORT" "$WORK/pending" > "$BOX/config"
printf 'mallory.token = "%s"\n\nphone.token = "%s"\nphone.own = true\n' \
    "$MALLORY_TOKEN" "$PHONE_TOKEN" > "$BOX/contacts"

start_receiver() {
    "$LAUNCHER" "$BOX/config" > "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
}

stop_receiver() {
    kill "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null
}

# run_lua_cases: the Lua on standard input gets arg[1..5] =
# DIR PORT MALLORY_TOKEN PHONE_TOKEN WORK.
run_lua_cases() {
    "$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" > "$WORK/lua.out" 2>&1
    lua_status=$?
    while IFS= read -r line; do
        case "$line" in
            "section "*) echo ""; echo "${line#section }" ;;
            "ok "*)      ok "${line#ok }" ;;
            "-- "*)      note_fail "${line#-- }" ;;
            *)           info "$line" ;;
        esac
    done < "$WORK/lua.out"
    if [ "$lua_status" -ne 0 ]; then
        note_fail "the stand-in contact stopped with status $lua_status"
    fi
}

finish() {
    rm -f $RAM_FILES
    echo ""
    if [ "$FAILURES" -eq 0 ]; then
        printf "  \033[32mall cases passed\033[0m\n\n"
        exit 0
    fi
    printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
    info "daemon log: $WORK/daemon.log"
    exit 1
}
