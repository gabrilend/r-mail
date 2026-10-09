#!/bin/sh
# test-router-left-alone.sh — check that a mailbox never touches the router unless its config asks it to open the port
#
# Until 2026-10-08 every mailbox, at every start, ran a "security check" on
# the home router: it opened a test port through UPnP, asked whether
# NAT-PMP answered, and messaged every contact when either did.  The owner
# wants the router left alone (#411): checking whether the router has
# those protocols on is the installer's job, done once, and opening the
# port happens only when the config says `auto_port_forward = true`.
#
# The daemon finds its router programs (upnpc, natpmpc) in its own
# deps/bin/ before the program path, so hiding them from the path proves
# nothing.  This test builds a throwaway checkout -- the real daemon and
# libraries, linked in -- whose deps/bin/ holds stand-in programs that
# write down every time they are run and touch no network.
#
# Cases, one mailbox started three times:
#   defaults         neither program is run at all; the log has no router
#                    lines; no warning is written to the outbox
#   asked to open    with auto_port_forward = true the stand-in upnpc is
#                    run to open the port, the log says it was mapped, and
#                    the opening is recorded in .state/nat_mapping.json
#   cleaning up      started again with the defaults, the recorded opening
#                    is removed (upnpc -d) -- and nothing else is run
#
# Usage:
#   scripts/test-router-left-alone.sh          # use the enclosing checkout
#   scripts/test-router-left-alone.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/router-left-alone"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-router-left-alone-*"
PORT=59509
CHECKOUT="$WORK/checkout"
BOX="$WORK/box"
CALLS="$WORK/router-calls"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail router-left-alone test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

rm -rf "$WORK"
rm -f $RAM_FILES
mkdir -p "$CHECKOUT/deps/bin" "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/attachments"

# The throwaway checkout: the real daemon, launcher, libraries and Lua,
# and a deps/bin/ of stand-ins.  The daemon takes its own folder from the
# path it was started by, so a link to rmail.lua is enough.
ln -s "$DIR/rmail.lua" "$CHECKOUT/rmail.lua"
cp "$DIR/run-rmail.sh" "$CHECKOUT/run-rmail.sh"
ln -s "$DIR/libs" "$CHECKOUT/libs"
ln -s "$DIR/deps/lua" "$CHECKOUT/deps/lua"

# Each stand-in writes its name and arguments to $CALLS and answers the way
# the real program does when the router agrees, so an opening "works".
cat > "$CHECKOUT/deps/bin/upnpc" <<EOF
#!/bin/sh
echo "upnpc \$*" >> "$CALLS"
case "\$*" in
    *" -a "*) echo "external 203.0.113.9:\$5 TCP is redirected to internal \$4:\$6" ;;
esac
EOF
cat > "$CHECKOUT/deps/bin/natpmpc" <<EOF
#!/bin/sh
echo "natpmpc \$*" >> "$CALLS"
EOF
chmod +x "$CHECKOUT/deps/bin/upnpc" "$CHECKOUT/deps/bin/natpmpc"

printf 'bob.ip = "192.0.2.7"\nbob.port = 9\nbob.token = "router-left-alone-not-a-secret"\n' > "$BOX/contacts"

# run_once <config extra lines>: start the daemon, wait until its start-up
# work is over (the public address check comes after the router work),
# stop it.
run_once() {
    printf 'name = receiver\nport = %s\n%s' "$PORT" "$1" > "$BOX/config"
    : > "$WORK/daemon.log"
    "$CHECKOUT/run-rmail.sh" "$BOX/config" > "$WORK/daemon.log" 2>&1 &
    pid=$!
    waited=0
    # the first start records the addresses ("public IP recorded"); later
    # ones find them unchanged and go straight to "startup: announcing"
    while [ "$waited" -lt 60 ] && ! grep -q "public IP\|LAN IP\|startup: " "$WORK/daemon.log"; do
        sleep 1
        waited=$((waited + 1))
    done
    sleep 1
    kill "$pid"
    wait "$pid" 2>/dev/null
    if [ "$waited" -ge 60 ]; then
        note_fail "the daemon never finished starting"
        info "daemon log: $WORK/daemon.log"
    fi
}

echo ""
echo "defaults"
: > "$CALLS"
run_once ""
if [ -s "$CALLS" ]; then
    note_fail "router programs were run: $(tr '\n' ';' < "$CALLS")"
else
    ok "neither router program was run"
fi
if grep -qi "upnp\|nat-pmp\|natpmp\|security" "$WORK/daemon.log"; then
    note_fail "the log mentions the router: $(grep -i 'upnp\|nat-pmp\|natpmp\|security' "$WORK/daemon.log" | head -1)"
else
    ok "the log says nothing about the router"
fi
if ls "$BOX/outbox" | grep -q SECURITY; then
    note_fail "a security message was written to the outbox"
else
    ok "no security message in the outbox"
fi

echo ""
echo "asked to open the port (auto_port_forward = true)"
: > "$CALLS"
run_once "auto_port_forward = true
"
if grep -q "^upnpc -e rmail -a [0-9.]* $PORT $PORT TCP" "$CALLS"; then
    ok "upnpc was run to open port $PORT"
else
    note_fail "upnpc was not run to open the port: $(tr '\n' ';' < "$CALLS")"
fi
if grep -q "port $PORT mapped via upnp" "$WORK/daemon.log"; then
    ok "the log says the port was mapped"
else
    note_fail "no log line for the mapping"
fi
if grep -q '"protocol" *: *"upnp"' "$BOX/.state/nat_mapping.json" 2>/dev/null; then
    ok "the opening is recorded"
else
    note_fail "the opening is not recorded"
fi
if grep -q -- " -s" "$CALLS" || grep -q "^natpmpc" "$CALLS"; then
    note_fail "the router was probed besides: $(tr '\n' ';' < "$CALLS")"
else
    ok "nothing besides the opening was asked of the router"
fi

echo ""
echo "started again with the defaults: the recorded opening is removed"
: > "$CALLS"
run_once ""
if grep -q "^upnpc -d $PORT TCP" "$CALLS"; then
    ok "upnpc was run to remove the opening"
else
    note_fail "the opening was not removed: $(tr '\n' ';' < "$CALLS")"
fi
calls_count=$(wc -l < "$CALLS")
if [ "$calls_count" -eq 1 ]; then
    ok "and nothing else was run"
else
    note_fail "$calls_count router calls instead of 1: $(tr '\n' ';' < "$CALLS")"
fi

rm -f $RAM_FILES
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "daemon log: $WORK/daemon.log"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
