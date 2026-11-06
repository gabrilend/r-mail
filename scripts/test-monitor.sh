#!/bin/sh
# test-monitor.sh — check that scripts/rmail-monitor.lua finds the mailboxes on a machine and says what each runs (#713)
#
# Four mailboxes under the test root:
#
#   running   a systemd user service file names its config, and a daemon
#             is running for it
#   stopped   a runit service file names its config; nothing running
#   openrc    an openrc service file, whose command_args="..." wraps the
#             command line in its own quoting; nothing running
#   byhand    no service file; a daemon started by hand, with the config
#             given as a relative path from inside the mailbox
#   hidden    an openrc service file names it, and its config says
#             `monitor = no`
#
# The service files sit under a stand-in root (RMAIL_MONITOR_ROOT) and a
# stand-in HOME, so nothing on the real machine is read or written, and
# the version cache goes to a stand-in XDG_STATE_HOME.  Processes are
# the real /proc, so lines are picked out by the test root's paths:
# another daemon running on this machine is not this test's business.
#
# Cases:
#   version     rmail.lua --version prints the version rmail.lua carries,
#               and a started daemon writes it to .state/version
#   abilities   with no arguments the monitor says what it can do
#   list        running, stopped, openrc and by-hand mailboxes are listed with
#               their ports, pids and services; the hidden one is not
#   plain       list --plain is one tab-separated line per mailbox
#   tell        tell names the config, status, service file and version;
#               the hidden mailbox is not told about
#   new         a mailbox past the version the monitor last saw is said
#               to be new once, naming the story; the next list is quiet
#   restart     a running daemon that last ran an older version is told
#               to restart; a stopped one is told what it runs next
#   story       story prints the chapters between two versions, and
#               says when there are none
#   restarting  restart goes through the service manager, with the same
#               commands as restart-mailboxes.sh (stand-ins for systemctl,
#               sv, rc-service, sudo and id record what they were asked):
#               a mailbox started by hand is not touched; --dry-run says
#               the command and runs nothing; a runit service that is not
#               enabled is named with the command that enables it;
#               --behind restarts only the running mailbox that last ran
#               an older version, waits for its new pid, and says it now
#               runs the version on disk; not root, sv goes through sudo;
#               a refused restart is said and fails; and with nothing
#               behind, --behind says so
#
# Usage:
#   scripts/test-monitor.sh          # use the enclosing checkout
#   scripts/test-monitor.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
MONITOR="$DIR/scripts/rmail-monitor.lua"
WORK="/tmp/rmail/tests/monitor"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-monitor-*"
PORT_RUNNING=59533
PORT_STOPPED=59534
PORT_BYHAND=59535
PORT_HIDDEN=59536
PORT_OPENRC=59537

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_for <seconds> <shell test>: 0 once it holds, 1 at the deadline
wait_for() {
    n=0
    while [ "$n" -lt $(($1 * 10)) ]; do
        if eval "$2"; then return 0; fi
        sleep 0.1
        n=$((n + 1))
    done
    return 1
}

monitor() {
    HOME="$WORK/home" RMAIL_MONITOR_ROOT="$WORK/root" XDG_STATE_HOME="$WORK/state" \
        "$LUA" "$MONITOR" "$@"
}

# make_box <name> <port> [extra config line]
make_box() {
    mkdir -p "$WORK/$1/inbox" "$WORK/$1/outbox" "$WORK/$1/.state"
    printf 'name = %s\nport = %s\n%s\n' "$1" "$2" "${3:-}" > "$WORK/$1/config"
    : > "$WORK/$1/contacts"
    printf '198.51.100.7\n' > "$WORK/$1/.state/public_ip"
}

echo ""
echo "rmail monitor test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
rm -f $RAM_FILES
mkdir -p "$WORK/home/.config/systemd/user" "$WORK/root/etc/sv/rmail-stopped" "$WORK/root/etc/init.d" "$WORK/state"
make_box running "$PORT_RUNNING"
make_box stopped "$PORT_STOPPED"
make_box byhand "$PORT_BYHAND"
make_box hidden "$PORT_HIDDEN" "monitor = no"
make_box openrc "$PORT_OPENRC"

# service files in the shapes scripts/.templates/services/ gives them
cat > "$WORK/home/.config/systemd/user/rmail-running.service" <<EOF
[Unit]
Description=rmail messaging daemon ($WORK/running)
[Service]
ExecStart=$LUA $DIR/rmail.lua $WORK/running/config
EOF
cat > "$WORK/root/etc/sv/rmail-stopped/run" <<EOF
#!/bin/sh
# rmail runit service for the mailbox at $WORK/stopped
exec chpst -u me $LUA $DIR/rmail.lua $WORK/stopped/config >>$WORK/stopped.log 2>&1
EOF
cat > "$WORK/root/etc/init.d/rmail-hidden" <<EOF
#!/sbin/openrc-run
description="rmail messaging daemon ($WORK/hidden)"
command_args="$DIR/rmail.lua $WORK/hidden/config"
EOF
cat > "$WORK/root/etc/init.d/rmail-openrc" <<EOF
#!/sbin/openrc-run
description="rmail messaging daemon ($WORK/openrc)"
command_args="$DIR/rmail.lua $WORK/openrc/config"
EOF
# not rmail's: a service file that is not named rmail-* is not read
cat > "$WORK/home/.config/systemd/user/other.service" <<EOF
ExecStart=$LUA $DIR/rmail.lua $WORK/stopped/other-config
EOF

PIDS=""
stop_all() {
    for p in $PIDS $(cat "$WORK"/*.pid 2>/dev/null); do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
}
trap stop_all EXIT

"$LAUNCHER" "$WORK/running/config" > "$WORK/running.log" 2>&1 &
PID_RUNNING=$!
PIDS="$PIDS $PID_RUNNING"
( cd "$WORK/byhand" && exec "$LAUNCHER" config ) > "$WORK/byhand.log" 2>&1 &
PID_BYHAND=$!
PIDS="$PIDS $PID_BYHAND"
# the hidden mailbox runs too, so that leaving it out is the opt-out's
# doing and not just its being stopped
"$LAUNCHER" "$WORK/hidden/config" > "$WORK/hidden.log" 2>&1 &
PIDS="$PIDS $!"

for box in running byhand hidden; do
    wait_for 15 "grep -q 'listening on' '$WORK/$box.log'" \
        || note_fail "the $box daemon did not start: $(tail -3 "$WORK/$box.log" | tr '\n' ' ')"
done

VERSION=$(sed -n 's/^local RMAIL_VERSION = "\(.*\)"$/\1/p' "$DIR/rmail.lua")

echo ""
echo "version"
[ -n "$VERSION" ] && [ "$("$LUA" "$DIR/rmail.lua" --version)" = "rmail $VERSION" ] \
    && ok "rmail.lua --version says rmail $VERSION, the version it carries" \
    || note_fail "rmail.lua --version said: $("$LUA" "$DIR/rmail.lua" --version 2>&1 | head -2 | tr '\n' ' ') (carries '$VERSION')"
[ "$(cat "$WORK/running/.state/version" 2>/dev/null)" = "$VERSION" ] \
    && ok "a started daemon writes the version it runs to .state/version" \
    || note_fail ".state/version holds: $(cat "$WORK/running/.state/version" 2>&1)"
grep -q "version: $VERSION" "$WORK/running.log" \
    && ok "and logs it" || note_fail "no version line in the daemon's log"

echo ""
echo "abilities"
monitor > "$WORK/help.out" 2>&1
if grep -q "I can list every rmail mailbox" "$WORK/help.out" && grep -q "rmail-monitor.lua story" "$WORK/help.out" \
   && grep -q "cannot do yet" "$WORK/help.out"; then
    ok "with no arguments it says what it can do, what to type for each, and what it cannot do yet"
else
    note_fail "the monitor's own description: $(head -5 "$WORK/help.out" | tr '\n' ' ')"
fi
monitor swing-a-sword > "$WORK/unknown.out" 2>&1
[ $? -eq 2 ] && grep -q "I cannot swing-a-sword" "$WORK/unknown.out" \
    && ok "asked for something it cannot do, it says so and lists what it can" \
    || note_fail "an unknown ability: $(head -2 "$WORK/unknown.out" | tr '\n' ' ')"

echo ""
echo "list"
monitor list > "$WORK/list.out" 2>&1
# the stanza for one mailbox: its path line and the indented lines after it
stanza() { awk -v m="  $WORK/$1" '$0 == m { on = 1; next } on && /^      / { print; next } { on = 0 }' "$WORK/list.out"; }
stanza running | grep -q "running (pid $PID_RUNNING), port $PORT_RUNNING, version $VERSION" \
    && stanza running | grep -q "rmail-running (systemd user)" \
    && ok "a running service: its pid, port, version, and the service that starts it" \
    || note_fail "running: $(stanza running | tr '\n' ' ')"
stanza stopped | grep -q "stopped, port $PORT_STOPPED" && stanza stopped | grep -q "rmail-stopped (runit)" \
    && ok "a stopped service is listed, with its runit service" \
    || note_fail "stopped: $(stanza stopped | tr '\n' ' ')"
stanza byhand | grep -q "running (pid $PID_BYHAND), port $PORT_BYHAND" && stanza byhand | grep -q "started by hand" \
    && ok "a daemon started by hand with a relative config is found through its process" \
    || note_fail "by hand: $(stanza byhand | tr '\n' ' ')"
if grep -q "$WORK/hidden" "$WORK/list.out"; then
    note_fail "a mailbox whose config says monitor = no was listed"
else
    ok "a mailbox whose config says monitor = no is not listed, though it runs"
fi
stanza openrc | grep -q "stopped, port $PORT_OPENRC" && stanza openrc | grep -q "rmail-openrc (openrc)" \
    && ok "an openrc service file's quoted command line is read" \
    || note_fail "openrc: $(stanza openrc | tr '\n' ' ')"
grep -q "other-config" "$WORK/list.out" \
    && note_fail "a service file not named rmail-* was read" \
    || ok "a service file not named rmail or rmail-* is not read"

echo ""
echo "plain"
monitor list --plain | grep "^$WORK/" > "$WORK/plain.out"
expect="$WORK/byhand	running	$PID_BYHAND	$PORT_BYHAND	$VERSION	-
$WORK/openrc	stopped	-	$PORT_OPENRC	$VERSION	rmail-openrc
$WORK/running	running	$PID_RUNNING	$PORT_RUNNING	$VERSION	rmail-running
$WORK/stopped	stopped	-	$PORT_STOPPED	$VERSION	rmail-stopped"
[ "$(cat "$WORK/plain.out")" = "$expect" ] \
    && ok "list --plain: one tab-separated line per mailbox, sorted, nothing else" \
    || note_fail "list --plain gave: $(cat "$WORK/plain.out" | tr '\t\n' '|;')"

echo ""
echo "tell"
monitor tell "$WORK/running" > "$WORK/tell.out" 2>&1
grep -q "config: *$WORK/running/config" "$WORK/tell.out" \
    && grep -q "service file: *$WORK/home/.config/systemd/user/rmail-running.service" "$WORK/tell.out" \
    && grep -q "last ran: *$VERSION" "$WORK/tell.out" \
    && ok "tell: the config, the service file, and the version it last ran" \
    || note_fail "tell running: $(cat "$WORK/tell.out" | tr '\n' ' ')"
monitor tell rmail-stopped > "$WORK/tell2.out" 2>&1
grep -q "status: *stopped" "$WORK/tell2.out" \
    && ok "a mailbox can be named by its service" || note_fail "tell rmail-stopped: $(head -3 "$WORK/tell2.out" | tr '\n' ' ')"
monitor tell "$WORK/hidden" > "$WORK/tell3.out" 2>&1
[ $? -eq 1 ] && ! grep -q "port" "$WORK/tell3.out" \
    && ok "the hidden mailbox is not told about either" \
    || note_fail "tell hidden: $(head -3 "$WORK/tell3.out" | tr '\n' ' ')"

echo ""
echo "new"
CACHE="$WORK/state/rmail/monitor-versions"
grep -q "^$VERSION	$WORK/running$" "$CACHE" 2>/dev/null \
    && ok "the first look remembers each mailbox's version, and says nothing new" \
    || note_fail "the version cache holds: $(cat "$CACHE" 2>&1 | tr '\t\n' '|;')"
grep -q "new since" "$WORK/list.out" && note_fail "the first look called something new"
sed -i "s#^$VERSION	$WORK/running\$#0.0.1	$WORK/running#" "$CACHE"
monitor list > "$WORK/list2.out" 2>&1
grep -q "new since I last looked: 0.0.1 -> $VERSION; what changed: rmail-monitor.lua story 0.0.1 $VERSION" "$WORK/list2.out" \
    && ok "a mailbox past the version last seen is new, and the story between is named" \
    || note_fail "after the version moved: $(grep -A4 "$WORK/running" "$WORK/list2.out" | tr '\n' ' ')"
monitor list > "$WORK/list3.out" 2>&1
grep -q "new since" "$WORK/list3.out" \
    && note_fail "the same news was told twice" \
    || ok "and it is said once: the next look is quiet"

echo ""
echo "restart"
printf '0.0.5\n' > "$WORK/running/.state/version"
printf '0.0.5\n' > "$WORK/stopped/.state/version"
monitor list > "$WORK/list4.out" 2>&1
grep -A4 "^  $WORK/running$" "$WORK/list4.out" | grep -q "restart it to run $VERSION" \
    && ok "a running daemon that last ran an older version is told to restart" \
    || note_fail "running behind: $(grep -A4 "^  $WORK/running$" "$WORK/list4.out" | tr '\n' ' ')"
grep -A4 "^  $WORK/stopped$" "$WORK/list4.out" | grep -q "runs $VERSION when started" \
    && ok "a stopped one is told what it runs when started" \
    || note_fail "stopped behind: $(grep -A4 "^  $WORK/stopped$" "$WORK/list4.out" | tr '\n' ' ')"

echo ""
echo "story"
monitor story 0.0.1 "$VERSION" > "$WORK/story.out" 2>&1
first=$(head -1 "$DIR/transitions/$VERSION.md" 2>/dev/null)
[ -n "$first" ] && grep -qF "$first" "$WORK/story.out" \
    && ok "story prints the chapter for each version after FROM up to TO" \
    || note_fail "story 0.0.1 $VERSION: $(head -2 "$WORK/story.out" | tr '\n' ' ')"
monitor story "$VERSION" "$VERSION" > "$WORK/story2.out" 2>&1
grep -q "Nothing changed between $VERSION and $VERSION" "$WORK/story2.out" \
    && ok "and says so when there is no chapter between" \
    || note_fail "story $VERSION $VERSION: $(head -2 "$WORK/story2.out" | tr '\n' ' ')"
monitor story > "$WORK/story3.out" 2>&1
grep -qF "$first" "$WORK/story3.out" \
    && ok "with no versions it tells the whole story up to this checkout's" \
    || note_fail "story: $(head -2 "$WORK/story3.out" | tr '\n' ' ')"

echo ""
echo "restarting"
# {{{ stand-ins for the service managers
# Each records the command it was given in $WORK/calls.  The systemd and
# runit ones restart the test's daemon the way the real ones would: stop
# the old process, start a new one.  rc-service refuses.  id says what
# FAKE_UID says, so the monitor can be made to think it is not root.
mkdir -p "$WORK/bin"
REAL_ID=$(command -v id)
: > "$WORK/calls"
echo "$PID_RUNNING" > "$WORK/running.pid"
cat > "$WORK/bin/restart-box" <<EOF
#!/bin/sh
# restart-box <box>: stop the daemon in $WORK/<box>.pid and start another
old=\$(cat "$WORK/\$1.pid" 2>/dev/null)
if [ -n "\$old" ]; then
    kill "\$old" 2>/dev/null
    n=0; while kill -0 "\$old" 2>/dev/null && [ \$n -lt 50 ]; do sleep 0.1; n=\$((n + 1)); done
fi
"$LAUNCHER" "$WORK/\$1/config" >> "$WORK/\$1.log" 2>&1 < /dev/null &
echo \$! > "$WORK/\$1.pid"
EOF
cat > "$WORK/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$WORK/calls"
[ "\$*" = "--user restart rmail-running.service" ] && exec "$WORK/bin/restart-box" running
exit 1
EOF
cat > "$WORK/bin/sv" <<EOF
#!/bin/sh
echo "sv \$*" >> "$WORK/calls"
[ "\$*" = "restart $WORK/root/var/service/rmail-stopped" ] && exec "$WORK/bin/restart-box" stopped
exit 1
EOF
cat > "$WORK/bin/rc-service" <<EOF
#!/bin/sh
echo "rc-service \$*" >> "$WORK/calls"
echo " * rc-service: service \$1 does not exist" >&2
exit 1
EOF
cat > "$WORK/bin/sudo" <<EOF
#!/bin/sh
echo "sudo \$*" >> "$WORK/calls"
exec "\$@"
EOF
cat > "$WORK/bin/id" <<EOF
#!/bin/sh
if [ "\$1" = "-u" ] && [ -n "\$FAKE_UID" ]; then echo "\$FAKE_UID"; exit 0; fi
exec "$REAL_ID" "\$@"
EOF
chmod +x "$WORK/bin/"*
restart() {
    PATH="$WORK/bin:$PATH" RMAIL_MONITOR_RESTART_WAIT=20 monitor restart "$@"
}
# }}}

monitor > "$WORK/help2.out" 2>&1
grep -q "I can restart a mailbox" "$WORK/help2.out" && grep -q "rmail-monitor.lua restart MAILBOX" "$WORK/help2.out" \
    && ! grep -q "cannot do yet.*restart a mailbox" "$WORK/help2.out" \
    && ok "it says it can restart a mailbox, and no longer that it cannot" \
    || note_fail "the monitor's own description: $(grep -i restart "$WORK/help2.out" | tr '\n' ' ')"

restart "$WORK/byhand" > "$WORK/r-byhand.out" 2>&1
[ $? -eq 1 ] && grep -q "started by hand (pid $PID_BYHAND)" "$WORK/r-byhand.out" && [ ! -s "$WORK/calls" ] \
    && kill -0 "$PID_BYHAND" 2>/dev/null \
    && ok "a mailbox started by hand is not restarted, and is left running" \
    || note_fail "restart byhand: $(cat "$WORK/r-byhand.out" "$WORK/calls" | tr '\n' ' ')"

restart rmail-running --dry-run > "$WORK/r-dry.out" 2>&1
[ $? -eq 0 ] && grep -q "^  systemctl --user restart rmail-running.service$" "$WORK/r-dry.out" \
    && [ ! -s "$WORK/calls" ] && kill -0 "$PID_RUNNING" 2>/dev/null \
    && ok "--dry-run says the command and runs nothing" \
    || note_fail "restart --dry-run: $(cat "$WORK/r-dry.out" "$WORK/calls" | tr '\n' ' ')"

restart rmail-stopped > "$WORK/r-noenable.out" 2>&1
[ $? -eq 1 ] && grep -q "not enabled (nothing at $WORK/root/var/service/rmail-stopped)" "$WORK/r-noenable.out" \
    && grep -q "ln -s $WORK/root/etc/sv/rmail-stopped $WORK/root/var/service/" "$WORK/r-noenable.out" \
    && [ ! -s "$WORK/calls" ] \
    && ok "a runit service that is not enabled is named, with the command that enables it" \
    || note_fail "restart a runit service not enabled: $(cat "$WORK/r-noenable.out" | tr '\n' ' ')"

# running last ran 0.0.5 (set above): --behind restarts it and only it
restart --behind > "$WORK/r-behind.out" 2>&1
status=$?
NEW_RUNNING=$(cat "$WORK/running.pid")
[ $status -eq 0 ] && [ "$(cat "$WORK/calls")" = "systemctl --user restart rmail-running.service" ] \
    && ok "--behind restarts the running mailbox that last ran an older version, and no other" \
    || note_fail "restart --behind ($status): $(cat "$WORK/r-behind.out" "$WORK/calls" | tr '\n' ' ')"
[ "$NEW_RUNNING" != "$PID_RUNNING" ] && kill -0 "$NEW_RUNNING" 2>/dev/null && ! kill -0 "$PID_RUNNING" 2>/dev/null \
    && grep -q "running again (pid $NEW_RUNNING), version $VERSION" "$WORK/r-behind.out" \
    && [ "$(cat "$WORK/running/.state/version")" = "$VERSION" ] \
    && ok "it waits for the new pid and says the version it runs now" \
    || note_fail "after --behind: old $PID_RUNNING new $NEW_RUNNING: $(cat "$WORK/r-behind.out" | tr '\n' ' ')"

mkdir -p "$WORK/root/var/service"
ln -s "$WORK/root/etc/sv/rmail-stopped" "$WORK/root/var/service/rmail-stopped"
: > "$WORK/calls"
FAKE_UID=1000 restart "$WORK/stopped" > "$WORK/r-runit.out" 2>&1
status=$?
[ $status -eq 0 ] && grep -q "^sudo sv restart $WORK/root/var/service/rmail-stopped$" "$WORK/calls" \
    && grep -q "running again (pid $(cat "$WORK/stopped.pid" 2>/dev/null)), version $VERSION" "$WORK/r-runit.out" \
    && ok "not root, a runit service is restarted through sudo, and a stopped one is started" \
    || note_fail "restart runit ($status): $(cat "$WORK/r-runit.out" "$WORK/calls" | tr '\n' ' ')"

: > "$WORK/calls"
restart rmail-openrc > "$WORK/r-openrc.out" 2>&1
[ $? -eq 1 ] && grep -q "^rc-service rmail-openrc restart$" "$WORK/calls" \
    && grep -q "refused the restart" "$WORK/r-openrc.out" \
    && ok "a restart the service manager refuses is said, and fails" \
    || note_fail "restart openrc: $(cat "$WORK/r-openrc.out" "$WORK/calls" | tr '\n' ' ')"

: > "$WORK/calls"
restart --behind > "$WORK/r-none.out" 2>&1
[ $? -eq 0 ] && grep -q "nothing to restart" "$WORK/r-none.out" && [ ! -s "$WORK/calls" ] \
    && ok "with nothing behind, --behind says so and runs nothing" \
    || note_fail "restart --behind again: $(cat "$WORK/r-none.out" "$WORK/calls" | tr '\n' ' ')"

stop_all
PIDS=""
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "monitor output: $WORK/list.out"
exit 1
