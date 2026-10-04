#!/bin/sh
# test-restart-mailboxes.sh — check the script that restarts every mailbox
# after an update, and the tool that builds it from its template
#
# The restart script is built per machine from a template that holds one
# restart method for each kind of service manager (#622).  This builds it
# into a scratch program folder for each manager, and runs it against
# stand-in service commands (sv, systemctl, rc-service, sudo) that do
# nothing but write down what they were asked.  Nothing real is restarted.
#
# Checked: only the chosen manager's block is kept; an existing built
# script (holding the owner's list) is not overwritten; the list is
# restarted; names given as arguments are restarted instead, without
# changing the list; the prompt fills the list and the file keeps it; an
# unknown name stops the run before anything is restarted; a service that
# does not come back makes the run fail; each manager sends its restart
# the right way (through sudo, or not, as that manager needs).
#
# Run as an ordinary user: the root checks expect sudo to be used.
#
# Usage:
#   scripts/test-restart-mailboxes.sh          # use the enclosing checkout
#   scripts/test-restart-mailboxes.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
BUILDER="$DIR/scripts/make-restart-script.sh"
WORK="/tmp/rmail/tests/restart-mailboxes"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail restart-mailboxes test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ "$(id -u)" = 0 ]; then
    note_fail "run this as an ordinary user; as root, sudo is never used and the root checks cannot pass"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/bin"
CALLS="$WORK/calls"

# {{{ stand-in service commands
# Each writes one line per call to $CALLS.  A service is "down" after a
# restart when its name is in STUB_DOWN; otherwise it is running.
cat > "$WORK/bin/sudo" <<'STUB'
#!/bin/sh
echo "sudo $*" >> "$CALLS"
exec "$@"
STUB
cat > "$WORK/bin/sv" <<'STUB'
#!/bin/sh
echo "sv $*" >> "$CALLS"
name=$(basename "$2")
case " $STUB_DOWN " in
    *" $name "*) state=down ;;
    *) state=run ;;
esac
case "$1" in
    restart) echo "ok: $state: $2" ;;
    status)  echo "$state: $2: (pid 1) 5s" ;;
esac
STUB
cat > "$WORK/bin/systemctl" <<'STUB'
#!/bin/sh
scope=system
if [ "$1" = --user ]; then scope=user; shift; fi
echo "systemctl $scope $*" >> "$CALLS"
cmd="$1"; shift
[ "$1" = --quiet ] && shift
name="${1%.service}"
case "$cmd" in
    cat)       [ -f "$UNITS/$scope/$name" ] ;;
    restart)   exit 0 ;;
    is-active) case " $STUB_DOWN " in *" $name "*) exit 3 ;; esac; exit 0 ;;
esac
STUB
cat > "$WORK/bin/rc-service" <<'STUB'
#!/bin/sh
echo "rc-service $*" >> "$CALLS"
case "$2" in
    status) case " $STUB_DOWN " in *" $1 "*) exit 3 ;; esac; exit 0 ;;
esac
exit 0
STUB
chmod 755 "$WORK/bin/"*
# }}}

export CALLS
export SVDIR="$WORK/svdir"
export INITD="$WORK/initd"
export UNITS="$WORK/units"
export RMAIL_RESTART_SETTLE=0
export PATH="$WORK/bin:$PATH"
mkdir -p "$SVDIR/mail-a" "$SVDIR/mail-b" "$INITD" "$UNITS/user" "$UNITS/system"
: > "$INITD/mail-a"
: > "$UNITS/user/mail-a"
: > "$UNITS/system/mail-b"

# {{{ fresh_checkout <name>
# A scratch program folder holding only the template, so each case
# builds into a folder of its own.
fresh_checkout() {
    mkdir -p "$WORK/$1/scripts/.templates"
    cp "$DIR/scripts/.templates/restart-mailboxes.sh" "$WORK/$1/scripts/.templates/"
    echo "$WORK/$1"
}
# }}}

# {{{ set_list <checkout> <names>
set_list() {
    sed "s/^MAILBOX_SERVICES=.*/MAILBOX_SERVICES=\"$2\"/" "$1/scripts/restart-mailboxes.sh" > "$1/list.tmp"
    cat "$1/list.tmp" > "$1/scripts/restart-mailboxes.sh"
    rm -f "$1/list.tmp"
}
# }}}

echo "building: one manager's block, the folder filled in"
for m in runit systemd openrc nixos; do
    c=$(fresh_checkout "build-$m")
    if ! "$BUILDER" "$m" "$c" > /dev/null; then
        note_fail "$m: the builder failed"
        continue
    fi
    b="$c/scripts/restart-mailboxes.sh"
    blocks=$(grep -c '^# {{{ manager: ' "$b")
    if [ "$blocks" = 1 ] && grep -q "^# {{{ manager: $m\$" "$b" \
       && grep -q "^DIR=\"$c\"\$" "$b" && grep -q "^SERVICE_MANAGER=\"$m\"\$" "$b" \
       && [ -x "$b" ]; then
        ok "$m: one block, folder and manager filled in, executable"
    else
        note_fail "$m: $blocks manager blocks, or a placeholder left"
    fi
done
if "$BUILDER" upstart "$(fresh_checkout build-bad)" > /dev/null 2>&1; then
    note_fail "an unknown manager was accepted"
else
    ok "an unknown manager is refused"
fi

echo "building: an existing script keeps its list"
c=$(fresh_checkout keep)
"$BUILDER" runit "$c" > /dev/null
set_list "$c" "mail-a"
"$BUILDER" runit "$c" > /dev/null
if grep -q '^MAILBOX_SERVICES="mail-a"$' "$c/scripts/restart-mailboxes.sh"; then
    ok "a second build kept the list"
else
    note_fail "a second build overwrote the list"
fi
# --force rebuilds from the template (a marker line stands in for a
# template change) and carries the list across.
echo "# stale copy" >> "$c/scripts/restart-mailboxes.sh"
"$BUILDER" --force runit "$c" > /dev/null
if grep -q '^MAILBOX_SERVICES="mail-a"$' "$c/scripts/restart-mailboxes.sh" \
   && ! grep -q '^# stale copy$' "$c/scripts/restart-mailboxes.sh"; then
    ok "--force rebuilt it and kept the list"
else
    note_fail "--force did not rebuild it, or lost the list"
fi

echo "runit: the list, arguments, unknown names, a service that stays down"
c=$(fresh_checkout runit)
"$BUILDER" runit "$c" > /dev/null
set_list "$c" "mail-a mail-b"
: > "$CALLS"
if "$c/scripts/restart-mailboxes.sh" > "$WORK/out" 2>&1 \
   && grep -q "^sudo sv restart $SVDIR/mail-a\$" "$CALLS" \
   && grep -q "^sudo sv restart $SVDIR/mail-b\$" "$CALLS"; then
    ok "every listed service restarted, through sudo"
else
    note_fail "the list was not restarted as expected"
    info "$(cat "$WORK/out")"
fi
: > "$CALLS"
"$c/scripts/restart-mailboxes.sh" mail-b > "$WORK/out" 2>&1
if grep -q "restart $SVDIR/mail-b\$" "$CALLS" && ! grep -q "restart $SVDIR/mail-a\$" "$CALLS" \
   && grep -q '^MAILBOX_SERVICES="mail-a mail-b"$' "$c/scripts/restart-mailboxes.sh"; then
    ok "a name given as an argument is restarted instead, and the list is unchanged"
else
    note_fail "an argument did not replace the list for one run"
fi
: > "$CALLS"
set_list "$c" "mail-a no-such-mailbox"
if "$c/scripts/restart-mailboxes.sh" > "$WORK/out" 2>&1; then
    note_fail "an unknown name did not fail the run"
elif grep -q restart "$CALLS"; then
    note_fail "an unknown name failed the run, but only after restarting others"
elif grep -q "no-such-mailbox" "$WORK/out"; then
    ok "an unknown name stops the run before anything restarts, and is named"
else
    note_fail "an unknown name failed the run without naming it"
fi
set_list "$c" "mail-a mail-b"
if STUB_DOWN="mail-b" "$c/scripts/restart-mailboxes.sh" > "$WORK/out" 2>&1; then
    note_fail "a service that stayed down did not fail the run"
elif grep -q "mail-b is not running" "$WORK/out"; then
    ok "a service that stays down fails the run, and is named"
else
    note_fail "a service that stayed down failed the run without saying which"
fi

echo "--add and --check: what the installer uses"
c=$(fresh_checkout add)
"$BUILDER" runit "$c" > /dev/null
: > "$CALLS"
"$c/scripts/restart-mailboxes.sh" --add mail-a > /dev/null
"$c/scripts/restart-mailboxes.sh" --add mail-b > /dev/null
"$c/scripts/restart-mailboxes.sh" --add mail-a > /dev/null
if grep -q '^MAILBOX_SERVICES="mail-a mail-b"$' "$c/scripts/restart-mailboxes.sh" && ! grep -q restart "$CALLS"; then
    ok "--add appends each name once and restarts nothing"
else
    note_fail "--add did not build the list as expected"
    info "$(grep MAILBOX_SERVICES= "$c/scripts/restart-mailboxes.sh")"
fi
if "$c/scripts/restart-mailboxes.sh" --add "bad name" > /dev/null 2>&1; then
    note_fail "--add accepted a name with a space"
else
    ok "--add refuses a name that is not a service name"
fi
if "$c/scripts/restart-mailboxes.sh" --check > /dev/null 2>&1 && ! grep -q restart "$CALLS"; then
    ok "--check passes when every listed service is installed, and restarts nothing"
else
    note_fail "--check failed with every service installed"
fi
"$c/scripts/restart-mailboxes.sh" --add not-installed-yet > /dev/null
if "$c/scripts/restart-mailboxes.sh" --check > "$WORK/out" 2>&1; then
    note_fail "--check passed with a listed service that is not installed"
elif grep -q not-installed-yet "$WORK/out"; then
    ok "--check fails on a service not installed yet, and names it"
else
    note_fail "--check failed without naming the missing service"
fi

echo "the empty list: asked on a terminal, refused without one"
c=$(fresh_checkout ask)
"$BUILDER" runit "$c" > /dev/null
: > "$CALLS"
if "$c/scripts/restart-mailboxes.sh" < /dev/null > "$WORK/out" 2>&1; then
    note_fail "an empty list with no terminal did not fail"
elif grep -q restart "$CALLS"; then
    note_fail "an empty list with no terminal restarted something"
else
    ok "an empty list with no terminal stops with an error"
fi
# script(1) gives the restart script a terminal; the names arrive on it
# as typed lines, the last one blank.
printf 'mail-a\nnot a name\nmail-b\n\n' |
    script -qec "$c/scripts/restart-mailboxes.sh" /dev/null > "$WORK/out" 2>&1
if grep -q '^MAILBOX_SERVICES="mail-a mail-b"$' "$c/scripts/restart-mailboxes.sh" \
   && grep -q "restart $SVDIR/mail-a\$" "$CALLS" && grep -q "restart $SVDIR/mail-b\$" "$CALLS"; then
    ok "the typed names were saved into the list (the bad one refused) and restarted"
else
    note_fail "the typed names were not saved and restarted"
    info "$(grep MAILBOX_SERVICES= "$c/scripts/restart-mailboxes.sh")"
fi
if sh -n "$c/scripts/restart-mailboxes.sh" && [ -x "$c/scripts/restart-mailboxes.sh" ]; then
    ok "the rewritten script still parses and is executable"
else
    note_fail "the rewritten script is broken"
fi

echo "systemd, openrc and nixos: each restart sent the right way"
c=$(fresh_checkout systemd)
"$BUILDER" systemd "$c" > /dev/null
: > "$CALLS"
"$c/scripts/restart-mailboxes.sh" mail-a mail-b > "$WORK/out" 2>&1
if grep -q '^systemctl user restart mail-a.service$' "$CALLS" \
   && ! grep -q '^sudo systemctl --user' "$CALLS" \
   && grep -q '^sudo systemctl restart mail-b.service$' "$CALLS"; then
    ok "systemd: a user service without sudo, a system service with it"
else
    note_fail "systemd: user and system services not restarted the right way"
    info "$(cat "$CALLS")"
fi
c=$(fresh_checkout openrc)
"$BUILDER" openrc "$c" > /dev/null
: > "$CALLS"
"$c/scripts/restart-mailboxes.sh" mail-a > "$WORK/out" 2>&1
if grep -q '^sudo rc-service mail-a restart$' "$CALLS"; then
    ok "openrc: restarted through sudo"
else
    note_fail "openrc: not restarted the right way"
fi
c=$(fresh_checkout nixos)
"$BUILDER" nixos "$c" > /dev/null
: > "$CALLS"
"$c/scripts/restart-mailboxes.sh" mail-b > "$WORK/out" 2>&1
if grep -q '^sudo systemctl restart mail-b.service$' "$CALLS"; then
    ok "nixos: restarted through sudo"
else
    note_fail "nixos: not restarted the right way"
fi

rm -rf "$WORK"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n"
    exit 0
fi
printf "  \033[31m%d case(s) failed\033[0m\n" "$FAILURES"
exit 1
