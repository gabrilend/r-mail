#!/bin/sh
# test-run-rmail-interpreters.sh — check which Lua run-rmail.sh picks when there is no compiled one (#905)
#
# rmail.lua uses `goto`, which Lua 5.1 lacks, and OpenWrt's plain `lua` is
# a Lua 5.1.  run-rmail.sh passes over an interpreter that cannot read a
# goto, and when that leaves none, says what rmail needs instead of
# letting the daemon stop on a syntax error.
#
# Each case runs run-rmail.sh with a PATH holding only stand-ins: small
# scripts named like interpreters that write down how they were called
# and run the real one (the lua5.1, lua5.3, lua5.4 and luajit found on
# this machine).  The daemon is started with no arguments, so rmail.lua
# prints its usage and stops: which interpreter printed it is the answer.
#
# Cases:
#   only lua5.1      refused, naming it and Lua 5.2 or later; no syntax error
#   lua is a 5.1     the same, as on OpenWrt
#   lua5.1 + lua5.3  lua5.3 runs rmail.lua; lua5.1 is never started on it
#   lua is a 5.3     a plain `lua` that can read a goto is used
#   luajit           used
#   none             "no lua interpreter found", as before
#   compiled         deps/lua/bin/lua is used first, as before
#
# Usage:
#   scripts/test-run-rmail-interpreters.sh          # use the enclosing checkout
#   scripts/test-run-rmail-interpreters.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/run-rmail-interpreters"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail run-rmail interpreters test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

LUA51=$(command -v lua5.1)
LUA53=$(command -v lua5.3 || command -v lua5.4)
LUAJIT=$(command -v luajit)
if [ -z "$LUA51" ] || [ -z "$LUA53" ]; then
    note_fail "this test needs a Lua 5.1 and a Lua 5.3 or 5.4 on the PATH (found: ${LUA51:-no 5.1}, ${LUA53:-no 5.3})"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/prog" "$WORK/tools"
cp "$DIR/run-rmail.sh" "$DIR/rmail.lua" "$WORK/prog/"
ln -s "$(command -v dirname)" "$WORK/tools/dirname"

# stand_in <name> <real interpreter>: logs "<name> <first argument>"
stand_in() {
    printf '#!/bin/sh\necho "%s $1" >> "%s/used"\nexec "%s" "$@"\n' "$1" "$WORK" "$2" > "$WORK/bin/$1"
    chmod +x "$WORK/bin/$1"
}
# run_case: run-rmail.sh with only the stand-ins and the tools
run_case() {
    : > "$WORK/used"
    PATH="$WORK/bin:$WORK/tools" /bin/sh "$WORK/prog/run-rmail.sh" > "$WORK/out" 2>&1
    status=$?
}
fresh() { rm -rf "$WORK/bin"; mkdir -p "$WORK/bin"; }
started_on() {  # the interpreter that ran rmail.lua, not just the probe
    grep -v ' -e$' "$WORK/used" | cut -d' ' -f1 | head -n 1
}

echo ""
fresh; stand_in lua5.1 "$LUA51"
run_case
if [ "$status" != 0 ] && grep -q "rmail needs Lua 5.2 or later, or LuaJIT; this machine has only lua5.1" "$WORK/out" \
   && ! grep -q "expected near" "$WORK/out" && [ -z "$(started_on)" ]; then
    ok "only lua5.1: refused, naming it and what rmail needs"
else
    note_fail "only lua5.1: status $status, said [$(tr '\n' ' ' < "$WORK/out")], started on [$(started_on)]"
fi

fresh; stand_in lua "$LUA51"
run_case
if [ "$status" != 0 ] && grep -q "this machine has only lua$" "$WORK/out" && grep -q "opkg install lua5.3 luasocket5.3" "$WORK/out"; then
    ok "a plain lua that is a 5.1, as on OpenWrt: refused, with the packages to add"
else
    note_fail "lua as 5.1: status $status, said [$(tr '\n' ' ' < "$WORK/out")]"
fi

fresh; stand_in lua5.1 "$LUA51"; stand_in lua5.3 "$LUA53"
run_case
if [ "$(started_on)" = lua5.3 ] && grep -q "usage: rmail.lua" "$WORK/out" && ! grep -q '^lua5.1' "$WORK/used"; then
    ok "lua5.1 and lua5.3: rmail.lua runs on lua5.3, and lua5.1 is never tried"
else
    note_fail "lua5.1 + lua5.3: started on [$(started_on)], calls [$(tr '\n' ',' < "$WORK/used")], said [$(head -2 "$WORK/out" | tr '\n' ' ')]"
fi

fresh; stand_in lua5.1 "$LUA51"; stand_in lua "$LUA53"
run_case
if [ "$(started_on)" = lua ] && grep -q "usage: rmail.lua" "$WORK/out"; then
    ok "a plain lua that reads a goto is used, after lua5.1 is passed over"
else
    note_fail "lua as 5.3: started on [$(started_on)], said [$(head -2 "$WORK/out" | tr '\n' ' ')]"
fi

if [ -n "$LUAJIT" ]; then
    fresh; stand_in luajit "$LUAJIT"; stand_in lua5.1 "$LUA51"
    run_case
    [ "$(started_on)" = luajit ] && grep -q "usage: rmail.lua" "$WORK/out" \
        && ok "luajit is used" || note_fail "luajit: started on [$(started_on)], said [$(head -2 "$WORK/out" | tr '\n' ' ')]"
else
    info "no luajit here: its case is not run"
fi

fresh
run_case
[ "$status" != 0 ] && grep -q "no lua interpreter found" "$WORK/out" \
    && ok "none at all: no lua interpreter found, as before" || note_fail "none: said [$(tr '\n' ' ' < "$WORK/out")]"

fresh; stand_in lua5.1 "$LUA51"
mkdir -p "$WORK/prog/deps/lua/bin"
printf '#!/bin/sh\necho "compiled $1" >> "%s/used"\nexec "%s" "$@"\n' "$WORK" "$LUA53" > "$WORK/prog/deps/lua/bin/lua"
chmod +x "$WORK/prog/deps/lua/bin/lua"
run_case
[ "$(started_on)" = compiled ] && grep -q "usage: rmail.lua" "$WORK/out" \
    && ok "a compiled deps/lua/bin/lua is used first, as before" \
    || note_fail "compiled: started on [$(started_on)], said [$(head -2 "$WORK/out" | tr '\n' ' ')]"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
