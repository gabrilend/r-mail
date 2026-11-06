#!/bin/sh
# run-rmail.sh — start the rmail daemon
# auto-detects whether Lua was compiled locally by install.sh
#
# Without a compiled Lua, the first interpreter on the PATH that can read
# rmail.lua is used.  rmail.lua uses `goto`, which Lua 5.1 does not have
# (Lua 5.2 and later do, and so does LuaJIT), so a Lua 5.1 is passed over:
# started on it, the daemon would stop at once with a syntax error naming a
# line of rmail.lua, which says nothing about the real cause.  OpenWrt's
# plain `lua` is a Lua 5.1, kept for its web interface (#905).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -x "$SCRIPT_DIR/deps/lua/bin/lua" ]; then
    exec "$SCRIPT_DIR/deps/lua/bin/lua" "$SCRIPT_DIR/rmail.lua" "$@"
fi

passed_over=""
for _lua in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
    command -v "$_lua" >/dev/null 2>&1 || continue
    # Can it read a goto?  Compiled, not run.  (Lua 5.1's load takes no
    # string either, so it fails this twice over.)
    if "$_lua" -e 'assert(load("goto done ::done::"))' >/dev/null 2>&1; then
        exec "$_lua" "$SCRIPT_DIR/rmail.lua" "$@"
    fi
    passed_over="${passed_over:+$passed_over, }$_lua"
done

if [ -n "$passed_over" ]; then
    echo "error: rmail needs Lua 5.2 or later, or LuaJIT; this machine has only $passed_over" >&2
    echo "  (Lua 5.1 has no goto, which rmail.lua uses.  On OpenWrt: opkg install lua5.3 luasocket5.3)" >&2
else
    echo "error: no lua interpreter found (tried lua5.4, luajit, lua5.3, lua5.2, lua5.1, lua)" >&2
fi
exit 1
