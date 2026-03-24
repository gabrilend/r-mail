#!/bin/sh
# run-rmail.sh — start the rmail daemon
# auto-detects whether Lua was compiled locally by install.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -x "$SCRIPT_DIR/deps/lua/bin/lua" ]; then
    exec "$SCRIPT_DIR/deps/lua/bin/lua" "$SCRIPT_DIR/rmail.lua" "$@"
fi

for _lua in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
    if command -v "$_lua" >/dev/null 2>&1; then
        exec "$_lua" "$SCRIPT_DIR/rmail.lua" "$@"
    fi
done

echo "error: no lua interpreter found (tried lua5.4, luajit, lua5.3, lua5.2, lua5.1, lua)" >&2
exit 1
