#!/bin/sh
# run-rmail.sh — start the rmail daemon
# auto-detects whether Lua was compiled locally by install.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -x "$SCRIPT_DIR/deps/lua/bin/lua" ]; then
    exec "$SCRIPT_DIR/deps/lua/bin/lua" "$SCRIPT_DIR/rmail.lua" "$@"
else
    exec lua "$SCRIPT_DIR/rmail.lua" "$@"
fi
