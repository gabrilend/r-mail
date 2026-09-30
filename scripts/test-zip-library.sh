#!/bin/sh
# test-zip-library.sh — check that rmail's copy of the shared zip library is the library, and that it works on rmail's Lua
#
# rmail packs and reads attachment zips with the shared zip library
# (my-libs/zip, rmail #405), carried as a copy in libs/ so rmail still
# works when installed on a machine without my-libs.  A copy can drift: an
# edit made here, or the library moving on without the copy being made
# again.  This test fails on either, and then runs the library's own
# checks (round trips, hand-built hostile zips, broken compression tables)
# under the Lua rmail itself runs on: the one install.sh builds into
# deps/lua when present, else lua5.4.
#
# A development check: it needs the library's folder.  To bring the copy
# back in line: <library>/install-into libs/
#
# Usage:
#   scripts/test-zip-library.sh                  # this checkout, the usual library folder
#   scripts/test-zip-library.sh /path            # another checkout
#   scripts/test-zip-library.sh /path /library   # and another library folder
#
# Exit status is 0 when the copy matches and every check passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LIBRARY="${2:-/home/ritz/programming/ai-stuff/my-libs/zip}"

echo ""
echo "rmail zip library test"
echo "  checkout: $DIR"
echo "  library:  $LIBRARY"
echo ""

status=0
if ! "$LIBRARY/check-copy" "$DIR/libs" "$LIBRARY"; then
    status=1
fi

# The Lua rmail runs on: its own build first, as run-rmail.sh chooses.
if [ -x "$DIR/deps/lua/bin/lua" ]; then
    LUA="$DIR/deps/lua/bin/lua"
else
    LUA=$(command -v lua5.4)
fi
if [ -z "$LUA" ]; then
    echo "no Lua 5.4 to run the library's checks on"
    exit 1
fi
output=$("$LUA" "$LIBRARY/tests/test-zip.lua" "$LIBRARY" "/tmp/rmail/tests/zip-library" 2>&1)
counts=$(printf '%s\n' "$output" | grep '^counts ' | tail -n 1)
# No counts line: the checks crashed part-way; shown whole.
if [ -z "$counts" ]; then
    echo "the library's checks crashed on $LUA:"
    printf '%s\n' "$output"
    exit 1
fi
passed=$(echo "$counts" | cut -d' ' -f2)
failed=$(echo "$counts" | cut -d' ' -f3)
echo "library checks on $LUA: $passed passed, $failed failed"
printf '%s\n' "$output" | grep 'FAIL' || true
if [ "$failed" -ne 0 ]; then
    status=1
fi
exit "$status"
