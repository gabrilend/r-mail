#!/bin/sh
# test-license-harvest.sh — check that compiling a dependency keeps its licence
#
# install.sh builds eight third-party projects from source and drops the
# results into deps/ and libs/.  Each of those projects requires that a binary
# redistribution carry its copyright notice, and the portable-drive generators
# do redistribute binaries.  install.sh therefore harvests each project's
# licence file out of its unpacked source tree at build time.
#
# This script proves that harvesting still works, without downloading or
# compiling anything: it lifts the real harvest routine straight out of
# install.sh, points it at synthetic source trees shaped like the real ones,
# and checks what lands.  Lifting rather than copying is deliberate — a
# duplicated copy of the routine would drift away from the original and start
# passing while the real thing was broken.
#
# Usage:
#   scripts/test-license-harvest.sh          # use the enclosing checkout
#   scripts/test-license-harvest.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

INSTALLER="$DIR/scripts/install.sh"

# RAM-backed scratch space, per project convention.  Rebuilt every run so a
# previous run's leftovers can never make a broken case look like a pass.
WORK="/tmp/rmail/tests/license-harvest"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail licence-harvest test"
echo "  checkout: $DIR"
echo ""

if [ ! -f "$INSTALLER" ]; then
    note_fail "no install script at $INSTALLER"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# ---- lift the routine out of the installer --------------------------------
#
# sed prints from the function's opening line to the first line that is a bare
# closing brace, which is how every function in install.sh ends.  If install.sh
# is ever reformatted so that is no longer true, this extraction fails loudly
# below rather than silently testing nothing.

ROUTINE="$WORK/save_notice.sh"
sed -n '/^save_notice() {$/,/^}$/p' "$INSTALLER" > "$ROUTINE"

if [ ! -s "$ROUTINE" ]; then
    note_fail "could not lift save_notice out of install.sh"
    info "the function may have been renamed or reindented"
    exit 1
fi
ok "lifted the harvest routine from install.sh ($(wc -l < "$ROUTINE") lines)"

# ---- stand in for the installer's environment -----------------------------
#
# The routine expects DEPS and BUILD to point somewhere, and expects the
# installer's three message helpers to exist.  Nothing else.

DEPS="$WORK/deps"
BUILD="$WORK/build"
mkdir -p "$DEPS" "$BUILD"

warn() { printf "       (warned: %s)\n" "$*"; }
# `ok` and `info` are already defined above and are close enough in shape.

. "$ROUTINE"

# ---- synthetic source trees ------------------------------------------------
#
# Each mirrors where the real upstream keeps its terms.  The point is the
# layout, not the wording, so the contents are just markers we can grep for.

mkdir -p "$BUILD/libnatpmp-fake"
echo "BSD 3-clause, libnatpmp, Thomas Bernard" > "$BUILD/libnatpmp-fake/LICENSE"

mkdir -p "$BUILD/openssl-fake"
echo "Apache License 2.0, OpenSSL" > "$BUILD/openssl-fake/LICENSE.txt"

# miniupnpc keeps its licence one level down, inside the subproject directory.
mkdir -p "$BUILD/miniupnp-fake/miniupnpc"
echo "BSD 3-clause, miniupnpc" > "$BUILD/miniupnp-fake/miniupnpc/LICENSE"

# Info-ZIP spells it the British way in some releases; the search covers both.
mkdir -p "$BUILD/zip-fake"
echo "Info-ZIP licence" > "$BUILD/zip-fake/LICENCE"

# Lua ships no standalone licence file at all — the terms live in the manual
# and at the foot of the public header, both named explicitly by install.sh.
mkdir -p "$BUILD/lua-fake/doc" "$BUILD/lua-fake/src"
echo "<html>MIT terms for Lua</html>" > "$BUILD/lua-fake/doc/readme.html"
echo "/* Copyright (C) 1994-2023 Lua.org, PUC-Rio. */" > "$BUILD/lua-fake/src/lua.h"

# A project that genuinely has no notice anywhere — the case that must warn.
mkdir -p "$BUILD/bare-fake/src"
echo "int main(void){return 0;}" > "$BUILD/bare-fake/src/main.c"

# ---- cases -----------------------------------------------------------------

check_kept() {
    # check_kept NAME EXPECTED_FILENAME
    if [ -f "$DEPS/licenses/$1/$2" ]; then
        ok "$1: kept $2"
    else
        note_fail "$1: expected $2 in deps/licenses/$1/, not there"
        info "found instead: $(ls "$DEPS/licenses/$1" 2>/dev/null | tr '\n' ' ')"
    fi
}

echo ""
info "case: licence at the root of the source tree"
save_notice libnatpmp "$BUILD/libnatpmp-fake" >/dev/null
check_kept libnatpmp LICENSE

info "case: licence with an extension"
save_notice openssl "$BUILD/openssl-fake" >/dev/null
check_kept openssl LICENSE.txt

info "case: licence one directory down"
save_notice miniupnpc "$BUILD/miniupnp-fake/miniupnpc" >/dev/null
check_kept miniupnpc LICENSE

info "case: British spelling"
save_notice zip "$BUILD/zip-fake" >/dev/null
check_kept zip LICENCE

info "case: no standalone licence, paths named explicitly"
save_notice lua "$BUILD/lua-fake" doc/readme.html src/lua.h >/dev/null
check_kept lua readme.html
check_kept lua lua.h

echo ""
info "case: nothing to find — must warn and report failure"
if save_notice bare "$BUILD/bare-fake" >/dev/null; then
    note_fail "bare tree reported success; a binary would ship with no notice"
else
    ok "bare tree reported failure, as it should"
fi

info "case: source tree missing entirely — must warn and report failure"
if save_notice ghost "$BUILD/does-not-exist" >/dev/null; then
    note_fail "missing tree reported success"
else
    ok "missing tree reported failure, as it should"
fi

info "case: a failed harvest leaves no empty directory behind"
if [ -d "$DEPS/licenses/bare" ]; then
    note_fail "empty deps/licenses/bare/ left behind; reads as 'nothing required'"
else
    ok "no empty directory left behind"
fi

# ---- rebuilding must not carry the previous version's notice forward -------
#
# install.sh --force recompiles against whatever version is pinned now.  If a
# harvest from the previously pinned version survived, it would misdescribe
# the binary actually shipped, and its mere presence would be counted as a
# successful harvest — masking a new source tree that has no notice at all.

echo ""
info "case: a rebuilt dependency drops the old version's notice"
mkdir -p "$BUILD/bumped-fake"
echo "notice for version one" > "$BUILD/bumped-fake/COPYING"
save_notice bumped "$BUILD/bumped-fake" >/dev/null

rm -f "$BUILD/bumped-fake/COPYING"
echo "notice for version two" > "$BUILD/bumped-fake/LICENSE"
save_notice bumped "$BUILD/bumped-fake" >/dev/null

if [ -f "$DEPS/licenses/bumped/COPYING" ]; then
    note_fail "version one's notice survived the rebuild"
else
    ok "version one's notice was dropped"
fi
check_kept bumped LICENSE

info "case: a rebuild against a tree that lost its notice must fail"
rm -f "$BUILD/bumped-fake/LICENSE"
if save_notice bumped "$BUILD/bumped-fake" >/dev/null; then
    note_fail "rebuild reported success while the tree had no notice"
    info "a leftover notice from an earlier run is masking the gap"
else
    ok "rebuild reported failure, as it should"
fi

# ---- every dependency install.sh compiles should have a call ---------------
#
# Catches the most likely future regression: somebody adds a ninth compiled
# dependency and forgets that its notice has to travel with the binary.

echo ""
info "case: every compiled dependency is harvested"
for dep in lua openssl luasocket miniupnpc libnatpmp zip unzip; do
    if grep -q "save_notice $dep " "$INSTALLER"; then
        ok "$dep has a harvest call in install.sh"
    else
        note_fail "$dep is compiled by install.sh but never harvested"
    fi
done

echo ""
if [ "$FAILURES" -eq 0 ]; then
    ok "all cases passed"
    rm -rf "$WORK"
    exit 0
fi

fail "$FAILURES case(s) failed — scratch kept at $WORK for inspection"
exit 1
